use std::path::Path;
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rusqlite::{params, Connection, OptionalExtension};

use crate::crypto::{self, KdfParams};
use crate::session::lock;

/// Current on-disk format. Everything is encrypted in the browser; the
/// server stores Argon2id hashes of client proofs and opaque blobs only.
const SCHEMA_VERSION: i64 = 3;

const SCHEMA: &str = r#"
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      login_id TEXT UNIQUE NOT NULL,
      auth_hash TEXT NOT NULL,
      kdf TEXT NOT NULL,
      name TEXT NOT NULL DEFAULT 'My Vault',
      logo TEXT DEFAULT NULL,
      recovery_enabled INTEGER NOT NULL DEFAULT 0,
      master_key_enabled INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS vaults (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL UNIQUE,
      encrypted_data TEXT NOT NULL,
      vault_key_wrapped TEXT NOT NULL,
      recovery_key_wrapped TEXT,
      recovery_auth_hash TEXT,
      master_key_wrapped TEXT,
      master_auth_hash TEXT,
      revision INTEGER NOT NULL DEFAULT 1,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TRIGGER IF NOT EXISTS update_user_timestamp
    AFTER UPDATE ON users
    BEGIN
      UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

    CREATE TRIGGER IF NOT EXISTS update_vault_timestamp
    AFTER UPDATE ON vaults
    BEGIN
      UPDATE vaults SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;
"#;

#[derive(Debug, Clone, serde::Serialize)]
pub struct PublicUser {
    pub id: i64,
    pub login_id: String,
    pub name: String,
    pub logo: Option<String>,
    pub recovery_enabled: bool,
    pub master_key_enabled: bool,
}

const USER_COLUMNS: &str = "id, login_id, name, logo, recovery_enabled, master_key_enabled";

fn map_user_row(row: &rusqlite::Row) -> rusqlite::Result<PublicUser> {
    Ok(PublicUser {
        id: row.get(0)?,
        login_id: row.get(1)?,
        name: row.get(2)?,
        logo: row.get(3)?,
        recovery_enabled: row.get::<_, i64>(4)? != 0,
        master_key_enabled: row.get::<_, i64>(5)? != 0,
    })
}

/// Everything the browser needs to decrypt its vault (all opaque blobs).
#[derive(Debug, Clone)]
pub struct VaultRecord {
    pub kdf: serde_json::Value,
    pub vault_key_wrapped: String,
    pub encrypted_data: String,
    pub revision: i64,
}

/// Key material produced by the browser for a password (re)set.
pub struct E2eKeys<'a> {
    pub auth_key: &'a str,
    pub kdf: &'a KdfParams,
    pub vault_key_wrapped: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryMethod {
    Phrase,
    MasterKey,
}

impl RecoveryMethod {
    fn columns(self) -> (&'static str, &'static str, &'static str) {
        match self {
            RecoveryMethod::Phrase => ("recovery_key_wrapped", "recovery_auth_hash", "recovery_enabled"),
            RecoveryMethod::MasterKey => ("master_key_wrapped", "master_auth_hash", "master_key_enabled"),
        }
    }
}

#[derive(Debug)]
pub enum DbError {
    /// Wrong proof / unknown account (deliberately unspecific).
    Unauthorized,
    /// Optimistic concurrency failure on vault save.
    Conflict(i64),
    /// Username already registered.
    Taken,
    NotFound,
    /// Internal failure: logged server-side, never sent to clients.
    Internal(String),
}

impl From<rusqlite::Error> for DbError {
    fn from(err: rusqlite::Error) -> Self {
        DbError::Internal(err.to_string())
    }
}

type DbResult<T> = Result<T, DbError>;

pub struct Database {
    conn: Mutex<Connection>,
    server_secret: Vec<u8>,
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = path.parent() {
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

fn hash_and_kdf(keys: &E2eKeys) -> DbResult<(String, String)> {
    let auth_hash = crypto::hash_secret(keys.auth_key).map_err(DbError::Internal)?;
    let kdf = serde_json::to_string(keys.kdf).map_err(|e| DbError::Internal(e.to_string()))?;
    Ok((auth_hash, kdf))
}

impl Database {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(path).map_err(|e| e.to_string())?;
        restrict_permissions(path);

        // Databases from xVault 1.x/2.x (server-side encryption) are not
        // supported: refuse to start instead of misreading them.
        let legacy: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name = 'password_hash'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n > 0)
            .unwrap_or(false);
        if legacy {
            return Err(format!(
                "{} uses the pre-3.0 format (server-side encryption). Archive it and start with a new database file.",
                path.display()
            ));
        }

        conn.execute_batch(SCHEMA).map_err(|e| e.to_string())?;
        conn.pragma_update(None, "journal_mode", "WAL").map_err(|e| e.to_string())?;
        conn.pragma_update(None, "secure_delete", "ON").map_err(|e| e.to_string())?;
        conn.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?1)",
            params![SCHEMA_VERSION.to_string()],
        )
        .map_err(|e| e.to_string())?;

        let secret: Option<String> = conn
            .query_row("SELECT value FROM meta WHERE key = 'server_secret'", [], |r| r.get(0))
            .optional()
            .map_err(|e| e.to_string())?;
        let server_secret = match secret.and_then(|s| hex::decode(s).ok()) {
            Some(bytes) if bytes.len() == 32 => bytes,
            _ => {
                let bytes = crypto::random_bytes::<32>().to_vec();
                conn.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES ('server_secret', ?1)",
                    params![hex::encode(&bytes)],
                )
                .map_err(|e| e.to_string())?;
                bytes
            }
        };

        Ok(Database {
            conn: Mutex::new(conn),
            server_secret,
        })
    }

    // -----------------------------------------------------------------------
    // Accounts
    // -----------------------------------------------------------------------

    /// KDF parameters for a login ID; deterministic fake ones when the
    /// account does not exist (no enumeration).
    pub fn prelogin(&self, login_id: &str) -> DbResult<KdfParams> {
        let conn = lock(&self.conn);
        let kdf: Option<String> = conn
            .query_row("SELECT kdf FROM users WHERE login_id = ?1", params![login_id], |r| r.get(0))
            .optional()?;
        match kdf {
            Some(kdf) => serde_json::from_str(&kdf)
                .map_err(|_| DbError::Internal("stored KDF params are corrupted".into())),
            None => Ok(KdfParams::fake(&self.server_secret, login_id)),
        }
    }

    /// Creates an account under a (normalized) username chosen by the user.
    pub fn create_user(&self, username: &str, keys: &E2eKeys, encrypted_data: &str) -> DbResult<i64> {
        let (auth_hash, kdf) = hash_and_kdf(keys)?;
        let mut conn = lock(&self.conn);
        let tx = conn.transaction()?;
        let inserted = tx.execute(
            "INSERT INTO users (login_id, auth_hash, kdf) VALUES (?1, ?2, ?3)",
            params![username, auth_hash, kdf],
        );
        match inserted {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(err, _)) if err.code == rusqlite::ErrorCode::ConstraintViolation => {
                return Err(DbError::Taken);
            }
            Err(err) => return Err(err.into()),
        }
        let user_id = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO vaults (user_id, encrypted_data, vault_key_wrapped) VALUES (?1, ?2, ?3)",
            params![user_id, encrypted_data, keys.vault_key_wrapped],
        )?;
        tx.commit()?;
        Ok(user_id)
    }

    /// Sign-in: verifies the client auth key (constant work for unknown IDs).
    pub fn authenticate(&self, login_id: &str, auth_key: &str) -> DbResult<PublicUser> {
        let found = {
            let conn = lock(&self.conn);
            conn.query_row(
                &format!("SELECT {USER_COLUMNS}, auth_hash FROM users WHERE login_id = ?1"),
                params![login_id],
                |row| Ok((map_user_row(row)?, row.get::<_, String>(6)?)),
            )
            .optional()?
        };
        match found {
            Some((user, hash)) if crypto::verify_secret(auth_key, &hash) => Ok(user),
            Some(_) => Err(DbError::Unauthorized),
            None => {
                crypto::dummy_verify(auth_key);
                Err(DbError::Unauthorized)
            }
        }
    }

    pub fn get_user_profile(&self, user_id: i64) -> DbResult<PublicUser> {
        let conn = lock(&self.conn);
        conn.query_row(
            &format!("SELECT {USER_COLUMNS} FROM users WHERE id = ?1"),
            params![user_id],
            map_user_row,
        )
        .optional()?
        .ok_or(DbError::NotFound)
    }

    pub fn update_user_profile(
        &self,
        user_id: i64,
        name: Option<&str>,
        logo: Option<Option<&str>>,
    ) -> DbResult<()> {
        let conn = lock(&self.conn);
        if let Some(name) = name {
            conn.execute("UPDATE users SET name = ?1 WHERE id = ?2", params![name, user_id])?;
        }
        if let Some(logo) = logo {
            conn.execute("UPDATE users SET logo = ?1 WHERE id = ?2", params![logo, user_id])?;
        }
        Ok(())
    }

    /// Re-authentication for sensitive operations.
    pub fn verify_auth_key(&self, user_id: i64, auth_key: &str) -> DbResult<()> {
        let hash: Option<String> = {
            let conn = lock(&self.conn);
            conn.query_row("SELECT auth_hash FROM users WHERE id = ?1", params![user_id], |r| r.get(0))
                .optional()?
        };
        match hash {
            Some(hash) if crypto::verify_secret(auth_key, &hash) => Ok(()),
            _ => Err(DbError::Unauthorized),
        }
    }

    fn replace_password(conn: &mut Connection, user_id: i64, keys: &E2eKeys) -> DbResult<()> {
        let (auth_hash, kdf) = hash_and_kdf(keys)?;
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE users SET auth_hash = ?1, kdf = ?2 WHERE id = ?3",
            params![auth_hash, kdf, user_id],
        )?;
        tx.execute(
            "UPDATE vaults SET vault_key_wrapped = ?1 WHERE user_id = ?2",
            params![keys.vault_key_wrapped, user_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn change_password(&self, user_id: i64, current_auth_key: &str, keys: &E2eKeys) -> DbResult<()> {
        self.verify_auth_key(user_id, current_auth_key)?;
        let mut conn = lock(&self.conn);
        Self::replace_password(&mut conn, user_id, keys)
    }

    pub fn delete_user(&self, user_id: i64) -> DbResult<()> {
        let conn = lock(&self.conn);
        if conn.execute("DELETE FROM users WHERE id = ?1", params![user_id])? == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Vault (opaque blobs + optimistic concurrency)
    // -----------------------------------------------------------------------

    pub fn get_vault(&self, user_id: i64) -> DbResult<VaultRecord> {
        let conn = lock(&self.conn);
        let (kdf, wrapped, data, revision): (String, String, String, i64) = conn
            .query_row(
                "SELECT u.kdf, v.vault_key_wrapped, v.encrypted_data, v.revision \
                 FROM users u JOIN vaults v ON v.user_id = u.id WHERE u.id = ?1",
                params![user_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?
            .ok_or(DbError::NotFound)?;
        Ok(VaultRecord {
            kdf: serde_json::from_str(&kdf).map_err(|e| DbError::Internal(e.to_string()))?,
            vault_key_wrapped: wrapped,
            encrypted_data: data,
            revision,
        })
    }

    /// Replaces the encrypted vault only if nobody saved since `base_revision`.
    pub fn save_vault(&self, user_id: i64, encrypted_data: &str, base_revision: i64) -> DbResult<i64> {
        let conn = lock(&self.conn);
        let changes = conn.execute(
            "UPDATE vaults SET encrypted_data = ?1, revision = revision + 1 WHERE user_id = ?2 AND revision = ?3",
            params![encrypted_data, user_id, base_revision],
        )?;
        let current: Option<i64> = conn
            .query_row("SELECT revision FROM vaults WHERE user_id = ?1", params![user_id], |r| r.get(0))
            .optional()?;
        match (changes, current) {
            (1, Some(revision)) => Ok(revision),
            (_, Some(revision)) => Err(DbError::Conflict(revision)),
            (_, None) => Err(DbError::NotFound),
        }
    }

    // -----------------------------------------------------------------------
    // Recovery (phrase / master-key file)
    // -----------------------------------------------------------------------

    pub fn set_recovery(
        &self,
        user_id: i64,
        method: RecoveryMethod,
        material: Option<(&str, &str)>,
    ) -> DbResult<()> {
        let (wrapped_col, hash_col, flag_col) = method.columns();
        let (proof_hash, wrapped) = match material {
            Some((proof, wrapped)) => (
                Some(crypto::hash_secret(proof).map_err(DbError::Internal)?),
                Some(wrapped.to_string()),
            ),
            None => (None, None),
        };
        let enabled = i64::from(proof_hash.is_some());
        let mut conn = lock(&self.conn);
        let tx = conn.transaction()?;
        tx.execute(
            &format!("UPDATE vaults SET {wrapped_col} = ?1, {hash_col} = ?2 WHERE user_id = ?3"),
            params![wrapped, proof_hash, user_id],
        )?;
        tx.execute(
            &format!("UPDATE users SET {flag_col} = ?1 WHERE id = ?2"),
            params![enabled, user_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Verifies a recovery proof and returns (user id, wrapped vault key).
    /// Unknown account, disabled method and wrong proof all look the same.
    pub fn recovery_challenge(
        &self,
        login_id: &str,
        method: RecoveryMethod,
        proof: &str,
    ) -> DbResult<(i64, String)> {
        let (wrapped_col, hash_col, _) = method.columns();
        let row: Option<(i64, Option<String>, Option<String>)> = {
            let conn = lock(&self.conn);
            conn.query_row(
                &format!(
                    "SELECT u.id, v.{wrapped_col}, v.{hash_col} \
                     FROM users u JOIN vaults v ON v.user_id = u.id WHERE u.login_id = ?1"
                ),
                params![login_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
        };
        match row {
            Some((user_id, Some(wrapped), Some(hash))) => {
                if crypto::verify_secret(proof, &hash) {
                    Ok((user_id, wrapped))
                } else {
                    Err(DbError::Unauthorized)
                }
            }
            _ => {
                crypto::dummy_verify(proof);
                Err(DbError::Unauthorized)
            }
        }
    }

    /// Finishes a recovery: new password material replaces the old.
    pub fn recovery_complete(
        &self,
        login_id: &str,
        method: RecoveryMethod,
        proof: &str,
        keys: &E2eKeys,
    ) -> DbResult<i64> {
        let (user_id, _) = self.recovery_challenge(login_id, method, proof)?;
        let mut conn = lock(&self.conn);
        Self::replace_password(&mut conn, user_id, keys)?;
        Ok(user_id)
    }
}

/// Checks that a logo is a reasonably small raster data URL.
pub fn is_valid_logo(logo: &str) -> bool {
    const MAX: usize = 256 * 1024;
    let allowed = ["data:image/png;base64,", "data:image/jpeg;base64,", "data:image/webp;base64,", "data:image/gif;base64,"];
    logo.len() <= MAX
        && allowed.iter().any(|prefix| {
            logo.strip_prefix(prefix)
                .map(|b64| BASE64.decode(b64).is_ok())
                .unwrap_or(false)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_db(name: &str) -> (Database, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("xvault-test-{name}-{}.sqlite", std::process::id()));
        let _ = fs::remove_file(&path);
        (Database::open(&path).unwrap(), path)
    }

    fn kdf() -> KdfParams {
        KdfParams {
            algorithm: "argon2id".into(),
            salt: BASE64.encode([1u8; 16]),
            memory: 65536,
            iterations: 3,
            parallelism: 1,
        }
    }

    fn proof(c: char) -> String {
        std::iter::repeat(c).take(64).collect()
    }

    #[test]
    fn account_lifecycle() {
        let (db, path) = temp_db("e2e");
        let kdf = kdf();
        let auth = proof('a');
        let keys = E2eKeys { auth_key: &auth, kdf: &kdf, vault_key_wrapped: "wrapped-v1" };
        let login_id = "alice".to_string();
        let user_id = db.create_user(&login_id, &keys, "blob-v1").unwrap();
        assert!(matches!(db.create_user("alice", &keys, "other"), Err(DbError::Taken)));

        assert_eq!(db.prelogin(&login_id).unwrap(), kdf);
        assert!(db.authenticate(&login_id, &auth).is_ok());
        assert!(matches!(db.authenticate(&login_id, &proof('b')), Err(DbError::Unauthorized)));
        assert!(matches!(db.authenticate("NOPE0000", &auth), Err(DbError::Unauthorized)));

        // Optimistic concurrency.
        let record = db.get_vault(user_id).unwrap();
        assert_eq!(record.encrypted_data, "blob-v1");
        let rev = db.save_vault(user_id, "blob-v2", record.revision).unwrap();
        assert!(matches!(db.save_vault(user_id, "blob-stale", record.revision), Err(DbError::Conflict(r)) if r == rev));

        // Password change keeps the vault, swaps the wrap.
        let new_auth = proof('c');
        let new_keys = E2eKeys { auth_key: &new_auth, kdf: &kdf, vault_key_wrapped: "wrapped-v2" };
        assert!(db.change_password(user_id, &proof('z'), &new_keys).is_err());
        db.change_password(user_id, &auth, &new_keys).unwrap();
        assert!(db.authenticate(&login_id, &new_auth).is_ok());
        assert_eq!(db.get_vault(user_id).unwrap().vault_key_wrapped, "wrapped-v2");

        // Recovery phrase.
        let rproof = proof('d');
        db.set_recovery(user_id, RecoveryMethod::Phrase, Some((&rproof, "recovery-wrap"))).unwrap();
        assert!(db.recovery_challenge(&login_id, RecoveryMethod::Phrase, &proof('e')).is_err());
        assert!(db.recovery_challenge(&login_id, RecoveryMethod::MasterKey, &rproof).is_err());
        let (_, wrapped) = db.recovery_challenge(&login_id, RecoveryMethod::Phrase, &rproof).unwrap();
        assert_eq!(wrapped, "recovery-wrap");
        let final_auth = proof('f');
        let final_keys = E2eKeys { auth_key: &final_auth, kdf: &kdf, vault_key_wrapped: "wrapped-v3" };
        db.recovery_complete(&login_id, RecoveryMethod::Phrase, &rproof, &final_keys).unwrap();
        assert!(db.authenticate(&login_id, &final_auth).is_ok());

        db.delete_user(user_id).unwrap();
        assert!(db.get_vault(user_id).is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn unknown_prelogin_is_indistinguishable() {
        let (db, path) = temp_db("prelogin");
        let a = db.prelogin("UNKNOWN1").unwrap();
        assert_eq!(a, db.prelogin("UNKNOWN1").unwrap());
        assert_eq!(a.memory, crypto::DEFAULT_KDF_MEMORY_KIB);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn refuses_pre_3_0_databases() {
        let path = std::env::temp_dir().join(format!("xvault-test-old-{}.sqlite", std::process::id()));
        let _ = fs::remove_file(&path);
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE users (id INTEGER PRIMARY KEY, login_id TEXT, password_hash TEXT NOT NULL);")
            .unwrap();
        assert!(Database::open(&path).is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn logo_validation() {
        assert!(is_valid_logo("data:image/png;base64,iVBORw0KGgo="));
        assert!(!is_valid_logo("data:image/svg+xml;base64,PHN2Zz4="));
        assert!(!is_valid_logo("javascript:alert(1)"));
    }
}
