use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto;

pub const SESSION_COOKIE_NAME: &str = "xvault_session";
/// A session dies after this much inactivity...
pub const SESSION_IDLE_MS: i64 = 12 * 60 * 60 * 1000;
/// ...and in any case this long after sign-in, however active it is.
pub const SESSION_ABSOLUTE_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// Oldest sessions are evicted beyond this many per user.
pub const MAX_SESSIONS_PER_USER: usize = 10;

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Locks a mutex, recovering the data if a previous holder panicked, so one
/// panic never turns into a permanent outage of every later request.
pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Debug, Clone)]
pub struct Session {
    pub user_id: i64,
    pub login_id: String,
    pub created_at: i64,
    pub last_seen: i64,
}

impl Session {
    pub fn expires_at(&self) -> i64 {
        (self.last_seen + SESSION_IDLE_MS).min(self.created_at + SESSION_ABSOLUTE_MS)
    }
}

#[derive(Default)]
pub struct SessionStore {
    inner: Mutex<HashMap<String, Session>>,
}

impl SessionStore {
    pub fn create(&self, user_id: i64, login_id: &str) -> (String, i64) {
        let token = crypto::random_token();
        let now = now_ms();
        let session = Session {
            user_id,
            login_id: login_id.to_string(),
            created_at: now,
            last_seen: now,
        };
        let expires_at = session.expires_at();
        let mut store = lock(&self.inner);

        // Cap concurrent sessions per user: evict the oldest ones.
        let mut mine: Vec<(String, i64)> = store
            .iter()
            .filter(|(_, s)| s.user_id == user_id)
            .map(|(t, s)| (t.clone(), s.created_at))
            .collect();
        if mine.len() >= MAX_SESSIONS_PER_USER {
            mine.sort_by_key(|(_, created)| *created);
            for (old, _) in mine.iter().take(mine.len() + 1 - MAX_SESSIONS_PER_USER) {
                store.remove(old);
            }
        }

        store.insert(token.clone(), session);
        (token, expires_at)
    }

    /// Returns the session if still valid, refreshing its idle timer (never
    /// beyond the absolute lifetime).
    pub fn get(&self, token: &str) -> Option<Session> {
        let mut store = lock(&self.inner);
        let now = now_ms();
        let session = store.get_mut(token)?;
        if session.expires_at() <= now {
            store.remove(token);
            return None;
        }
        session.last_seen = now;
        Some(session.clone())
    }

    pub fn destroy(&self, token: &str) {
        lock(&self.inner).remove(token);
    }

    /// Revokes every session of a user, optionally keeping the current one.
    /// Called on password change, account recovery and account deletion.
    pub fn revoke_user(&self, user_id: i64, keep_token: Option<&str>) {
        lock(&self.inner).retain(|token, session| {
            session.user_id != user_id || Some(token.as_str()) == keep_token
        });
    }

    pub fn cleanup(&self) {
        let now = now_ms();
        lock(&self.inner).retain(|_, session| session.expires_at() > now);
    }
}

// ---------------------------------------------------------------------------
// Brute-force protection
// ---------------------------------------------------------------------------

/// How long an entry is remembered after its last failure.
const FAILURE_MEMORY_MS: i64 = 24 * 60 * 60 * 1000;
const BASE_LOCK_MS: i64 = 60 * 1000;
const MAX_LOCK_MS: i64 = 60 * 60 * 1000;
const MAX_ENTRIES: usize = 100_000;

/// Failure budgets per key kind.
pub const LIMIT_ACCOUNT_IP: u32 = 5;
pub const LIMIT_IP: u32 = 30;
pub const LIMIT_ACCOUNT: u32 = 100;
pub const LIMIT_USER_REAUTH: u32 = 5;

#[derive(Debug, Clone, Default)]
struct Entry {
    failures: u32,
    locked_until: i64,
    last_failure: i64,
}

/// Exponential-backoff limiter keyed by arbitrary strings ("ip:…",
/// "acct:…", "acct-ip:…", "user:…"). Once `limit` failures accumulate, each
/// further failure doubles the lock (1 min, 2 min, … capped at 1 h).
/// Attempts made *while locked* are rejected without touching the entry, so
/// an attacker cannot extend a lock indefinitely by poking it.
#[derive(Default)]
pub struct RateLimiter {
    inner: Mutex<HashMap<String, Entry>>,
}

#[derive(Debug, Clone, Copy)]
pub struct Blocked {
    pub retry_after_ms: i64,
}

impl RateLimiter {
    /// Fails if any of the keys is currently locked.
    pub fn check(&self, keys: &[String]) -> Result<(), Blocked> {
        let store = lock(&self.inner);
        let now = now_ms();
        let retry_after_ms = keys
            .iter()
            .filter_map(|key| store.get(key))
            .map(|entry| entry.locked_until - now)
            .max()
            .unwrap_or(0);
        if retry_after_ms > 0 {
            Err(Blocked { retry_after_ms })
        } else {
            Ok(())
        }
    }

    /// Records a failure on each `(key, limit)`; returns the smallest number
    /// of attempts left before a lock kicks in.
    pub fn fail(&self, keys: &[(String, u32)]) -> u32 {
        let mut store = lock(&self.inner);
        let now = now_ms();
        if store.len() >= MAX_ENTRIES {
            store.retain(|_, e| e.locked_until > now || now - e.last_failure < BASE_LOCK_MS);
        }
        let mut left = u32::MAX;
        for (key, limit) in keys {
            let entry = store.entry(key.clone()).or_default();
            if now - entry.last_failure > FAILURE_MEMORY_MS {
                *entry = Entry::default();
            }
            entry.failures += 1;
            entry.last_failure = now;
            if entry.failures >= *limit {
                let exponent = (entry.failures - limit).min(10);
                let lock_ms = (BASE_LOCK_MS << exponent).min(MAX_LOCK_MS);
                entry.locked_until = now + lock_ms;
            }
            left = left.min(limit.saturating_sub(entry.failures));
        }
        left
    }

    pub fn success(&self, keys: &[String]) {
        let mut store = lock(&self.inner);
        for key in keys {
            store.remove(key);
        }
    }

    pub fn cleanup(&self) {
        let now = now_ms();
        lock(&self.inner)
            .retain(|_, e| e.locked_until > now || now - e.last_failure <= FAILURE_MEMORY_MS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_after_limit_and_rejects_without_extending() {
        let limiter = RateLimiter::default();
        let key = "acct:X".to_string();
        for _ in 0..3 {
            assert!(limiter.check(&[key.clone()]).is_ok());
            limiter.fail(&[(key.clone(), 3)]);
        }
        let blocked = limiter.check(&[key.clone()]).unwrap_err();
        assert!(blocked.retry_after_ms > 0 && blocked.retry_after_ms <= BASE_LOCK_MS);
        // A check while locked does not extend the lock.
        let again = limiter.check(&[key.clone()]).unwrap_err();
        assert!(again.retry_after_ms <= blocked.retry_after_ms);
        limiter.success(&[key.clone()]);
        assert!(limiter.check(&[key]).is_ok());
    }

    #[test]
    fn sessions_revocation_and_cap() {
        let store = SessionStore::default();
        let (keep, _) = store.create(1, "A");
        let (other, _) = store.create(1, "A");
        let (foreign, _) = store.create(2, "B");
        store.revoke_user(1, Some(&keep));
        assert!(store.get(&keep).is_some());
        assert!(store.get(&other).is_none());
        assert!(store.get(&foreign).is_some());

        for _ in 0..(MAX_SESSIONS_PER_USER * 2) {
            store.create(3, "C");
        }
        let count = lock(&store.inner).values().filter(|s| s.user_id == 3).count();
        assert_eq!(count, MAX_SESSIONS_PER_USER);
    }
}
