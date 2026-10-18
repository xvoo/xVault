# xVault

Self-hosted, **zero-knowledge** vault for 2FA codes (TOTP / HOTP / Steam) and
passwords. Everything is encrypted in the browser; the server only ever stores
ciphertext and never sees your password, your vault key or your secrets.

> **Fork of [Kisakay/xVault](https://github.com/Kisakay/xVault)** — a lightweight
> self-hosted 2FA manager by Anaïs Saraiva. This fork rebuilds the security model
> (end-to-end encryption), hardens the server, and adds password storage and a much
> larger set of importers. Original work © its author, MIT-licensed (see `LICENSE`).

## What this fork changes

- **End-to-end encryption.** Argon2id (64 MiB) → HKDF → AES-256-GCM, all in the
  browser. The login proof sent to the server is separate from the encryption key,
  and the server stores only an Argon2id hash of it plus opaque blobs.
- **Server hardening.** Brute-force limits per IP / account with exponential
  back-off, idle + absolute session lifetimes, `__Host-` `Secure` cookies, strict
  CSP / HSTS / anti-framing, CSRF protection, per-route body limits, no account
  enumeration, fail-closed configuration, optimistic concurrency on saves.
- **Accounts you name yourself.** Choose a username (3–32 chars), confirmation of
  the password, live strength meter, optional invitation code.
- **Recovery.** 24-word recovery phrase and an encrypted `.key` master file that
  survive password changes.
- **More than TOTP.** HOTP, Steam Guard, SHA-1/256/512, 4–10 digits, any period,
  Google Authenticator export QR, plus a password vault.
- **Universal import.** Proton Authenticator, Aegis, 2FAS, andOTP (incl. encrypted
  exports), FreeOTP+, Raivo, Authenticator Pro, LastPass Authenticator, Steam
  `.maFile`; Bitwarden (incl. password-protected), 1Password, KeePass XML, Proton
  Pass, Enpass, Keeper and browser CSV exports.
- **Client hygiene.** Auto-lock, clipboard wiped after 30 s, sanitized imports,
  encrypted backups (`xVault-V3`), self-hosted fonts (no third-party requests).
- **Hardened deployment.** Non-root, sandboxed systemd unit; read-only Docker
  container without capabilities.

Build and deployment details below.

## Stack

- **Frontend:** Svelte 5 + TypeScript + Vite + Material Web Components (MD3)
- **Backend:** Rust (Axum) + SQLite (rusqlite, bundled)
- **Client crypto:** Argon2id (hash-wasm) + HKDF + AES-256-GCM (Web Crypto)
- **Server crypto:** Argon2id hashes of client proofs only

## Security model

```
password ──Argon2id(salt, 64 MiB, t=3)──► master key
master key ──HKDF──► auth key   → sent to the server as a login proof
           └─HKDF──► wrap key   → never leaves the browser

random vault key (256-bit) ──AES-256-GCM──► encrypted vault       (stored server-side)
wrap key ──AES-256-GCM──► wrapped vault key                       (stored server-side)
```

- The server stores `Argon2id(auth key)` with a per-user random salt; it cannot
  decrypt anything. A stolen database only allows offline guessing against
  Argon2id (memory-hard), per account.
- The recovery phrase (24 words, 256-bit) and the `.key` master file wrap the
  same vault key with their own keys, so they survive password changes.
- Every ciphertext is AES-GCM authenticated and bound to its purpose
  (associated data): tampering is detected, blobs cannot be swapped.
- Databases from xVault 1.x/2.x (server-side encryption) are refused at
  startup: archive the old file and start with a new one.

Server hardening: per-IP / per-account / per-(account, IP) brute-force limits
with exponential back-off, re-authentication limits for sensitive actions,
sessions with idle (12 h) and absolute (7 days) lifetimes revoked on password
change / recovery, `HttpOnly; SameSite=Strict; Secure` (`__Host-`) cookies,
strict CSP, HSTS, anti-framing, CSRF protection (JSON-only + Origin check),
per-route body limits, generic error messages, no account enumeration (fake
KDF salts, constant-time checks), fail-closed configuration, registration
closed by default (or invitation-code only).

Client hardening: auto-lock after 10 min idle or 5 min hidden, clipboard wiped
30 s after copying a secret, HTTPS required, strong-password policy (12+
chars, entropy check), only `http(s)` links stored, sanitized imports, no
third-party requests (fonts are self-hosted).

## Requirements

- Node.js 20+, npm
- Rust (cargo)
- HTTPS in production (Web Crypto is unavailable on plain `http://` except `localhost`)

## Install & run

```bash
npm install
npm run backend:build
cp config.example.json config.json   # then edit it

npm run dev:all   # dev: Vite on 127.0.0.1:5173 (API proxied) + backend
npm run prod      # build frontend + release binary
npm run start     # run the release binary (serves ./dist itself)
```

## Config

`config.json` (gitignored) — any invalid value stops the server at startup:

```json
{
  "SERVER_HOST": "127.0.0.1",
  "SERVER_PORT": 58951,
  "SERVER_URL": "https://vault.example.com",
  "ALLOW_REGISTRATION": true,
  "REGISTRATION_CODE": "a-long-random-invitation-code",
  "TRUST_PROXY": true
}
```

| Key | Meaning |
| --- | --- |
| `SERVER_HOST` / `SERVER_PORT` | Listen address. Use an IP, not `localhost`. |
| `SERVER_URL` | Public URL. Its origin is the only one allowed to call the API; `https://` enables Secure cookies and HSTS. |
| `ALLOW_REGISTRATION` | Sign-ups (default `false`). |
| `REGISTRATION_CODE` | Optional (16+ chars). When set, sign-ups also require this invitation code. |
| `TRUST_PROXY` | Use the right-most `X-Forwarded-For` hop as client IP (only behind a reverse proxy). |
| `ALLOWED_ORIGINS` | Extra API origins (development only). |

Environment variables (and a `.env` in the working directory) override the
file: same names, plus `XVAULT_DB_PATH`, `XVAULT_DIST_DIR`, `XVAULT_CONFIG_PATH`.

## Usage

1. Create an account: pick your **username** (3–32 chars, case-insensitive)
   and a strong password (12+ chars, confirmed twice).
2. In **Security**, create a recovery phrase and/or a `.key` file — without
   them a forgotten password means the vault is lost.
3. Add accounts: Base32 secret, `otpauth://` (TOTP, HOTP, Steam, SHA-1/256/512,
   4–10 digits, any period), QR scan, or a Google Authenticator export QR.
4. **Security → Universal import**: Proton Authenticator, Aegis, 2FAS, andOTP
   (incl. encrypted exports), FreeOTP+, Raivo, Authenticator Pro, LastPass
   Authenticator, Steam `.maFile`, otpauth lists; Bitwarden (incl.
   password-protected), 1Password `.1pux`/`.1pif`, KeePass XML, Proton Pass,
   Enpass, Keeper, and Chrome / Edge / Firefox / Safari / LastPass / Dashlane /
   NordPass / RoboForm CSV.
5. **Backup**: export an encrypted `xVault-V3` file (own password, Argon2id +
   AES-GCM); restore V3 files or plain xVault-V2 exports.

## Deploy

### systemd (hardened, non-root)

```bash
npm run prod
sudo useradd --system --home /var/lib/xvault --shell /usr/sbin/nologin xvault
sudo install -d -o xvault -g xvault -m 0700 /var/lib/xvault
sudo install -d -m 0755 /opt/xvault /etc/xvault
sudo install -m 0755 backend/target/release/xvault /opt/xvault/xvault
sudo cp -r dist /opt/xvault/dist
sudo install -o root -g xvault -m 0640 config.json /etc/xvault/config.json
sudo cp deploy/xvault.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now xvault
systemd-analyze security xvault
```

### Docker

```bash
docker compose up -d
```

Read-only container, all capabilities dropped, non-root user. Data lives in
the `xvault_data` volume.

### Reverse proxy

Always put HTTPS in front (Caddy shown):

```
vault.example.com {
    request_body {
        max_size 40MB
    }
    reverse_proxy 127.0.0.1:58951
}
```

## Data & backup

- Database: `xVault.sqlite` (ciphertext only, created `0600`). Back it up.
- **Backup → Export** produces a portable encrypted file.

## Scripts

| Script | Action |
| --- | --- |
| `npm run dev` | Vite dev server (API proxied to the backend) |
| `npm run server` | Run backend (debug build) |
| `npm run build` | Build frontend to `dist/` |
| `npm run check` | svelte-check (types) |
| `npm run backend:build` | Build release binary |
| `npm run backend:test` | Rust tests (crypto, accounts, recovery, rate limiting) |

## License

MIT
