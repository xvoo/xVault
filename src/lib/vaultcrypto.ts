// Client-side (zero-knowledge) cryptography for xVault.
//
// The master password never leaves the browser. From it we derive, with
// Argon2id (memory-hard, per-account random salt):
//
//   masterKey ──HKDF──► authKey  (sent to the server as a login proof only)
//             └─HKDF──► wrapKey  (AES-256-GCM, never leaves the browser)
//
// A random 256-bit *vault key* encrypts the vault (AES-256-GCM). The server
// stores only that vault key wrapped by `wrapKey`, plus the encrypted vault.
// Recovery phrase / master-key file wrap the same vault key with keys
// derived from their own secrets, so they keep working across password
// changes. Every ciphertext is bound to its purpose via AES-GCM additional
// data, so a blob can never be swapped for another kind of blob.

import { argon2id } from 'hash-wasm';

export interface KdfParams {
  algorithm: 'argon2id';
  salt: string; // base64
  memory: number; // KiB
  iterations: number;
  parallelism: number;
}

export const DEFAULT_KDF = { memory: 64 * 1024, iterations: 3, parallelism: 1 } as const;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

export const toBase64 = (bytes: Uint8Array): string => {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
};

export const fromBase64 = (value: string): Uint8Array<ArrayBuffer> => {
  const binary = atob(value.replace(/\s+/g, ''));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
};

export const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

export const randomBytes = (length: number): Uint8Array<ArrayBuffer> => {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
};

/** Best-effort wipe of sensitive buffers once they are no longer needed. */
export const wipe = (...buffers: (Uint8Array | null | undefined)[]): void => {
  for (const buffer of buffers) {
    buffer?.fill(0);
  }
};

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

export const newKdfParams = (): KdfParams => ({
  algorithm: 'argon2id',
  salt: toBase64(randomBytes(16)),
  ...DEFAULT_KDF,
});

export const argon2 = async (secret: string, kdf: KdfParams): Promise<Uint8Array<ArrayBuffer>> => {
  if (kdf.algorithm !== 'argon2id') {
    throw new Error('Unsupported key derivation algorithm.');
  }
  const output = await argon2id({
    password: secret.normalize('NFKC'),
    salt: fromBase64(kdf.salt),
    iterations: kdf.iterations,
    parallelism: kdf.parallelism,
    memorySize: kdf.memory,
    hashLength: 32,
    outputType: 'binary',
  });
  return new Uint8Array(output);
};

const hkdf = async (
  ikm: Uint8Array<ArrayBuffer>,
  info: string,
  salt: Uint8Array<ArrayBuffer> = new Uint8Array(0),
): Promise<Uint8Array<ArrayBuffer>> => {
  const base = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode(info) },
    base,
    256,
  );
  return new Uint8Array(bits);
};

const importAesKey = (raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> =>
  crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);

export interface DerivedKeys {
  /** Login proof (hex). The server stores only an Argon2id hash of it. */
  authKey: string;
  /** Wraps / unwraps the vault key. Non-extractable, browser-only. */
  wrapKey: CryptoKey;
}

const splitKeys = async (
  ikm: Uint8Array<ArrayBuffer>,
  authInfo: string,
  wrapInfo: string,
  salt?: Uint8Array<ArrayBuffer>,
): Promise<DerivedKeys> => {
  const authBytes = await hkdf(ikm, authInfo, salt);
  const wrapBytes = await hkdf(ikm, wrapInfo, salt);
  const keys = { authKey: toHex(authBytes), wrapKey: await importAesKey(wrapBytes) };
  wipe(authBytes, wrapBytes);
  return keys;
};

/** Master password → auth key + wrap key (Argon2id then HKDF). */
export const deriveKeys = async (password: string, kdf: KdfParams): Promise<DerivedKeys> => {
  const master = await argon2(password, kdf);
  try {
    return await splitKeys(master, 'xvault/v2/auth', 'xvault/v2/wrap');
  } finally {
    wipe(master);
  }
};

export type RecoveryKind = 'phrase' | 'key';

/**
 * Recovery phrase (≥128-bit entropy) or master-key file secret (256-bit) →
 * recovery proof + recovery wrap key. The inputs are already high-entropy,
 * so HKDF (salted with the login ID) is sufficient here.
 */
export const deriveRecoveryKeys = async (
  secret: string,
  loginId: string,
  kind: RecoveryKind,
): Promise<DerivedKeys> => {
  const ikm = encoder.encode(secret);
  const salt = encoder.encode(`xvault-recovery:${loginId}`);
  try {
    return await splitKeys(ikm, `xvault/v2/recovery-${kind}/auth`, `xvault/v2/recovery-${kind}/wrap`, salt);
  } finally {
    wipe(ikm);
  }
};

// ---------------------------------------------------------------------------
// Authenticated encryption (AES-256-GCM, versioned envelope)
// ---------------------------------------------------------------------------

interface Envelope {
  v: 1;
  alg: 'A256GCM';
  iv: string;
  ct: string;
}

export type Purpose = 'vault-key' | 'vault-data' | 'backup' | 'master-key-file';

export const seal = async (
  key: CryptoKey,
  plaintext: Uint8Array<ArrayBuffer>,
  purpose: Purpose,
): Promise<string> => {
  const iv = randomBytes(12);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode(`xvault/${purpose}`) },
    key,
    plaintext,
  );
  const envelope: Envelope = { v: 1, alg: 'A256GCM', iv: toBase64(iv), ct: toBase64(new Uint8Array(ciphertext)) };
  return JSON.stringify(envelope);
};

export const open = async (key: CryptoKey, sealed: string, purpose: Purpose): Promise<Uint8Array<ArrayBuffer>> => {
  let envelope: Envelope;
  try {
    envelope = JSON.parse(sealed) as Envelope;
  } catch {
    throw new Error('Encrypted data is corrupted.');
  }
  if (envelope.v !== 1 || envelope.alg !== 'A256GCM') {
    throw new Error('Unsupported encryption format.');
  }
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromBase64(envelope.iv), additionalData: encoder.encode(`xvault/${purpose}`) },
    key,
    fromBase64(envelope.ct),
  );
  return new Uint8Array(plaintext);
};

export const sealJson = (key: CryptoKey, value: unknown, purpose: Purpose): Promise<string> =>
  seal(key, encoder.encode(JSON.stringify(value)), purpose);

export const openJson = async <T>(key: CryptoKey, sealed: string, purpose: Purpose): Promise<T> => {
  const bytes = await open(key, sealed, purpose);
  try {
    return JSON.parse(decoder.decode(bytes)) as T;
  } finally {
    wipe(bytes);
  }
};

// ---------------------------------------------------------------------------
// Vault key
// ---------------------------------------------------------------------------

export const generateVaultKey = (): Uint8Array<ArrayBuffer> => randomBytes(32);

/** Non-extractable AES-GCM key used for vault contents while unlocked. */
export const importVaultKey = (raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> => importAesKey(raw);

export const wrapVaultKey = (raw: Uint8Array<ArrayBuffer>, wrapKey: CryptoKey): Promise<string> =>
  seal(wrapKey, raw, 'vault-key');

/** Throws when the wrap key is wrong (AES-GCM authentication failure). */
export const unwrapVaultKey = async (wrapped: string, wrapKey: CryptoKey): Promise<Uint8Array<ArrayBuffer>> => {
  const raw = await open(wrapKey, wrapped, 'vault-key');
  if (raw.length !== 32) {
    wipe(raw);
    throw new Error('Invalid vault key.');
  }
  return raw;
};

// ---------------------------------------------------------------------------
// Password-protected files (backups, master-key files)
// ---------------------------------------------------------------------------

export const deriveFileKey = async (passphrase: string, kdf: KdfParams, purpose: Purpose): Promise<CryptoKey> => {
  const master = await argon2(passphrase, kdf);
  try {
    const bytes = await hkdf(master, `xvault/v2/file/${purpose}`);
    try {
      return await importAesKey(bytes);
    } finally {
      wipe(bytes);
    }
  } finally {
    wipe(master);
  }
};

// ---------------------------------------------------------------------------
// Password strength
// ---------------------------------------------------------------------------

const COMMON = new Set([
  'password', 'password1', 'password123', '123456789012', 'qwertyuiop', 'azertyuiop',
  'motdepasse', 'iloveyou', 'letmein', 'welcome', 'admin', 'administrator', 'passw0rd',
  'qwerty123', 'azerty123', '1q2w3e4r5t', 'trustno1', 'changeme', 'xvault',
]);

/** Rough entropy estimate (bits) from length and character classes. */
export const estimateEntropy = (password: string): number => {
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^A-Za-z0-9]/.test(password)) pool += 33;
  const unique = new Set(password).size;
  // Penalize heavy repetition ("aaaaaaaaaaaa1").
  const effectiveLength = Math.min(password.length, unique * 2.5);
  return Math.round(effectiveLength * Math.log2(Math.max(pool, 1)));
};

export const MIN_PASSWORD_LENGTH = 12;

/** Returns an error message, or null when the password is acceptable. */
export const checkNewPassword = (password: string): string | null => {
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `Use at least ${MIN_PASSWORD_LENGTH} characters.`;
  }
  if (password.length > 1024) {
    return 'That password is too long.';
  }
  if (COMMON.has(password.toLowerCase())) {
    return 'That password is too common.';
  }
  if (estimateEntropy(password) < 50) {
    return 'That password is too predictable — mix words, numbers and symbols, or make it longer.';
  }
  return null;
};
