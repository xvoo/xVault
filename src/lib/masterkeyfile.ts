// The xVault ".key" master backup file: a last-resort credential that can
// restore vault access if the password *and* the recovery phrase are lost.
// It carries a random 256-bit master secret, always encrypted with a
// passphrase (Argon2id + AES-256-GCM).

import { deriveFileKey, newKdfParams, open, seal, type KdfParams } from './vaultcrypto';

export const MASTER_KEY_FORMAT = 'xVault-MasterKey-V2';
export const MIN_FILE_PASSPHRASE = 12;

export interface MasterKeyFilePayload {
  loginId: string;
  masterSecret: string;
  createdAt: string;
}

interface MasterKeyFileV2 {
  format: typeof MASTER_KEY_FORMAT;
  loginId: string;
  kdf: KdfParams;
  payload: string; // sealed envelope
}

export const buildMasterKeyFile = async (
  payload: MasterKeyFilePayload,
  passphrase: string,
): Promise<Blob> => {
  if (passphrase.length < MIN_FILE_PASSPHRASE) {
    throw new Error(`The file passphrase needs at least ${MIN_FILE_PASSPHRASE} characters.`);
  }
  const kdf = newKdfParams();
  const key = await deriveFileKey(passphrase, kdf, 'master-key-file');
  const sealed = await seal(key, new TextEncoder().encode(JSON.stringify(payload)), 'master-key-file');
  const file: MasterKeyFileV2 = { format: MASTER_KEY_FORMAT, loginId: payload.loginId, kdf, payload: sealed };
  return new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' });
};

export const parseMasterKeyFile = async (
  fileText: string,
  passphrase?: string,
): Promise<MasterKeyFilePayload> => {
  let envelope: MasterKeyFileV2;
  try {
    envelope = JSON.parse(fileText) as MasterKeyFileV2;
  } catch {
    throw new Error('This does not look like an xVault .key file.');
  }

  let payload: MasterKeyFilePayload;
  if (envelope.format === MASTER_KEY_FORMAT) {
    if (!passphrase) {
      throw Object.assign(new Error('This recovery file is passphrase-protected.'), { needsPassphrase: true });
    }
    const key = await deriveFileKey(passphrase, envelope.kdf, 'master-key-file');
    try {
      const bytes = await open(key, envelope.payload, 'master-key-file');
      payload = JSON.parse(new TextDecoder().decode(bytes)) as MasterKeyFilePayload;
    } catch {
      throw new Error('Incorrect passphrase, or the recovery file is corrupted.');
    }
  } else {
    throw new Error('Unsupported recovery file format.');
  }

  if (!/^[0-9a-f]{64}$/.test(payload.masterSecret ?? '') || !payload.loginId) {
    throw new Error('Recovery file is corrupted.');
  }
  return payload;
};

export const downloadBlob = (blob: Blob, filename: string): void => {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = 'noopener';
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};

export const downloadMasterKeyFile = (blob: Blob, loginId: string): void =>
  downloadBlob(blob, `xvault-recovery-${loginId}.key`);
