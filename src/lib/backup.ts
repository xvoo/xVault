// Portable vault backups. Current format (xVault-V3) is encrypted in the
// browser with a backup password (Argon2id + AES-256-GCM): the file is
// useless without it. Older formats are still readable for restores:
// xVault-V2 (plaintext JSON produced by the old server export) and a bare
// { entries, folders, passwords } object.

import { sanitizeVaultData } from './sanitize';
import type { VaultData } from './types';
import { deriveFileKey, newKdfParams, openJson, sealJson, type KdfParams } from './vaultcrypto';

export const BACKUP_FORMAT = 'xVault-V3';

interface BackupV3 {
  format: typeof BACKUP_FORMAT;
  createdAt: string;
  kdf: KdfParams;
  data: string;
}

export class BackupPasswordRequired extends Error {
  constructor() {
    super('This backup is encrypted. Enter its backup password.');
  }
}

export const buildBackup = async (data: VaultData, password: string): Promise<Blob> => {
  const kdf = newKdfParams();
  const key = await deriveFileKey(password, kdf, 'backup');
  const backup: BackupV3 = {
    format: BACKUP_FORMAT,
    createdAt: new Date().toISOString(),
    kdf,
    data: await sealJson(key, data, 'backup'),
  };
  return new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
};

export const isEncryptedBackup = (text: string): boolean => {
  try {
    return (JSON.parse(text) as { format?: string }).format === BACKUP_FORMAT;
  } catch {
    return false;
  }
};

/** Returns the vault contained in a backup file, or null if it is not one. */
export const parseBackup = async (text: string, password?: string): Promise<VaultData | null> => {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(text) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return null;
  }

  if (parsed.format === BACKUP_FORMAT) {
    if (!password) {
      throw new BackupPasswordRequired();
    }
    const backup = parsed as unknown as BackupV3;
    const key = await deriveFileKey(password, backup.kdf, 'backup');
    try {
      return sanitizeVaultData(await openJson<unknown>(key, backup.data, 'backup'));
    } catch {
      throw new Error('Wrong backup password, or the file is corrupted.');
    }
  }

  if (parsed.format === 'xVault-V2' && typeof parsed.data === 'string') {
    try {
      return sanitizeVaultData(JSON.parse(parsed.data));
    } catch {
      throw new Error('This xVault-V2 backup is corrupted.');
    }
  }

  if (Array.isArray(parsed.entries) || Array.isArray(parsed.passwords)) {
    return sanitizeVaultData(parsed);
  }

  return null;
};
