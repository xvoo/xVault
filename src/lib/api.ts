import type { RecoveryMethod, User } from './types';
import type { KdfParams } from './vaultcrypto';

// All calls are same-origin: the API base is never configurable at runtime,
// so a tampered config file cannot redirect credentials elsewhere.
const API_BASE = '/api';

export interface AuthStatus {
  authenticated: boolean;
  loginId?: string;
  registrationEnabled?: boolean;
  inviteRequired?: boolean;
}

export interface ApiError extends Error {
  status?: number;
  attemptsLeft?: number;
  lockoutTime?: number;
  revision?: number;
}

const request = async <T>(path: string, init: RequestInit = {}): Promise<T> => {
  const headers = new Headers(init.headers);
  if (init.body !== undefined) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(`${API_BASE}${path}`, {
    credentials: 'same-origin',
    cache: 'no-store',
    ...init,
    headers,
  });

  let data: Record<string, unknown> | null = null;
  try {
    data = (await response.json()) as Record<string, unknown>;
  } catch {
    // Non-JSON body.
  }

  if (!response.ok) {
    const error = new Error(
      (data?.error as string) ?? `Request failed (${response.status})`,
    ) as ApiError;
    error.status = response.status;
    error.attemptsLeft = data?.attemptsLeft as number | undefined;
    error.lockoutTime = data?.lockoutTime as number | undefined;
    error.revision = data?.revision as number | undefined;
    throw error;
  }

  return data as T;
};

const post = <T>(path: string, body: unknown = {}): Promise<T> =>
  request<T>(path, { method: 'POST', body: JSON.stringify(body) });

const put = <T>(path: string, body: unknown): Promise<T> =>
  request<T>(path, { method: 'PUT', body: JSON.stringify(body) });

/** Key material produced in the browser for a password (re)set. */
export interface NewKeyMaterial {
  authKey: string;
  kdf: KdfParams;
  vaultKeyWrapped: string;
}

export interface VaultRecord {
  kdf: KdfParams;
  vaultKeyWrapped: string;
  encryptedData: string;
  revision: number;
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export const prelogin = (loginId: string): Promise<{ kdf: KdfParams }> =>
  post('/auth/prelogin', { loginId });

export const registerUser = (
  keys: NewKeyMaterial & { username: string; encryptedData: string; inviteCode?: string },
): Promise<{ success: boolean; loginId: string; user: User }> => post('/auth/register', keys);

export const loginUser = (loginId: string, authKey: string): Promise<{ success: boolean; user: User }> =>
  post('/auth/login', { loginId, authKey });

export const logoutUser = async (): Promise<void> => {
  await post('/auth/logout');
};

export const checkAuthStatus = async (): Promise<AuthStatus> => {
  try {
    return await request<AuthStatus>('/auth/status');
  } catch {
    return { authenticated: false };
  }
};

// ---------------------------------------------------------------------------
// Profile & account
// ---------------------------------------------------------------------------

export const getUserProfile = async (): Promise<User | null> => {
  try {
    const data = await request<{ success: boolean; user: User }>('/user/profile');
    return data.user;
  } catch {
    return null;
  }
};

export const updateUserProfile = (updates: { name?: string; logo?: string | null }): Promise<unknown> =>
  put('/user/profile', updates);

export const changePassword = (currentAuthKey: string, keys: NewKeyMaterial): Promise<unknown> =>
  post('/user/change-password', { currentAuthKey, ...keys });

export const deleteAccount = (authKey: string): Promise<unknown> =>
  post('/user/delete-account', { authKey });

// ---------------------------------------------------------------------------
// Vault (opaque encrypted blobs)
// ---------------------------------------------------------------------------

export const fetchVault = (): Promise<VaultRecord> => request<VaultRecord>('/vault');

export const saveVault = (encryptedData: string, revision: number): Promise<{ revision: number }> =>
  put('/vault', { encryptedData, revision });


// ---------------------------------------------------------------------------
// Recovery phrase & master-key file
// ---------------------------------------------------------------------------

export const enableRecovery = (
  method: RecoveryMethod,
  authKey: string,
  proof: string,
  wrapped: string,
): Promise<unknown> => post('/vault/recovery/enable', { method, authKey, proof, wrapped });

export const disableRecovery = (method: RecoveryMethod, authKey: string): Promise<unknown> =>
  post('/vault/recovery/disable', { method, authKey });

export const recoveryChallenge = (
  loginId: string,
  method: RecoveryMethod,
  proof: string,
): Promise<{ wrapped: string }> => post('/auth/recover/challenge', { loginId, method, proof });

export const recoveryComplete = (
  body: { loginId: string; method: RecoveryMethod; proof: string } & NewKeyMaterial,
): Promise<unknown> => post('/auth/recover/complete', body);
