import {
  changePassword,
  checkAuthStatus,
  deleteAccount,
  disableRecovery,
  enableRecovery,
  fetchVault,
  getUserProfile,
  loginUser,
  logoutUser,
  prelogin,
  recoveryChallenge,
  recoveryComplete,
  registerUser,
  saveVault,
  updateUserProfile,
  type ApiError,
  type NewKeyMaterial,
} from './api';
import { BackupPasswordRequired, buildBackup, isEncryptedBackup, parseBackup } from './backup';
import { ImportPasswordRequired, parseImportFile, type ImportResult } from './importers';
import { buildMasterKeyFile, downloadBlob, downloadMasterKeyFile, MIN_FILE_PASSPHRASE, parseMasterKeyFile } from './masterkeyfile';
import { generateMasterKeySecret, generateMnemonic, normalizeMnemonic, validateMnemonic } from './mnemonic';
import { deriveEntryName, isMigrationUri, makeOtpSource, parseMigrationUri, parseOtpAuthUri, type ParsedOtpSource } from './otpauth';
import { sanitizeColor, sanitizeIcon, sanitizeMarker, sanitizeUrl, sanitizeVaultData } from './sanitize';
import type { Folder, OtpAlgorithm, OtpType, PasswordEntry, RecoveryMethod, TOTPEntry, User, VaultData } from './types';
import { generateId } from './uuid';
import {
  checkNewPassword,
  deriveKeys,
  deriveRecoveryKeys,
  generateVaultKey,
  importVaultKey,
  newKdfParams,
  openJson,
  sealJson,
  unwrapVaultKey,
  wipe,
  wrapVaultKey,
  type DerivedKeys,
  type KdfParams,
} from './vaultcrypto';

export type Screen = 'booting' | 'auth' | 'locked' | 'vault';
export type NavPanel = 'codes' | 'passwords' | 'backup' | 'security' | 'info';
export type AuthMode = 'login' | 'register';
export type SaveStatus = 'idle' | 'saving' | 'saved' | 'error';
export type ToastTone = 'success' | 'error' | 'info';
export type EntryDialogMode = 'create' | 'edit' | null;
export type PasswordDialogMode = 'create' | 'edit' | null;
export type ThemeMode = 'light' | 'dark';

interface ToastMessage {
  message: string;
  tone: ToastTone;
}

export interface ConfirmRequest {
  title: string;
  message: string;
  confirmLabel: string;
  danger?: boolean;
  action: () => void | Promise<void>;
}

export interface PasswordPrompt {
  title: string;
  message: string;
  label: string;
  confirm?: boolean; // ask twice (new secrets)
  minLength?: number;
  submitLabel: string;
  resolve: (value: string | null) => void;
}

export interface PendingFlags {
  auth: boolean;
  unlock: boolean;
  export: boolean;
  import: boolean;
  profile: boolean;
  password: boolean;
  danger: boolean;
  recovery: boolean;
  masterKey: boolean;
  recoverAccount: boolean;
}

export interface RecoveryPhraseReveal {
  mnemonic: string;
  confirmed: boolean;
}

/** Locks the vault after this long without interaction... */
export const AUTO_LOCK_IDLE_MS = 10 * 60 * 1000;
/** ...or after the tab has been hidden this long. */
export const AUTO_LOCK_HIDDEN_MS = 5 * 60 * 1000;
/** Copied secrets are wiped from the clipboard after this delay. */
export const CLIPBOARD_CLEAR_MS = 30 * 1000;

export const app = $state({
  screen: 'booting' as Screen,
  authMode: 'login' as AuthMode,
  registrationEnabled: false,
  inviteRequired: false,
  activePanel: 'codes' as NavPanel,
  user: null as User | null,
  entries: [] as TOTPEntry[],
  folders: [] as Folder[],
  passwords: [] as PasswordEntry[],
  search: '',
  activeFolderId: null as string | null,
  entryDialogMode: null as EntryDialogMode,
  editingEntryId: null as string | null,
  passwordDialogMode: null as PasswordDialogMode,
  editingPasswordId: null as string | null,
  passwordSearch: '',
  folderDialogOpen: false,
  editingFolderId: null as string | null,
  qrScannerOpen: false,
  qrScannerMessage: null as string | null,
  registerLoginId: null as string | null,
  authError: null as string | null,
  unlockError: null as string | null,
  unlockAttemptsLeft: undefined as number | undefined,
  saveStatus: 'idle' as SaveStatus,
  saveMessage: null as string | null,
  copiedEntryId: null as string | null,
  toast: null as ToastMessage | null,
  confirm: null as ConfirmRequest | null,
  passwordPrompt: null as PasswordPrompt | null,
  recoveryPhraseReveal: null as RecoveryPhraseReveal | null,
  masterKeyDialogOpen: false,
  importPreview: null as ImportResult | null,
  recoverFlowOpen: false,
  pending: {
    auth: false,
    unlock: false,
    export: false,
    import: false,
    profile: false,
    password: false,
    danger: false,
    recovery: false,
    masterKey: false,
    recoverAccount: false,
  } as PendingFlags,
});

/**
 * Key material of the unlocked vault. Deliberately kept out of `$state`
 * (never proxied, never rendered): a non-extractable AES-GCM key, the
 * current KDF parameters and the server revision we last saw.
 */
let unlocked: { vaultKey: CryptoKey; kdf: KdfParams; revision: number } | null = null;

export const getVisiblePasswords = (): PasswordEntry[] => {
  const query = app.passwordSearch.trim().toLowerCase();
  if (!query) {
    return app.passwords;
  }
  return app.passwords.filter((entry) => {
    const haystack = `${entry.title} ${entry.username} ${entry.url ?? ''}`.toLowerCase();
    return haystack.includes(query);
  });
};

export const getVisibleEntries = (): TOTPEntry[] => {
  const query = app.search.trim().toLowerCase();
  const foldersById = new Map(app.folders.map((folder) => [folder.id, folder]));

  return app.entries.filter((entry) => {
    if (app.activeFolderId && entry.folderId !== app.activeFolderId) {
      return false;
    }
    if (!query) {
      return true;
    }
    const folderName = entry.folderId ? (foldersById.get(entry.folderId)?.name ?? '') : '';
    const haystack = `${entry.name} ${folderName}`.toLowerCase();
    return haystack.includes(query);
  });
};

const THEME_KEY = 'xvault-theme';

const resolveTheme = (): ThemeMode => {
  try {
    const stored = localStorage.getItem(THEME_KEY);
    if (stored === 'light' || stored === 'dark') {
      return stored;
    }
  } catch {
    // Storage unavailable.
  }
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
};

export const theme = $state<{ mode: ThemeMode }>({ mode: resolveTheme() });

export const toggleTheme = (): void => {
  theme.mode = theme.mode === 'dark' ? 'light' : 'dark';
  try {
    localStorage.setItem(THEME_KEY, theme.mode);
  } catch {
    // Storage unavailable.
  }
};

// ---------------------------------------------------------------------------
// Toasts, confirmations, password prompts
// ---------------------------------------------------------------------------

let toastTimer: ReturnType<typeof setTimeout> | null = null;

export const showToast = (message: string, tone: ToastTone = 'info'): void => {
  app.toast = { message, tone };
  if (toastTimer) {
    clearTimeout(toastTimer);
  }
  toastTimer = setTimeout(() => {
    app.toast = null;
  }, 3600);
};

export const clearToast = (): void => {
  app.toast = null;
};

export const askConfirm = (request: ConfirmRequest): void => {
  app.confirm = request;
};

export const closeConfirm = (): void => {
  app.confirm = null;
};

/** Opens the shared password dialog; resolves to null when cancelled. */
export const askPassword = (
  options: Omit<PasswordPrompt, 'resolve'>,
): Promise<string | null> =>
  new Promise((resolve) => {
    app.passwordPrompt?.resolve(null);
    app.passwordPrompt = { ...options, resolve };
  });

export const resolvePasswordPrompt = (value: string | null): void => {
  const prompt = app.passwordPrompt;
  app.passwordPrompt = null;
  prompt?.resolve(value);
};

const errorMessage = (error: unknown, fallback: string): string => {
  const apiError = error as ApiError;
  if (apiError?.status === 429 && apiError.lockoutTime) {
    return `Too many failed attempts. Try again in ${apiError.lockoutTime} minute${apiError.lockoutTime === 1 ? '' : 's'}.`;
  }
  if (apiError?.status && apiError.status < 500 && apiError.message) {
    return apiError.message;
  }
  return fallback;
};

// ---------------------------------------------------------------------------
// Secure context guard
// ---------------------------------------------------------------------------

/**
 * Web Crypto (`crypto.subtle`) only exists on HTTPS or localhost, and the
 * whole vault is encrypted in the browser, so nothing works without it.
 */
export const isSecureContextOk = (): boolean => window.isSecureContext && !!crypto?.subtle;

export const requireSecureContext = (feature = 'xVault'): boolean => {
  if (isSecureContextOk()) {
    return true;
  }
  showToast(
    `${feature} needs a secure connection (HTTPS, or "localhost"). Plain http:// is refused to protect your password.`,
    'error',
  );
  return false;
};

// ---------------------------------------------------------------------------
// Clipboard (auto-cleared)
// ---------------------------------------------------------------------------

let clipboardTimer: ReturnType<typeof setTimeout> | null = null;

const writeClipboard = async (value: string): Promise<void> => {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    const textarea = document.createElement('textarea');
    textarea.value = value;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    const copied = document.execCommand('copy');
    document.body.removeChild(textarea);
    if (!copied) {
      throw new Error('Clipboard unavailable');
    }
  }
};

/** Copies a secret, then wipes it from the clipboard if it is still there. */
const copySecret = async (value: string): Promise<void> => {
  await writeClipboard(value);
  if (clipboardTimer) {
    clearTimeout(clipboardTimer);
  }
  clipboardTimer = setTimeout(async () => {
    clipboardTimer = null;
    try {
      const current = await navigator.clipboard.readText();
      if (current === value) {
        await navigator.clipboard.writeText('');
      }
    } catch {
      // readText unavailable (Firefox, denied permission): clear anyway,
      // a stale secret on the clipboard is the bigger risk.
      try {
        await navigator.clipboard.writeText('');
      } catch {
        // Page not focused; nothing more we can do.
      }
    }
  }, CLIPBOARD_CLEAR_MS);
};

// ---------------------------------------------------------------------------
// Auto-lock
// ---------------------------------------------------------------------------

let idleTimer: ReturnType<typeof setTimeout> | null = null;
let hiddenTimer: ReturnType<typeof setTimeout> | null = null;
let lastActivity = 0;

const resetIdleTimer = (): void => {
  const now = Date.now();
  // Throttle: mousemove fires constantly.
  if (now - lastActivity < 1000 && idleTimer) {
    return;
  }
  lastActivity = now;
  if (idleTimer) {
    clearTimeout(idleTimer);
  }
  idleTimer = setTimeout(() => {
    if (app.screen === 'vault') {
      lockVault();
      showToast('Vault locked after inactivity', 'info');
    }
  }, AUTO_LOCK_IDLE_MS);
};

const onVisibilityChange = (): void => {
  if (document.visibilityState === 'hidden') {
    hiddenTimer = setTimeout(() => {
      if (app.screen === 'vault') {
        lockVault();
      }
    }, AUTO_LOCK_HIDDEN_MS);
  } else if (hiddenTimer) {
    clearTimeout(hiddenTimer);
    hiddenTimer = null;
  }
};

const ACTIVITY_EVENTS = ['pointerdown', 'keydown', 'mousemove', 'touchstart', 'wheel'] as const;

const startAutoLock = (): void => {
  stopAutoLock();
  for (const event of ACTIVITY_EVENTS) {
    window.addEventListener(event, resetIdleTimer, { passive: true });
  }
  document.addEventListener('visibilitychange', onVisibilityChange);
  lastActivity = 0;
  resetIdleTimer();
};

const stopAutoLock = (): void => {
  for (const event of ACTIVITY_EVENTS) {
    window.removeEventListener(event, resetIdleTimer);
  }
  document.removeEventListener('visibilitychange', onVisibilityChange);
  if (idleTimer) clearTimeout(idleTimer);
  if (hiddenTimer) clearTimeout(hiddenTimer);
  idleTimer = null;
  hiddenTimer = null;
};

// ---------------------------------------------------------------------------
// Boot & authentication
// ---------------------------------------------------------------------------

export const boot = async (): Promise<void> => {
  app.screen = 'booting';
  try {
    const status = await checkAuthStatus();
    app.registrationEnabled = status.registrationEnabled === true;
    app.inviteRequired = status.inviteRequired === true;
    if (!app.registrationEnabled) {
      app.authMode = 'login';
    }
    if (status.authenticated) {
      app.user = await getUserProfile();
      app.screen = app.user ? 'locked' : 'auth';
      return;
    }
  } catch {
    // Treated as signed out.
  }
  app.screen = 'auth';
};

export const setAuthMode = (mode: AuthMode): void => {
  if (mode === 'register' && !app.registrationEnabled) {
    app.authMode = 'login';
    app.authError = 'Registration is disabled on this server.';
    return;
  }
  app.authMode = mode;
  app.authError = null;
};

/** Generates fresh key material for `password` around an existing raw vault key. */
const buildKeyMaterial = async (
  password: string,
  rawVaultKey: Uint8Array<ArrayBuffer>,
): Promise<NewKeyMaterial & { kdf: KdfParams }> => {
  const kdf = newKdfParams();
  const keys = await deriveKeys(password, kdf);
  return { authKey: keys.authKey, kdf, vaultKeyWrapped: await wrapVaultKey(rawVaultKey, keys.wrapKey) };
};

const applyVault = (data: VaultData): void => {
  app.entries = data.entries;
  app.folders = data.folders;
  app.passwords = data.passwords;
  if (app.activeFolderId && !app.folders.some((folder) => folder.id === app.activeFolderId)) {
    app.activeFolderId = null;
  }
};

const enterVault = (vaultKey: CryptoKey, kdf: KdfParams, revision: number, data: VaultData): void => {
  unlocked = { vaultKey, kdf, revision };
  applyVault(data);
  app.screen = 'vault';
  app.activePanel = 'codes';
  app.saveStatus = 'saved';
  app.saveMessage = 'End-to-end encrypted';
  app.unlockError = null;
  app.unlockAttemptsLeft = undefined;
  startAutoLock();
};

/** Decrypts the server copy of the vault with keys derived from `password`. */
const openVaultWithPassword = async (password: string, keys?: DerivedKeys): Promise<void> => {
  const record = await fetchVault();
  const derived = keys ?? (await deriveKeys(password, record.kdf));
  let raw: Uint8Array<ArrayBuffer>;
  try {
    raw = await unwrapVaultKey(record.vaultKeyWrapped, derived.wrapKey);
  } catch {
    throw new Error('Incorrect password.');
  }
  const vaultKey = await importVaultKey(raw);
  wipe(raw);
  const data = sanitizeVaultData(await openJson<unknown>(vaultKey, record.encryptedData, 'vault-data'));
  enterVault(vaultKey, record.kdf, record.revision, data);
};

// ---------------------------------------------------------------------------
// Usernames (chosen by the user, case-insensitive)
// ---------------------------------------------------------------------------

export const USERNAME_MIN = 3;
export const USERNAME_MAX = 32;

/** Same rules as the server: lowercase a-z, 0-9, `.` `_` `-` (not at the edges). */
export const normalizeUsername = (raw: string): string => raw.trim().toLowerCase();

export const usernameProblem = (raw: string): string | null => {
  const name = normalizeUsername(raw);
  if (name.length < USERNAME_MIN) return `At least ${USERNAME_MIN} characters.`;
  if (name.length > USERNAME_MAX) return `At most ${USERNAME_MAX} characters.`;
  if (!/^[a-z0-9._-]+$/.test(name)) return 'Only letters (no accents), digits, ".", "_" and "-".';
  if (!/^[a-z0-9]/.test(name) || !/[a-z0-9]$/.test(name)) return 'Must start and end with a letter or digit.';
  return null;
};

export interface AuthForm {
  username: string;
  password: string;
  confirmPassword?: string;
  inviteCode?: string;
}

export const submitAuth = async ({ username, password, confirmPassword = '', inviteCode = '' }: AuthForm): Promise<void> => {
  const id = normalizeUsername(username);
  const registering = app.authMode === 'register';

  if (!id) {
    app.authError = 'Username is required.';
    return;
  }
  if (!password) {
    app.authError = 'Password is required.';
    return;
  }
  if (!isSecureContextOk()) {
    app.authError = 'xVault only works over HTTPS (or on localhost): your password would otherwise travel unprotected.';
    return;
  }
  if (registering) {
    const problem = usernameProblem(id) ?? checkNewPassword(password);
    if (problem) {
      app.authError = problem;
      return;
    }
    if (password !== confirmPassword) {
      app.authError = 'The passwords do not match.';
      return;
    }
  }

  app.authError = null;
  app.pending.auth = true;

  try {
    if (registering) {
      if (!app.registrationEnabled) {
        app.authError = 'Registration is disabled on this server.';
        return;
      }
      const raw = generateVaultKey();
      try {
        const material = await buildKeyMaterial(password, raw);
        const vaultKey = await importVaultKey(raw);
        const empty: VaultData = { entries: [], folders: [], passwords: [] };
        const encryptedData = await sealJson(vaultKey, empty, 'vault-data');
        const result = await registerUser({
          username: id,
          ...material,
          encryptedData,
          inviteCode: inviteCode.trim() || undefined,
        });
        app.user = result.user;
        app.registerLoginId = result.loginId;
        unlocked = { vaultKey, kdf: material.kdf, revision: 1 };
        applyVault(empty);
      } finally {
        wipe(raw);
      }
      return;
    }

    const info = await prelogin(id);
    const keys = await deriveKeys(password, info.kdf);
    const result = await loginUser(id, keys.authKey);
    app.user = result.user;
    await openVaultWithPassword(password, keys);
    showToast('Vault unlocked', 'success');
  } catch (error) {
    const apiError = error as ApiError & { code?: string };
    app.authError = errorMessage(error, 'The authentication request failed.');
    if (apiError.status === 409) {
      app.authError = 'This username is already taken — pick another one.';
    } else if (apiError.status === 401 && apiError.attemptsLeft !== undefined) {
      app.authError = `Wrong username or password. Attempts left before a temporary lock: ${apiError.attemptsLeft}.`;
    }
    if (app.user && app.screen !== 'vault' && !registering) {
      // Signed in, but decryption failed: fall back to unlock.
      app.screen = 'locked';
    }
  } finally {
    app.pending.auth = false;
  }
};

/** After sign-up: open the vault straight on the recovery-phrase setup. */
export const setUpRecoveryAfterRegistration = async (): Promise<void> => {
  acknowledgeRegistration();
  app.activePanel = 'security';
  await startRecoveryPhraseSetup();
};

export const acknowledgeRegistration = (): void => {
  app.registerLoginId = null;
  if (unlocked) {
    app.screen = 'vault';
    app.activePanel = 'codes';
    app.saveStatus = 'saved';
    app.saveMessage = 'End-to-end encrypted';
    startAutoLock();
  } else {
    app.screen = 'locked';
  }
};

// ---------------------------------------------------------------------------
// Unlock / lock / sign out
// ---------------------------------------------------------------------------

export const submitUnlock = async (password: string): Promise<void> => {
  if (!password) {
    app.unlockError = 'Password is required.';
    return;
  }
  if (!requireSecureContext('Unlocking')) {
    return;
  }

  app.unlockError = null;
  app.unlockAttemptsLeft = undefined;
  app.pending.unlock = true;

  try {
    await openVaultWithPassword(password);
    showToast('Vault unlocked', 'success');
  } catch (error) {
    const apiError = error as ApiError;
    if (apiError.status === 401 && apiError.message === 'Authentication required') {
      await signOut();
      app.authError = 'Your session expired. Sign in again.';
      return;
    }
    app.unlockError = errorMessage(error, (error as Error).message || 'Unable to unlock the vault.');
    app.unlockAttemptsLeft = apiError.attemptsLeft;
  } finally {
    app.pending.unlock = false;
  }
};

const resetUiState = (): void => {
  app.entries = [];
  app.folders = [];
  app.passwords = [];
  app.search = '';
  app.passwordSearch = '';
  app.activeFolderId = null;
  app.entryDialogMode = null;
  app.editingEntryId = null;
  app.passwordDialogMode = null;
  app.editingPasswordId = null;
  app.qrScannerOpen = false;
  app.qrScannerMessage = null;
  app.folderDialogOpen = false;
  app.editingFolderId = null;
  app.copiedEntryId = null;
  app.unlockError = null;
  app.unlockAttemptsLeft = undefined;
  app.confirm = null;
  app.saveStatus = 'idle';
  app.saveMessage = null;
  app.recoveryPhraseReveal = null;
  app.masterKeyDialogOpen = false;
  app.importPreview = null;
  resolvePasswordPrompt(null);
};

export const lockVault = (): void => {
  // Never lose an edit made just before locking: push it out first.
  flushPendingSave();
  stopAutoLock();
  unlocked = null;
  resetUiState();
  app.screen = app.user ? 'locked' : 'auth';
};

export const signOut = async (): Promise<void> => {
  flushPendingSave();
  await saveQueue.catch(() => undefined);
  stopAutoLock();
  unlocked = null;
  try {
    await logoutUser();
  } catch {
    // Server-side session will expire on its own.
  }
  resetUiState();
  app.screen = 'auth';
  app.authMode = 'login';
  app.user = null;
  app.registerLoginId = null;
  app.authError = null;
};

// ---------------------------------------------------------------------------
// Persistence: debounced, serialized, revision-checked saves
// ---------------------------------------------------------------------------

let saveTimer: ReturnType<typeof setTimeout> | null = null;
let pendingSave: (() => void) | null = null;
let saveQueue: Promise<void> = Promise.resolve();

const persist = async (snapshot: VaultData, session: NonNullable<typeof unlocked>): Promise<void> => {
  const encryptedData = await sealJson(session.vaultKey, snapshot, 'vault-data');
  try {
    const result = await saveVault(encryptedData, session.revision);
    session.revision = result.revision;
    if (unlocked === session) {
      app.saveStatus = 'saved';
      app.saveMessage = 'End-to-end encrypted';
    }
  } catch (error) {
    if (unlocked !== session) {
      return;
    }
    app.saveStatus = 'error';
    const apiError = error as ApiError;
    if (apiError.status === 409) {
      app.saveMessage = 'Changed on another device';
      showToast('The vault was changed on another device. Lock and unlock to load the latest version.', 'error');
    } else {
      app.saveMessage = 'Unable to save encrypted data';
      showToast('Encrypted save failed. Your latest changes are still in memory — keep this tab open and retry.', 'error');
    }
  }
};

export const queueSave = (): void => {
  const session = unlocked;
  if (!session || app.screen !== 'vault') {
    return;
  }
  // Snapshot now: what is saved is exactly what the user saw.
  const snapshot: VaultData = $state.snapshot({
    entries: app.entries,
    folders: app.folders,
    passwords: app.passwords,
  });
  if (saveTimer) {
    clearTimeout(saveTimer);
  }
  app.saveStatus = 'saving';
  app.saveMessage = 'Encrypting changes';

  pendingSave = () => {
    pendingSave = null;
    saveTimer = null;
    saveQueue = saveQueue.then(() => persist(snapshot, session)).catch(() => undefined);
  };
  saveTimer = setTimeout(() => pendingSave?.(), 300);
};

const flushPendingSave = (): void => {
  if (saveTimer) {
    clearTimeout(saveTimer);
    saveTimer = null;
  }
  pendingSave?.();
};

// ---------------------------------------------------------------------------
// OTP entries
// ---------------------------------------------------------------------------

export interface EntryDraft {
  accountName: string;
  issuer: string;
  secret: string;
  type: OtpType;
  algorithm: OtpAlgorithm;
  digits: number;
  period: number;
  counter: number;
  folderId: string | null;
  icon: string;
  isCustomIcon: boolean;
}

export const openEntryDialog = (mode: 'create' | 'edit', entryId: string | null = null): void => {
  app.entryDialogMode = mode;
  app.editingEntryId = entryId;
  app.qrScannerOpen = false;
  app.qrScannerMessage = null;
};

export const closeEntryDialog = (): void => {
  app.entryDialogMode = null;
  app.editingEntryId = null;
};

const entryFromSource = (source: ParsedOtpSource, folderId?: string): TOTPEntry => ({
  id: generateId(),
  name: deriveEntryName(source.accountName, source.issuer) || 'Account',
  secret: source.secret,
  icon: '',
  type: source.type,
  algorithm: source.algorithm,
  digits: source.digits,
  period: source.period,
  counter: source.counter,
  folderId,
});

/** Adds every account of a Google Authenticator export QR at once. */
export const importMigrationQr = (uri: string): number => {
  const sources = parseMigrationUri(uri);
  if (sources.length === 0) {
    showToast('No account found in that export QR code.', 'error');
    return 0;
  }
  app.entries = [...app.entries, ...sources.map((source) => entryFromSource(source))];
  queueSave();
  showToast(`Imported ${sources.length} account${sources.length === 1 ? '' : 's'} from Google Authenticator`, 'success');
  return sources.length;
};

export const saveEntry = (draft: EntryDraft): void => {
  let input: Parameters<typeof makeOtpSource>[0] = {
    accountName: draft.accountName,
    issuer: draft.issuer,
    secret: draft.secret.trim(),
    type: draft.type,
    algorithm: draft.algorithm,
    digits: draft.digits,
    period: draft.period,
    counter: draft.counter,
  };

  if (isMigrationUri(input.secret)) {
    try {
      if (importMigrationQr(input.secret) > 0) closeEntryDialog();
    } catch (error) {
      showToast((error as Error).message, 'error');
    }
    return;
  }

  try {
    const parsed = parseOtpAuthUri(input.secret);
    if (parsed) {
      input = {
        ...parsed,
        accountName: parsed.accountName || input.accountName,
        issuer: parsed.issuer || input.issuer,
      };
    }
  } catch (error) {
    showToast((error as Error).message, 'error');
    return;
  }

  const source = makeOtpSource(input);
  if (!source) {
    showToast('The secret key must be a valid Base32 string (A–Z, 2–7).', 'error');
    return;
  }
  if (!source.accountName && !source.issuer) {
    showToast('An account name is required.', 'error');
    return;
  }

  const icon = sanitizeIcon(draft.icon, draft.isCustomIcon);
  const folderId = draft.folderId ?? undefined;
  const isEditing = app.entryDialogMode === 'edit' && app.editingEntryId;

  if (isEditing) {
    const id = app.editingEntryId as string;
    app.entries = app.entries.map((entry) =>
      entry.id === id
        ? {
            ...entry,
            name: deriveEntryName(source.accountName, source.issuer),
            secret: source.secret,
            type: source.type,
            algorithm: source.algorithm,
            digits: source.digits,
            period: source.period,
            counter: source.counter,
            folderId,
            ...icon,
          }
        : entry,
    );
    showToast('Entry updated', 'success');
  } else {
    app.entries = [...app.entries, { ...entryFromSource(source, folderId), ...icon }];
    showToast('Account added', 'success');
  }

  closeEntryDialog();
  queueSave();
};

/** HOTP: moves to the next counter value (and persists it). */
export const advanceHotp = (entryId: string): void => {
  app.entries = app.entries.map((entry) =>
    entry.id === entryId ? { ...entry, counter: (entry.counter ?? 0) + 1 } : entry,
  );
  queueSave();
};

export const deleteEntry = (entryId: string): void => {
  const entry = app.entries.find((item) => item.id === entryId);
  if (!entry) {
    return;
  }
  askConfirm({
    title: 'Delete account',
    message: `Remove "${entry.name}" and its stored secret from this vault? This cannot be undone.`,
    confirmLabel: 'Delete',
    danger: true,
    action: () => {
      app.entries = app.entries.filter((item) => item.id !== entryId);
      if (app.copiedEntryId === entryId) {
        app.copiedEntryId = null;
      }
      queueSave();
      showToast('Account deleted', 'info');
    },
  });
};

// ---------------------------------------------------------------------------
// Folders
// ---------------------------------------------------------------------------

export const openFolderDialog = (folderId: string | null = null): void => {
  app.editingFolderId = folderId;
  app.folderDialogOpen = true;
};

export const closeFolderDialog = (): void => {
  app.folderDialogOpen = false;
  app.editingFolderId = null;
};

export const saveFolder = (name: string, icon: string, color: string): void => {
  const trimmedName = name.trim().slice(0, 100);
  if (!trimmedName) {
    showToast('A folder name is required.', 'error');
    return;
  }
  const safeIcon = sanitizeMarker(icon);
  const safeColor = sanitizeColor(color);
  const isEditing = app.editingFolderId !== null;

  if (isEditing) {
    const id = app.editingFolderId as string;
    app.folders = app.folders.map((folder) =>
      folder.id === id ? { ...folder, name: trimmedName, icon: safeIcon, color: safeColor } : folder,
    );
    showToast('Folder updated', 'success');
  } else {
    app.folders = [...app.folders, { id: generateId(), name: trimmedName, icon: safeIcon, color: safeColor }];
    showToast('Folder created', 'success');
  }

  closeFolderDialog();
  queueSave();
};

export const deleteFolder = (folderId: string): void => {
  const folder = app.folders.find((item) => item.id === folderId);
  if (!folder) {
    return;
  }
  askConfirm({
    title: 'Delete folder',
    message: `Delete "${folder.name}"? Entries inside it become ungrouped and are kept.`,
    confirmLabel: 'Delete',
    danger: true,
    action: () => {
      app.folders = app.folders
        .filter((item) => item.id !== folderId)
        .map((item) => (item.parentId === folderId ? { ...item, parentId: undefined } : item));
      app.entries = app.entries.map((entry) =>
        entry.folderId === folderId ? { ...entry, folderId: undefined } : entry,
      );
      if (app.activeFolderId === folderId) {
        app.activeFolderId = null;
      }
      queueSave();
      showToast('Folder deleted', 'info');
    },
  });
};

// ---------------------------------------------------------------------------
// Passwords
// ---------------------------------------------------------------------------

export interface PasswordDraft {
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  folderId: string | null;
}

export const openPasswordDialog = (mode: 'create' | 'edit', passwordId: string | null = null): void => {
  app.passwordDialogMode = mode;
  app.editingPasswordId = passwordId;
};

export const closePasswordDialog = (): void => {
  app.passwordDialogMode = null;
  app.editingPasswordId = null;
};

export const savePasswordEntry = (draft: PasswordDraft): void => {
  const title = draft.title.trim().slice(0, 500);
  const password = draft.password.slice(0, 4096);

  if (!title) {
    showToast('A title is required.', 'error');
    return;
  }
  if (!password) {
    showToast('A password is required.', 'error');
    return;
  }
  const rawUrl = draft.url.trim();
  const url = sanitizeUrl(rawUrl);
  if (rawUrl && !url) {
    showToast('Only http:// and https:// links can be saved.', 'error');
    return;
  }

  const now = new Date().toISOString();
  const fields = {
    title,
    username: draft.username.trim().slice(0, 500),
    password,
    url,
    notes: draft.notes.trim().slice(0, 20_000) || undefined,
    folderId: draft.folderId ?? undefined,
  };
  const isEditing = app.passwordDialogMode === 'edit' && app.editingPasswordId;

  if (isEditing) {
    const id = app.editingPasswordId as string;
    app.passwords = app.passwords.map((entry) =>
      entry.id === id ? { ...entry, ...fields, updatedAt: now } : entry,
    );
    showToast('Password updated', 'success');
  } else {
    app.passwords = [...app.passwords, { id: generateId(), ...fields, createdAt: now, updatedAt: now }];
    showToast('Password saved', 'success');
  }

  closePasswordDialog();
  queueSave();
};

export const deletePasswordEntry = (passwordId: string): void => {
  const entry = app.passwords.find((item) => item.id === passwordId);
  if (!entry) {
    return;
  }
  askConfirm({
    title: 'Delete password',
    message: `Remove "${entry.title}" from this vault? This cannot be undone.`,
    confirmLabel: 'Delete',
    danger: true,
    action: () => {
      app.passwords = app.passwords.filter((item) => item.id !== passwordId);
      queueSave();
      showToast('Password deleted', 'info');
    },
  });
};

export const copyPasswordField = async (value: string, label: string): Promise<void> => {
  try {
    await copySecret(value);
    showToast(`${label} copied — clipboard clears in ${CLIPBOARD_CLEAR_MS / 1000}s`, 'success');
  } catch {
    showToast(`Unable to copy ${label.toLowerCase()}.`, 'error');
  }
};

export const copyCode = async (entry: TOTPEntry, code: string): Promise<void> => {
  try {
    await copySecret(code);
  } catch {
    showToast('Unable to copy the code.', 'error');
    return;
  }
  app.copiedEntryId = entry.id;
  showToast(`Code copied for ${entry.name}`, 'success');
  setTimeout(() => {
    if (app.copiedEntryId === entry.id) {
      app.copiedEntryId = null;
    }
  }, 1500);
};

/** Login IDs are not secret, but keep the same clipboard hygiene. */
export const copyLoginId = async (loginId: string): Promise<void> => {
  try {
    await writeClipboard(loginId);
    showToast('Login ID copied', 'success');
  } catch {
    showToast('Unable to copy — write the login ID down manually.', 'error');
  }
};

// ---------------------------------------------------------------------------
// Re-authentication helpers
// ---------------------------------------------------------------------------

/** Derives the current keys from `password` and proves them locally. */
const reauthenticate = async (password: string): Promise<{ keys: DerivedKeys; rawVaultKey: Uint8Array<ArrayBuffer> }> => {
  if (!unlocked) {
    throw new Error('The vault is locked.');
  }
  const record = await fetchVault();
  const keys = await deriveKeys(password, record.kdf);
  try {
    const rawVaultKey = await unwrapVaultKey(record.vaultKeyWrapped, keys.wrapKey);
    return { keys, rawVaultKey };
  } catch {
    throw new Error('Current password is incorrect.');
  }
};

// ---------------------------------------------------------------------------
// Backups (encrypted in the browser)
// ---------------------------------------------------------------------------

export const exportVaultAction = async (): Promise<void> => {
  if (!unlocked) {
    return;
  }
  const password = await askPassword({
    title: 'Encrypt backup',
    message:
      'Choose a password for this backup file. You will need it to restore. Using your vault password is fine.',
    label: 'Backup password',
    confirm: true,
    minLength: 12,
    submitLabel: 'Encrypt & download',
  });
  if (!password) {
    return;
  }
  app.pending.export = true;
  try {
    const data: VaultData = $state.snapshot({ entries: app.entries, folders: app.folders, passwords: app.passwords });
    const blob = await buildBackup(data, password);
    downloadBlob(blob, `xvault-backup-${new Date().toISOString().slice(0, 10)}.json`);
    showToast('Encrypted backup downloaded', 'success');
  } catch (error) {
    showToast((error as Error).message || 'Failed to export the vault.', 'error');
  } finally {
    app.pending.export = false;
  }
};

const MAX_IMPORT_BYTES = 50 * 1024 * 1024;

export const importVaultFromFile = async (file: File): Promise<void> => {
  if (!unlocked) {
    return;
  }
  if (file.size > MAX_IMPORT_BYTES) {
    showToast('That file is too large to import.', 'error');
    return;
  }
  app.pending.import = true;
  try {
    const text = await file.text();
    let password: string | undefined;
    if (isEncryptedBackup(text)) {
      password =
        (await askPassword({
          title: 'Restore backup',
          message: 'Enter the password used when this backup was created.',
          label: 'Backup password',
          submitLabel: 'Decrypt',
        })) ?? undefined;
      if (!password) return;
    }
    const data = await parseBackup(text, password);
    if (!data) {
      // Not an xVault backup: try the universal importer instead.
      await previewUniversalImport(file);
      return;
    }
    askConfirm({
      title: 'Replace vault',
      message: `Replace the current vault with this backup (${data.entries.length} 2FA codes, ${data.passwords.length} passwords)? Current items not in the backup will be lost.`,
      confirmLabel: 'Replace',
      danger: true,
      action: () => {
        applyVault(data);
        app.activeFolderId = null;
        queueSave();
        showToast('Vault restored from backup', 'success');
      },
    });
  } catch (error) {
    if (error instanceof BackupPasswordRequired) return;
    showToast((error as Error).message || 'Failed to import the backup file.', 'error');
  } finally {
    app.pending.import = false;
  }
};

// ---------------------------------------------------------------------------
// Profile & security
// ---------------------------------------------------------------------------

export const saveProfile = async (name: string): Promise<void> => {
  const trimmed = name.trim();
  if (!trimmed || trimmed.length > 100) {
    showToast('Vault name must be 1-100 characters.', 'error');
    return;
  }
  app.pending.profile = true;
  try {
    await updateUserProfile({ name: trimmed });
    if (app.user) {
      app.user = { ...app.user, name: trimmed };
    }
    showToast('Profile updated', 'success');
  } catch (error) {
    showToast(errorMessage(error, 'Failed to update the profile.'), 'error');
  } finally {
    app.pending.profile = false;
  }
};

export const changeVaultPassword = async (
  currentPassword: string,
  newPassword: string,
  confirmPassword: string,
): Promise<void> => {
  if (!currentPassword || !newPassword) {
    showToast('Current and new passwords are required.', 'error');
    return;
  }
  const weakness = checkNewPassword(newPassword);
  if (weakness) {
    showToast(weakness, 'error');
    return;
  }
  if (newPassword !== confirmPassword) {
    showToast('The new passwords do not match.', 'error');
    return;
  }

  app.pending.password = true;
  let raw: Uint8Array<ArrayBuffer> | null = null;
  try {
    const current = await reauthenticate(currentPassword);
    raw = current.rawVaultKey;
    const material = await buildKeyMaterial(newPassword, raw);
    await changePassword(current.keys.authKey, material);
    if (unlocked) {
      unlocked.kdf = material.kdf;
    }
    showToast('Password changed. Other devices were signed out.', 'success');
  } catch (error) {
    showToast(errorMessage(error, (error as Error).message || 'Failed to change the password.'), 'error');
  } finally {
    wipe(raw);
    app.pending.password = false;
  }
};

// ---------------------------------------------------------------------------
// Universal import (passwords + third-party 2FA)
// ---------------------------------------------------------------------------

export const previewUniversalImport = async (file: File): Promise<void> => {
  if (file.size > MAX_IMPORT_BYTES) {
    showToast('That file is too large to import.', 'error');
    return;
  }
  app.pending.import = true;
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    let password: string | undefined;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const result = await parseImportFile(bytes, file.name, password);
        if (result.passwords.length === 0 && result.totps.length === 0) {
          showToast('Nothing recognizable was found in that file.', 'error');
          return;
        }
        app.importPreview = result;
        return;
      } catch (error) {
        if (!(error instanceof ImportPasswordRequired)) {
          throw error;
        }
        password =
          (await askPassword({
            title: 'Encrypted export',
            message: attempt === 0 ? error.message : 'Wrong password. Try again.',
            label: 'Export password',
            submitLabel: 'Decrypt',
          })) ?? undefined;
        if (!password) return;
      }
    }
    showToast('Could not decrypt that export.', 'error');
  } catch (error) {
    showToast((error as Error).message || 'Could not parse that file.', 'error');
  } finally {
    app.pending.import = false;
  }
};

export const cancelUniversalImport = (): void => {
  app.importPreview = null;
};

export const confirmUniversalImport = (): void => {
  const preview = app.importPreview;
  if (!preview) {
    return;
  }

  const now = new Date().toISOString();
  const newPasswords: PasswordEntry[] = preview.passwords.map((item) => ({
    id: generateId(),
    title: item.title.slice(0, 500) || 'Login',
    username: item.username.slice(0, 500),
    password: item.password.slice(0, 4096),
    url: sanitizeUrl(item.url),
    notes: item.notes?.slice(0, 20_000),
    createdAt: now,
    updatedAt: now,
  }));

  const newEntries: TOTPEntry[] = preview.totps.map((item) => entryFromSource(item));

  app.passwords = [...app.passwords, ...newPasswords];
  app.entries = [...app.entries, ...newEntries];
  app.importPreview = null;

  queueSave();
  showToast(
    `Imported ${newPasswords.length} password${newPasswords.length === 1 ? '' : 's'} and ${newEntries.length} 2FA code${newEntries.length === 1 ? '' : 's'}.`,
    'success',
  );
};

// ---------------------------------------------------------------------------
// Recovery phrase
// ---------------------------------------------------------------------------

export const startRecoveryPhraseSetup = async (): Promise<void> => {
  if (!requireSecureContext('Recovery phrase generation')) {
    return;
  }
  const mnemonic = await generateMnemonic(24);
  app.recoveryPhraseReveal = { mnemonic, confirmed: false };
};

export const cancelRecoveryPhraseSetup = (): void => {
  app.recoveryPhraseReveal = null;
};

/** Wraps the vault key for a recovery method and registers it server-side. */
const enableRecoveryMethod = async (
  method: RecoveryMethod,
  password: string,
  secret: string,
): Promise<void> => {
  if (!app.user) throw new Error('Not signed in.');
  const { keys, rawVaultKey } = await reauthenticate(password);
  try {
    const recovery = await deriveRecoveryKeys(secret, app.user.loginId, method);
    const wrapped = await wrapVaultKey(rawVaultKey, recovery.wrapKey);
    await enableRecovery(method, keys.authKey, recovery.authKey, wrapped);
  } finally {
    wipe(rawVaultKey);
  }
};

export const confirmRecoveryPhraseSaved = async (password: string, confirmed: boolean): Promise<void> => {
  const reveal = app.recoveryPhraseReveal;
  if (!reveal || !app.user) {
    return;
  }
  if (!confirmed) {
    showToast('Confirm that you wrote the phrase down first.', 'error');
    return;
  }
  if (!password) {
    showToast('Enter your current password to confirm.', 'error');
    return;
  }

  app.pending.recovery = true;
  try {
    await enableRecoveryMethod('phrase', password, normalizeMnemonic(reveal.mnemonic));
    app.user = { ...app.user, recoveryEnabled: true };
    app.recoveryPhraseReveal = null;
    showToast('Recovery phrase enabled', 'success');
  } catch (error) {
    showToast(errorMessage(error, (error as Error).message || 'Failed to enable the recovery phrase.'), 'error');
  } finally {
    app.pending.recovery = false;
  }
};

const disableRecoveryMethod = async (method: RecoveryMethod, password: string): Promise<void> => {
  const { keys, rawVaultKey } = await reauthenticate(password);
  wipe(rawVaultKey);
  await disableRecovery(method, keys.authKey);
};

export const disableRecoveryPhraseAction = async (password: string): Promise<void> => {
  if (!app.user) return;
  if (!password) {
    showToast('Password confirmation is required.', 'error');
    return;
  }
  app.pending.recovery = true;
  try {
    await disableRecoveryMethod('phrase', password);
    app.user = { ...app.user, recoveryEnabled: false };
    showToast('Recovery phrase disabled', 'info');
  } catch (error) {
    showToast(errorMessage(error, (error as Error).message || 'Failed to disable the recovery phrase.'), 'error');
  } finally {
    app.pending.recovery = false;
  }
};

// ---------------------------------------------------------------------------
// Master-key (.key) file
// ---------------------------------------------------------------------------

export const openMasterKeyDialog = (): void => {
  if (!requireSecureContext('Master-key file generation')) {
    return;
  }
  app.masterKeyDialogOpen = true;
};

export const closeMasterKeyDialog = (): void => {
  app.masterKeyDialogOpen = false;
};

export const generateAndDownloadMasterKey = async (password: string, filePassphrase: string): Promise<void> => {
  if (!app.user) return;
  if (!password) {
    showToast('Enter your current password to confirm.', 'error');
    return;
  }
  if (filePassphrase.length < MIN_FILE_PASSPHRASE) {
    showToast(`The file passphrase needs at least ${MIN_FILE_PASSPHRASE} characters.`, 'error');
    return;
  }

  app.pending.masterKey = true;
  try {
    const secret = generateMasterKeySecret();
    // Build the file first: if anything fails here, nothing changed server-side.
    const blob = await buildMasterKeyFile(
      { loginId: app.user.loginId, masterSecret: secret, createdAt: new Date().toISOString() },
      filePassphrase,
    );
    await enableRecoveryMethod('key', password, secret);
    downloadMasterKeyFile(blob, app.user.loginId);
    app.user = { ...app.user, masterKeyEnabled: true };
    app.masterKeyDialogOpen = false;
    showToast('Recovery key file generated. Any previous file no longer works.', 'success');
  } catch (error) {
    showToast(errorMessage(error, (error as Error).message || 'Failed to enable the master key file.'), 'error');
  } finally {
    app.pending.masterKey = false;
  }
};

export const disableMasterKeyAction = async (password: string): Promise<void> => {
  if (!app.user) return;
  if (!password) {
    showToast('Password confirmation is required.', 'error');
    return;
  }
  app.pending.masterKey = true;
  try {
    await disableRecoveryMethod('key', password);
    app.user = { ...app.user, masterKeyEnabled: false };
    showToast('Master key file disabled. Any previously downloaded file no longer works.', 'info');
  } catch (error) {
    showToast(errorMessage(error, (error as Error).message || 'Failed to disable the master key file.'), 'error');
  } finally {
    app.pending.masterKey = false;
  }
};

// ---------------------------------------------------------------------------
// Account recovery (forgotten password)
// ---------------------------------------------------------------------------

export const openRecoverFlow = (): void => {
  app.recoverFlowOpen = true;
};

export const closeRecoverFlow = (): void => {
  app.recoverFlowOpen = false;
};

type RecoverResult = { success: boolean; error?: string; attemptsLeft?: number; needsPassphrase?: boolean };

const recoverAccount = async (
  loginId: string,
  method: RecoveryMethod,
  secret: string,
  newPassword: string,
): Promise<RecoverResult> => {
  const weakness = checkNewPassword(newPassword);
  if (weakness) {
    return { success: false, error: weakness };
  }
  const recovery = await deriveRecoveryKeys(secret, loginId, method);
  try {
    const { wrapped } = await recoveryChallenge(loginId, method, recovery.authKey);
    let raw: Uint8Array<ArrayBuffer>;
    try {
      raw = await unwrapVaultKey(wrapped, recovery.wrapKey);
    } catch {
      return { success: false, error: 'Invalid recovery credentials.' };
    }
    try {
      const material = await buildKeyMaterial(newPassword, raw);
      await recoveryComplete({ loginId, method, proof: recovery.authKey, ...material });
    } finally {
      wipe(raw);
    }
    app.recoverFlowOpen = false;
    showToast('Password reset. Sign in with your new password.', 'success');
    return { success: true };
  } catch (error) {
    const apiError = error as ApiError;
    return { success: false, error: errorMessage(error, 'Unable to recover this account.'), attemptsLeft: apiError.attemptsLeft };
  }
};

export const recoverWithPhrase = async (
  loginId: string,
  mnemonic: string,
  newPassword: string,
): Promise<RecoverResult> => {
  if (!requireSecureContext('Recovery-phrase restore')) {
    return { success: false };
  }
  if (!(await validateMnemonic(mnemonic))) {
    return { success: false, error: 'That recovery phrase does not look right. Check the word order and spelling.' };
  }
  app.pending.recoverAccount = true;
  try {
    return await recoverAccount(normalizeUsername(loginId), 'phrase', normalizeMnemonic(mnemonic), newPassword);
  } finally {
    app.pending.recoverAccount = false;
  }
};

export const recoverWithMasterKeyFile = async (
  fileText: string,
  filePassphrase: string,
  newPassword: string,
): Promise<RecoverResult> => {
  if (!requireSecureContext('Master-key file restore')) {
    return { success: false };
  }
  app.pending.recoverAccount = true;
  try {
    let payload;
    try {
      payload = await parseMasterKeyFile(fileText, filePassphrase || undefined);
    } catch (error) {
      const err = error as Error & { needsPassphrase?: boolean };
      return { success: false, error: err.message, needsPassphrase: err.needsPassphrase };
    }
    return await recoverAccount(payload.loginId, 'key', payload.masterSecret, newPassword);
  } finally {
    app.pending.recoverAccount = false;
  }
};

export const deleteAccountAction = async (password: string): Promise<void> => {
  if (!password) {
    showToast('Password confirmation is required.', 'error');
    return;
  }
  askConfirm({
    title: 'Delete account',
    message:
      'This permanently removes the user record and the stored vault payload from the server database. There is no recovery.',
    confirmLabel: 'Delete everything',
    danger: true,
    action: async () => {
      app.pending.danger = true;
      try {
        const { keys, rawVaultKey } = await reauthenticate(password);
        wipe(rawVaultKey);
        await deleteAccount(keys.authKey);
        await signOut();
        showToast('Account deleted', 'info');
      } catch (error) {
        showToast(errorMessage(error, (error as Error).message || 'Failed to delete the account.'), 'error');
      } finally {
        app.pending.danger = false;
      }
    },
  });
};
