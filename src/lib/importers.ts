import { unzipSync } from 'fflate';
import { scrypt } from 'hash-wasm';

import {
  isMigrationUri,
  makeOtpSource,
  parseAlgorithm,
  parseMigrationUri,
  parseOtpAuthUri,
  parseOtpType,
  type ParsedOtpSource,
} from './otpauth';
import { bytesToBase32 } from './totp';
import type { OtpType } from './types';
import { argon2, fromBase64, type KdfParams } from './vaultcrypto';

// Universal import. Detects and parses, entirely in the browser:
//
// Passwords — Bitwarden (JSON, password-protected JSON, CSV), 1Password
//   (.1pux, .1pif, CSV), KeePass / KeePassXC (XML, CSV), Proton Pass (JSON,
//   ZIP), Enpass (JSON), Keeper (JSON), Chrome / Edge / Brave / Opera,
//   Firefox, Safari / iCloud Keychain, LastPass, Dashlane, NordPass,
//   RoboForm, and any CSV/JSON with recognizable columns (`,` `;` or tab).
// 2FA — Aegis (plain + encrypted), 2FAS (plain + encrypted), andOTP (plain
//   + encrypted .aes), Proton Authenticator, FreeOTP+, Raivo, Authenticator Pro / Stratum,
//   LastPass Authenticator, Bitwarden Authenticator, Proton / Ente Auth,
//   Google Authenticator export (otpauth-migration://), Steam Guard
//   (.maFile), and any otpauth:// URI anywhere in a text/JSON file.

export interface ImportedPassword {
  title: string;
  username: string;
  password: string;
  url?: string;
  notes?: string;
}

export type ImportedTotp = ParsedOtpSource;

export interface ImportResult {
  passwords: ImportedPassword[];
  totps: ImportedTotp[];
  sourceFormat: string;
  skipped: number;
}

export class ImportPasswordRequired extends Error {
  constructor(app: string) {
    super(`This ${app} export is encrypted. Enter the password used to protect it.`);
  }
}

class WrongImportPassword extends ImportPasswordRequired {}

const emptyResult = (sourceFormat: string): ImportResult => ({
  passwords: [],
  totps: [],
  sourceFormat,
  skipped: 0,
});

const decoder = new TextDecoder();
const encoder = new TextEncoder();

const str = (value: unknown): string => (typeof value === 'string' ? value : typeof value === 'number' ? String(value) : '');

// ---------------------------------------------------------------------------
// Generic field resolution (CSV rows and flat JSON records)
// ---------------------------------------------------------------------------

const ALIASES = {
  title: ['title', 'name', 'item_name', 'account_name', 'label', 'service', 'site_name', 'entry'],
  username: [
    'username', 'login_username', 'user_name', 'login', 'login_name', 'user', 'email', 'email_address',
    'account', 'useremail', 'item_username', 'item_email',
  ],
  password: ['password', 'login_password', 'pass', 'pwd', 'passwd'],
  url: [
    'url', 'login_uri', 'website', 'site', 'uri', 'link', 'hostname', 'origin_url', 'web_site', 'login_url',
    'website_url', 'urls', 'matchurl', 'address',
  ],
  notes: ['notes', 'note', 'extra', 'comments', 'comment', 'description', 'notesplain'],
  secret: [
    'totp', 'login_totp', 'otp_secret', 'otpsecret', 'secret', '2fa_secret', 'otpauth', 'otp', 'otp_url',
    'otpurl', 'one-time_password', 'one_time_password', 'twofactor', 'two_factor_secret', 'totp_secret',
    'totpuri', 'mfa', 'authenticator_key', 'timeotp-secret-base32',
  ],
  issuer: ['issuer', 'issuername', 'issuer_name', 'service_name'],
  digits: ['digits'],
  period: ['period', 'timestep', 'time_step', 'timer', 'interval'],
  algorithm: ['algorithm', 'algo', 'hash'],
  counter: ['counter'],
  type: ['type', 'kind'],
} as const;

const normalizeKey = (key: string): string => key.trim().toLowerCase().replace(/\s+/g, '_');

const pick = (record: Record<string, unknown>, aliases: readonly string[]): string | undefined => {
  const normalized = new Map(Object.entries(record).map(([key, value]) => [normalizeKey(key), value]));
  for (const alias of aliases) {
    const value = normalized.get(alias);
    const text = Array.isArray(value) ? str(value[0]) : str(value);
    if (text.trim()) {
      return text.trim();
    }
  }
  return undefined;
};

/** Accepts an otpauth URI, a Steam URI or a bare Base32 secret. */
const parseSecretField = (
  raw: string,
  defaults: { accountName: string; issuer?: string; type?: OtpType; digits?: number; period?: number; algorithm?: string; counter?: number },
): ParsedOtpSource | null => {
  const trimmed = raw.trim();
  if (!trimmed) return null;
  if (/^otpauth:\/\//i.test(trimmed)) {
    try {
      const parsed = parseOtpAuthUri(trimmed);
      if (parsed) {
        return { ...parsed, accountName: parsed.accountName || defaults.accountName, issuer: parsed.issuer || defaults.issuer || '' };
      }
    } catch {
      return null;
    }
  }
  if (/^steam:\/\//i.test(trimmed)) {
    return makeOtpSource({ accountName: defaults.accountName, issuer: defaults.issuer || 'Steam', secret: trimmed.slice(8), type: 'steam' });
  }
  return makeOtpSource({
    accountName: defaults.accountName,
    issuer: defaults.issuer,
    secret: trimmed,
    type: defaults.type,
    digits: defaults.digits,
    period: defaults.period,
    algorithm: parseAlgorithm(defaults.algorithm),
    counter: defaults.counter,
  });
};

const NON_LOGIN_TYPES = new Set(['note', 'securenote', 'card', 'identity', 'sshkey', 'ssh_key', 'cryptowallet', 'crypto_wallet', 'creditcard']);

const recordToEntries = (record: Record<string, unknown>): { password?: ImportedPassword; totp?: ParsedOtpSource } => {
  const title = pick(record, ALIASES.title);
  const username = pick(record, ALIASES.username);
  const password = pick(record, ALIASES.password);
  const url = pick(record, ALIASES.url);
  const notes = pick(record, ALIASES.notes);
  const secretRaw = pick(record, ALIASES.secret);
  const type = pick(record, ALIASES.type)?.toLowerCase();

  const label = title || username || url || 'Imported item';
  const result: { password?: ImportedPassword; totp?: ParsedOtpSource } = {};

  if (password && !(type && NON_LOGIN_TYPES.has(type))) {
    result.password = { title: label, username: username ?? '', password, url, notes };
  }

  if (secretRaw) {
    const totp = parseSecretField(secretRaw, {
      accountName: username || label,
      issuer: pick(record, ALIASES.issuer) ?? (username ? title : undefined),
      type: type && ['hotp', 'steam'].includes(type) ? parseOtpType(type) : undefined,
      digits: Number(pick(record, ALIASES.digits)) || undefined,
      period: Number(pick(record, ALIASES.period)) || undefined,
      algorithm: pick(record, ALIASES.algorithm),
      counter: Number(pick(record, ALIASES.counter)) || undefined,
    });
    if (totp) result.totp = totp;
  }

  return result;
};

const pushRecord = (result: ImportResult, record: Record<string, unknown>): void => {
  const { password, totp } = recordToEntries(record);
  if (password) result.passwords.push(password);
  if (totp) result.totps.push(totp);
  if (!password && !totp) result.skipped++;
};

// ---------------------------------------------------------------------------
// CSV (quoted fields, embedded separators/newlines, "" escapes; , ; or tab)
// ---------------------------------------------------------------------------

const detectDelimiter = (headerLine: string): string => {
  const counts = [',', ';', '\t'].map((d) => [d, headerLine.split(d).length - 1] as const);
  counts.sort((a, b) => b[1] - a[1]);
  return counts[0][1] > 0 ? counts[0][0] : ',';
};

const parseCsvRows = (text: string): string[][] => {
  const input = text.replace(/^﻿/, '').replace(/\r\n?/g, '\n');
  const delimiter = detectDelimiter(input.split('\n', 1)[0] ?? '');
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let inQuotes = false;

  for (let i = 0; i < input.length; i++) {
    const char = input[i];
    if (inQuotes) {
      if (char === '"') {
        if (input[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += char;
      }
      continue;
    }
    if (char === '"' && field === '') {
      inQuotes = true;
    } else if (char === delimiter) {
      row.push(field);
      field = '';
    } else if (char === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += char;
    }
  }
  row.push(field);
  rows.push(row);
  return rows.filter((cells) => !(cells.length === 1 && cells[0].trim() === ''));
};

const parseCsv = (text: string, format = 'CSV'): ImportResult => {
  const rows = parseCsvRows(text);
  if (rows.length < 2) {
    throw new Error('CSV file has no data rows.');
  }
  const headers = rows[0].map((header) => header.trim());
  const result = emptyResult(format);
  for (const cells of rows.slice(1)) {
    const record: Record<string, unknown> = {};
    headers.forEach((header, index) => {
      record[header] = cells[index] ?? '';
    });
    pushRecord(result, record);
  }
  return result;
};

// ---------------------------------------------------------------------------
// Password managers (JSON / XML)
// ---------------------------------------------------------------------------

interface BitwardenItem {
  type?: number;
  name?: string | null;
  notes?: string | null;
  login?: {
    username?: string | null;
    password?: string | null;
    totp?: string | null;
    uris?: Array<{ uri?: string | null }> | null;
  } | null;
}

const parseBitwardenItems = (items: BitwardenItem[], format: string): ImportResult => {
  const result = emptyResult(format);
  for (const item of items) {
    if (!item.login) {
      result.skipped++;
      continue;
    }
    const label = item.name?.trim() || item.login.username?.trim() || 'Imported item';
    let matched = false;
    if (item.login.password) {
      result.passwords.push({
        title: label,
        username: item.login.username ?? '',
        password: item.login.password,
        url: item.login.uris?.[0]?.uri ?? undefined,
        notes: item.notes ?? undefined,
      });
      matched = true;
    }
    if (item.login.totp) {
      const totp = parseSecretField(item.login.totp, { accountName: item.login.username?.trim() || label, issuer: item.login.username ? label : '' });
      if (totp) {
        result.totps.push(totp);
        matched = true;
      }
    }
    if (!matched) result.skipped++;
  }
  return result;
};

// Bitwarden "password protected" export: KDF → HKDF-expand(enc, mac) →
// AES-256-CBC + HMAC-SHA256 ("2.iv|ct|mac").
const hkdfExpand = async (prk: Uint8Array<ArrayBuffer>, info: string): Promise<Uint8Array<ArrayBuffer>> => {
  const key = await crypto.subtle.importKey('raw', prk, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const block = new Uint8Array([...encoder.encode(info), 1]);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, block));
};

const decryptBitwardenString = async (
  encString: string,
  encKey: Uint8Array<ArrayBuffer>,
  macKey: Uint8Array<ArrayBuffer>,
): Promise<string> => {
  const match = /^2\.([^|]+)\|([^|]+)\|([^|]+)$/.exec(encString);
  if (!match) throw new Error('Unsupported Bitwarden encryption type.');
  const [iv, ct, mac] = [fromBase64(match[1]), fromBase64(match[2]), fromBase64(match[3])];
  const hmacKey = await crypto.subtle.importKey('raw', macKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const macData = new Uint8Array([...iv, ...ct]);
  if (!(await crypto.subtle.verify('HMAC', hmacKey, mac, macData))) {
    throw new WrongImportPassword('Bitwarden');
  }
  const aesKey = await crypto.subtle.importKey('raw', encKey, { name: 'AES-CBC' }, false, ['decrypt']);
  return decoder.decode(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, aesKey, ct));
};

const decryptBitwardenExport = async (data: Record<string, unknown>, password?: string): Promise<unknown> => {
  if (!data.passwordProtected) {
    throw new Error('This Bitwarden export is tied to your Bitwarden account key. Re-export it as "Password protected" or unencrypted JSON.');
  }
  if (!password) throw new ImportPasswordRequired('Bitwarden');
  const salt = encoder.encode(str(data.salt));
  let master: Uint8Array<ArrayBuffer>;
  if (Number(data.kdfType) === 1) {
    const saltHash = new Uint8Array(await crypto.subtle.digest('SHA-256', salt));
    master = await argon2(password, {
      algorithm: 'argon2id',
      salt: btoa(String.fromCharCode(...saltHash)),
      memory: Number(data.kdfMemory) * 1024,
      iterations: Number(data.kdfIterations),
      parallelism: Number(data.kdfParallelism),
    } as KdfParams);
  } else {
    const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    master = new Uint8Array(
      await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: Number(data.kdfIterations) }, material, 256),
    );
  }
  const encKey = await hkdfExpand(master, 'enc');
  const macKey = await hkdfExpand(master, 'mac');
  await decryptBitwardenString(str(data.encKeyValidation_DO_NOT_EDIT), encKey, macKey);
  return JSON.parse(await decryptBitwardenString(str(data.data), encKey, macKey));
};

interface OnePuxField {
  designation?: string;
  value?: string;
}

const parse1Pux = (data: { accounts?: Array<{ vaults?: Array<{ items?: Array<Record<string, unknown>> }> }> }): ImportResult => {
  const result = emptyResult('1Password 1PUX');
  for (const account of data.accounts ?? []) {
    for (const vault of account.vaults ?? []) {
      for (const item of vault.items ?? []) {
        const overview = (item.overview ?? {}) as { title?: string; url?: string };
        const details = (item.details ?? {}) as {
          loginFields?: OnePuxField[];
          notesPlain?: string;
          password?: string;
          sections?: Array<{ fields?: Array<{ title?: string; value?: Record<string, unknown> }> }>;
        };
        const fields = details.loginFields ?? [];
        const username = fields.find((f) => f.designation === 'username')?.value ?? '';
        const password = fields.find((f) => f.designation === 'password')?.value ?? details.password ?? '';
        const title = overview.title || username || 'Imported item';
        let matched = false;
        if (password) {
          result.passwords.push({ title, username, password, url: overview.url, notes: details.notesPlain });
          matched = true;
        }
        for (const section of details.sections ?? []) {
          for (const field of section.fields ?? []) {
            const totp = str(field.value?.totp);
            if (totp) {
              const parsed = parseSecretField(totp, { accountName: username || title, issuer: title });
              if (parsed) {
                result.totps.push(parsed);
                matched = true;
              }
            }
          }
        }
        if (!matched) result.skipped++;
      }
    }
  }
  return result;
};

const parse1Pif = (text: string): ImportResult => {
  const result = emptyResult('1Password 1PIF');
  for (const chunk of text.split(/^\*\*\*[0-9a-f-]+\*\*\*$/m)) {
    const trimmed = chunk.trim();
    if (!trimmed.startsWith('{')) continue;
    try {
      const item = JSON.parse(trimmed) as {
        title?: string;
        location?: string;
        secureContents?: { fields?: OnePuxField[]; notesPlain?: string; sections?: Array<{ fields?: Array<{ v?: string; n?: string }> }> };
      };
      const fields = item.secureContents?.fields ?? [];
      const username = fields.find((f) => f.designation === 'username')?.value ?? '';
      const password = fields.find((f) => f.designation === 'password')?.value ?? '';
      const title = item.title || username || 'Imported item';
      let matched = false;
      if (password) {
        result.passwords.push({ title, username, password, url: item.location, notes: item.secureContents?.notesPlain });
        matched = true;
      }
      for (const section of item.secureContents?.sections ?? []) {
        for (const field of section.fields ?? []) {
          if (field.n?.startsWith('TOTP') && field.v) {
            const parsed = parseSecretField(field.v, { accountName: username || title, issuer: title });
            if (parsed) {
              result.totps.push(parsed);
              matched = true;
            }
          }
        }
      }
      if (!matched) result.skipped++;
    } catch {
      result.skipped++;
    }
  }
  return result;
};

const parseKeePassXml = (text: string): ImportResult => {
  const doc = new DOMParser().parseFromString(text, 'application/xml');
  if (doc.querySelector('parsererror')) {
    throw new Error('This XML file could not be parsed.');
  }
  const result = emptyResult('KeePass XML');
  for (const entry of Array.from(doc.getElementsByTagName('Entry'))) {
    // Skip history snapshots nested inside <History>.
    if (entry.parentElement?.tagName === 'History') continue;
    const record: Record<string, string> = {};
    for (const node of Array.from(entry.children)) {
      if (node.tagName !== 'String') continue;
      const key = node.getElementsByTagName('Key')[0]?.textContent ?? '';
      const value = node.getElementsByTagName('Value')[0]?.textContent ?? '';
      record[key] = value;
    }
    pushRecord(result, {
      title: record.Title,
      username: record.UserName,
      password: record.Password,
      url: record.URL,
      notes: record.Notes,
      otp: record.otp || record['TimeOtp-Secret-Base32'] || record['TOTP Seed'],
      period: record['TimeOtp-Period'] || record['TOTP Settings']?.split(';')[0],
      digits: record['TimeOtp-Length'],
      algorithm: record['TimeOtp-Algorithm']?.replace('HMAC-', ''),
    });
  }
  return result;
};

interface ProtonItem {
  data?: {
    type?: string;
    metadata?: { name?: string; note?: string };
    content?: { itemEmail?: string; itemUsername?: string; username?: string; password?: string; urls?: string[]; totpUri?: string };
  };
}

const parseProtonPass = (data: { vaults?: Record<string, { items?: ProtonItem[] }> }): ImportResult => {
  const result = emptyResult('Proton Pass');
  for (const vault of Object.values(data.vaults ?? {})) {
    for (const item of vault.items ?? []) {
      const content = item.data?.content;
      if (item.data?.type !== 'login' || !content) {
        result.skipped++;
        continue;
      }
      const username = content.itemUsername || content.username || content.itemEmail || '';
      const title = item.data.metadata?.name || username || 'Imported item';
      let matched = false;
      if (content.password) {
        result.passwords.push({ title, username, password: content.password, url: content.urls?.[0], notes: item.data.metadata?.note });
        matched = true;
      }
      if (content.totpUri) {
        const totp = parseSecretField(content.totpUri, { accountName: username || title, issuer: title });
        if (totp) {
          result.totps.push(totp);
          matched = true;
        }
      }
      if (!matched) result.skipped++;
    }
  }
  return result;
};

const parseEnpass = (data: { items?: Array<{ title?: string; note?: string; fields?: Array<{ type?: string; label?: string; value?: string }> }> }): ImportResult => {
  const result = emptyResult('Enpass JSON');
  for (const item of data.items ?? []) {
    const fields = item.fields ?? [];
    const get = (...types: string[]) => fields.find((f) => types.includes((f.type ?? '').toLowerCase()) && f.value)?.value ?? '';
    pushRecord(result, {
      title: item.title,
      username: get('username') || get('email'),
      password: get('password'),
      url: get('url'),
      notes: item.note,
      totp: get('totp'),
    });
  }
  return result;
};

const parseKeeper = (data: { records?: Array<Record<string, unknown>> }): ImportResult => {
  const result = emptyResult('Keeper JSON');
  for (const record of data.records ?? []) {
    const custom = (record.custom_fields ?? {}) as Record<string, unknown>;
    const totp = Object.entries(custom).find(([key, value]) => key.startsWith('$oneTimeCode') || key.startsWith('TFC') || str(value).startsWith('otpauth://'));
    pushRecord(result, { ...record, totp: totp ? str(totp[1]) : undefined });
  }
  return result;
};

// ---------------------------------------------------------------------------
// Authenticator apps
// ---------------------------------------------------------------------------

interface AegisEntry {
  type?: string;
  name?: string;
  issuer?: string;
  info?: { secret?: string; digits?: number; period?: number; algo?: string; counter?: number };
}

interface AegisExport {
  version?: number;
  header?: {
    slots?: Array<{ type?: number; key?: string; key_params?: { nonce?: string; tag?: string }; n?: number; r?: number; p?: number; salt?: string }> | null;
    params?: { nonce?: string; tag?: string } | null;
  };
  db?: { entries?: AegisEntry[] } | string;
}

const hexToBytes = (hex: string): Uint8Array<ArrayBuffer> => {
  const clean = hex.replace(/\s+/g, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return bytes;
};

const aesGcmDecrypt = async (
  key: Uint8Array<ArrayBuffer>,
  iv: Uint8Array<ArrayBuffer>,
  data: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> => {
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, data));
};

const decryptAegis = async (data: AegisExport, password?: string): Promise<{ entries?: AegisEntry[] }> => {
  if (!password) throw new ImportPasswordRequired('Aegis');
  const slots = (data.header?.slots ?? []).filter((slot) => slot.type === 1);
  for (const slot of slots) {
    try {
      const derived = await scrypt({
        password: password.normalize('NFKC'),
        salt: hexToBytes(slot.salt ?? ''),
        costFactor: slot.n ?? 32768,
        blockSize: slot.r ?? 8,
        parallelism: slot.p ?? 1,
        hashLength: 32,
        outputType: 'binary',
      });
      const masterKey = await aesGcmDecrypt(
        new Uint8Array(derived),
        hexToBytes(slot.key_params?.nonce ?? ''),
        new Uint8Array([...hexToBytes(slot.key ?? ''), ...hexToBytes(slot.key_params?.tag ?? '')]),
      );
      const content = fromBase64(String(data.db));
      const plaintext = await aesGcmDecrypt(
        masterKey,
        hexToBytes(data.header?.params?.nonce ?? ''),
        new Uint8Array([...content, ...hexToBytes(data.header?.params?.tag ?? '')]),
      );
      return JSON.parse(decoder.decode(plaintext)) as { entries?: AegisEntry[] };
    } catch {
      // Try the next password slot.
    }
  }
  throw new WrongImportPassword('Aegis');
};

const parseAegis = async (data: AegisExport, password?: string): Promise<ImportResult> => {
  const db = typeof data.db === 'string' ? await decryptAegis(data, password) : data.db;
  const result = emptyResult('Aegis');
  for (const entry of db?.entries ?? []) {
    const type = (entry.type ?? 'totp').toLowerCase();
    const source =
      ['totp', 'hotp', 'steam'].includes(type) && entry.info?.secret
        ? makeOtpSource({
            accountName: entry.name,
            issuer: entry.issuer,
            secret: entry.info.secret,
            type: parseOtpType(type),
            algorithm: parseAlgorithm(entry.info.algo),
            digits: entry.info.digits,
            period: entry.info.period,
            counter: entry.info.counter,
          })
        : null;
    if (source) result.totps.push(source);
    else result.skipped++;
  }
  return result;
};

interface TwoFasService {
  name?: string;
  secret?: string;
  otp?: { account?: string; issuer?: string; digits?: number; period?: number; algorithm?: string; tokenType?: string; counter?: number };
}

const parseTwoFas = async (data: { services?: TwoFasService[]; servicesEncrypted?: string }, password?: string): Promise<ImportResult> => {
  let services = data.services ?? [];
  if (data.servicesEncrypted) {
    if (!password) throw new ImportPasswordRequired('2FAS');
    const [ciphertext, salt, iv] = data.servicesEncrypted.split(':').map((part) => fromBase64(part));
    try {
      const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
      const key = new Uint8Array(
        await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 10_000 }, material, 256),
      );
      services = JSON.parse(decoder.decode(await aesGcmDecrypt(key, iv, ciphertext))) as TwoFasService[];
    } catch {
      throw new WrongImportPassword('2FAS');
    }
  }
  const result = emptyResult('2FAS');
  for (const service of services) {
    const source = makeOtpSource({
      accountName: service.otp?.account || service.name,
      issuer: service.otp?.issuer || service.name,
      secret: service.secret ?? '',
      type: parseOtpType(service.otp?.tokenType),
      algorithm: parseAlgorithm(service.otp?.algorithm),
      digits: service.otp?.digits,
      period: service.otp?.period,
      counter: service.otp?.counter,
    });
    if (source) result.totps.push(source);
    else result.skipped++;
  }
  return result;
};

/** andOTP encrypted backup: [iterations:4][salt:12][iv:12][ciphertext+tag]. */
const decryptAndOtp = async (bytes: Uint8Array<ArrayBuffer>, password?: string): Promise<unknown> => {
  if (!password) throw new ImportPasswordRequired('andOTP');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const iterations = view.getUint32(0);
  const salt = bytes.slice(4, 16);
  const iv = bytes.slice(16, 28);
  try {
    const material = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    const key = new Uint8Array(
      await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-1', salt, iterations }, material, 256),
    );
    return JSON.parse(decoder.decode(await aesGcmDecrypt(key, iv, bytes.slice(28))));
  } catch {
    throw new WrongImportPassword('andOTP');
  }
};

/** Flat authenticator-app records (andOTP, Raivo, generic). */
const otpRecord = (record: Record<string, unknown>): ParsedOtpSource | null => {
  const secret = pick(record, ALIASES.secret);
  if (!secret) return null;
  const issuer = pick(record, ALIASES.issuer) ?? '';
  const account = pick(record, ['account', 'accountname', 'account_name', 'label', 'name', 'username', 'user']) ?? '';
  return parseSecretField(secret, {
    accountName: issuer && account.startsWith(`${issuer}:`) ? account.slice(issuer.length + 1) : account,
    issuer,
    type: parseOtpType(pick(record, ALIASES.type)),
    digits: Number(pick(record, ALIASES.digits)) || undefined,
    period: Number(pick(record, ALIASES.period)) || undefined,
    algorithm: pick(record, ALIASES.algorithm),
    counter: Number(pick(record, ALIASES.counter)) || undefined,
  });
};

const parseFreeOtpPlus = (data: { tokens?: Array<Record<string, unknown>> }): ImportResult => {
  const result = emptyResult('FreeOTP+');
  for (const token of data.tokens ?? []) {
    const secret = Array.isArray(token.secret)
      ? bytesToBase32(Uint8Array.from(token.secret as number[], (b) => b & 0xff))
      : str(token.secret);
    const source = makeOtpSource({
      accountName: str(token.label),
      issuer: str(token.issuerExt) || str(token.issuerInt),
      secret,
      type: parseOtpType(token.type),
      algorithm: parseAlgorithm(token.algo),
      digits: Number(token.digits),
      period: Number(token.period),
      counter: Number(token.counter),
    });
    if (source) result.totps.push(source);
    else result.skipped++;
  }
  return result;
};

const parseAuthenticatorPro = (data: { Authenticators?: Array<Record<string, unknown>> }): ImportResult => {
  const result = emptyResult('Authenticator Pro');
  const types: Record<number, OtpType> = { 1: 'hotp', 2: 'totp', 4: 'steam' };
  const algorithms = ['SHA1', 'SHA256', 'SHA512'];
  for (const item of data.Authenticators ?? []) {
    const source = makeOtpSource({
      accountName: str(item.Username),
      issuer: str(item.Issuer),
      secret: str(item.Secret),
      type: types[Number(item.Type)] ?? 'totp',
      algorithm: parseAlgorithm(algorithms[Number(item.Algorithm)] ?? 'SHA1'),
      digits: Number(item.Digits),
      period: Number(item.Period),
      counter: Number(item.Counter),
    });
    if (source) result.totps.push(source);
    else result.skipped++;
  }
  return result;
};

const parseLastPassAuthenticator = (data: { accounts?: Array<Record<string, unknown>> }): ImportResult => {
  const result = emptyResult('LastPass Authenticator');
  for (const account of data.accounts ?? []) {
    const source = makeOtpSource({
      accountName: str(account.userName) || str(account.originalUserName),
      issuer: str(account.issuerName) || str(account.originalIssuerName),
      secret: str(account.secret),
      algorithm: parseAlgorithm(account.algorithm),
      digits: Number(account.digits),
      period: Number(account.timeStep),
    });
    if (source) result.totps.push(source);
    else result.skipped++;
  }
  return result;
};

const parseSteamMaFile = (data: { shared_secret?: string; account_name?: string }): ImportResult => {
  const result = emptyResult('Steam Guard (.maFile)');
  const source = makeOtpSource({
    accountName: data.account_name ?? 'Steam',
    issuer: 'Steam',
    secret: bytesToBase32(fromBase64(data.shared_secret ?? '')),
    type: 'steam',
  });
  if (source) result.totps.push(source);
  else result.skipped++;
  return result;
};

/**
 * Proton Authenticator: { version, entries: [{ content: { uri, name,
 * entry_type } }] } — `uri` is an otpauth:// URI, or steam://SECRET.
 */
const parseProtonAuthenticator = (data: { entries?: Array<{ content?: { uri?: string; name?: string; entry_type?: string } }> }): ImportResult => {
  const result = emptyResult('Proton Authenticator');
  for (const entry of data.entries ?? []) {
    const uri = entry.content?.uri ?? '';
    const name = entry.content?.name ?? '';
    const source = parseSecretField(uri, {
      accountName: name,
      issuer: /steam/i.test(entry.content?.entry_type ?? '') ? 'Steam' : '',
      type: /steam/i.test(entry.content?.entry_type ?? '') ? 'steam' : undefined,
    });
    if (source) result.totps.push(source);
    else result.skipped++;
  }
  return result;
};

// ---------------------------------------------------------------------------
// Fallbacks: otpauth:// anywhere, plain-text lists
// ---------------------------------------------------------------------------

const OTP_URI = /otpauth(?:-migration)?:\/\/[^\s"'<>\\]+/gi;

const collectUris = (text: string, result: ImportResult): void => {
  for (const match of text.match(OTP_URI) ?? []) {
    try {
      if (isMigrationUri(match)) {
        result.totps.push(...parseMigrationUri(match));
      } else {
        const parsed = parseOtpAuthUri(match);
        if (parsed) result.totps.push(parsed);
      }
    } catch {
      result.skipped++;
    }
  }
};

const parsePlainText = (text: string): ImportResult => {
  const result = emptyResult('otpauth / secret list');
  collectUris(text, result);
  if (result.totps.length === 0) {
    // One bare Base32 secret per line ("label: SECRET" accepted too).
    text.split(/\r?\n/).forEach((line, index) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) return;
      const [label, secret] = trimmed.includes(':') ? trimmed.split(/:(.*)/s).map((s) => s.trim()) : ['', trimmed];
      const source = makeOtpSource({ accountName: label || `Imported account ${index + 1}`, secret });
      if (source) result.totps.push(source);
      else result.skipped++;
    });
  }
  if (result.totps.length === 0) {
    throw new Error('Unrecognized file format.');
  }
  return result;
};

const parseGenericArray = (items: unknown[], format = 'Generic JSON'): ImportResult => {
  const result = emptyResult(format);
  for (const item of items) {
    if (typeof item === 'string') {
      const before = result.totps.length;
      collectUris(item, result);
      if (result.totps.length === before) {
        const source = makeOtpSource({ accountName: 'Imported account', secret: item });
        if (source) result.totps.push(source);
        else result.skipped++;
      }
      continue;
    }
    if (!item || typeof item !== 'object') {
      result.skipped++;
      continue;
    }
    const record = item as Record<string, unknown>;
    const { password } = recordToEntries(record);
    const totp = otpRecord(record);
    if (password) result.passwords.push(password);
    if (totp) result.totps.push(totp);
    if (!password && !totp) {
      // Nested shapes (e.g. { content: { uri } }): look for URIs inside.
      const before = result.totps.length;
      collectUris(JSON.stringify(record), result);
      if (result.totps.length === before) result.skipped++;
    }
  }
  return result;
};

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

const parseJsonValue = async (data: unknown, password?: string): Promise<ImportResult> => {
  if (Array.isArray(data)) {
    return parseGenericArray(data, data.some((d) => d && typeof d === 'object' && 'secret' in d) ? 'andOTP / Raivo / generic' : 'Generic JSON');
  }
  if (!data || typeof data !== 'object') {
    throw new Error('Unrecognized JSON export format.');
  }
  const record = data as Record<string, unknown>;

  if (record.encrypted === true && typeof record.data === 'string') {
    return parseJsonValue(await decryptBitwardenExport(record, password), password);
  }
  if (Array.isArray(record.items) && record.items.some((i) => i && typeof i === 'object' && ('login' in i || 'type' in i))) {
    if ((record.items as Array<Record<string, unknown>>).some((i) => Array.isArray(i.fields))) {
      return parseEnpass(record as Parameters<typeof parseEnpass>[0]);
    }
    return parseBitwardenItems(record.items as BitwardenItem[], 'Bitwarden JSON');
  }
  if (Array.isArray(record.accounts) && (record.accounts as unknown[]).some((a) => a && typeof a === 'object' && 'vaults' in a)) {
    return parse1Pux(record as Parameters<typeof parse1Pux>[0]);
  }
  if (record.db !== undefined && record.header !== undefined) {
    return parseAegis(record as AegisExport, password);
  }
  if (record.db && typeof record.db === 'object') {
    return parseAegis(record as AegisExport, password);
  }
  if (Array.isArray(record.services) || typeof record.servicesEncrypted === 'string') {
    return parseTwoFas(record as Parameters<typeof parseTwoFas>[0], password);
  }
  if (Array.isArray(record.tokens)) {
    return parseFreeOtpPlus(record as Parameters<typeof parseFreeOtpPlus>[0]);
  }
  if (Array.isArray(record.Authenticators)) {
    return parseAuthenticatorPro(record as Parameters<typeof parseAuthenticatorPro>[0]);
  }
  if (Array.isArray(record.accounts) && (record.accounts as unknown[]).some((a) => a && typeof a === 'object' && 'secret' in a)) {
    return parseLastPassAuthenticator(record as Parameters<typeof parseLastPassAuthenticator>[0]);
  }
  if (record.vaults && typeof record.vaults === 'object') {
    return parseProtonPass(record as Parameters<typeof parseProtonPass>[0]);
  }
  if (Array.isArray(record.records)) {
    return parseKeeper(record as Parameters<typeof parseKeeper>[0]);
  }
  if (
    Array.isArray(record.entries) &&
    (record.entries as unknown[]).some((e) => e && typeof e === 'object' && 'content' in e)
  ) {
    return parseProtonAuthenticator(record as Parameters<typeof parseProtonAuthenticator>[0]);
  }
  if (typeof record.salt === 'string' && typeof record.content === 'string' && !record.entries) {
    throw new Error('This Proton Authenticator export is password-protected. Export it again from Proton Authenticator without a password, import it, then delete the file.');
  }
  if (typeof record.shared_secret === 'string') {
    return parseSteamMaFile(record as Parameters<typeof parseSteamMaFile>[0]);
  }
  for (const key of ['entries', 'data', 'list']) {
    if (Array.isArray(record[key])) {
      return parseGenericArray(record[key] as unknown[]);
    }
  }

  const single = emptyResult('Generic JSON');
  pushRecord(single, record);
  if (single.passwords.length || single.totps.length) return single;

  // Last resort: any otpauth URI anywhere in the document.
  const scan = emptyResult('otpauth URIs');
  collectUris(JSON.stringify(record), scan);
  if (scan.totps.length) return scan;

  throw new Error('Unrecognized JSON export format.');
};

const parseText = async (text: string, fileName: string, password?: string): Promise<ImportResult> => {
  const trimmed = text.replace(/^﻿/, '').trim();
  if (!trimmed) {
    throw new Error('File is empty.');
  }

  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    let data: unknown;
    try {
      data = JSON.parse(trimmed);
    } catch {
      throw new Error('File looks like JSON but failed to parse.');
    }
    return parseJsonValue(data, password);
  }
  if (trimmed.startsWith('<')) {
    return parseKeePassXml(trimmed);
  }
  if (/^\*\*\*[0-9a-f-]+\*\*\*$/m.test(trimmed) || fileName.toLowerCase().endsWith('.1pif')) {
    return parse1Pif(trimmed);
  }
  if (/^\s*otpauth(-migration)?:\/\//im.test(trimmed)) {
    return parsePlainText(trimmed);
  }

  const firstLine = trimmed.split(/\r?\n/, 1)[0] ?? '';
  if (/[,;\t]/.test(firstLine)) {
    return parseCsv(trimmed);
  }
  return parsePlainText(trimmed);
};

const mergeResults = (results: ImportResult[], format: string): ImportResult => ({
  passwords: results.flatMap((r) => r.passwords),
  totps: results.flatMap((r) => r.totps),
  skipped: results.reduce((sum, r) => sum + r.skipped, 0),
  sourceFormat: format,
});

const isZip = (bytes: Uint8Array): boolean => bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04;

const MAX_UNZIPPED = 100 * 1024 * 1024;

const parseZip = async (bytes: Uint8Array, password?: string): Promise<ImportResult> => {
  let total = 0;
  const files = unzipSync(bytes, {
    filter: (file) => {
      total += file.originalSize;
      if (total > MAX_UNZIPPED) throw new Error('Archive is too large to import.');
      return /\.(json|csv|txt|xml|data)$/i.test(file.name) && !file.name.startsWith('__MACOSX');
    },
  });
  const results: ImportResult[] = [];
  for (const [name, content] of Object.entries(files)) {
    try {
      results.push(await parseText(decoder.decode(content), name, password));
    } catch (error) {
      if (error instanceof ImportPasswordRequired) throw error;
      // Skip unrelated files inside the archive.
    }
  }
  if (results.length === 0) {
    throw new Error('No supported export was found inside this archive.');
  }
  const formats = [...new Set(results.map((r) => r.sourceFormat))].join(' + ');
  return mergeResults(results, `ZIP (${formats})`);
};

/** Entry point: raw file bytes in, vendor-neutral items out. */
export const parseImportFile = async (
  input: Uint8Array<ArrayBuffer>,
  fileName = '',
  password?: string,
): Promise<ImportResult> => {
  if (isZip(input)) {
    return parseZip(input, password);
  }
  const lowerName = fileName.toLowerCase();
  if (lowerName.endsWith('.aes') || lowerName.endsWith('.json.aes')) {
    return parseJsonValue(await decryptAndOtp(input, password), password);
  }
  return parseText(decoder.decode(input), fileName, password);
};
