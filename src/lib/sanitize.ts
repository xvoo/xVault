// Normalizes anything that enters the vault (typed by hand, imported from a
// file, or decrypted from an old backup) so the UI never has to trust it:
// bounded lengths, safe URL schemes, valid colors, valid OTP parameters.

import { isValidBase32Secret, normalizeSecret, parseAlgorithm, parseOtpType } from './otpauth';
import { clampDigits, clampPeriod } from './totp';
import type { Folder, PasswordEntry, TOTPEntry, VaultData } from './types';
import { generateId } from './uuid';

const MAX_TEXT = 500;
const MAX_NOTES = 20_000;
const MAX_SECRET = 1_000;
const MAX_ICON_DATA_URL = 1_500_000;

const text = (value: unknown, max = MAX_TEXT): string =>
  typeof value === 'string' ? value.slice(0, max) : '';

const optionalText = (value: unknown, max = MAX_TEXT): string | undefined => {
  const result = text(value, max).trim();
  return result ? result : undefined;
};

const id = (value: unknown): string =>
  typeof value === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(value) ? value : generateId();

/**
 * Keeps only http(s) URLs. A bare domain ("github.com") gets https://;
 * anything with another scheme (javascript:, data:, file:...) is dropped.
 */
export const sanitizeUrl = (value: unknown): string | undefined => {
  const raw = text(value, 2048).trim();
  if (!raw) return undefined;
  const candidate = /^[a-z][a-z0-9+.-]*:/i.test(raw) ? raw : `https://${raw}`;
  try {
    const url = new URL(candidate);
    if (url.protocol === 'http:' || url.protocol === 'https:') {
      return url.toString();
    }
  } catch {
    // fall through
  }
  return undefined;
};

export const sanitizeColor = (value: unknown): string =>
  typeof value === 'string' && /^#[0-9a-f]{6}$/i.test(value) ? value : '#7cc4fa';

/** At most 2 user-perceived characters (an emoji or two letters). */
export const sanitizeMarker = (value: unknown): string => {
  const raw = text(value, 64).trim();
  if (!raw) return '';
  const Segmenter = (Intl as unknown as { Segmenter?: new (l?: string, o?: { granularity: string }) => { segment: (s: string) => Iterable<{ segment: string }> } }).Segmenter;
  if (Segmenter) {
    return Array.from(new Segmenter(undefined, { granularity: 'grapheme' }).segment(raw), (s) => s.segment)
      .slice(0, 2)
      .join('');
  }
  return Array.from(raw).slice(0, 2).join('');
};

export const SAFE_IMAGE_PREFIX = /^data:image\/(png|jpeg|webp|gif);base64,[A-Za-z0-9+/=]+$/;

export const sanitizeIcon = (icon: unknown, isCustom: unknown): { icon: string; isCustomIcon: boolean } => {
  const value = typeof icon === 'string' ? icon : '';
  if (isCustom && value.length <= MAX_ICON_DATA_URL && SAFE_IMAGE_PREFIX.test(value)) {
    return { icon: value, isCustomIcon: true };
  }
  return { icon: sanitizeMarker(value), isCustomIcon: false };
};

export const sanitizeEntry = (raw: unknown): TOTPEntry | null => {
  if (!raw || typeof raw !== 'object') return null;
  const entry = raw as Record<string, unknown>;
  const secret = normalizeSecret(text(entry.secret, MAX_SECRET));
  if (!isValidBase32Secret(secret)) return null;
  const type = parseOtpType(entry.type);
  const counter = Math.trunc(Number(entry.counter ?? 0));
  return {
    id: id(entry.id),
    name: text(entry.name).trim() || 'Account',
    secret,
    ...sanitizeIcon(entry.icon, entry.isCustomIcon),
    type,
    algorithm: parseAlgorithm(entry.algorithm),
    digits: clampDigits(entry.digits as number | undefined, type),
    period: clampPeriod(entry.period as number | undefined),
    counter: Number.isFinite(counter) && counter >= 0 ? counter : 0,
    folderId: optionalText(entry.folderId, 64),
  };
};

export const sanitizeFolder = (raw: unknown): Folder | null => {
  if (!raw || typeof raw !== 'object') return null;
  const folder = raw as Record<string, unknown>;
  const name = text(folder.name, 100).trim();
  if (!name) return null;
  return {
    id: id(folder.id),
    name,
    icon: sanitizeMarker(folder.icon),
    color: sanitizeColor(folder.color),
    isExpanded: folder.isExpanded === true ? true : undefined,
    parentId: optionalText(folder.parentId, 64),
  };
};

export const sanitizePassword = (raw: unknown): PasswordEntry | null => {
  if (!raw || typeof raw !== 'object') return null;
  const entry = raw as Record<string, unknown>;
  const password = text(entry.password, 4096);
  const title = text(entry.title).trim();
  if (!password && !title) return null;
  const now = new Date().toISOString();
  const icon = sanitizeIcon(entry.icon, entry.isCustomIcon);
  return {
    id: id(entry.id),
    title: title || 'Login',
    username: text(entry.username).trim(),
    password,
    url: sanitizeUrl(entry.url),
    notes: optionalText(entry.notes, MAX_NOTES),
    icon: icon.icon || undefined,
    isCustomIcon: icon.isCustomIcon || undefined,
    folderId: optionalText(entry.folderId, 64),
    linkedEntryId: optionalText(entry.linkedEntryId, 64),
    createdAt: optionalText(entry.createdAt, 64) ?? now,
    updatedAt: optionalText(entry.updatedAt, 64) ?? now,
  };
};

const list = <T>(value: unknown, map: (item: unknown) => T | null): T[] =>
  Array.isArray(value) ? value.map(map).filter((item): item is T => item !== null) : [];

export const sanitizeVaultData = (raw: unknown): VaultData => {
  const data = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
  return {
    entries: list(data.entries, sanitizeEntry),
    folders: list(data.folders, sanitizeFolder),
    passwords: list(data.passwords, sanitizePassword),
  };
};
