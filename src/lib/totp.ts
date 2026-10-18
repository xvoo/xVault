// One-time password generation with Web Crypto:
// TOTP (RFC 6238), HOTP (RFC 4226) and Steam Guard, with SHA-1/256/512.

import type { OtpAlgorithm, OtpType } from './types';

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const STEAM_CHARS = '23456789BCDFGHJKMNPQRTVWXY';

export const normalizeBase32 = (secret: string): string =>
  secret.toUpperCase().replace(/[\s-]+/g, '').replace(/=+$/, '');

export const base32ToBytes = (secret: string): Uint8Array<ArrayBuffer> => {
  const clean = normalizeBase32(secret);
  const bytes = new Uint8Array(Math.floor((clean.length * 5) / 8));
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (const char of clean) {
    const value = BASE32_CHARS.indexOf(char);
    if (value === -1) {
      throw new Error('Invalid base32 character in key');
    }
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes[index++] = (buffer >> bits) & 0xff;
    }
  }
  return bytes;
};

export const bytesToBase32 = (bytes: Uint8Array): string => {
  let output = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += BASE32_CHARS[(buffer >> bits) & 31];
    }
  }
  if (bits > 0) {
    output += BASE32_CHARS[(buffer << (5 - bits)) & 31];
  }
  return output;
};

const counterToBytes = (counter: bigint): Uint8Array<ArrayBuffer> => {
  const bytes = new Uint8Array(8);
  let value = counter;
  for (let i = 7; i >= 0; i -= 1) {
    bytes[i] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
};

const HASHES: Record<OtpAlgorithm, string> = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

export interface OtpOptions {
  type?: OtpType;
  algorithm?: OtpAlgorithm;
  digits?: number;
  period?: number;
  counter?: number;
  timestamp?: number;
}

export const clampDigits = (digits: number | undefined, type: OtpType = 'totp'): number => {
  if (type === 'steam') return 5;
  const value = Math.trunc(Number(digits));
  return Number.isFinite(value) && value >= 4 && value <= 10 ? value : 6;
};

export const clampPeriod = (period: number | undefined): number => {
  const value = Math.trunc(Number(period));
  return Number.isFinite(value) && value >= 1 && value <= 3600 ? value : 30;
};

/** Generates the current code (TOTP/Steam) or the code at `counter` (HOTP). */
export const generateOtp = async (secret: string, options: OtpOptions = {}): Promise<string> => {
  const type = options.type ?? 'totp';
  const period = clampPeriod(options.period);
  const digits = clampDigits(options.digits, type);
  const algorithm = type === 'steam' ? 'SHA1' : (options.algorithm ?? 'SHA1');

  const counter =
    type === 'hotp'
      ? BigInt(Math.max(0, Math.trunc(options.counter ?? 0)))
      : BigInt(Math.floor((options.timestamp ?? Date.now()) / 1000 / period));

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    base32ToBytes(secret),
    { name: 'HMAC', hash: HASHES[algorithm] ?? 'SHA-1' },
    false,
    ['sign'],
  );
  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, counterToBytes(counter)));

  const offset = signature[signature.length - 1] & 0x0f;
  const binary =
    (((signature[offset] & 0x7f) << 24) |
      ((signature[offset + 1] & 0xff) << 16) |
      ((signature[offset + 2] & 0xff) << 8) |
      (signature[offset + 3] & 0xff)) >>>
    0;

  if (type === 'steam') {
    let value = binary;
    let code = '';
    for (let i = 0; i < 5; i++) {
      code += STEAM_CHARS[value % STEAM_CHARS.length];
      value = Math.floor(value / STEAM_CHARS.length);
    }
    return code;
  }

  // 10 digits exceed 2^31: use BigInt for the modulo.
  return (BigInt(binary) % 10n ** BigInt(digits)).toString().padStart(digits, '0');
};

/** Backwards-compatible TOTP helper. */
export const generateTOTP = (
  secret: string,
  options: { period?: number; digits?: number; timestamp?: number } = {},
): Promise<string> => generateOtp(secret, { ...options, type: 'totp' });

export const getTimeRemaining = (period: number = 30): number => {
  const safe = clampPeriod(period);
  const epoch = Math.floor(Date.now() / 1000);
  return safe - (epoch % safe);
};
