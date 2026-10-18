import { bytesToBase32, clampDigits, clampPeriod, normalizeBase32 } from './totp';
import type { OtpAlgorithm, OtpType } from './types';

const BASE32_SECRET = /^[A-Z2-7]+=*$/;

export interface ParsedOtpSource {
  accountName: string;
  issuer: string;
  secret: string;
  type: OtpType;
  algorithm: OtpAlgorithm;
  digits: number;
  period: number;
  counter: number;
}

export const normalizeSecret = (secret: string): string => normalizeBase32(secret);

export const isValidBase32Secret = (secret: string): boolean => {
  const normalized = normalizeSecret(secret);
  return normalized.length >= 8 && BASE32_SECRET.test(normalized);
};

export const parseAlgorithm = (value: unknown): OtpAlgorithm => {
  const text = String(value ?? '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (text === 'SHA256') return 'SHA256';
  if (text === 'SHA512') return 'SHA512';
  return 'SHA1';
};

export const parseOtpType = (value: unknown): OtpType => {
  const text = String(value ?? '').toLowerCase();
  if (text === 'hotp') return 'hotp';
  if (text === 'steam') return 'steam';
  return 'totp';
};

/** Builds a normalized OTP source, clamping every parameter to a safe range. */
export const makeOtpSource = (input: {
  accountName?: string;
  issuer?: string;
  secret: string;
  type?: OtpType;
  algorithm?: OtpAlgorithm;
  digits?: number;
  period?: number;
  counter?: number;
}): ParsedOtpSource | null => {
  const secret = normalizeSecret(input.secret);
  if (!isValidBase32Secret(secret)) {
    return null;
  }
  const type = input.type ?? 'totp';
  const counter = Math.trunc(Number(input.counter ?? 0));
  return {
    accountName: (input.accountName ?? '').trim().slice(0, 200),
    issuer: (input.issuer ?? '').trim().slice(0, 200),
    secret,
    type,
    algorithm: input.algorithm ?? 'SHA1',
    digits: clampDigits(input.digits, type),
    period: clampPeriod(input.period),
    counter: Number.isFinite(counter) && counter >= 0 ? counter : 0,
  };
};

const safeDecode = (value: string): string => {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
};

/**
 * Parses `otpauth://totp/...`, `otpauth://hotp/...` and Steam variants
 * (`otpauth://steam/...`, or `encoder=steam`). Returns null when the input
 * is not an otpauth URI; throws when it is one but is malformed.
 */
export const parseOtpAuthUri = (input: string): ParsedOtpSource | null => {
  const trimmed = input.trim();
  if (!/^otpauth:\/\//i.test(trimmed)) {
    return null;
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new Error('The OTP URI is malformed.');
  }

  const host = url.hostname.toLowerCase();
  if (!['totp', 'hotp', 'steam'].includes(host)) {
    throw new Error('Only otpauth://totp, hotp and steam URIs are supported.');
  }

  const params = url.searchParams;
  const rawLabel = safeDecode(url.pathname.replace(/^\/+/, ''));
  const [labelIssuer, ...labelRest] = rawLabel.split(':');
  const labelAccount = labelRest.join(':').trim();
  const issuer = (params.get('issuer') ?? (labelAccount ? labelIssuer : '')).trim();
  const accountName = (labelAccount || labelIssuer).trim();
  const isSteam = host === 'steam' || params.get('encoder')?.toLowerCase() === 'steam';
  const type: OtpType = isSteam ? 'steam' : host === 'hotp' ? 'hotp' : 'totp';

  const source = makeOtpSource({
    accountName,
    issuer,
    secret: params.get('secret') ?? '',
    type,
    algorithm: parseAlgorithm(params.get('algorithm')),
    digits: Number(params.get('digits') ?? (isSteam ? 5 : 6)),
    period: Number(params.get('period') ?? 30),
    counter: Number(params.get('counter') ?? 0),
  });
  if (!source) {
    throw new Error('The OTP URI does not contain a valid Base32 secret.');
  }
  return source;
};

// ---------------------------------------------------------------------------
// Google Authenticator export: otpauth-migration://offline?data=<protobuf>
// ---------------------------------------------------------------------------

class ProtoReader {
  private offset = 0;
  constructor(private readonly bytes: Uint8Array) {}

  get done(): boolean {
    return this.offset >= this.bytes.length;
  }

  varint(): bigint {
    let result = 0n;
    let shift = 0n;
    while (this.offset < this.bytes.length) {
      const byte = this.bytes[this.offset++];
      result |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) return result;
      shift += 7n;
      if (shift > 70n) break;
    }
    throw new Error('Malformed migration payload.');
  }

  bytesField(): Uint8Array {
    const length = Number(this.varint());
    if (length < 0 || this.offset + length > this.bytes.length) {
      throw new Error('Malformed migration payload.');
    }
    const slice = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return slice;
  }

  skip(wireType: number): void {
    if (wireType === 0) this.varint();
    else if (wireType === 2) this.bytesField();
    else if (wireType === 1) this.offset += 8;
    else if (wireType === 5) this.offset += 4;
    else throw new Error('Malformed migration payload.');
  }
}

const decodeMigrationOtp = (bytes: Uint8Array): ParsedOtpSource | null => {
  const reader = new ProtoReader(bytes);
  const decoder = new TextDecoder();
  let secret: Uint8Array | null = null;
  let name = '';
  let issuer = '';
  let algorithm: OtpAlgorithm = 'SHA1';
  let digits = 6;
  let type: OtpType = 'totp';
  let counter = 0;

  while (!reader.done) {
    const tag = Number(reader.varint());
    const field = tag >> 3;
    const wire = tag & 7;
    if (field === 1 && wire === 2) secret = reader.bytesField();
    else if (field === 2 && wire === 2) name = decoder.decode(reader.bytesField());
    else if (field === 3 && wire === 2) issuer = decoder.decode(reader.bytesField());
    else if (field === 4 && wire === 0) algorithm = ({ 2: 'SHA256', 3: 'SHA512' } as Record<number, OtpAlgorithm>)[Number(reader.varint())] ?? 'SHA1';
    else if (field === 5 && wire === 0) digits = Number(reader.varint()) === 2 ? 8 : 6;
    else if (field === 6 && wire === 0) type = Number(reader.varint()) === 1 ? 'hotp' : 'totp';
    else if (field === 7 && wire === 0) counter = Number(reader.varint());
    else reader.skip(wire);
  }

  if (!secret) return null;
  // The label is often "Issuer:account"; keep just the account part.
  const account = issuer && name.startsWith(`${issuer}:`) ? name.slice(issuer.length + 1) : name;
  return makeOtpSource({ accountName: account, issuer, secret: bytesToBase32(secret), type, algorithm, digits, counter });
};

export const isMigrationUri = (input: string): boolean =>
  /^otpauth-migration:\/\//i.test(input.trim());

/** Decodes every account contained in a Google Authenticator export QR. */
export const parseMigrationUri = (input: string): ParsedOtpSource[] => {
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    throw new Error('The migration URI is malformed.');
  }
  const data = url.searchParams.get('data');
  if (!data) {
    throw new Error('The migration URI has no data.');
  }
  const base64 = data.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '+');
  const binary = atob(base64);
  const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));

  const reader = new ProtoReader(bytes);
  const results: ParsedOtpSource[] = [];
  while (!reader.done) {
    const tag = Number(reader.varint());
    if (tag >> 3 === 1 && (tag & 7) === 2) {
      const otp = decodeMigrationOtp(reader.bytesField());
      if (otp) results.push(otp);
    } else {
      reader.skip(tag & 7);
    }
  }
  return results;
};

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

export const deriveEntryName = (accountName: string, issuer: string): string => {
  const cleanAccountName = accountName.trim();
  const cleanIssuer = issuer.trim();
  if (cleanIssuer && cleanAccountName) {
    return `${cleanIssuer}: ${cleanAccountName}`;
  }
  return cleanAccountName || cleanIssuer;
};

export const splitEntryName = (name: string): { title: string; subtitle: string | null } => {
  const [head, ...tail] = name.split(':');
  const subtitle = tail.join(':').trim();
  if (!subtitle) {
    return { title: name.trim(), subtitle: null };
  }
  return { title: subtitle, subtitle: head.trim() };
};
