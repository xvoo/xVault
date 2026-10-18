import { estimateEntropy } from './vaultcrypto';

export interface PasswordGeneratorOptions {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
}

const CHARSETS = {
  uppercase: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
  lowercase: 'abcdefghijkmnopqrstuvwxyz',
  numbers: '23456789',
  symbols: '!@#$%^&*()-_=+[]{}?',
} as const;

export const DEFAULT_PASSWORD_OPTIONS: PasswordGeneratorOptions = {
  length: 20,
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: true,
};

/** Uniform random integer in [0, max) — rejection sampling, no modulo bias. */
const randomIndex = (max: number): number => {
  const limit = Math.floor(0x1_0000_0000 / max) * max;
  const buffer = new Uint32Array(1);
  do {
    crypto.getRandomValues(buffer);
  } while (buffer[0] >= limit);
  return buffer[0] % max;
};

export const generatePassword = (options: PasswordGeneratorOptions = DEFAULT_PASSWORD_OPTIONS): string => {
  const pools: string[] = [];
  if (options.uppercase) pools.push(CHARSETS.uppercase);
  if (options.lowercase) pools.push(CHARSETS.lowercase);
  if (options.numbers) pools.push(CHARSETS.numbers);
  if (options.symbols) pools.push(CHARSETS.symbols);

  if (pools.length === 0) {
    pools.push(CHARSETS.lowercase);
  }

  const alphabet = pools.join('');
  const requested = Math.trunc(Number(options.length));
  const length = Number.isFinite(requested) ? Math.min(128, Math.max(Math.max(4, pools.length), requested)) : 20;

  // Guarantee at least one character from each selected pool, then fill the
  // rest uniformly, and shuffle so the guaranteed characters aren't
  // predictably placed at the start.
  const required = pools.map((pool) => pool[randomIndex(pool.length)]);
  const rest = Array.from({ length: length - required.length }, () => alphabet[randomIndex(alphabet.length)]);
  const combined = [...required, ...rest];

  for (let i = combined.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1);
    [combined[i], combined[j]] = [combined[j], combined[i]];
  }

  return combined.join('');
};

export type PasswordStrength = 'weak' | 'fair' | 'strong' | 'excellent';

export const estimatePasswordStrength = (password: string): PasswordStrength => {
  if (!password) return 'weak';
  // Entropy estimate that penalizes repetition ("Aaaaaaaaaaaa1" is weak).
  const bits = estimateEntropy(password);
  if (bits >= 100) return 'excellent';
  if (bits >= 70) return 'strong';
  if (bits >= 45) return 'fair';
  return 'weak';
};
