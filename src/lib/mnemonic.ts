import { BIP39_WORDLIST } from './bip39-wordlist';

// BIP-0039-style mnemonic encoding (entropy + checksum -> word list) used for
// the xVault recovery phrase. This is intentionally *not* wired to BIP32/44
// derivation paths or any wallet-interop seed format: xVault only needs a
// human-writable, checksummed representation of random key material, which
// it then runs through PBKDF2 to derive an opaque secret the backend can use
// to unwrap the vault key. None of this ever touches the server.

const WORD_BITS = 11;

const WORD_INDEX: ReadonlyMap<string, number> = new Map(
  BIP39_WORDLIST.map((word, index) => [word, index]),
);

export const normalizeMnemonic = (phrase: string): string =>
  phrase.trim().toLowerCase().replace(/\s+/g, ' ');

const bytesToBinary = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((byte) => byte.toString(2).padStart(8, '0'))
    .join('');

const binaryToBytes = (bits: string): Uint8Array => {
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }
  return bytes;
};

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');

const entropyToMnemonic = async (entropy: Uint8Array): Promise<string> => {
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', entropy as BufferSource));
  const checksumBitCount = (entropy.length * 8) / 32;
  const bits = bytesToBinary(entropy) + bytesToBinary(hash).slice(0, checksumBitCount);

  const words: string[] = [];
  for (let i = 0; i < bits.length / WORD_BITS; i++) {
    const chunk = bits.slice(i * WORD_BITS, (i + 1) * WORD_BITS);
    words.push(BIP39_WORDLIST[parseInt(chunk, 2)]);
  }
  return words.join(' ');
};

/**
 * Generates a fresh recovery phrase. 24 words (256 bits of entropy) by
 * default — the same strength used for the master-key file.
 */
export const generateMnemonic = async (wordCount: 12 | 24 = 24): Promise<string> => {
  const entropyBits = wordCount === 24 ? 256 : 128;
  const entropy = new Uint8Array(entropyBits / 8);
  crypto.getRandomValues(entropy);
  return entropyToMnemonic(entropy);
};

/**
 * Verifies a mnemonic's checksum and word-list membership. Catches typos and
 * transcription errors before the user ever submits them for recovery.
 */
export const validateMnemonic = async (phrase: string): Promise<boolean> => {
  const words = normalizeMnemonic(phrase).split(' ').filter(Boolean);
  if (words.length !== 12 && words.length !== 24) {
    return false;
  }

  const indices = words.map((word) => WORD_INDEX.get(word));
  if (indices.some((index) => index === undefined)) {
    return false;
  }

  const bits = indices.map((index) => (index as number).toString(2).padStart(WORD_BITS, '0')).join('');
  const entropyBitCount = Math.floor((bits.length * 32) / 33);
  const checksumBitCount = bits.length - entropyBitCount;

  const entropyBytes = binaryToBytes(bits.slice(0, entropyBitCount));
  const expectedChecksum = bits.slice(entropyBitCount);

  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', entropyBytes as BufferSource));
  const actualChecksum = bytesToBinary(hash).slice(0, checksumBitCount);

  return actualChecksum === expectedChecksum;
};

/**
 * Generates a brand new 256-bit master-key secret for the `.key` recovery
 * file. Unlike the recovery phrase, this is raw random key material (never
 * meant to be memorized), so it is used directly as the wrap/unwrap secret
 * without any passphrase-style KDF.
 */
export const generateMasterKeySecret = (): string => {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
};
