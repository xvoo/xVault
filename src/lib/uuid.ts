// `crypto.randomUUID()` is restricted to secure contexts (HTTPS or
// `localhost`) by the Web Crypto spec — it is simply `undefined` on plain
// `http://` origins such as a LAN IP, which is how xVault is commonly
// self-hosted. `crypto.getRandomValues()` has no such restriction, so this
// builds a standard v4 UUID from it whenever the native method is missing.
export const generateId = (): string => {
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }

  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);

  bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10

  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
};
