export interface Folder {
  id: string;
  name: string;
  icon: string; // Emoji ou icône pour le dossier
  color: string; // Couleur du dossier (code hexadécimal)
  isExpanded?: boolean; // État d'expansion du dossier dans l'UI
  parentId?: string; // ID du dossier parent, undefined si à la racine
}

export type OtpType = 'totp' | 'hotp' | 'steam';
export type OtpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';

export interface TOTPEntry {
  id: string;
  name: string;
  secret: string; // Base32
  icon: string; // Peut être un nom d'icône ou une image base64
  isCustomIcon?: boolean; // Flag pour indiquer si l'icône est une image base64
  type?: OtpType; // défaut : 'totp'
  algorithm?: OtpAlgorithm; // défaut : 'SHA1'
  period?: number; // TOTP / Steam
  digits?: number;
  counter?: number; // HOTP
  folderId?: string; // ID du dossier parent, null/undefined si à la racine
}

export interface PasswordEntry {
  id: string;
  title: string;
  username: string;
  password: string;
  url?: string;
  notes?: string;
  icon?: string;
  isCustomIcon?: boolean;
  folderId?: string;
  linkedEntryId?: string; // ID d'une TOTPEntry associée (2FA du même compte)
  createdAt: string;
  updatedAt: string;
}

export interface VaultData {
  entries: TOTPEntry[];
  folders: Folder[];
  passwords: PasswordEntry[];
}

export interface User {
  id: number;
  loginId: string;
  name: string;
  logo?: string;
  recoveryEnabled?: boolean;
  masterKeyEnabled?: boolean;
}

export type RecoveryMethod = 'phrase' | 'key';
