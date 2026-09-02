// Équivalent réduit de frontend(app)/src/lib/vaultCrypto.ts pour la popup : MÊME ordre de
// chiffrement/déchiffrement des champs, mais via lib/wasmCrypto.ts (qui prend la vault_key en
// paramètre explicite à chaque appel) plutôt que les commandes Tauri (qui la gardent côté Rust).

import * as wasmCrypto from "./wasmCrypto";
import type { TrashedVaultEntry, VaultEntry, VaultEntryInput } from "../api/types";

export type EntryType = "login" | "card" | "identity" | "note";

/** Repli sûr pour un `entry_type` que ce client ne reconnaît pas — même raison que côté desktop. */
export function normalizeEntryType(raw: string): EntryType {
  return raw === "card" || raw === "identity" || raw === "note" ? raw : "login";
}

/** Placeholder chiffré pour le champ `password` des entrées de type "note" — voir la même
 * constante côté desktop : le backend exige `encrypted_password` non vide pour tous les types. */
export const NOTE_TYPE_PASSWORD_PLACEHOLDER = "(non applicable — note sécurisée)";

export interface PlainVaultEntry {
  id: string;
  siteName: string;
  username: string;
  loginEmail: string;
  password: string;
  preferredLoginType: "username" | "email";
  isFavorite: boolean;
  folder: string;
  notes: string;
  url: string;
  entryType: EntryType;
  extraFields: Record<string, string>;
  updatedAt: string;
  version: number;
  hasAttachments: boolean;
  useCount: number;
}

export interface PlainTrashedEntry {
  id: string;
  siteName: string;
  username: string;
  loginEmail: string;
  isFavorite: boolean;
  deletedAt: string;
  folder: string;
}

/** Ne garde que les valeurs string d'un objet quelconque — voir la même fonction côté desktop pour
 * le détail du pourquoi (blob corrompu/champ d'une version future, ou reçu d'un AUTRE utilisateur
 * via le partage — jamais garanti bien formé). */
export function coerceExtraFields(parsed: unknown): Record<string, string> {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(parsed)) {
    if (typeof value === "string") result[key] = value;
  }
  return result;
}

export function parseExtraFields(json: string): Record<string, string> {
  if (!json) return {};
  try {
    return coerceExtraFields(JSON.parse(json));
  } catch {
    return {};
  }
}

/** Déchiffre les champs d'une entrée en parallèle avec la vault_key fournie — voir
 * lib/session.ts pour d'où elle vient (jamais persistée au-delà de la fenêtre de verrouillage). */
export async function decryptEntry(entry: VaultEntry, vaultKey: Uint8Array): Promise<PlainVaultEntry> {
  const dec = (blob: string) => wasmCrypto.decryptField(vaultKey, blob);

  const [siteName, username, loginEmail, password, preferredLoginType, folder, notes, url, extraFieldsJson] = await Promise.all([
    dec(entry.encrypted_site_name),
    entry.encrypted_username ? dec(entry.encrypted_username) : Promise.resolve(""),
    entry.encrypted_login_email ? dec(entry.encrypted_login_email) : Promise.resolve(""),
    dec(entry.encrypted_password),
    dec(entry.encrypted_preferred_login_type),
    entry.encrypted_folder ? dec(entry.encrypted_folder) : Promise.resolve(""),
    entry.encrypted_notes ? dec(entry.encrypted_notes) : Promise.resolve(""),
    entry.encrypted_url ? dec(entry.encrypted_url) : Promise.resolve(""),
    entry.encrypted_extra_fields ? dec(entry.encrypted_extra_fields) : Promise.resolve(""),
  ]);

  return {
    id: entry.id,
    siteName,
    username,
    loginEmail,
    password,
    preferredLoginType: preferredLoginType === "email" ? "email" : "username",
    isFavorite: entry.is_favorite,
    folder,
    notes,
    url,
    entryType: normalizeEntryType(entry.entry_type),
    extraFields: parseExtraFields(extraFieldsJson),
    updatedAt: entry.updated_at,
    version: entry.version,
    hasAttachments: entry.has_attachments,
    useCount: entry.use_count,
  };
}

/** Déchiffre une entrée de la corbeille — pas de mot de passe (le backend ne le renvoie pas pour
 * cet écran, voir TrashedVaultEntry), juste de quoi identifier l'entrée avant restauration/purge. */
export async function decryptTrashedEntry(entry: TrashedVaultEntry, vaultKey: Uint8Array): Promise<PlainTrashedEntry> {
  const dec = (blob: string) => wasmCrypto.decryptField(vaultKey, blob);

  const [siteName, username, loginEmail, folder] = await Promise.all([
    dec(entry.encrypted_site_name),
    entry.encrypted_username ? dec(entry.encrypted_username) : Promise.resolve(""),
    entry.encrypted_login_email ? dec(entry.encrypted_login_email) : Promise.resolve(""),
    entry.encrypted_folder ? dec(entry.encrypted_folder) : Promise.resolve(""),
  ]);

  return {
    id: entry.id,
    siteName,
    username,
    loginEmail,
    isFavorite: entry.is_favorite,
    deletedAt: entry.deleted_at,
    folder,
  };
}

/** Chiffre les champs d'un formulaire avant envoi au backend — voir la même fonction côté desktop
 * pour le détail des règles (`username`/`loginEmail`/`folder`/`notes`/`url` vides -> `null`,
 * `passwordChanged`/`expectedVersion` déterminés par l'appelant). */
export async function encryptEntry(
  plain: Omit<PlainVaultEntry, "id" | "updatedAt" | "version" | "hasAttachments" | "useCount">,
  vaultKey: Uint8Array,
  passwordChanged = false,
  expectedVersion?: number,
): Promise<VaultEntryInput> {
  const hasExtraFields = Object.keys(plain.extraFields).length > 0;
  const enc = (text: string) => wasmCrypto.encryptField(vaultKey, text);

  const [
    encrypted_site_name,
    encrypted_username,
    encrypted_login_email,
    encrypted_password,
    encrypted_preferred_login_type,
    encrypted_folder,
    encrypted_notes,
    encrypted_url,
    encrypted_extra_fields,
  ] = await Promise.all([
    enc(plain.siteName),
    plain.username.trim() ? enc(plain.username) : Promise.resolve(null),
    plain.loginEmail.trim() ? enc(plain.loginEmail) : Promise.resolve(null),
    enc(plain.password),
    enc(plain.preferredLoginType),
    plain.folder.trim() ? enc(plain.folder) : Promise.resolve(null),
    plain.notes.trim() ? enc(plain.notes) : Promise.resolve(null),
    plain.url.trim() ? enc(plain.url) : Promise.resolve(null),
    hasExtraFields ? enc(JSON.stringify(plain.extraFields)) : Promise.resolve(null),
  ]);

  return {
    encrypted_site_name,
    encrypted_username,
    encrypted_login_email,
    encrypted_password,
    encrypted_preferred_login_type,
    is_favorite: plain.isFavorite,
    encrypted_folder,
    encrypted_notes,
    encrypted_url,
    entry_type: plain.entryType,
    encrypted_extra_fields,
    password_changed: passwordChanged,
    expected_version: expectedVersion ?? null,
  };
}
