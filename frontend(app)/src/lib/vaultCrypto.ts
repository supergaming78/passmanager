// Convertit entre la forme CHIFFRÉE d'une entrée (celle échangée avec le backend, voir
// api/types.ts::VaultEntry) et sa forme EN CLAIR utilisée par l'UI (voir PlainVaultEntry). Chaque
// champ passe individuellement par les commandes Tauri de chiffrement/déchiffrement
// (api/tauri.ts) — jamais de crypto en JS, voir src-tauri/src/crypto.rs.

import * as tauri from "../api/tauri";
import type { TrashedVaultEntry, VaultEntry, VaultEntryInput } from "../api/types";

/** Type d'entrée dédié — "login" (défaut, comportement historique) ou un des types ajoutés
 * ensuite. Une valeur inconnue (ancienne donnée, client plus récent...) doit toujours être ramenée
 * à "login" par normalizeEntryType() ci-dessous plutôt que de faire planter quoi que ce soit. */
export type EntryType = "login" | "card" | "identity" | "note";

/** Repli sûr pour un `entry_type` que ce client ne reconnaît pas (valeur future ajoutée par une
 * version plus récente de l'app, ou donnée corrompue) — jamais d'erreur, toujours "login". */
export function normalizeEntryType(raw: string): EntryType {
  return raw === "card" || raw === "identity" || raw === "note" ? raw : "login";
}

/** Placeholder chiffré pour le champ `password` des entrées de type "note" — ce type n'a pas de
 * secret "mot de passe" à proprement parler (voir VaultEntryForm.tsx, qui masque entièrement ce
 * champ pour ce type), mais le backend exige `encrypted_password` non vide (`min = 1`, partagé
 * avec le type "login") : plutôt qu'un changement de contrainte serveur pour un seul type sur
 * quatre, ce texte fixe comble l'obligation sans jamais être montré, révélé, copié ni proposé au
 * générateur pour ce type. */
export const NOTE_TYPE_PASSWORD_PLACEHOLDER = "(non applicable — note sécurisée)";

export interface PlainVaultEntry {
  id: string;
  siteName: string;
  username: string;
  loginEmail: string;
  password: string;
  preferredLoginType: "username" | "email";
  isFavorite: boolean;
  /** Dossier d'organisation (ex: "Travail", "Perso") — "" = pas de dossier assigné, même
   * convention que username/loginEmail. Chiffré côté serveur comme le reste du contenu. */
  folder: string;
  /** Notes libres — "" = aucune. Chiffrées comme le reste. */
  notes: string;
  /** URL du site — "" = aucune. Chiffrée comme le reste ; sert au bouton "Ouvrir le site". */
  url: string;
  /** Type d'entrée dédié — voir EntryType. Détermine quels champs génériques ci-dessus sont
   * affichés/étiquetés comment (voir VaultEntryForm.tsx/Vault.tsx) et si `extraFields` a un sens. */
  entryType: EntryType;
  /** Champs additionnels spécifiques au type (ex: date d'expiration/CVV pour une carte) — objet
   * VIDE pour "login"/"note" (aucun champ additionnel défini pour ces types). Un seul blob JSON
   * chiffré côté serveur (voir VaultEntry.encrypted_extra_fields), jamais interprété par le
   * serveur — purement une convention côté client. */
  extraFields: Record<string, string>;
  /** Dernière modification — métadonnée EN CLAIR côté serveur (comme isFavorite), jamais
   * chiffrée : sert à afficher "modifié il y a X" et à repérer les mots de passe anciens. */
  updatedAt: string;
  /** Compteur de version — métadonnée EN CLAIR, incrémentée à chaque modification côté serveur.
   * À renvoyer via `encryptEntry(..., expectedVersion)` lors d'une modification, pour détecter un
   * conflit d'édition (voir PUT /vault/{id} côté backend). */
  version: number;
  /** Vrai si cette entrée a au moins une pièce jointe — métadonnée EN CLAIR calculée côté serveur
   * (voir VaultEntry.has_attachments), sert au filtre "avec pièce jointe" sans avoir à interroger
   * GET /vault/{id}/attachments pour chaque entrée. */
  hasAttachments: boolean;
}

/** Version corbeille : PAS de mot de passe (voir TrashedVaultEntry, le backend ne le renvoie pas
 * pour cet écran — voir api/types.ts) — juste de quoi identifier l'entrée avant de la restaurer
 * ou la purger. */
export interface PlainTrashedEntry {
  id: string;
  siteName: string;
  username: string;
  loginEmail: string;
  isFavorite: boolean;
  deletedAt: string;
  folder: string;
}

/** Déchiffre les champs d'une entrée en parallèle (indépendants les uns des autres, pas de
 * raison de les attendre en série). */
export async function decryptEntry(entry: VaultEntry): Promise<PlainVaultEntry> {
  const [siteName, username, loginEmail, password, preferredLoginType, folder, notes, url, extraFieldsJson] = await Promise.all([
    tauri.decryptField(entry.encrypted_site_name),
    entry.encrypted_username ? tauri.decryptField(entry.encrypted_username) : Promise.resolve(""),
    entry.encrypted_login_email ? tauri.decryptField(entry.encrypted_login_email) : Promise.resolve(""),
    tauri.decryptField(entry.encrypted_password),
    tauri.decryptField(entry.encrypted_preferred_login_type),
    entry.encrypted_folder ? tauri.decryptField(entry.encrypted_folder) : Promise.resolve(""),
    entry.encrypted_notes ? tauri.decryptField(entry.encrypted_notes) : Promise.resolve(""),
    entry.encrypted_url ? tauri.decryptField(entry.encrypted_url) : Promise.resolve(""),
    entry.encrypted_extra_fields ? tauri.decryptField(entry.encrypted_extra_fields) : Promise.resolve(""),
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
  };
}

/** Parse le JSON déchiffré de `extraFields` — jamais d'exception sur un blob absent/corrompu
 * (ex: donnée d'une version future de l'app dont ce client ne connaît pas encore la forme) :
 * repli sur un objet vide, jamais une entrée illisible pour autant. Exportée : réutilisée par
 * lib/emergencyAccess.ts, qui déchiffre les entrées via un trousseau différent (pas tauri.decryptField)
 * mais doit reconstruire le même PlainVaultEntry. */
export function parseExtraFields(json: string): Record<string, string> {
  if (!json) return {};
  try {
    return coerceExtraFields(JSON.parse(json));
  } catch {
    return {};
  }
}

/** Ne garde QUE les valeurs réellement string d'un objet quelconque — un blob corrompu (ou, pour
 * lib/entrySharing.ts, envoyé par un AUTRE utilisateur via le partage d'entrée, jamais garanti bien
 * formé) pourrait sinon injecter un nombre/objet/tableau comme "valeur", affiché tel quel dans un
 * `<input value={...}>` (coercion silencieuse en "[object Object]" par React/le DOM — pas une
 * faille, mais un affichage trompeur qu'il vaut mieux exclure proprement ici). Exportée : réutilisée
 * par lib/entrySharing.ts::coerceSharedContent, même besoin sur une source différente (JSON déjà
 * parsé, pas encore une chaîne à parser).*/
export function coerceExtraFields(parsed: unknown): Record<string, string> {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return {};
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(parsed)) {
    if (typeof value === "string") result[key] = value;
  }
  return result;
}

/** Déchiffre une entrée de la corbeille (pas de mot de passe — voir PlainTrashedEntry). */
export async function decryptTrashedEntry(entry: TrashedVaultEntry): Promise<PlainTrashedEntry> {
  const [siteName, username, loginEmail, folder] = await Promise.all([
    tauri.decryptField(entry.encrypted_site_name),
    entry.encrypted_username ? tauri.decryptField(entry.encrypted_username) : Promise.resolve(""),
    entry.encrypted_login_email ? tauri.decryptField(entry.encrypted_login_email) : Promise.resolve(""),
    entry.encrypted_folder ? tauri.decryptField(entry.encrypted_folder) : Promise.resolve(""),
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

/** Chiffre les champs d'un formulaire avant envoi au backend. `username`/`loginEmail`/`folder`/`notes`/`url`
 * vides -> `null` plutôt qu'une chaîne chiffrée vide, cohérent avec le fait que ces champs sont
 * optionnels côté backend (voir VaultEntryInput). `passwordChanged` doit être `true` UNIQUEMENT si
 * l'appelant sait que le mot de passe a RÉELLEMENT changé (voir VaultEntryInput::password_changed
 * côté backend, pour l'archivage dans l'historique) — laissé à `false` par défaut (ajout d'une
 * nouvelle entrée : rien à archiver, ou modification qui ne touche pas le mot de passe).
 * `expectedVersion` : à fournir UNIQUEMENT lors d'une modification (voir PlainVaultEntry.version)
 * pour activer la détection de conflit d'édition côté serveur — `undefined` (ajout d'une nouvelle
 * entrée, pas encore de version à comparer) désactive simplement le contrôle. */
export async function encryptEntry(
  plain: Omit<PlainVaultEntry, "id" | "updatedAt" | "version" | "hasAttachments">,
  passwordChanged = false,
  expectedVersion?: number,
): Promise<VaultEntryInput> {
  const hasExtraFields = Object.keys(plain.extraFields).length > 0;

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
    tauri.encryptField(plain.siteName),
    plain.username.trim() ? tauri.encryptField(plain.username) : Promise.resolve(null),
    plain.loginEmail.trim() ? tauri.encryptField(plain.loginEmail) : Promise.resolve(null),
    tauri.encryptField(plain.password),
    tauri.encryptField(plain.preferredLoginType),
    plain.folder.trim() ? tauri.encryptField(plain.folder) : Promise.resolve(null),
    plain.notes.trim() ? tauri.encryptField(plain.notes) : Promise.resolve(null),
    plain.url.trim() ? tauri.encryptField(plain.url) : Promise.resolve(null),
    hasExtraFields ? tauri.encryptField(JSON.stringify(plain.extraFields)) : Promise.resolve(null),
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
