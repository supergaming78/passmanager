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

/** Regroupe plusieurs opérations de chiffrement/déchiffrement en UN SEUL appel IPC Tauri —
 * CORRECTIF PERF (retour utilisateur, 2026-09-02). Chaque entrée du coffre a jusqu'à 9 champs
 * chiffrés séparément (voir decryptEntry/encryptEntry ci-dessous) : avant ce correctif, les
 * déchiffrer/chiffrer signifiait jusqu'à 9 appels IPC séparés (chacun avec son propre aller-retour
 * de sérialisation à travers le pont Tauri, et sa propre lecture/effacement de la clé côté Rust —
 * voir src-tauri/src/lib.rs::encrypt_vault_fields/decrypt_vault_fields). `values` porte un slot par
 * champ, `null`/`undefined`/`""` pour un champ absent (repli direct sur `emptyValue`, jamais envoyé
 * à `op`) — les slots présents sont regroupés dans UN SEUL appel à `op`, puis redistribués à leur
 * position d'origine. Erreur sur un seul champ -> tout le lot échoue (même comportement "tout ou
 * rien" que l'ancien `Promise.all()`, juste déplacé dans le seul appel `op`). Exportée : réutilisée
 * par lib/emergencyAccess.ts et lib/sharedVault.ts, mêmes trousseaux de clés différents (voir
 * tauri.decryptEmergencyFields/encryptSharedVaultFields/decryptSharedVaultFields). */
export async function batchedCryptoOp<T>(
  values: (string | null | undefined)[],
  emptyValue: T,
  op: (nonEmpty: string[]) => Promise<T[]>,
): Promise<T[]> {
  const indices: number[] = [];
  const nonEmpty: string[] = [];
  values.forEach((v, i) => {
    if (v) {
      indices.push(i);
      nonEmpty.push(v);
    }
  });
  const results = nonEmpty.length > 0 ? await op(nonEmpty) : [];
  const output = new Array<T>(values.length).fill(emptyValue);
  indices.forEach((originalIndex, resultIndex) => {
    output[originalIndex] = results[resultIndex];
  });
  return output;
}

/** Nombre de champs chiffrés par entrée du coffre personnel — voir decryptEntries() ci-dessous. */
const FIELDS_PER_ENTRY = 9;

/** Déchiffre une LISTE d'entrées en UN SEUL appel IPC — CORRECTIF PERF (retour utilisateur,
 * 2026-09-02). decryptEntry() ci-dessous groupe déjà les 9 champs D'UNE entrée en un appel, mais
 * `Promise.all(entries.map(decryptEntry))` (voir Vault.tsx, AutoBackupSettings.tsx,
 * ImportExportBar.tsx — les trois écrans qui chargent le coffre EN BLOC) restait N appels IPC
 * lancés en parallèle pour N entrées. Ici, TOUS les champs de TOUTES les entrées sont aplatis dans
 * un seul tableau, un seul appel IPC pour l'écran entier, puis redécoupés par tranche de
 * FIELDS_PER_ENTRY pour reconstruire chaque entrée — même principe que
 * lib/emergencyAccess.ts::openEmergencyVault. Mêmes semantics "tout ou rien" qu'avant : un
 * `Promise.all` échouait déjà entièrement si UNE SEULE entrée était corrompue, inchangé ici. */
export async function decryptEntries(entries: VaultEntry[]): Promise<PlainVaultEntry[]> {
  const flatCiphertexts = entries.flatMap((entry) => [
    entry.encrypted_site_name,
    entry.encrypted_username,
    entry.encrypted_login_email,
    entry.encrypted_password,
    entry.encrypted_preferred_login_type,
    entry.encrypted_folder,
    entry.encrypted_notes,
    entry.encrypted_url,
    entry.encrypted_extra_fields,
  ]);
  const flatPlaintexts = await batchedCryptoOp(flatCiphertexts, "", tauri.decryptFields);

  return entries.map((entry, i) => {
    const base = i * FIELDS_PER_ENTRY;
    const [siteName, username, loginEmail, password, preferredLoginType, folder, notes, url, extraFieldsJson] =
      flatPlaintexts.slice(base, base + FIELDS_PER_ENTRY);
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
  });
}

/** Déchiffre UNE SEULE entrée — voir decryptEntries() ci-dessus pour le cas général (à préférer
 * pour charger PLUSIEURS entrées d'un coup, un seul appel IPC au lieu d'un par entrée). */
export async function decryptEntry(entry: VaultEntry): Promise<PlainVaultEntry> {
  return (await decryptEntries([entry]))[0];
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

/** Déchiffre une entrée de la corbeille (pas de mot de passe — voir PlainTrashedEntry). Voir
 * batchedCryptoOp() ci-dessus (un seul appel IPC pour les 4 champs). */
export async function decryptTrashedEntry(entry: TrashedVaultEntry): Promise<PlainTrashedEntry> {
  const [siteName, username, loginEmail, folder] = await batchedCryptoOp(
    [entry.encrypted_site_name, entry.encrypted_username, entry.encrypted_login_email, entry.encrypted_folder],
    "",
    tauri.decryptFields,
  );

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

/** Chiffre une LISTE d'entrées en UN SEUL appel IPC — CORRECTIF PERF (retour utilisateur,
 * 2026-09-02), même principe que decryptEntries() ci-dessus. `passwordChanged`/`expectedVersion`
 * s'appliquent alors à TOUTES les entrées du lot : ne convient QUE pour un cas où ces deux valeurs
 * sont réellement les mêmes pour tout le lot — l'ajout en bloc à l'import (voir
 * ImportExportBar.tsx::handleImportSelected, `toAdd`) : `passwordChanged` reste toujours à `false`
 * (aucune de ces entrées n'a d'"ancien" mot de passe à archiver, ce sont de nouvelles entrées) et
 * `expectedVersion` n'a jamais de sens à l'ajout. Pour une modification avec un `expectedVersion`
 * PROPRE à CHAQUE entrée (voir reassignFolder() dans Vault.tsx, qui isole aussi l'échec de chaque
 * appel réseau individuellement), garder encryptEntry() ci-dessous en boucle. */
export async function encryptEntries(
  plains: Omit<PlainVaultEntry, "id" | "updatedAt" | "version" | "hasAttachments">[],
  passwordChanged = false,
  expectedVersion?: number,
): Promise<VaultEntryInput[]> {
  const flatPlaintexts: (string | null)[] = plains.flatMap((plain) => {
    const hasExtraFields = Object.keys(plain.extraFields).length > 0;
    return [
      plain.siteName,
      plain.username.trim() ? plain.username : null,
      plain.loginEmail.trim() ? plain.loginEmail : null,
      plain.password,
      plain.preferredLoginType,
      plain.folder.trim() ? plain.folder : null,
      plain.notes.trim() ? plain.notes : null,
      plain.url.trim() ? plain.url : null,
      hasExtraFields ? JSON.stringify(plain.extraFields) : null,
    ];
  });
  const flatCiphertexts = await batchedCryptoOp<string | null>(flatPlaintexts, null, tauri.encryptFields);

  return plains.map((plain, i) => {
    const base = i * FIELDS_PER_ENTRY;
    // siteName/password/preferredLoginType toujours fournis -> toujours présents dans le lot
    // envoyé, jamais repliés sur `null` ; d'où le `as string` ci-dessous (VaultEntryInput les
    // déclare non-nullables, voir api/types.ts).
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
    ] = flatCiphertexts.slice(base, base + FIELDS_PER_ENTRY);
    return {
      encrypted_site_name: encrypted_site_name as string,
      encrypted_username,
      encrypted_login_email,
      encrypted_password: encrypted_password as string,
      encrypted_preferred_login_type: encrypted_preferred_login_type as string,
      is_favorite: plain.isFavorite,
      encrypted_folder,
      encrypted_notes,
      encrypted_url,
      entry_type: plain.entryType,
      encrypted_extra_fields,
      password_changed: passwordChanged,
      expected_version: expectedVersion ?? null,
    };
  });
}

/** Chiffre UNE SEULE entrée — voir encryptEntries() ci-dessus pour le cas général (plusieurs
 * entrées PARTAGEANT le même passwordChanged/expectedVersion, un seul appel IPC pour tout le lot).
 * `username`/`loginEmail`/`folder`/`notes`/`url` vides -> `null` plutôt qu'une chaîne chiffrée vide,
 * cohérent avec le fait que ces champs sont optionnels côté backend (voir VaultEntryInput).
 * `passwordChanged` doit être `true` UNIQUEMENT si l'appelant sait que le mot de passe a RÉELLEMENT
 * changé (voir VaultEntryInput::password_changed côté backend, pour l'archivage dans l'historique)
 * — laissé à `false` par défaut (ajout d'une nouvelle entrée : rien à archiver, ou modification qui
 * ne touche pas le mot de passe). `expectedVersion` : à fournir UNIQUEMENT lors d'une modification
 * (voir PlainVaultEntry.version) pour activer la détection de conflit d'édition côté serveur —
 * `undefined` (ajout d'une nouvelle entrée, pas encore de version à comparer) désactive simplement
 * le contrôle. */
export async function encryptEntry(
  plain: Omit<PlainVaultEntry, "id" | "updatedAt" | "version" | "hasAttachments">,
  passwordChanged = false,
  expectedVersion?: number,
): Promise<VaultEntryInput> {
  return (await encryptEntries([plain], passwordChanged, expectedVersion))[0];
}
