// Orchestration des coffres partagés familiaux — combine les appels réseau (api/client.ts) et les
// commandes Tauri de chiffrement (api/tauri.ts, voir src-tauri/src/shared_vault.rs) pour les flux
// à plusieurs étapes, même principe que lib/entrySharing.ts/lib/emergencyAccess.ts (dont ce module
// réutilise d'ailleurs ensureEmergencyKeys : UN SEUL trousseau de clés X25519 par utilisateur pour
// les trois fonctionnalités). Jamais de crypto en JS ici non plus.
//
// Différence structurelle avec lib/entrySharing.ts : un coffre partagé a sa PROPRE clé symétrique
// (générée une fois à sa création), scellée individuellement pour chaque membre — ses entrées sont
// chiffrées avec CETTE clé, jamais celle du coffre personnel de l'utilisateur. La clé déchiffrée
// (`vaultKeyB64`) ne vit qu'en mémoire JS locale au composant qui l'affiche, jamais persistée
// ailleurs (même principe que la clé de coffre déchiffrée dans lib/emergencyAccess.ts pour un
// accès d'urgence consulté).

import * as api from "../api/client";
import * as tauri from "../api/tauri";
import { ensureEmergencyKeys } from "./emergencyAccess";
import { normalizeEntryType, coerceExtraFields, type EntryType } from "./vaultCrypto";
import type { SharedVaultMemberView, SharedVaultEntryInput } from "../api/types";

type AuthorizedRequest = <T,>(fn: (accessToken: string) => Promise<T>) => Promise<T>;

/** Un coffre partagé DÉJÀ déverrouillé (clé symétrique déchiffrée) pour l'utilisateur courant —
 * `vaultKeyB64` ne doit JAMAIS être persisté (localStorage, disque...), uniquement gardé en état
 * React le temps de la session/de l'écran ouvert. */
export interface UnlockedSharedVault {
  id: string;
  name: string;
  vaultKeyB64: string;
  isOwner: boolean;
  createdBy: string;
  createdAt: string;
}

export interface PlainSharedVaultEntry {
  id: string;
  siteName: string;
  username: string;
  loginEmail: string;
  password: string;
  preferredLoginType: "username" | "email";
  notes: string;
  url: string;
  entryType: EntryType;
  extraFields: Record<string, string>;
  createdBy: string;
  updatedAt: string;
  version: number;
}

/** Liste les coffres partagés dont l'utilisateur est membre, déjà DÉVERROUILLÉS (clé + nom en
 * clair) — descelle la clé de CHACUN avec sa propre clé privée (une seule résolution de clé
 * privée, réutilisée pour tous : `ensureEmergencyKeys` s'assure qu'elle existe, un seul appel
 * réseau pour la récupérer). Un coffre dont le descellement échouerait (donnée corrompue, clé
 * privée invalide) est silencieusement omis plutôt que de faire échouer tout l'écran — best-effort,
 * comme le reste de cette app pour des opérations agrégées sur plusieurs éléments indépendants. */
export async function listMySharedVaults(authorizedRequest: AuthorizedRequest): Promise<UnlockedSharedVault[]> {
  await ensureEmergencyKeys(authorizedRequest);
  const [views, ownKeys] = await Promise.all([
    authorizedRequest((token) => api.listSharedVaults(token)),
    authorizedRequest((token) => api.getOwnEmergencyKeys(token)),
  ]);

  const unlocked = await Promise.allSettled(
    views.map(async (view) => {
      const vaultKeyB64 = await tauri.unsealSharedVaultKey(view.sealed_vault_key, ownKeys.encrypted_private_key);
      const name = await tauri.decryptSharedVaultField(view.encrypted_name, vaultKeyB64);
      return { id: view.id, name, vaultKeyB64, isOwner: view.is_owner, createdBy: view.created_by, createdAt: view.created_at };
    }),
  );

  return unlocked.filter((r): r is PromiseFulfilledResult<UnlockedSharedVault> => r.status === "fulfilled").map((r) => r.value);
}

/** Récupère UN coffre partagé précis, déverrouillé — pas d'endpoint dédié côté backend (voir
 * GET /shared-vaults, qui liste tout) : à l'échelle d'un usage familial, quelques coffres partagés
 * au plus par compte, refiltrer côté client après un listage complet reste largement suffisant
 * plutôt que d'ajouter une route pour un gain marginal. `undefined` si l'id est introuvable/plus
 * accessible (coffre supprimé entre-temps, appelant retiré...). */
export async function getUnlockedSharedVault(authorizedRequest: AuthorizedRequest, vaultId: string): Promise<UnlockedSharedVault | undefined> {
  const all = await listMySharedVaults(authorizedRequest);
  return all.find((v) => v.id === vaultId);
}

/** Crée un nouveau coffre partagé — l'appelant en devient automatiquement propriétaire et premier
 * membre. Génère une clé symétrique fraîche, chiffre le nom avec elle, la scelle pour sa PROPRE
 * clé publique (il doit lui aussi détenir une copie scellée pour déchiffrer les entrées qu'il
 * ajoute ensuite). */
export async function createSharedVault(authorizedRequest: AuthorizedRequest, name: string): Promise<string> {
  await ensureEmergencyKeys(authorizedRequest);
  const ownKeys = await authorizedRequest((token) => api.getOwnEmergencyKeys(token));

  const vaultKeyB64 = await tauri.generateSharedVaultKey();
  const encrypted_name = await tauri.encryptSharedVaultField(name, vaultKeyB64);
  const sealed_vault_key = await tauri.sealSharedVaultKey(vaultKeyB64, ownKeys.public_key);

  const { id } = await authorizedRequest((token) => api.createSharedVault(token, { encrypted_name, sealed_vault_key }));
  return id;
}

/** Supprime DÉFINITIVEMENT un coffre partagé entier — réservé au propriétaire (vérifié côté
 * serveur). */
export function deleteSharedVault(authorizedRequest: AuthorizedRequest, vaultId: string): Promise<void> {
  return authorizedRequest((token) => api.deleteSharedVault(token, vaultId));
}

/** Invite un nouveau membre — réservé au propriétaire (vérifié côté serveur). Résout la clé
 * publique du futur membre (réutilise GET /emergency/keys/{email}, générique), scelle la clé du
 * coffre pour lui côté Rust. Le futur membre doit déjà avoir configuré ses propres clés — sinon la
 * résolution de sa clé publique échoue en 404 (même limitation que le partage d'entrée 1-vers-1,
 * voir lib/entrySharing.ts::shareEntry). */
export async function inviteMember(authorizedRequest: AuthorizedRequest, vaultId: string, vaultKeyB64: string, memberEmail: string): Promise<void> {
  const { public_key } = await authorizedRequest((token) => api.getPublicKey(token, memberEmail));
  const sealed_vault_key = await tauri.sealSharedVaultKey(vaultKeyB64, public_key);
  await authorizedRequest((token) => api.inviteSharedVaultMember(token, vaultId, { member_email: memberEmail, sealed_vault_key }));
}

/** Liste les membres d'un coffre partagé — n'importe quel membre peut la consulter. */
export function listMembers(authorizedRequest: AuthorizedRequest, vaultId: string): Promise<SharedVaultMemberView[]> {
  return authorizedRequest((token) => api.listSharedVaultMembers(token, vaultId));
}

/** Retire un membre — même route pour "quitter soi-même" ou "le propriétaire retire quelqu'un
 * d'autre", l'autorisation est vérifiée côté serveur (voir handlers/shared_vault.rs). */
export function removeMember(authorizedRequest: AuthorizedRequest, vaultId: string, memberEmail: string): Promise<void> {
  return authorizedRequest((token) => api.removeSharedVaultMember(token, vaultId, memberEmail));
}

/** Chiffre les champs d'un formulaire avant envoi, avec la clé SYMÉTRIQUE du coffre partagé (pas
 * la clé du coffre personnel — voir tauri.encryptSharedVaultField). */
async function encryptSharedEntry(
  plain: Omit<PlainSharedVaultEntry, "id" | "createdBy" | "updatedAt" | "version">,
  vaultKeyB64: string,
  expectedVersion?: number,
): Promise<SharedVaultEntryInput> {
  const hasExtraFields = Object.keys(plain.extraFields).length > 0;

  const [
    encrypted_site_name,
    encrypted_username,
    encrypted_login_email,
    encrypted_password,
    encrypted_preferred_login_type,
    encrypted_notes,
    encrypted_url,
    encrypted_extra_fields,
  ] = await Promise.all([
    tauri.encryptSharedVaultField(plain.siteName, vaultKeyB64),
    plain.username.trim() ? tauri.encryptSharedVaultField(plain.username, vaultKeyB64) : Promise.resolve(null),
    plain.loginEmail.trim() ? tauri.encryptSharedVaultField(plain.loginEmail, vaultKeyB64) : Promise.resolve(null),
    tauri.encryptSharedVaultField(plain.password, vaultKeyB64),
    tauri.encryptSharedVaultField(plain.preferredLoginType, vaultKeyB64),
    plain.notes.trim() ? tauri.encryptSharedVaultField(plain.notes, vaultKeyB64) : Promise.resolve(null),
    plain.url.trim() ? tauri.encryptSharedVaultField(plain.url, vaultKeyB64) : Promise.resolve(null),
    hasExtraFields ? tauri.encryptSharedVaultField(JSON.stringify(plain.extraFields), vaultKeyB64) : Promise.resolve(null),
  ]);

  return {
    encrypted_site_name,
    encrypted_username,
    encrypted_login_email,
    encrypted_password,
    encrypted_preferred_login_type,
    encrypted_notes,
    encrypted_url,
    entry_type: plain.entryType,
    encrypted_extra_fields,
    expected_version: expectedVersion ?? null,
  };
}

/** Déchiffre les champs d'une entrée de coffre partagé en parallèle, avec sa clé symétrique. */
async function decryptSharedEntry(entry: { id: string; encrypted_site_name: string; encrypted_username: string | null; encrypted_login_email: string | null; encrypted_password: string; encrypted_preferred_login_type: string; encrypted_notes: string | null; encrypted_url: string | null; entry_type: string; encrypted_extra_fields: string | null; created_by: string; updated_at: string; version: number }, vaultKeyB64: string): Promise<PlainSharedVaultEntry> {
  const [siteName, username, loginEmail, password, preferredLoginType, notes, url, extraFieldsJson] = await Promise.all([
    tauri.decryptSharedVaultField(entry.encrypted_site_name, vaultKeyB64),
    entry.encrypted_username ? tauri.decryptSharedVaultField(entry.encrypted_username, vaultKeyB64) : Promise.resolve(""),
    entry.encrypted_login_email ? tauri.decryptSharedVaultField(entry.encrypted_login_email, vaultKeyB64) : Promise.resolve(""),
    tauri.decryptSharedVaultField(entry.encrypted_password, vaultKeyB64),
    tauri.decryptSharedVaultField(entry.encrypted_preferred_login_type, vaultKeyB64),
    entry.encrypted_notes ? tauri.decryptSharedVaultField(entry.encrypted_notes, vaultKeyB64) : Promise.resolve(""),
    entry.encrypted_url ? tauri.decryptSharedVaultField(entry.encrypted_url, vaultKeyB64) : Promise.resolve(""),
    entry.encrypted_extra_fields ? tauri.decryptSharedVaultField(entry.encrypted_extra_fields, vaultKeyB64) : Promise.resolve(""),
  ]);

  let extraFields: Record<string, string> = {};
  if (extraFieldsJson) {
    try {
      extraFields = coerceExtraFields(JSON.parse(extraFieldsJson));
    } catch {
      extraFields = {};
    }
  }

  return {
    id: entry.id,
    siteName,
    username,
    loginEmail,
    password,
    preferredLoginType: preferredLoginType === "email" ? "email" : "username",
    notes,
    url,
    entryType: normalizeEntryType(entry.entry_type),
    extraFields,
    createdBy: entry.created_by,
    updatedAt: entry.updated_at,
    version: entry.version,
  };
}

/** Liste les entrées d'un coffre partagé, déjà déchiffrées. Une entrée dont le déchiffrement
 * échouerait est omise plutôt que de faire échouer tout l'écran (même best-effort que
 * listMySharedVaults ci-dessus). */
export async function listEntries(authorizedRequest: AuthorizedRequest, vaultId: string, vaultKeyB64: string): Promise<PlainSharedVaultEntry[]> {
  const raw = await authorizedRequest((token) => api.listSharedVaultEntries(token, vaultId));
  const decrypted = await Promise.allSettled(raw.map((entry) => decryptSharedEntry(entry, vaultKeyB64)));
  return decrypted.filter((r): r is PromiseFulfilledResult<PlainSharedVaultEntry> => r.status === "fulfilled").map((r) => r.value);
}

/** Ajoute une entrée — visible IMMÉDIATEMENT par tous les membres (même clé symétrique). */
export async function addEntry(
  authorizedRequest: AuthorizedRequest,
  vaultId: string,
  vaultKeyB64: string,
  plain: Omit<PlainSharedVaultEntry, "id" | "createdBy" | "updatedAt" | "version">,
): Promise<string> {
  const payload = await encryptSharedEntry(plain, vaultKeyB64);
  const { id } = await authorizedRequest((token) => api.addSharedVaultEntry(token, vaultId, payload));
  return id;
}

/** Modifie une entrée existante — `expectedVersion` active la détection de conflit d'édition côté
 * serveur (voir PUT /shared-vaults/{id}/entries/{entry_id}), encore plus pertinente ici que pour
 * le coffre personnel : plusieurs membres différents peuvent modifier la même entrée. */
export async function updateEntry(
  authorizedRequest: AuthorizedRequest,
  vaultId: string,
  entryId: string,
  vaultKeyB64: string,
  plain: Omit<PlainSharedVaultEntry, "id" | "createdBy" | "updatedAt" | "version">,
  expectedVersion: number,
): Promise<void> {
  const payload = await encryptSharedEntry(plain, vaultKeyB64, expectedVersion);
  await authorizedRequest((token) => api.updateSharedVaultEntry(token, vaultId, entryId, payload));
}

/** Supprime DÉFINITIVEMENT une entrée (pas de corbeille pour les coffres partagés). */
export function deleteEntry(authorizedRequest: AuthorizedRequest, vaultId: string, entryId: string): Promise<void> {
  return authorizedRequest((token) => api.deleteSharedVaultEntry(token, vaultId, entryId));
}
