// Orchestration des coffres partagés familiaux — équivalent de frontend(app)/src/lib/sharedVault.ts,
// recomposé à partir des fonctions WASM déjà exportées (generateSharedVaultKey/sealForSharedVault/
// unsealSharedVault, isolées cryptographiquement des deux autres usages du même trousseau — voir
// wasmCrypto.ts). Réutilise le même trousseau de clés X25519 que l'accès d'urgence/le partage
// d'entrée (lib/emergencyAccess.ts::ensureEmergencyKeys).
//
// Différence avec l'app desktop : pas d'état Tauri, la clé du coffre PERSONNEL (`vaultKey:
// Uint8Array`) et celle du coffre PARTAGÉ (`vaultKeyB64: string`, décodée à la volée) transitent
// toutes deux explicitement en paramètre à chaque appel — jamais persistées ailleurs qu'en état
// React le temps de l'écran ouvert (même principe que emergencyAccess.ts/entrySharing.ts).

import * as api from "../api/client";
import * as wasmCrypto from "./wasmCrypto";
import { ensureEmergencyKeys } from "./emergencyAccess";
import { normalizeEntryType, coerceExtraFields, type EntryType } from "./vaultCrypto";
import { base64ToBytes } from "./base64";
import type { AuthorizedRequest } from "./session";
import type { SharedVaultMemberView, SharedVaultEntryInput, SharedVaultEntry } from "../api/types";

/** Un coffre partagé DÉJÀ déverrouillé (clé symétrique déchiffrée) pour l'utilisateur courant —
 * `vaultKeyB64` ne doit JAMAIS être persisté (chrome.storage, disque...), uniquement gardé en état
 * React le temps de l'écran ouvert. */
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

/** Liste les coffres partagés dont l'utilisateur est membre, déjà déverrouillés — descelle la clé
 * de chacun avec sa propre clé privée (une seule résolution, réutilisée pour tous). Un coffre dont
 * le descellement échouerait est silencieusement omis plutôt que de faire échouer tout l'écran. */
export async function listMySharedVaults(vaultKey: Uint8Array, authorizedRequest: AuthorizedRequest): Promise<UnlockedSharedVault[]> {
  await ensureEmergencyKeys(vaultKey, authorizedRequest);
  const [views, ownKeys] = await Promise.all([
    authorizedRequest((token) => api.listSharedVaults(token)),
    authorizedRequest((token) => api.getOwnEmergencyKeys(token)),
  ]);

  const privateKeyB64 = await wasmCrypto.decryptField(vaultKey, ownKeys.encrypted_private_key);

  const unlocked = await Promise.allSettled(
    views.map(async (view) => {
      const vaultKeyB64 = await wasmCrypto.unsealSharedVault(view.sealed_vault_key, privateKeyB64);
      const name = await wasmCrypto.decryptField(base64ToBytes(vaultKeyB64), view.encrypted_name);
      return { id: view.id, name, vaultKeyB64, isOwner: view.is_owner, createdBy: view.created_by, createdAt: view.created_at };
    }),
  );

  return unlocked.filter((r): r is PromiseFulfilledResult<UnlockedSharedVault> => r.status === "fulfilled").map((r) => r.value);
}

/** Récupère UN coffre partagé précis, déverrouillé — pas d'endpoint dédié côté backend (voir
 * GET /shared-vaults, qui liste tout), refiltré côté client (même choix que côté desktop). */
export async function getUnlockedSharedVault(vaultKey: Uint8Array, vaultId: string, authorizedRequest: AuthorizedRequest): Promise<UnlockedSharedVault | undefined> {
  const all = await listMySharedVaults(vaultKey, authorizedRequest);
  return all.find((v) => v.id === vaultId);
}

/** Crée un nouveau coffre partagé — l'appelant en devient automatiquement propriétaire et premier
 * membre. */
export async function createSharedVault(vaultKey: Uint8Array, name: string, authorizedRequest: AuthorizedRequest): Promise<string> {
  await ensureEmergencyKeys(vaultKey, authorizedRequest);
  const ownKeys = await authorizedRequest((token) => api.getOwnEmergencyKeys(token));

  const sharedVaultKeyB64 = await wasmCrypto.generateSharedVaultKey();
  const encrypted_name = await wasmCrypto.encryptField(base64ToBytes(sharedVaultKeyB64), name);
  const sealed_vault_key = await wasmCrypto.sealForSharedVault(sharedVaultKeyB64, ownKeys.public_key);

  const { id } = await authorizedRequest((token) => api.createSharedVault(token, { encrypted_name, sealed_vault_key }));
  return id;
}

export function deleteSharedVault(vaultId: string, authorizedRequest: AuthorizedRequest): Promise<void> {
  return authorizedRequest((token) => api.deleteSharedVault(token, vaultId));
}

/** Invite un nouveau membre — réservé au propriétaire (vérifié côté serveur). Le futur membre doit
 * déjà avoir configuré ses propres clés — sinon la résolution de sa clé publique échoue en 404
 * (même limitation que le partage d'entrée 1-vers-1). */
export async function inviteMember(vaultId: string, vaultKeyB64: string, memberEmail: string, authorizedRequest: AuthorizedRequest): Promise<void> {
  const { public_key: publicKey } = await authorizedRequest((token) => api.getPublicKey(token, memberEmail));
  const sealed_vault_key = await wasmCrypto.sealForSharedVault(vaultKeyB64, publicKey);
  await authorizedRequest((token) => api.inviteSharedVaultMember(token, vaultId, { member_email: memberEmail, sealed_vault_key }));
}

export function listMembers(vaultId: string, authorizedRequest: AuthorizedRequest): Promise<SharedVaultMemberView[]> {
  return authorizedRequest((token) => api.listSharedVaultMembers(token, vaultId));
}

/** Retire un membre — même route pour "quitter soi-même" ou "le propriétaire retire quelqu'un
 * d'autre", l'autorisation est vérifiée côté serveur. */
export function removeMember(vaultId: string, memberEmail: string, authorizedRequest: AuthorizedRequest): Promise<void> {
  return authorizedRequest((token) => api.removeSharedVaultMember(token, vaultId, memberEmail));
}

async function encryptSharedEntry(
  plain: Omit<PlainSharedVaultEntry, "id" | "createdBy" | "updatedAt" | "version">,
  vaultKeyB64: string,
  expectedVersion?: number,
): Promise<SharedVaultEntryInput> {
  const keyBytes = base64ToBytes(vaultKeyB64);
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
    wasmCrypto.encryptField(keyBytes, plain.siteName),
    plain.username.trim() ? wasmCrypto.encryptField(keyBytes, plain.username) : Promise.resolve(null),
    plain.loginEmail.trim() ? wasmCrypto.encryptField(keyBytes, plain.loginEmail) : Promise.resolve(null),
    wasmCrypto.encryptField(keyBytes, plain.password),
    wasmCrypto.encryptField(keyBytes, plain.preferredLoginType),
    plain.notes.trim() ? wasmCrypto.encryptField(keyBytes, plain.notes) : Promise.resolve(null),
    plain.url.trim() ? wasmCrypto.encryptField(keyBytes, plain.url) : Promise.resolve(null),
    hasExtraFields ? wasmCrypto.encryptField(keyBytes, JSON.stringify(plain.extraFields)) : Promise.resolve(null),
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

async function decryptSharedEntry(entry: SharedVaultEntry, vaultKeyB64: string): Promise<PlainSharedVaultEntry> {
  const keyBytes = base64ToBytes(vaultKeyB64);
  const [siteName, username, loginEmail, password, preferredLoginType, notes, url, extraFieldsJson] = await Promise.all([
    wasmCrypto.decryptField(keyBytes, entry.encrypted_site_name),
    entry.encrypted_username ? wasmCrypto.decryptField(keyBytes, entry.encrypted_username) : Promise.resolve(""),
    entry.encrypted_login_email ? wasmCrypto.decryptField(keyBytes, entry.encrypted_login_email) : Promise.resolve(""),
    wasmCrypto.decryptField(keyBytes, entry.encrypted_password),
    wasmCrypto.decryptField(keyBytes, entry.encrypted_preferred_login_type),
    entry.encrypted_notes ? wasmCrypto.decryptField(keyBytes, entry.encrypted_notes) : Promise.resolve(""),
    entry.encrypted_url ? wasmCrypto.decryptField(keyBytes, entry.encrypted_url) : Promise.resolve(""),
    entry.encrypted_extra_fields ? wasmCrypto.decryptField(keyBytes, entry.encrypted_extra_fields) : Promise.resolve(""),
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
 * échouerait est omise plutôt que de faire échouer tout l'écran. */
export async function listEntries(vaultId: string, vaultKeyB64: string, authorizedRequest: AuthorizedRequest): Promise<PlainSharedVaultEntry[]> {
  const raw = await authorizedRequest((token) => api.listSharedVaultEntries(token, vaultId));
  const decrypted = await Promise.allSettled(raw.map((entry) => decryptSharedEntry(entry, vaultKeyB64)));
  return decrypted.filter((r): r is PromiseFulfilledResult<PlainSharedVaultEntry> => r.status === "fulfilled").map((r) => r.value);
}

export async function addEntry(
  vaultId: string,
  vaultKeyB64: string,
  plain: Omit<PlainSharedVaultEntry, "id" | "createdBy" | "updatedAt" | "version">,
  authorizedRequest: AuthorizedRequest,
): Promise<string> {
  const payload = await encryptSharedEntry(plain, vaultKeyB64);
  const { id } = await authorizedRequest((token) => api.addSharedVaultEntry(token, vaultId, payload));
  return id;
}

export async function updateEntry(
  vaultId: string,
  entryId: string,
  vaultKeyB64: string,
  plain: Omit<PlainSharedVaultEntry, "id" | "createdBy" | "updatedAt" | "version">,
  expectedVersion: number,
  authorizedRequest: AuthorizedRequest,
): Promise<void> {
  const payload = await encryptSharedEntry(plain, vaultKeyB64, expectedVersion);
  await authorizedRequest((token) => api.updateSharedVaultEntry(token, vaultId, entryId, payload));
}

export function deleteEntry(vaultId: string, entryId: string, authorizedRequest: AuthorizedRequest): Promise<void> {
  return authorizedRequest((token) => api.deleteSharedVaultEntry(token, vaultId, entryId));
}
