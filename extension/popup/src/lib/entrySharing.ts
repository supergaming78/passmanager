// Orchestration du partage sécurisé d'une entrée — équivalent de frontend(app)/src/lib/entrySharing.ts,
// recomposé à partir des fonctions WASM déjà exportées (seal_for_share/unseal_share, isolées
// cryptographiquement du scellement d'accès d'urgence — voir wasmCrypto.ts). Réutilise le même
// trousseau de clés que l'accès d'urgence (lib/emergencyAccess.ts::ensureEmergencyKeys).

import * as api from "../api/client";
import * as wasmCrypto from "./wasmCrypto";
import { ensureEmergencyKeys } from "./emergencyAccess";
import { normalizeEntryType, coerceExtraFields, type PlainVaultEntry, type EntryType } from "./vaultCrypto";
import type { AuthorizedRequest } from "./session";

interface ExportableEntry {
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
}

function toSealableContent(entry: PlainVaultEntry): ExportableEntry {
  const { siteName, username, loginEmail, password, preferredLoginType, isFavorite, folder, notes, url, entryType, extraFields } = entry;
  return { siteName, username, loginEmail, password, preferredLoginType, isFavorite, folder, notes, url, entryType, extraFields };
}

function str(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/** Ne fait JAMAIS confiance à la forme d'un blob venant d'un AUTRE utilisateur (voir le même
 * commentaire côté desktop) — chaque champ est coercé individuellement plutôt qu'un simple cast. */
function coerceSharedContent(parsed: unknown): ExportableEntry {
  const obj = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
  return {
    siteName: str(obj.siteName),
    username: str(obj.username),
    loginEmail: str(obj.loginEmail),
    password: str(obj.password),
    preferredLoginType: obj.preferredLoginType === "email" ? "email" : "username",
    isFavorite: obj.isFavorite === true,
    folder: str(obj.folder),
    notes: str(obj.notes),
    url: str(obj.url),
    entryType: normalizeEntryType(str(obj.entryType)),
    extraFields: coerceExtraFields(obj.extraFields),
  };
}

/** Partage une entrée déjà déchiffrée avec un autre utilisateur (par email) — nécessite que le
 * destinataire ait déjà son propre trousseau de clés publié (sinon `getPublicKey` échoue en 404,
 * remonté tel quel via getErrorMessage). */
export async function shareEntry(entry: PlainVaultEntry, recipientEmail: string, authorizedRequest: AuthorizedRequest): Promise<void> {
  const { public_key: publicKey } = await authorizedRequest((token) => api.getPublicKey(token, recipientEmail));
  const sealed_entry = await wasmCrypto.sealForShare(JSON.stringify(toSealableContent(entry)), publicKey);
  await authorizedRequest((token) => api.shareVaultEntry(token, entry.id, { shared_with_email: recipientEmail, sealed_entry }));
}

/** Re-partage avec tous les destinataires actuels après modification de l'entrée — sinon leur
 * copie scellée reste périmée. Best-effort : un échec par destinataire ne doit pas bloquer les autres. */
export async function reseedEntryShares(entry: PlainVaultEntry, authorizedRequest: AuthorizedRequest): Promise<void> {
  const shares = await authorizedRequest((token) => api.listVaultEntryShares(token, entry.id));
  await Promise.allSettled(shares.map((s) => shareEntry(entry, s.shared_with_email, authorizedRequest)));
}

export function listMyShares(vaultId: string, authorizedRequest: AuthorizedRequest) {
  return authorizedRequest((token) => api.listVaultEntryShares(token, vaultId));
}

export function listSharedWithMe(authorizedRequest: AuthorizedRequest) {
  return authorizedRequest((token) => api.listSharedWithMe(token));
}

export function revokeShare(shareId: string, authorizedRequest: AuthorizedRequest) {
  return authorizedRequest((token) => api.revokeShare(token, shareId));
}

/** Récupère et déchiffre une entrée partagée AVEC moi — lecture seule (id synthétique = shareId,
 * jamais renvoyée en PUT). Appelle ensureEmergencyKeys d'abord : c'est ce qui rend l'utilisateur
 * "partageable" en premier lieu, comme sur desktop. */
export async function openSharedEntry(vaultKey: Uint8Array, shareId: string, authorizedRequest: AuthorizedRequest): Promise<PlainVaultEntry> {
  await ensureEmergencyKeys(vaultKey, authorizedRequest);

  const [{ encrypted_private_key }, shared] = await Promise.all([
    authorizedRequest((token) => api.getOwnEmergencyKeys(token)),
    authorizedRequest((token) => api.getSharedEntry(token, shareId)),
  ]);

  const privateKeyB64 = await wasmCrypto.decryptField(vaultKey, encrypted_private_key);
  const plaintext = await wasmCrypto.unsealShare(shared.sealed_entry, privateKeyB64);

  let parsed: unknown;
  try {
    parsed = JSON.parse(plaintext);
  } catch {
    parsed = null;
  }
  const content = coerceSharedContent(parsed);

  return { id: shareId, ...content, updatedAt: "", version: 0, hasAttachments: false, useCount: 0 };
}
