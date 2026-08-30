// Orchestration de l'accès d'urgence — équivalent de frontend(app)/src/lib/emergencyAccess.ts,
// recomposé en TypeScript à partir des fonctions WASM déjà exportées (aucun nouveau code Rust/WASM
// nécessaire, voir le plan). Même trousseau de clés X25519 que le partage d'entrée (lib/entrySharing.ts) :
// ensureEmergencyKeys() est le point d'entrée commun aux deux fonctionnalités.

import * as api from "../api/client";
import * as wasmCrypto from "./wasmCrypto";
import { bytesToBase64, base64ToBytes } from "./base64";
import { decryptEntry, type PlainVaultEntry } from "./vaultCrypto";
import type { AuthorizedRequest } from "./session";
import type { EmergencyContact } from "../api/types";

async function hasEmergencyKeys(authorizedRequest: AuthorizedRequest): Promise<boolean> {
  try {
    await authorizedRequest((token) => api.getOwnEmergencyKeys(token));
    return true;
  } catch {
    return false; // 404 = pas encore configuré côté serveur
  }
}

/** Génère et publie le trousseau de clés de l'utilisateur s'il n'en a pas déjà un — préalable à
 * TOUTE opération d'accès d'urgence ou de partage (accepter un contact, partager une entrée...). */
export async function ensureEmergencyKeys(vaultKey: Uint8Array, authorizedRequest: AuthorizedRequest): Promise<void> {
  if (await hasEmergencyKeys(authorizedRequest)) return;

  const pair = await wasmCrypto.generateKeypair();
  const encryptedPrivateKey = await wasmCrypto.encryptField(vaultKey, pair.privateKey);
  await authorizedRequest((token) =>
    api.upsertEmergencyKeys(token, { public_key: pair.publicKey, encrypted_private_key: encryptedPrivateKey }),
  );
}

/** Scelle la vault_key du propriétaire pour UN contact (avec sa clé publique) — à refaire à chaque
 * fois que le contact est ajouté/accepté, et après tout événement qui changerait la clé de coffre
 * (hors périmètre ici, voir reseedAllContacts). */
export async function seedContactKey(
  vaultKey: Uint8Array,
  contactId: string,
  contactEmail: string,
  authorizedRequest: AuthorizedRequest,
): Promise<void> {
  const { public_key: publicKey } = await authorizedRequest((token) => api.getPublicKey(token, contactEmail));
  const sealed_vault_key = await wasmCrypto.seal(bytesToBase64(vaultKey), publicKey);
  await authorizedRequest((token) => api.seedEmergencyContact(token, contactId, { sealed_vault_key }));
}

/** Rescelle la vault_key pour tous les contacts déjà acceptés (`status !== "pending"`) — utile
 * après un changement d'email (qui ne change PAS la clé de coffre, contrairement à un changement de
 * mot de passe maître, hors périmètre de cette popup). Best-effort : un contact en échec ne doit
 * jamais bloquer les autres. */
export async function reseedAllContacts(vaultKey: Uint8Array, authorizedRequest: AuthorizedRequest): Promise<void> {
  const contacts = await authorizedRequest((token) => api.listEmergencyContactsAsOwner(token));
  await Promise.allSettled(
    contacts
      .filter((c) => c.status !== "pending")
      .map((c) => seedContactKey(vaultKey, c.id, c.contact_email, authorizedRequest)),
  );
}

/** Déverrouille la vault_key d'un propriétaire ayant accordé l'accès d'urgence — renvoie les
 * octets bruts, à garder en mémoire JS locale au composant qui affiche ce coffre (PAS dans
 * chrome.storage.session : accès occasionnel/lecture seule, pas besoin de survivre à une fermeture
 * de popup, contrairement à la vault_key principale — voir le plan). */
export async function unlockEmergencyVaultKey(
  myVaultKey: Uint8Array,
  sealedVaultKey: string,
  encryptedPrivateKey: string,
): Promise<Uint8Array> {
  const privateKeyB64 = await wasmCrypto.decryptField(myVaultKey, encryptedPrivateKey);
  const ownerKeyB64 = await wasmCrypto.unseal(sealedVaultKey, privateKeyB64);
  return base64ToBytes(ownerKeyB64);
}

/** Récupère et déchiffre en une fois toutes les entrées d'un coffre d'urgence accordé — combine
 * getOwnEmergencyKeys + getEmergencyVault + unlockEmergencyVaultKey + decryptEntry (lib/vaultCrypto.ts,
 * déjà générique sur la clé fournie). */
export async function openEmergencyVault(
  myVaultKey: Uint8Array,
  contactId: string,
  authorizedRequest: AuthorizedRequest,
): Promise<PlainVaultEntry[]> {
  const [{ encrypted_private_key }, vault] = await Promise.all([
    authorizedRequest((token) => api.getOwnEmergencyKeys(token)),
    authorizedRequest((token) => api.getEmergencyVault(token, contactId)),
  ]);
  const ownerKey = await unlockEmergencyVaultKey(myVaultKey, vault.sealed_vault_key, encrypted_private_key);
  return Promise.all(vault.entries.map((entry) => decryptEntry(entry, ownerKey)));
}

export type { EmergencyContact };
