// Orchestration de l'accès d'urgence — combine les appels réseau (api/client.ts) et les commandes
// Tauri de chiffrement (api/tauri.ts, voir src-tauri/src/emergency.rs) pour les flux à plusieurs
// étapes, plutôt que de disperser cette logique dans les composants. Jamais de crypto en JS ici
// non plus : ce module ne fait qu'enchaîner des appels, comme lib/passwordChangeCrypto.ts.

import * as api from "../api/client";
import * as tauri from "../api/tauri";
import type { EmergencyContact } from "../api/types";
import { normalizeEntryType, parseExtraFields, type PlainVaultEntry } from "./vaultCrypto";

type AuthorizedRequest = <T,>(fn: (accessToken: string) => Promise<T>) => Promise<T>;

/** L'utilisateur a-t-il déjà configuré sa paire de clés d'accès d'urgence ? */
export async function hasEmergencyKeys(authorizedRequest: AuthorizedRequest): Promise<boolean> {
  try {
    await authorizedRequest((token) => api.getOwnEmergencyKeys(token));
    return true;
  } catch {
    return false;
  }
}

/** S'assure que l'utilisateur a une paire de clés configurée — la génère si besoin (première
 * utilisation de l'accès d'urgence). Sans effet si déjà configurée. Le coffre doit être
 * déverrouillé (la clé privée générée est chiffrée avec la clé du coffre actuelle). */
export async function ensureEmergencyKeys(authorizedRequest: AuthorizedRequest): Promise<void> {
  if (await hasEmergencyKeys(authorizedRequest)) return;
  const { public_key, encrypted_private_key } = await tauri.generateEmergencyKeypair();
  await authorizedRequest((token) => api.upsertEmergencyKeys(token, { public_key, encrypted_private_key }));
}

/** Scelle la clé de coffre ACTUELLE pour un contact précis (action du PROPRIÉTAIRE) — récupère sa
 * clé publique puis envoie le blob scellé au serveur. Peut être rappelée à tout moment pour
 * rafraîchir le blob (ex: après un changement de mot de passe maître, voir reseedAllContacts). */
export async function seedContactKey(authorizedRequest: AuthorizedRequest, contactId: string, contactEmail: string): Promise<void> {
  const { public_key } = await authorizedRequest((token) => api.getPublicKey(token, contactEmail));
  const sealed_vault_key = await tauri.sealVaultKeyForContact(public_key);
  await authorizedRequest((token) => api.seedEmergencyContact(token, contactId, { sealed_vault_key }));
}

/** Re-scelle la clé pour TOUS les contacts déjà acceptés — à appeler après un changement de mot
 * de passe maître (voir AuthContext.tsx), puisque la clé de coffre change et que chaque blob
 * scellé auparavant protège désormais l'ANCIENNE clé, devenue inutile. Best-effort par contact :
 * l'échec d'un seul ne doit jamais empêcher de re-sceller les autres, ni faire échouer le
 * changement de mot de passe lui-même. */
export async function reseedAllContacts(authorizedRequest: AuthorizedRequest): Promise<void> {
  let contacts: EmergencyContact[];
  try {
    contacts = await authorizedRequest((token) => api.listEmergencyContactsAsOwner(token));
  } catch {
    return; // pas de clés configurées, ou aucun contact — rien à re-sceller
  }
  const eligible = contacts.filter((c) => c.status !== "pending");
  await Promise.allSettled(eligible.map((c) => seedContactKey(authorizedRequest, c.id, c.contact_email)));
}

/** Ouvre la consultation d'urgence d'un coffre accordé (action du CONTACT) : récupère ses propres
 * clés, la vue du coffre distant (entrées + blob scellé), descelle la clé de coffre du
 * propriétaire côté Rust (voir tauri.unlockEmergencyVault — la clé ne quitte JAMAIS ce processus),
 * puis déchiffre chaque entrée. Renvoie les entrées déjà en clair, prêtes à afficher — voir
 * lockEmergencyVault() pour refermer proprement en quittant l'écran. */
export async function openEmergencyVault(authorizedRequest: AuthorizedRequest, contactId: string): Promise<PlainVaultEntry[]> {
  const [ownKeys, view] = await Promise.all([
    authorizedRequest((token) => api.getOwnEmergencyKeys(token)),
    authorizedRequest((token) => api.getEmergencyVault(token, contactId)),
  ]);

  await tauri.unlockEmergencyVault(view.sealed_vault_key, ownKeys.encrypted_private_key);

  return Promise.all(
    view.entries.map(async (entry): Promise<PlainVaultEntry> => {
      const [siteName, username, loginEmail, password, preferredLoginType, folder, notes, url, extraFieldsJson] = await Promise.all([
        tauri.decryptEmergencyField(entry.encrypted_site_name),
        entry.encrypted_username ? tauri.decryptEmergencyField(entry.encrypted_username) : Promise.resolve(""),
        entry.encrypted_login_email ? tauri.decryptEmergencyField(entry.encrypted_login_email) : Promise.resolve(""),
        tauri.decryptEmergencyField(entry.encrypted_password),
        tauri.decryptEmergencyField(entry.encrypted_preferred_login_type),
        entry.encrypted_folder ? tauri.decryptEmergencyField(entry.encrypted_folder) : Promise.resolve(""),
        entry.encrypted_notes ? tauri.decryptEmergencyField(entry.encrypted_notes) : Promise.resolve(""),
        entry.encrypted_url ? tauri.decryptEmergencyField(entry.encrypted_url) : Promise.resolve(""),
        entry.encrypted_extra_fields ? tauri.decryptEmergencyField(entry.encrypted_extra_fields) : Promise.resolve(""),
      ]);
      return {
        id: entry.id,
        siteName,
        username,
        loginEmail,
        password,
        preferredLoginType: preferredLoginType === "email" ? "email" : "username",
        entryType: normalizeEntryType(entry.entry_type),
        extraFields: parseExtraFields(extraFieldsJson),
        isFavorite: entry.is_favorite,
        folder,
        notes,
        url,
        updatedAt: entry.updated_at,
        version: entry.version,
        hasAttachments: entry.has_attachments,
      };
    }),
  );
}

/** Referme la consultation d'urgence en cours — à appeler en quittant l'écran (voir
 * tauri.lockEmergencyVault, efface la clé recopiée en mémoire côté Rust). */
export function closeEmergencyVault(): Promise<void> {
  return tauri.lockEmergencyVault();
}
