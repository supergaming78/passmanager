// Orchestration du partage sécurisé d'une entrée — combine les appels réseau (api/client.ts) et
// les commandes Tauri de chiffrement (api/tauri.ts, voir src-tauri/src/sharing.rs) pour les flux à
// plusieurs étapes, même principe que lib/emergencyAccess.ts (dont ce module réutilise d'ailleurs
// ensureEmergencyKeys/hasEmergencyKeys : UN SEUL trousseau de clés X25519 par utilisateur pour les
// deux fonctionnalités, voir le commentaire de src-tauri/src/sharing.rs). Jamais de crypto en JS
// ici non plus : ce module ne fait qu'enchaîner des appels.
//
// Contrairement à l'accès d'urgence (qui scelle une CLÉ DE COFFRE, qui sert ensuite à déchiffrer
// séparément chaque champ de chaque entrée), le partage d'entrée scelle directement le JSON des
// champs en clair d'UNE SEULE entrée — un seul appel de scellement/descellement suffit, pas de
// clé intermédiaire à faire transiter.

import * as api from "../api/client";
import * as tauri from "../api/tauri";
import { ensureEmergencyKeys } from "./emergencyAccess";
import type { SharedWithMeEntry, VaultShare } from "../api/types";
import { coerceExtraFields, normalizeEntryType, type PlainVaultEntry } from "./vaultCrypto";
import { asBool, asStr, type ExportableEntry } from "./vaultFile";

type AuthorizedRequest = <T,>(fn: (accessToken: string) => Promise<T>) => Promise<T>;

/** Les champs en clair d'une entrée à sceller — jamais `id`/`updatedAt` (métadonnées serveur, sans
 * rapport avec le contenu partagé), même principe que l'export de fichier (voir vaultFile.ts). */
function toSealableContent(entry: PlainVaultEntry): ExportableEntry {
  return {
    siteName: entry.siteName,
    username: entry.username,
    loginEmail: entry.loginEmail,
    password: entry.password,
    preferredLoginType: entry.preferredLoginType,
    isFavorite: entry.isFavorite,
    folder: entry.folder,
    notes: entry.notes,
    url: entry.url,
    entryType: entry.entryType,
    extraFields: entry.extraFields,
  };
}

/** Partage (ou re-partage, après une modification de l'entrée — voir reseedEntryShares) une entrée
 * déjà déchiffrée avec un autre utilisateur — action du PROPRIÉTAIRE. Résout la clé publique du
 * destinataire (réutilise GET /emergency/keys/{email}, générique), scelle le contenu côté Rust,
 * envoie le blob. Le destinataire doit déjà avoir configuré ses propres clés (voir
 * ensureEmergencyKeys) — sinon la résolution de sa clé publique échoue en 404 : aucun utilisateur
 * ne peut recevoir un partage avant d'avoir lui-même visité au moins une fois ses réglages. */
export async function shareEntry(authorizedRequest: AuthorizedRequest, entry: PlainVaultEntry, recipientEmail: string): Promise<void> {
  const { public_key } = await authorizedRequest((token) => api.getPublicKey(token, recipientEmail));
  const sealed_entry = await tauri.sealEntryForRecipient(JSON.stringify(toSealableContent(entry)), public_key);
  await authorizedRequest((token) => api.shareVaultEntry(token, entry.id, { shared_with_email: recipientEmail, sealed_entry }));
}

/** Les partages actifs d'UNE entrée, vus par son PROPRIÉTAIRE — pour l'écran de gestion. */
export function listMyShares(authorizedRequest: AuthorizedRequest, vaultId: string): Promise<VaultShare[]> {
  return authorizedRequest((token) => api.listVaultEntryShares(token, vaultId));
}

/** Tout ce qui a été partagé AVEC l'utilisateur connecté. */
export function listSharedWithMe(authorizedRequest: AuthorizedRequest): Promise<SharedWithMeEntry[]> {
  return authorizedRequest((token) => api.listSharedWithMe(token));
}

/** Révoque un partage (le propriétaire retire l'accès) ou le quitte (le destinataire s'en retire)
 * — même route des deux côtés, l'autorisation est vérifiée côté serveur. */
export function revokeShare(authorizedRequest: AuthorizedRequest, shareId: string): Promise<void> {
  return authorizedRequest((token) => api.revokeShare(token, shareId));
}

/** Re-scelle une entrée pour TOUS ses destinataires actuels — à appeler après une modification de
 * l'entrée elle-même (voir Vault.tsx, où l'entrée est enregistrée), puisque le contenu scellé est
 * désormais périmé (contrairement à un changement de mot de passe MAÎTRE, qui ne touche PAS ce
 * scellement — voir le commentaire en tête de fichier). Best-effort : l'échec d'un seul
 * destinataire ne doit jamais empêcher les autres, ni faire échouer l'enregistrement de l'entrée
 * lui-même. Si l'entrée n'a aucun partage actif (cas courant), ne fait rien de plus qu'un aller-
 * retour réseau vide. */
export async function reseedEntryShares(authorizedRequest: AuthorizedRequest, entry: PlainVaultEntry): Promise<void> {
  let shares: VaultShare[];
  try {
    shares = await listMyShares(authorizedRequest, entry.id);
  } catch {
    return;
  }
  await Promise.allSettled(shares.map((share) => shareEntry(authorizedRequest, entry, share.shared_with_email)));
}

/** Valide/coerce le JSON descellé d'un partage reçu en un ExportableEntry propre — CORRECTIF
 * SÉCURITÉ/ROBUSTESSE : ce JSON vient d'un AUTRE utilisateur (le propriétaire qui a partagé), qui
 * pourrait envoyer des types inattendus (volontairement ou par bug de son propre client) ; un
 * simple `as ExportableEntry` (cast, jamais vérifié à l'exécution) laissait passer n'importe quoi
 * tel quel jusqu'au rendu React. Réutilise les mêmes coercitions tolérantes que l'import de fichier
 * (voir vaultFile.ts::buildEntryFromRecord) plutôt que de faire confiance à la forme du JSON. */
function coerceSharedContent(raw: unknown): ExportableEntry {
  const record = typeof raw === "object" && raw !== null ? (raw as Record<string, unknown>) : {};
  const preferredLoginType = record.preferredLoginType === "email" ? "email" : "username";
  return {
    siteName: asStr(record.siteName),
    username: asStr(record.username),
    loginEmail: asStr(record.loginEmail),
    password: asStr(record.password),
    preferredLoginType,
    isFavorite: asBool(record.isFavorite),
    folder: asStr(record.folder),
    notes: asStr(record.notes),
    url: asStr(record.url),
    entryType: normalizeEntryType(asStr(record.entryType)),
    extraFields: coerceExtraFields(record.extraFields),
  };
}

/** Ouvre un partage reçu (action du DESTINATAIRE) : récupère ses propres clés et le blob scellé,
 * descelle côté Rust, puis parse le JSON obtenu — une seule opération, contrairement à
 * openEmergencyVault() qui déchiffre séparément chaque champ de chaque entrée (voir le commentaire
 * en tête de fichier). `id`/`updatedAt` sont reconstitués à partir du partage lui-même (l'entrée
 * partagée est une COPIE en lecture seule, elle n'a pas de "dernière modification" ni d'id de
 * coffre qui aurait un sens côté destinataire). */
export async function openSharedEntry(authorizedRequest: AuthorizedRequest, shareId: string): Promise<PlainVaultEntry> {
  await ensureEmergencyKeys(authorizedRequest);
  const [ownKeys, view] = await Promise.all([
    authorizedRequest((token) => api.getOwnEmergencyKeys(token)),
    authorizedRequest((token) => api.getSharedEntry(token, shareId)),
  ]);

  const plaintext = await tauri.unsealSharedEntry(view.sealed_entry, ownKeys.encrypted_private_key);
  const content = coerceSharedContent(JSON.parse(plaintext));

  // `version: 0`/`hasAttachments: false` factices : une entrée partagée est une COPIE scellée en
  // lecture seule (pièces jointes explicitement hors périmètre du partage, voir
  // toSealableContent() plus haut), jamais réenregistrée via PUT /vault/{id} — la détection de
  // conflit d'édition et le filtre "avec pièce jointe" n'ont donc aucun sens ici, ces deux champs
  // ne sont simplement jamais lus pour ce type d'entrée.
  return { id: shareId, updatedAt: "", version: 0, hasAttachments: false, ...content };
}
