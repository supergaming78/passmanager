// Construit/reconstruit la liste à plat de blobs chiffrés envoyée à prepare_password_change()
// (voir api/tauri.ts) — la commande Rust re-chiffre une liste plate de chaînes, sans connaître la
// notion d'"entrée" ; c'est ici qu'on fait le mapping entre les deux, en gérant proprement les
// champs optionnels (username/login_email/folder/notes/url) qui ne doivent JAMAIS être envoyés au
// re-chiffrement s'ils étaient déjà `null` (pas de raison de créer un blob chiffré pour un champ
// absent).
//
// L'HISTORIQUE de mots de passe (voir lib/vaultCrypto.ts et le tableau de bord de dossier) doit
// LUI AUSSI être re-chiffré à chaque changement de mot de passe maître — sinon ces anciennes
// versions deviendraient définitivement indéchiffrables avec la nouvelle clé. Il est ajouté à la
// MÊME liste plate que les entrées du coffre plutôt que re-chiffré via un second appel à
// prepare_password_change() : la dérivation Argon2id (ancienne ET nouvelle clé) qu'il déclenche
// est délibérément lente, un second appel doublerait inutilement l'attente pour l'utilisateur.
//
// Les PIÈCES JOINTES CHIFFRÉES (voir lib/vaultAttachments.ts) suivent exactement le même principe
// — ajoutées à la MÊME liste plate, pour la MÊME raison (un seul déclenchement Argon2id). Un oubli
// ici les laisserait indéfiniment chiffrées avec l'ANCIENNE clé après un changement de mot de
// passe maître (bug corrigé — voir AuthContext.tsx::changeMasterPassword).

import type {
  PasswordHistoryEntry,
  ReencryptedHistoryEntry,
  ReencryptedVaultAttachment,
  ReencryptedVaultEntry,
  VaultAttachment,
  VaultEntry,
} from "../api/types";

interface EntryPlan {
  id: string;
  siteNameIdx: number;
  usernameIdx: number | null;
  loginEmailIdx: number | null;
  passwordIdx: number;
  preferredLoginTypeIdx: number;
  folderIdx: number | null;
  notesIdx: number | null;
  urlIdx: number | null;
  extraFieldsIdx: number | null;
}

interface HistoryPlan {
  id: string;
  passwordIdx: number;
}

interface AttachmentPlan {
  id: string;
  filenameIdx: number;
  contentIdx: number;
}

/** Construit la liste plate de ciphertexts à re-chiffrer (entrées du coffre, PUIS historique, PUIS
 * pièces jointes), et les plans pour reconstruire les trois ensuite (voir rebuildEntries()/
 * rebuildHistory()/rebuildAttachments()). */
export function flattenForReencryption(
  entries: VaultEntry[],
  history: PasswordHistoryEntry[] = [],
  attachments: VaultAttachment[] = [],
): { ciphertexts: string[]; plans: EntryPlan[]; historyPlans: HistoryPlan[]; attachmentPlans: AttachmentPlan[] } {
  const ciphertexts: string[] = [];
  const plans: EntryPlan[] = [];

  for (const entry of entries) {
    const siteNameIdx = ciphertexts.push(entry.encrypted_site_name) - 1;

    let usernameIdx: number | null = null;
    if (entry.encrypted_username) {
      usernameIdx = ciphertexts.push(entry.encrypted_username) - 1;
    }

    let loginEmailIdx: number | null = null;
    if (entry.encrypted_login_email) {
      loginEmailIdx = ciphertexts.push(entry.encrypted_login_email) - 1;
    }

    const passwordIdx = ciphertexts.push(entry.encrypted_password) - 1;
    const preferredLoginTypeIdx = ciphertexts.push(entry.encrypted_preferred_login_type) - 1;

    let folderIdx: number | null = null;
    if (entry.encrypted_folder) {
      folderIdx = ciphertexts.push(entry.encrypted_folder) - 1;
    }

    let notesIdx: number | null = null;
    if (entry.encrypted_notes) {
      notesIdx = ciphertexts.push(entry.encrypted_notes) - 1;
    }

    let urlIdx: number | null = null;
    if (entry.encrypted_url) {
      urlIdx = ciphertexts.push(entry.encrypted_url) - 1;
    }

    // Champs additionnels des types dédiés (carte/identité) — voir lib/vaultCrypto.ts::EntryType.
    // Sans ça, ce blob resterait chiffré avec l'ANCIENNE clé après un changement de mot de passe
    // maître, indéfiniment indéchiffrable (même bug que celui déjà corrigé pour les pièces jointes,
    // voir le commentaire en tête de fichier).
    let extraFieldsIdx: number | null = null;
    if (entry.encrypted_extra_fields) {
      extraFieldsIdx = ciphertexts.push(entry.encrypted_extra_fields) - 1;
    }

    plans.push({ id: entry.id, siteNameIdx, usernameIdx, loginEmailIdx, passwordIdx, preferredLoginTypeIdx, folderIdx, notesIdx, urlIdx, extraFieldsIdx });
  }

  const historyPlans: HistoryPlan[] = [];
  for (const row of history) {
    const passwordIdx = ciphertexts.push(row.encrypted_password) - 1;
    historyPlans.push({ id: row.id, passwordIdx });
  }

  const attachmentPlans: AttachmentPlan[] = [];
  for (const attachment of attachments) {
    const filenameIdx = ciphertexts.push(attachment.encrypted_filename) - 1;
    const contentIdx = ciphertexts.push(attachment.encrypted_content) - 1;
    attachmentPlans.push({ id: attachment.id, filenameIdx, contentIdx });
  }

  return { ciphertexts, plans, historyPlans, attachmentPlans };
}

// CORRECTIF (robustesse) : indexer reencrypted[] directement (reencrypted[i]) renvoie silencieusement
// `undefined` en TypeScript si i est hors bornes — sans ce garde-fou, un décalage entre la liste
// envoyée à prepare_password_change() et celle reçue en retour (skew de version, bug futur de
// refactoring côté Rust, réponse malformée) produirait un ReencryptedVaultEntry/Attachment avec un
// champ `encrypted_password`/`encrypted_content` valant `undefined`, envoyé tel quel au serveur —
// un mot de passe/pièce jointe SILENCIEUSEMENT corrompu, découvert seulement plus tard au moment
// de le déchiffrer. Échouer bruyamment ici, tout de suite, est nettement préférable.
function at(reencrypted: string[], index: number): string {
  const value = reencrypted[index];
  if (value === undefined) {
    throw new Error(`Re-chiffrement incohérent : index ${index} absent de la réponse (${reencrypted.length} élément(s) reçu(s)).`);
  }
  return value;
}

/** Reconstruit les entrées re-chiffrées à partir du plan et de la liste plate renvoyée par
 * prepare_password_change() (voir api/tauri.ts::PasswordChangeResult.reencrypted_ciphertexts) —
 * MÊME ORDRE que celui construit par flattenForReencryption(), donc les index restent valides. */
export function rebuildEntries(plans: EntryPlan[], reencrypted: string[]): ReencryptedVaultEntry[] {
  return plans.map((plan) => ({
    id: plan.id,
    encrypted_site_name: at(reencrypted, plan.siteNameIdx),
    encrypted_username: plan.usernameIdx !== null ? at(reencrypted, plan.usernameIdx) : null,
    encrypted_login_email: plan.loginEmailIdx !== null ? at(reencrypted, plan.loginEmailIdx) : null,
    encrypted_password: at(reencrypted, plan.passwordIdx),
    encrypted_preferred_login_type: at(reencrypted, plan.preferredLoginTypeIdx),
    encrypted_folder: plan.folderIdx !== null ? at(reencrypted, plan.folderIdx) : null,
    encrypted_notes: plan.notesIdx !== null ? at(reencrypted, plan.notesIdx) : null,
    encrypted_url: plan.urlIdx !== null ? at(reencrypted, plan.urlIdx) : null,
    encrypted_extra_fields: plan.extraFieldsIdx !== null ? at(reencrypted, plan.extraFieldsIdx) : null,
  }));
}

/** Pendant de rebuildEntries(), pour l'historique de mots de passe. */
export function rebuildHistory(historyPlans: HistoryPlan[], reencrypted: string[]): ReencryptedHistoryEntry[] {
  return historyPlans.map((plan) => ({
    id: plan.id,
    encrypted_password: at(reencrypted, plan.passwordIdx),
  }));
}

/** Pendant de rebuildEntries()/rebuildHistory(), pour les pièces jointes chiffrées. */
export function rebuildAttachments(attachmentPlans: AttachmentPlan[], reencrypted: string[]): ReencryptedVaultAttachment[] {
  return attachmentPlans.map((plan) => ({
    id: plan.id,
    encrypted_filename: at(reencrypted, plan.filenameIdx),
    encrypted_content: at(reencrypted, plan.contentIdx),
  }));
}
