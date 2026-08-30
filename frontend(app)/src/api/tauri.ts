// Pont typé vers les commandes Tauri définies en Rust (voir src-tauri/src/lib.rs). Toute la
// cryptographie sensible (dérivation de clé, chiffrement/déchiffrement du coffre) vit côté Rust —
// ce module ne fait qu'appeler invoke(), jamais de logique crypto en JS.

import { invoke } from "@tauri-apps/api/core";

/**
 * Dérive les clés à partir de (email, mot de passe maître) et déverrouille le coffre côté Rust.
 * Renvoie UNIQUEMENT le hash d'authentification à envoyer au backend — la clé de chiffrement du
 * coffre ne quitte jamais le processus Rust (voir src-tauri/src/crypto.rs).
 */
export function deriveKeys(email: string, masterPassword: string): Promise<string> {
  return invoke<string>("derive_keys", { email, masterPassword });
}

/**
 * Calcule le hash d'authentification SANS déverrouiller/toucher au coffre en mémoire —
 * contrairement à deriveKeys() ci-dessus. À utiliser pour toute re-confirmation du mot de passe
 * maître pendant que le coffre est déjà déverrouillé avec la BONNE clé (changement d'email,
 * changement du plafond d'appareils, ancien mot de passe avant un changement de mot de passe) :
 * une faute de frappe dans ce champ ne doit jamais écraser la clé du coffre en mémoire par une
 * clé dérivée d'un mot de passe erroné avant même que le serveur n'ait rejeté le hash.
 */
export function computeAuthHash(email: string, masterPassword: string): Promise<string> {
  return invoke<string>("compute_auth_hash", { email, masterPassword });
}

/** Efface la clé du coffre de la mémoire Rust (déconnexion, verrouillage). */
export function lockVault(): Promise<void> {
  return invoke<void>("lock_vault");
}

/** Le coffre est-il déverrouillé (une clé est-elle actuellement en mémoire côté Rust) ? */
export function isVaultUnlocked(): Promise<boolean> {
  return invoke<boolean>("is_vault_unlocked");
}

/** Chiffre un champ en clair avec la clé actuellement en mémoire. Rejette si le coffre est verrouillé. */
export function encryptField(plaintext: string): Promise<string> {
  return invoke<string>("encrypt_vault_field", { plaintext });
}

/** Déchiffre un champ avec la clé actuellement en mémoire. Rejette si le coffre est verrouillé. */
export function decryptField(ciphertext: string): Promise<string> {
  return invoke<string>("decrypt_vault_field", { ciphertext });
}

export interface PasswordChangeResult {
  old_auth_hash: string;
  new_auth_hash: string;
  reencrypted_ciphertexts: string[];
}

/**
 * Prépare un changement de mot de passe maître : dérive l'ancien ET le nouveau jeu de clés, et
 * re-chiffre chaque blob de `ciphertexts` (déchiffré avec l'ancienne clé, rechiffré avec la
 * nouvelle) — DANS LE MÊME ORDRE en sortie. N'affecte PAS le coffre actuellement déverrouillé :
 * voir lib/passwordChangeCrypto.ts pour la reconstruction des entrées, et rappeler deriveKeys()
 * avec le nouveau mot de passe après confirmation du serveur pour déverrouiller avec la nouvelle
 * clé (voir la doc de la commande côté Rust, src-tauri/src/lib.rs).
 */
export function preparePasswordChange(
  email: string,
  oldPassword: string,
  newPassword: string,
  ciphertexts: string[],
): Promise<PasswordChangeResult> {
  return invoke<PasswordChangeResult>("prepare_password_change", { email, oldPassword, newPassword, ciphertexts });
}

/** Chiffre le contenu d'un fichier d'export avec un mot de passe SÉPARÉ du mot de passe maître —
 * voir lib/vaultFile.ts. Indépendant du coffre déverrouillé actuel. */
export function encryptExportContent(plaintext: string, password: string): Promise<string> {
  return invoke<string>("encrypt_export_content", { plaintext, password });
}

/** Déchiffre un fichier produit par encryptExportContent(). Rejette si le mot de passe est
 * incorrect ou si le contenu n'est pas un export chiffré reconnu. */
export function decryptExportContent(content: string, password: string): Promise<string> {
  return invoke<string>("decrypt_export_content", { content, password });
}

/** SHA-1 hexadécimal MAJUSCULE d'un texte — UNIQUEMENT pour la vérification de mots de passe
 * compromis (voir lib/breachCheck.ts), format imposé par l'API "Pwned Passwords" de
 * HaveIBeenPwned. Sans rapport avec le chiffrement du coffre. */
export function sha1Hex(plaintext: string): Promise<string> {
  return invoke<string>("sha1_hex", { plaintext });
}

// --- Déverrouillage rapide (Windows Hello) — voir src-tauri/src/quick_unlock.rs. Windows
// uniquement : ces commandes échouent explicitement ("indisponible") sur les autres plateformes
// plutôt que d'être absentes, pour garder un seul chemin d'appel côté frontend (voir
// isQuickUnlockAvailable(), à vérifier avant d'afficher le moindre bouton correspondant).

/** Le déverrouillage rapide est-il configuré sur cet appareil ? `false` inconditionnellement hors
 * Windows — sert à savoir s'il faut afficher le bouton correspondant. */
export function isQuickUnlockAvailable(): Promise<boolean> {
  return invoke<boolean>("is_quick_unlock_available");
}

/** Active le déverrouillage rapide : protège la clé ACTUELLEMENT en mémoire (le coffre doit déjà
 * être déverrouillé) et l'écrit sur disque, liée au compte Windows de la session en cours. */
export function enableQuickUnlock(): Promise<void> {
  return invoke<void>("enable_quick_unlock");
}

/** Désactive le déverrouillage rapide (supprime le fichier local). Best-effort côté appelant :
 * ne doit jamais faire échouer une déconnexion/un changement de mot de passe. */
export function disableQuickUnlock(): Promise<void> {
  return invoke<void>("disable_quick_unlock");
}

/** Demande une vérification Windows Hello (empreinte/visage/code PIN) puis, si elle réussit,
 * recharge la clé du coffre en mémoire SANS repasser par le mot de passe maître. */
export function tryQuickUnlock(): Promise<void> {
  return invoke<void>("try_quick_unlock");
}

// --- Accès d'urgence — voir src-tauri/src/emergency.rs et lib/emergencyAccess.ts pour
// l'orchestration côté client. Comme le reste de cette app, TOUTE la cryptographie (génération de
// clés, scellement, descellement) vit ici, jamais en JS.

export interface EmergencyKeypairResult {
  public_key: string;
  encrypted_private_key: string;
}

/** Génère la paire de clés X25519 de l'utilisateur (une fois, à la première configuration de
 * l'accès d'urgence) — la clé privée est immédiatement chiffrée avec la clé du coffre
 * actuellement déverrouillée avant d'être renvoyée. */
export function generateEmergencyKeypair(): Promise<EmergencyKeypairResult> {
  return invoke<EmergencyKeypairResult>("generate_emergency_keypair");
}

/** Chiffre la clé du coffre ACTUELLEMENT déverrouillée pour un contact de confiance, à partir de
 * sa clé publique — le blob renvoyé est à envoyer au serveur via api/client.ts::seedEmergencyContact. */
export function sealVaultKeyForContact(recipientPublicKey: string): Promise<string> {
  return invoke<string>("seal_vault_key_for_contact", { recipientPublicKey });
}

/** Déverrouille l'accès d'urgence à un AUTRE coffre (celui d'un propriétaire qui a accordé
 * l'accès) — recharge sa clé dans un emplacement SÉPARÉ du coffre local (voir
 * decryptEmergencyField/lockEmergencyVault ci-dessous), jamais dans le coffre déverrouillé
 * localement. */
export function unlockEmergencyVault(sealedVaultKey: string, encryptedPrivateKey: string): Promise<void> {
  return invoke<void>("unlock_emergency_vault", { sealedVaultKey, encryptedPrivateKey });
}

/** Referme l'accès d'urgence en cours — à appeler en quittant l'écran de consultation. */
export function lockEmergencyVault(): Promise<void> {
  return invoke<void>("lock_emergency_vault");
}

export function isEmergencyVaultUnlocked(): Promise<boolean> {
  return invoke<boolean>("is_emergency_vault_unlocked");
}

/** Déchiffre un champ du coffre D'URGENCE actuellement ouvert — PAS de fonction "encrypt"
 * symétrique, la consultation d'urgence est intentionnellement en lecture seule. */
export function decryptEmergencyField(ciphertext: string): Promise<string> {
  return invoke<string>("decrypt_emergency_field", { ciphertext });
}

// --- Partage sécurisé d'une entrée — voir src-tauri/src/sharing.rs et lib/entrySharing.ts.
// Réutilise le MÊME trousseau de clés X25519 par utilisateur que l'accès d'urgence ci-dessus
// (généré/déverrouillé via les mêmes commandes), mais avec un contexte de dérivation différent
// côté Rust — les deux usages restent cryptographiquement étanches l'un de l'autre.

/** Chiffre `plaintext` (le JSON d'une entrée en clair) pour le détenteur de `recipientPublicKey`.
 * Ne touche à aucun état — l'appelant fournit déjà le texte en clair (l'entrée est nécessairement
 * déjà déchiffrée pour être affichée avant de la partager). */
export function sealEntryForRecipient(plaintext: string, recipientPublicKey: string): Promise<string> {
  return invoke<string>("seal_entry_for_recipient", { plaintext, recipientPublicKey });
}

/** Déchiffre un blob de partage reçu — déchiffre D'ABORD sa propre clé privée (avec SA clé de
 * coffre LOCALE, déjà déverrouillée), puis descelle le contenu de l'entrée partagée, renvoyé
 * directement en clair (JSON à parser côté appelant, voir lib/entrySharing.ts). */
export function unsealSharedEntry(sealedEntry: string, encryptedPrivateKey: string): Promise<string> {
  return invoke<string>("unseal_shared_entry", { sealedEntry, encryptedPrivateKey });
}

// --- Coffres partagés familiaux — voir src-tauri/src/shared_vault.rs et lib/sharedVault.ts.
// Contexte de dérivation ENCORE différent du partage d'entrée ci-dessus, même trousseau X25519
// par utilisateur. Différence structurelle : la clé du coffre partagé est SYMÉTRIQUE et partagée
// par tous ses membres — d'où encrypt/decryptSharedVaultField ci-dessous, qui prennent la clé en
// PARAMÈTRE plutôt que de lire l'état du coffre PERSONNEL déverrouillé.

/** Génère une nouvelle clé symétrique pour un coffre partagé — appelée UNE SEULE FOIS, à sa création. */
export function generateSharedVaultKey(): Promise<string> {
  return invoke<string>("generate_shared_vault_key");
}

/** Scelle la clé (déjà en clair côté appelant) d'un coffre partagé pour la clé publique d'un membre. */
export function sealSharedVaultKey(vaultKeyB64: string, recipientPublicKey: string): Promise<string> {
  return invoke<string>("seal_shared_vault_key", { vaultKeyB64, recipientPublicKey });
}

/** Déchiffre la clé scellée d'un coffre partagé reçue (voir SharedVaultView::sealed_vault_key) —
 * déchiffre d'abord sa propre clé privée (coffre PERSONNEL local, déjà déverrouillé), puis
 * descelle la clé du coffre partagé, renvoyée en clair. */
export function unsealSharedVaultKey(sealedVaultKey: string, encryptedPrivateKey: string): Promise<string> {
  return invoke<string>("unseal_shared_vault_key", { sealedVaultKey, encryptedPrivateKey });
}

/** Chiffre un champ d'entrée de coffre partagé avec SA clé symétrique (fournie en paramètre). */
export function encryptSharedVaultField(plaintext: string, vaultKeyB64: string): Promise<string> {
  return invoke<string>("encrypt_shared_vault_field", { plaintext, vaultKeyB64 });
}

/** Déchiffre un champ d'entrée de coffre partagé avec SA clé symétrique. */
export function decryptSharedVaultField(ciphertext: string, vaultKeyB64: string): Promise<string> {
  return invoke<string>("decrypt_shared_vault_field", { ciphertext, vaultKeyB64 });
}

// --- Partage à usage limité ("aveugle") — voir src-tauri/src/lib.rs et lib/blindShare.ts. Le
// destinataire ne voit jamais l'identifiant ni le mot de passe dans l'UI : c'est la responsabilité
// de lib/blindShare.ts de ne jamais renvoyer la valeur descellée par unsealBlindShare ci-dessous
// au-delà de l'action de remplissage/copie immédiate, ces deux commandes ne font que sceller/
// desceller comme pour le partage classique.

/** Scelle `plaintext` (le nom du site, ou le JSON des identifiants) pour la clé publique d'un
 * destinataire. */
export function sealForBlindShare(plaintext: string, recipientPublicKey: string): Promise<string> {
  return invoke<string>("seal_for_blind_share", { plaintext, recipientPublicKey });
}

/** Déchiffre un blob de partage à usage limité reçu — déchiffre d'abord sa propre clé privée
 * (coffre PERSONNEL local, déjà déverrouillé), puis descelle le contenu. */
export function unsealBlindShare(sealedB64: string, encryptedPrivateKey: string): Promise<string> {
  return invoke<string>("unseal_blind_share", { sealedB64, encryptedPrivateKey });
}
