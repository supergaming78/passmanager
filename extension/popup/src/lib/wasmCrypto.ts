// Pont vers le module WASM (voir extension/wasm-bindings, construit depuis crypto-core — la MÊME
// crate que src-tauri/, voir crypto-core/src/crypto.rs::test_known_vector_matches_wasm_build pour
// la preuve d'équivalence cryptographique entre les deux cibles de compilation). Contrairement à
// l'app desktop (src-tauri/, où la clé du coffre ne quitte jamais la mémoire Rust), les fonctions
// exposées ici sont STATELESS : la vault_key transite en clair par le JS et doit être fournie à
// chaque appel — voir lib/session.ts pour comment sa durée de vie est bornée dans le temps.
//
// Build utilisé : pkg-web (--target web), PAS pkg-nodejs (--target nodejs, réservé au script de
// test extension/wasm-bindings/test-node.js — inutilisable ici, il s'appuie sur require()/fs/
// __dirname, absents dans une popup de navigateur).

import init, {
  derive_keys,
  encrypt_field,
  decrypt_field,
  sha1_hex,
  generate_keypair,
  seal as wasm_seal,
  unseal as wasm_unseal,
  seal_for_share,
  unseal_share,
  generate_shared_vault_key,
  seal_for_shared_vault,
  unseal_shared_vault,
  seal_for_blind_share,
  unseal_blind_share,
} from "../../../wasm-bindings/pkg-web/wasm_bindings.js";

let ready: Promise<void> | null = null;

/** Charge et instancie le binaire .wasm une seule fois (appels suivants no-op) — voir
 * `init()` généré par wasm-bindgen, qui fait un fetch() relatif à l'URL du module lui-même. */
function ensureInit(): Promise<void> {
  if (!ready) ready = init().then(() => undefined);
  return ready;
}

export interface DerivedKeys {
  authHashHex: string;
  vaultKey: Uint8Array;
}

export async function deriveKeys(email: string, masterPassword: string): Promise<DerivedKeys> {
  await ensureInit();
  const keys = derive_keys(email, masterPassword);
  return { authHashHex: keys.auth_hash_hex, vaultKey: keys.vault_key };
}

export async function encryptField(vaultKey: Uint8Array, plaintext: string): Promise<string> {
  await ensureInit();
  return encrypt_field(vaultKey, plaintext);
}

export async function decryptField(vaultKey: Uint8Array, blobB64: string): Promise<string> {
  await ensureInit();
  return decrypt_field(vaultKey, blobB64);
}

/** Utilisé pour la vérification anti-fuite (voir Vault.tsx côté desktop) — pas encore branché
 * dans la popup à cette phase, exporté pour rester prêt quand cet écran sera ajouté. */
export async function sha1Hex(plaintext: string): Promise<string> {
  await ensureInit();
  return sha1_hex(plaintext);
}

export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

/** Génère une paire de clés X25519 — utilisé pour l'accès d'urgence ET le partage d'entrée (même
 * trousseau, voir lib/emergencyAccess.ts). */
export async function generateKeypair(): Promise<KeyPair> {
  await ensureInit();
  const pair = generate_keypair();
  return { publicKey: pair.public_key, privateKey: pair.private_key };
}

/** Boîte scellée X25519 — accès d'urgence (voir lib/emergencyAccess.ts). Isolée cryptographiquement
 * de seal_for_share/unseal_share ci-dessous (info HKDF différente, voir crypto-core/src/sharing.rs). */
export async function seal(plaintext: string, recipientPublicKey: string): Promise<string> {
  await ensureInit();
  return wasm_seal(plaintext, recipientPublicKey);
}

export async function unseal(sealedB64: string, recipientPrivateKey: string): Promise<string> {
  await ensureInit();
  return wasm_unseal(sealedB64, recipientPrivateKey);
}

/** Boîte scellée X25519 — partage d'entrée (voir lib/entrySharing.ts). */
export async function sealForShare(plaintext: string, recipientPublicKey: string): Promise<string> {
  await ensureInit();
  return seal_for_share(plaintext, recipientPublicKey);
}

export async function unsealShare(sealedB64: string, recipientPrivateKey: string): Promise<string> {
  await ensureInit();
  return unseal_share(sealedB64, recipientPrivateKey);
}

// --- Coffres partagés familiaux (voir lib/sharedVault.ts). encryptField/decryptField ci-dessus
// servent DÉJÀ à chiffrer/déchiffrer les entrées d'un coffre partagé — elles sont génériques sur
// n'importe quelle clé, pas seulement celle du coffre personnel. Isolé cryptographiquement de
// seal/unseal et sealForShare/unsealShare (3e contexte HKDF, voir crypto-core/src/shared_vault.rs). ---

/** Génère une nouvelle clé symétrique pour un coffre partagé — appelée une seule fois, à sa
 * création. Renvoyée en base64 (transport/stockage), à décoder via base64ToBytes avant de la
 * passer à encryptField/decryptField ci-dessus. */
export async function generateSharedVaultKey(): Promise<string> {
  await ensureInit();
  return generate_shared_vault_key();
}

/** Scelle la clé (déjà en clair, base64) d'un coffre partagé pour la clé publique d'un membre. */
export async function sealForSharedVault(vaultKeyB64: string, recipientPublicKey: string): Promise<string> {
  await ensureInit();
  return seal_for_shared_vault(vaultKeyB64, recipientPublicKey);
}

/** Déchiffre la clé scellée d'un coffre partagé reçue, avec sa propre clé privée. Renvoie la clé
 * en base64, comme generateSharedVaultKey ci-dessus. */
export async function unsealSharedVault(sealedB64: string, recipientPrivateKey: string): Promise<string> {
  await ensureInit();
  return unseal_shared_vault(sealedB64, recipientPrivateKey);
}

// --- Partage à usage limité ("aveugle", voir lib/blindShare.ts). 4e contexte HKDF de séparation,
// isolé des trois autres usages (voir crypto-core/src/blind_share.rs). ---

/** Scelle le nom du site EN CLAIR, ou le JSON des identifiants (deux appels distincts, voir
 * lib/blindShare.ts) pour la clé publique d'un destinataire. */
export async function sealForBlindShare(plaintext: string, recipientPublicKey: string): Promise<string> {
  await ensureInit();
  return seal_for_blind_share(plaintext, recipientPublicKey);
}

/** Déchiffre un blob de partage à usage limité reçu, avec sa propre clé privée. */
export async function unsealBlindShare(sealedB64: string, recipientPrivateKey: string): Promise<string> {
  await ensureInit();
  return unseal_blind_share(sealedB64, recipientPrivateKey);
}
