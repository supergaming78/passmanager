//! Pont wasm-bindgen autour de `crypto-core` — expose au JS de la future extension navigateur un
//! miroir des commandes déjà exposées côté desktop par `frontend(app)/src-tauri/src/lib.rs` (même
//! logique, même code source sous-jacent, juste une couche d'intégration différente : ici
//! wasm-bindgen plutôt que `#[tauri::command]`). Voir crypto-core/src/lib.rs pour la logique
//! elle-même — ce fichier ne fait QUE convertir les types entre Rust et JS (String, Vec<u8>...) et
//! aplatir les erreurs `String` de crypto-core en `JsValue` (exception JS classique côté appelant).
//!
//! Pas de commande "verrouillage/déverrouillage du coffre en mémoire" ici (contrairement à
//! `VaultKeyState` côté desktop) : le modèle de session d'un service worker d'extension est un
//! sujet de Phase 2, une fois cette fondation crypto posée et vérifiée — voir le plan.

use wasm_bindgen::prelude::*;

fn to_key(bytes: &[u8]) -> Result<[u8; crypto_core::crypto::KEY_LEN], JsValue> {
    bytes
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("Clé invalide : {} octets attendus", crypto_core::crypto::KEY_LEN)))
}

fn to_js_err(e: String) -> JsValue {
    JsValue::from_str(&e)
}

/// Miroir de `crypto_core::crypto::DerivedKeys`, sous une forme que wasm-bindgen sait exposer
/// telle quelle au JS (accesseurs générés automatiquement pour chaque champ public).
#[wasm_bindgen(getter_with_clone)]
pub struct DerivedKeysJs {
    pub auth_hash_hex: String,
    pub vault_key: Vec<u8>,
}

#[wasm_bindgen]
pub fn derive_keys(email: String, master_password: String) -> DerivedKeysJs {
    let keys = crypto_core::crypto::derive_keys(&email, &master_password);
    DerivedKeysJs { auth_hash_hex: keys.auth_hash_hex, vault_key: keys.vault_key.to_vec() }
}

#[wasm_bindgen]
pub fn encrypt_field(vault_key: Vec<u8>, plaintext: String) -> Result<String, JsValue> {
    let key = to_key(&vault_key)?;
    crypto_core::crypto::encrypt_field(&key, &plaintext).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn decrypt_field(vault_key: Vec<u8>, blob_b64: String) -> Result<String, JsValue> {
    let key = to_key(&vault_key)?;
    crypto_core::crypto::decrypt_field(&key, &blob_b64).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn encrypt_export_content(plaintext: String, password: String) -> Result<String, JsValue> {
    crypto_core::crypto::encrypt_export_content(&plaintext, &password).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn decrypt_export_content(content: String, password: String) -> Result<String, JsValue> {
    crypto_core::crypto::decrypt_export_content(&content, &password).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn sha1_hex(plaintext: String) -> String {
    crypto_core::crypto::sha1_hex(&plaintext)
}

/// Miroir de `(String, String)` (clé publique, clé privée) — même remarque que DerivedKeysJs :
/// wasm-bindgen n'exporte pas les tuples Rust bruts de façon typée côté JS, d'où ce petit wrapper.
#[wasm_bindgen(getter_with_clone)]
pub struct KeyPairJs {
    pub public_key: String,
    pub private_key: String,
}

#[wasm_bindgen]
pub fn generate_keypair() -> KeyPairJs {
    let (public_key, private_key) = crypto_core::emergency::generate_keypair();
    KeyPairJs { public_key, private_key }
}

#[wasm_bindgen]
pub fn seal(plaintext: String, recipient_public_key_b64: String) -> Result<String, JsValue> {
    crypto_core::emergency::seal(&plaintext, &recipient_public_key_b64).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn unseal(sealed_b64: String, recipient_private_key_b64: String) -> Result<String, JsValue> {
    crypto_core::emergency::unseal(&sealed_b64, &recipient_private_key_b64).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn seal_for_share(plaintext: String, recipient_public_key_b64: String) -> Result<String, JsValue> {
    crypto_core::sharing::seal_for_share(&plaintext, &recipient_public_key_b64).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn unseal_share(sealed_b64: String, recipient_private_key_b64: String) -> Result<String, JsValue> {
    crypto_core::sharing::unseal_share(&sealed_b64, &recipient_private_key_b64).map_err(to_js_err)
}

// --- Coffres partagés familiaux (voir crypto_core::shared_vault). encrypt_field/decrypt_field
// ci-dessus servent DÉJÀ à chiffrer/déchiffrer les entrées d'un coffre partagé (fonctions déjà
// génériques sur n'importe quelle clé de KEY_LEN octets, pas seulement celle du coffre personnel
// dérivée du mot de passe maître) — seules la génération et le scellement/descellement de la clé
// du coffre partagé lui-même ont besoin de nouvelles fonctions ici. ---

#[wasm_bindgen]
pub fn generate_shared_vault_key() -> String {
    crypto_core::shared_vault::generate_vault_key()
}

#[wasm_bindgen]
pub fn seal_for_shared_vault(plaintext: String, recipient_public_key_b64: String) -> Result<String, JsValue> {
    crypto_core::shared_vault::seal_for_shared_vault(&plaintext, &recipient_public_key_b64).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn unseal_shared_vault(sealed_b64: String, recipient_private_key_b64: String) -> Result<String, JsValue> {
    crypto_core::shared_vault::unseal_shared_vault(&sealed_b64, &recipient_private_key_b64).map_err(to_js_err)
}

// --- Partage à usage limité ("aveugle", voir crypto_core::blind_share). Même remarque que pour
// les coffres partagés : seul le scellement/descellement a besoin d'une fonction dédiée (contexte
// HKDF distinct), rien d'autre de nouveau côté primitives. ---

#[wasm_bindgen]
pub fn seal_for_blind_share(plaintext: String, recipient_public_key_b64: String) -> Result<String, JsValue> {
    crypto_core::blind_share::seal_for_blind_share(&plaintext, &recipient_public_key_b64).map_err(to_js_err)
}

#[wasm_bindgen]
pub fn unseal_blind_share(sealed_b64: String, recipient_private_key_b64: String) -> Result<String, JsValue> {
    crypto_core::blind_share::unseal_blind_share(&sealed_b64, &recipient_private_key_b64).map_err(to_js_err)
}
