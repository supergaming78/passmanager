// crypto/emergency/sharing vivent maintenant dans `crypto-core` (partagé avec la future extension
// navigateur, compilée en WASM à partir du même code — voir crypto-core/src/lib.rs). `pub use`
// (pas un simple `use`) : rend `crate::crypto::...`/`crate::emergency::...`/`crate::sharing::...`
// résolvables depuis N'IMPORTE QUEL module de CE crate (ex: quick_unlock.rs, qui importe
// `crate::crypto::KEY_LEN`) exactement comme avant cette extraction — aucun autre fichier de ce
// crate n'a eu besoin d'être modifié.
pub use crypto_core::{crypto, emergency, sharing, shared_vault, blind_share};
mod state;
#[cfg(target_os = "windows")]
mod dpapi;
#[cfg(target_os = "windows")]
mod quick_unlock;

use state::{EmergencyVaultKeyState, VaultKeyState};
use tauri::State;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use zeroize::Zeroize;

/// Dérive les clés à partir de (email, mot de passe maître), déverrouille le coffre (stocke la
/// clé de chiffrement en mémoire, voir state.rs), et renvoie SEULEMENT le hash d'authentification
/// à envoyer au serveur (voir AuthPayload::master_password_hash côté backend) — la clé du coffre
/// elle-même ne quitte JAMAIS ce processus Rust, le JS ne la voit jamais.
#[tauri::command]
fn derive_keys(email: String, master_password: String, vault_state: State<VaultKeyState>) -> String {
    let keys = crypto::derive_keys(&email, &master_password);
    vault_state.set(keys.vault_key);
    keys.auth_hash_hex
}

/// Calcule le hash d'authentification (email, mot de passe) SANS toucher à la clé du coffre en
/// mémoire — contrairement à `derive_keys`, qui (re)déverrouille toujours le coffre comme effet
/// de bord. Destiné aux écrans qui redemandent le mot de passe maître pour re-confirmer
/// l'identité de l'utilisateur (changement d'email, changement du plafond d'appareils,
/// re-confirmation de l'ancien mot de passe avant un changement de mot de passe) : le coffre est
/// déjà déverrouillé avec la BONNE clé à ce moment-là, et une simple faute de frappe dans ce
/// champ de re-confirmation ne doit jamais écraser cette clé en mémoire par une clé dérivée
/// d'un mot de passe erroné avant même que le serveur n'ait eu la chance de rejeter le hash.
#[tauri::command]
fn compute_auth_hash(email: String, master_password: String) -> String {
    let mut keys = crypto::derive_keys(&email, &master_password);
    keys.vault_key.zeroize();
    keys.auth_hash_hex
}

/// Verrouille le coffre : efface la clé de chiffrement de la mémoire. À appeler à la
/// déconnexion explicite, et (à brancher côté frontend) après une période d'inactivité.
#[tauri::command]
fn lock_vault(vault_state: State<VaultKeyState>) {
    vault_state.clear();
}

/// Permet au frontend de savoir s'il doit rediriger vers l'écran de connexion (coffre verrouillé,
/// aucune clé en mémoire) ou peut afficher le coffre (déjà déverrouillé cette session).
#[tauri::command]
fn is_vault_unlocked(vault_state: State<VaultKeyState>) -> bool {
    vault_state.is_unlocked()
}

/// Chiffre un champ en clair du coffre avec la clé actuellement en mémoire.
/// Échoue explicitement si le coffre est verrouillé, plutôt que de paniquer ou de renvoyer un
/// résultat vide silencieux — le frontend doit alors renvoyer l'utilisateur se reconnecter.
#[tauri::command]
fn encrypt_vault_field(plaintext: String, vault_state: State<VaultKeyState>) -> Result<String, String> {
    let mut key = vault_state.get().ok_or_else(|| "Coffre verrouillé".to_string())?;
    let result = crypto::encrypt_field(&key, &plaintext);
    key.zeroize();
    result
}

/// Déchiffre un champ du coffre avec la clé actuellement en mémoire.
#[tauri::command]
fn decrypt_vault_field(ciphertext: String, vault_state: State<VaultKeyState>) -> Result<String, String> {
    let mut key = vault_state.get().ok_or_else(|| "Coffre verrouillé".to_string())?;
    let result = crypto::decrypt_field(&key, &ciphertext);
    key.zeroize();
    result
}

/// Version GROUPÉE de encrypt_vault_field() ci-dessus — CORRECTIF PERF (retour utilisateur,
/// 2026-09-02) : une seule entrée du coffre a jusqu'à 9 champs chiffrés séparément (site,
/// identifiant, email, mot de passe, préférence, dossier, notes, URL, champs additionnels) —
/// jusqu'ici, chiffrer/déchiffrer une entrée signifiait jusqu'à 9 appels IPC SÉPARÉS (chacun avec
/// son propre aller-retour de sérialisation à travers le pont Tauri, et sa propre lecture/effacement
/// de la clé), voir lib/vaultCrypto.ts. Pour N entrées visibles dans le coffre : jusqu'à 9×N appels.
/// Un seul appel groupé ici : la clé n'est récupérée/effacée QU'UNE FOIS pour tout le lot, pas une
/// fois par champ. Erreur sur UN SEUL champ -> toute la requête échoue (via `.collect()` sur un
/// itérateur de `Result`, qui s'arrête à la première erreur) — même comportement "tout ou rien"
/// que l'ancien `Promise.all()` côté JS, juste déplacé ici.
#[tauri::command]
fn encrypt_vault_fields(plaintexts: Vec<String>, vault_state: State<VaultKeyState>) -> Result<Vec<String>, String> {
    let mut key = vault_state.get().ok_or_else(|| "Coffre verrouillé".to_string())?;
    let result = plaintexts.iter().map(|p| crypto::encrypt_field(&key, p)).collect();
    key.zeroize();
    result
}

/// Version GROUPÉE de decrypt_vault_field() ci-dessus — même raisonnement que
/// encrypt_vault_fields() juste au-dessus.
#[tauri::command]
fn decrypt_vault_fields(ciphertexts: Vec<String>, vault_state: State<VaultKeyState>) -> Result<Vec<String>, String> {
    let mut key = vault_state.get().ok_or_else(|| "Coffre verrouillé".to_string())?;
    let result = ciphertexts.iter().map(|c| crypto::decrypt_field(&key, c)).collect();
    key.zeroize();
    result
}

/// Résultat de prepare_password_change() : les DEUX hash d'authentification à envoyer au serveur
/// (voir ChangeMasterPasswordPayload côté backend) et chaque blob re-chiffré, DANS LE MÊME ORDRE
/// que les `ciphertexts` fournis en entrée — reconstruire les entrées avec ce mapping par index
/// est la responsabilité de l'appelant JS (voir lib/passwordChangeCrypto.ts).
#[derive(serde::Serialize)]
struct PasswordChangeResult {
    old_auth_hash: String,
    new_auth_hash: String,
    reencrypted_ciphertexts: Vec<String>,
}

/// Prépare un changement de mot de passe maître EN UNE SEULE FOIS : dérive l'ancien ET le nouveau
/// jeu de clés, puis re-chiffre chaque blob fourni (déchiffré avec l'ancienne clé, rechiffré avec
/// la nouvelle) — tout se passe ici, en Rust ; aucune clé ni aucun contenu en clair ne transite
/// jamais par le JS, même temporairement. Si UN SEUL blob échoue à se déchiffrer (ex: mauvais
/// ancien mot de passe fourni), toute l'opération échoue avant d'avoir rien renvoyé — jamais de
/// résultat partiellement re-chiffré.
///
/// N'AFFECTE PAS le coffre actuellement déverrouillé (voir state.rs) : c'est un calcul isolé, la
/// clé de coffre en mémoire ne change pas ici. Une fois le backend confirmé le changement
/// (PUT /auth/password réussi), l'appelant JS doit rappeler derive_keys() avec le NOUVEAU mot de
/// passe pour déverrouiller le coffre avec la nouvelle clé, exactement comme à une connexion
/// normale — évite de dupliquer la logique de déverrouillage ici.
#[tauri::command]
fn prepare_password_change(
    email: String,
    old_password: String,
    new_password: String,
    ciphertexts: Vec<String>,
) -> Result<PasswordChangeResult, String> {
    let mut old_keys = crypto::derive_keys(&email, &old_password);
    let mut new_keys = crypto::derive_keys(&email, &new_password);

    let mut reencrypted = Vec::with_capacity(ciphertexts.len());
    for ciphertext in &ciphertexts {
        let plaintext = crypto::decrypt_field(&old_keys.vault_key, ciphertext)?;
        reencrypted.push(crypto::encrypt_field(&new_keys.vault_key, &plaintext)?);
    }

    let result = PasswordChangeResult {
        old_auth_hash: old_keys.auth_hash_hex.clone(),
        new_auth_hash: new_keys.auth_hash_hex.clone(),
        reencrypted_ciphertexts: reencrypted,
    };

    old_keys.vault_key.zeroize();
    new_keys.vault_key.zeroize();

    Ok(result)
}

/// Chiffre le contenu d'un fichier d'export (voir lib/vaultFile.ts côté frontend) avec un mot de
/// passe SÉPARÉ du mot de passe maître — indépendant du coffre déverrouillé actuel, ne touche pas
/// `vault_state`. Voir crypto.rs::encrypt_export_content pour le format produit.
#[tauri::command]
fn encrypt_export_content(plaintext: String, password: String) -> Result<String, String> {
    crypto::encrypt_export_content(&plaintext, &password)
}

/// Déchiffre un fichier produit par encrypt_export_content(). Renvoie une erreur explicite (mot de
/// passe incorrect, fichier corrompu, ou pas un export chiffré du tout) plutôt que de planter.
#[tauri::command]
fn decrypt_export_content(content: String, password: String) -> Result<String, String> {
    crypto::decrypt_export_content(&content, &password)
}

/// SHA-1 hexadécimal MAJUSCULE d'un mot de passe — UNIQUEMENT pour la vérification de mots de
/// passe compromis (API k-anonymat "Pwned Passwords" de HaveIBeenPwned, voir
/// lib/breachCheck.ts côté frontend, qui fait la requête réseau elle-même). Indépendant du coffre
/// déverrouillé actuel, comme encrypt_export_content ci-dessus.
#[tauri::command]
fn sha1_hex(plaintext: String) -> String {
    crypto::sha1_hex(&plaintext)
}

// =========================================================================
// DÉVERROUILLAGE RAPIDE (Windows uniquement, voir dpapi.rs/quick_unlock.rs) — chaque commande
// échoue explicitement ("indisponible") sur les autres plateformes plutôt que d'être absente du
// binaire, pour que le frontend garde un seul chemin d'appel uniforme (voir api/tauri.ts) et se
// contente de masquer le bouton correspondant si is_quick_unlock_available() renvoie `false`.
// =========================================================================

/// Le déverrouillage rapide est-il configuré sur cet appareil ? `false` inconditionnellement hors
/// Windows.
#[tauri::command]
fn is_quick_unlock_available(app: tauri::AppHandle) -> bool {
    #[cfg(target_os = "windows")]
    {
        quick_unlock::is_available(&app)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = app;
        false
    }
}

/// Active le déverrouillage rapide : protège la clé ACTUELLEMENT en mémoire (le coffre doit déjà
/// être déverrouillé via le mot de passe maître) et l'écrit sur disque, liée au compte Windows de
/// la session en cours (voir dpapi.rs).
#[tauri::command]
fn enable_quick_unlock(app: tauri::AppHandle, vault_state: State<VaultKeyState>) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        quick_unlock::enable(&app, &vault_state)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (app, vault_state);
        Err("Le déverrouillage rapide n'est disponible que sur Windows.".to_string())
    }
}

/// Désactive le déverrouillage rapide (supprime le fichier local) — appelée explicitement depuis
/// les Réglages, et automatiquement à la déconnexion / à tout changement de mot de passe maître
/// (voir AuthContext.tsx côté frontend, le blob deviendrait sinon trompeur après un tel
/// changement).
#[tauri::command]
fn disable_quick_unlock(app: tauri::AppHandle) {
    #[cfg(target_os = "windows")]
    {
        quick_unlock::disable(&app);
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = app;
    }
}

/// Demande une vérification Windows Hello puis, si elle réussit, recharge la clé du coffre en
/// mémoire SANS repasser par le mot de passe maître (voir quick_unlock.rs pour le flux complet).
#[tauri::command]
async fn try_quick_unlock(app: tauri::AppHandle, vault_state: State<'_, VaultKeyState>) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        quick_unlock::try_unlock(&app, &vault_state, "Déverrouiller PassManager").await
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (app, vault_state);
        Err("Le déverrouillage rapide n'est disponible que sur Windows.".to_string())
    }
}

// =========================================================================
// ACCÈS D'URGENCE (voir emergency.rs) — le propriétaire d'un coffre chiffre sa clé pour un
// contact de confiance ; ce contact peut plus tard la récupérer et consulter le coffre en LECTURE
// SEULE, jamais en écriture (voir EmergencyVaultKeyState, distinct de VaultKeyState).
// =========================================================================

#[derive(serde::Serialize)]
struct EmergencyKeypairResult {
    public_key: String,
    encrypted_private_key: String,
}

/// Génère la paire de clés X25519 de l'utilisateur (une fois, à la première configuration de
/// l'accès d'urgence) — la clé privée est immédiatement chiffrée avec la clé du coffre
/// ACTUELLEMENT déverrouillée avant d'être renvoyée : elle ne transite JAMAIS en clair, ni côté
/// JS, ni côté serveur (voir handlers/emergency.rs côté backend, qui la stocke telle quelle).
#[tauri::command]
fn generate_emergency_keypair(vault_state: State<VaultKeyState>) -> Result<EmergencyKeypairResult, String> {
    let mut key = vault_state.get().ok_or_else(|| "Coffre verrouillé".to_string())?;
    let (public_key, mut private_key_plain) = emergency::generate_keypair();
    let encrypted_private_key = crypto::encrypt_field(&key, &private_key_plain);
    key.zeroize();
    // CORRECTIF SÉCURITÉ : private_key_plain (la clé privée X25519 long-terme du compte, EN
    // CLAIR) ne doit jamais survivre en mémoire au-delà de son chiffrement ci-dessus — sans ce
    // zeroize(), le contenu de ce String restait sur le tas après libération, potentiellement
    // récupérable via un dump mémoire/fichier d'échange.
    private_key_plain.zeroize();
    Ok(EmergencyKeypairResult { public_key, encrypted_private_key: encrypted_private_key? })
}

/// Chiffre la clé du coffre ACTUELLEMENT déverrouillée pour un contact de confiance, à partir de
/// sa clé publique (récupérée au préalable depuis le serveur — voir emergency.rs::seal). Le blob
/// renvoyé est à envoyer au serveur ; lui seul (via sa clé privée) pourra un jour le déchiffrer.
#[tauri::command]
fn seal_vault_key_for_contact(recipient_public_key: String, vault_state: State<VaultKeyState>) -> Result<String, String> {
    let mut key = vault_state.get().ok_or_else(|| "Coffre verrouillé".to_string())?;
    let mut key_b64 = BASE64.encode(key);
    key.zeroize();
    // CORRECTIF SÉCURITÉ : key_b64 est une copie EN CLAIR de la clé du coffre (juste ré-encodée en
    // base64) — zeroize() APRÈS le scellement, jamais laissée traîner sur le tas.
    let result = emergency::seal(&key_b64, &recipient_public_key);
    key_b64.zeroize();
    result
}

/// Déverrouille l'accès d'urgence à un AUTRE coffre (celui d'un propriétaire qui a désigné
/// l'utilisateur courant comme contact de confiance, une fois l'accès effectivement accordé) :
/// déchiffre D'ABORD sa propre clé privée (avec SA clé de coffre à lui, déjà déverrouillée
/// normalement), puis s'en sert pour desceller la clé du coffre DISTANT — qui atterrit dans
/// EmergencyVaultKeyState, jamais dans VaultKeyState (qui reste celle du coffre local).
#[tauri::command]
fn unlock_emergency_vault(
    sealed_vault_key: String,
    encrypted_private_key: String,
    vault_state: State<VaultKeyState>,
    emergency_state: State<EmergencyVaultKeyState>,
) -> Result<(), String> {
    let mut my_key = vault_state.get().ok_or_else(|| "Coffre verrouillé".to_string())?;
    let private_key_result = crypto::decrypt_field(&my_key, &encrypted_private_key);
    my_key.zeroize();
    let mut private_key_b64 = private_key_result?;

    let unseal_result = emergency::unseal(&sealed_vault_key, &private_key_b64);
    // CORRECTIF SÉCURITÉ : private_key_b64 (clé privée X25519 en clair) ne sert plus une fois le
    // descellement fait, quel qu'en soit le résultat.
    private_key_b64.zeroize();
    let mut owner_key_b64 = unseal_result?;

    let owner_key_bytes = BASE64
        .decode(&owner_key_b64)
        .map_err(|_| "Clé de coffre distant invalide (base64)".to_string());
    // CORRECTIF SÉCURITÉ : owner_key_b64 est une copie EN CLAIR de la clé de coffre d'un AUTRE
    // utilisateur (le propriétaire ayant accordé l'accès d'urgence) — zeroize() dès qu'elle a été
    // redécodée en octets, jamais laissée traîner sur le tas.
    owner_key_b64.zeroize();
    let owner_key_bytes = owner_key_bytes?;
    let owner_key: [u8; crypto::KEY_LEN] = owner_key_bytes
        .try_into()
        .map_err(|_| "Clé de coffre distant invalide (longueur)".to_string())?;

    emergency_state.set(owner_key);
    Ok(())
}

/// Referme l'accès d'urgence en cours — à appeler en quittant l'écran de consultation, ou à la
/// déconnexion.
#[tauri::command]
fn lock_emergency_vault(emergency_state: State<EmergencyVaultKeyState>) {
    emergency_state.clear();
}

#[tauri::command]
fn is_emergency_vault_unlocked(emergency_state: State<EmergencyVaultKeyState>) -> bool {
    emergency_state.is_unlocked()
}

/// Déchiffre un champ du coffre D'URGENCE actuellement ouvert — PAS de commande "encrypt"
/// symétrique : la consultation d'urgence est intentionnellement LECTURE SEULE (il n'existe de
/// toute façon aucune route backend permettant d'écrire dans le coffre de quelqu'un d'autre).
#[tauri::command]
fn decrypt_emergency_field(ciphertext: String, emergency_state: State<EmergencyVaultKeyState>) -> Result<String, String> {
    let mut key = emergency_state.get().ok_or_else(|| "Coffre d'urgence non déverrouillé".to_string())?;
    let result = crypto::decrypt_field(&key, &ciphertext);
    key.zeroize();
    result
}

/// Version GROUPÉE de decrypt_emergency_field() ci-dessus — CORRECTIF PERF (retour utilisateur,
/// 2026-09-02), même raisonnement que encrypt_vault_fields()/decrypt_vault_fields() plus haut
/// (voir leur commentaire) : une entrée du coffre d'urgence a jusqu'à 9 champs chiffrés séparément
/// (voir lib/emergencyAccess.ts), un seul appel groupé ici au lieu de jusqu'à 9 appels IPC.
#[tauri::command]
fn decrypt_emergency_fields(ciphertexts: Vec<String>, emergency_state: State<EmergencyVaultKeyState>) -> Result<Vec<String>, String> {
    let mut key = emergency_state.get().ok_or_else(|| "Coffre d'urgence non déverrouillé".to_string())?;
    let result = ciphertexts.iter().map(|c| crypto::decrypt_field(&key, c)).collect();
    key.zeroize();
    result
}

// =========================================================================
// PARTAGE SÉCURISÉ D'UNE ENTRÉE (voir sharing.rs) — réutilise le MÊME trousseau de clés X25519 par
// utilisateur que l'accès d'urgence ci-dessus (table `user_keys` côté backend), mais avec un
// contexte HKDF différent (voir sharing::INFO_SHARE_SEAL) : les deux usages restent
// cryptographiquement étanches l'un de l'autre. Contrairement à l'accès d'urgence, aucun état
// Tauri persistant n'est nécessaire ici — chaque opération est ponctuelle (sceller un texte déjà
// en clair, ou desceller un blob pour l'afficher une fois), pas une session qui reste "ouverte".
// =========================================================================

/// Chiffre `plaintext` (le JSON d'une entrée en clair, voir lib/entrySharing.ts côté frontend) pour
/// le détenteur de `recipient_public_key`. Ne touche à AUCUN état — l'appelant fournit déjà le
/// texte en clair (il a nécessairement déchiffré l'entrée pour l'afficher avant de la partager).
#[tauri::command]
fn seal_entry_for_recipient(plaintext: String, recipient_public_key: String) -> Result<String, String> {
    sharing::seal_for_share(&plaintext, &recipient_public_key)
}

/// Déchiffre un blob de partage d'entrée reçu (voir sharing::seal_for_share) : déchiffre D'ABORD
/// sa propre clé privée (avec SA clé de coffre LOCALE, déjà déverrouillée normalement), puis s'en
/// sert pour desceller le contenu de l'entrée partagée — renvoyé directement en clair, jamais
/// stocké dans un état persistant (voir le commentaire de section ci-dessus).
#[tauri::command]
fn unseal_shared_entry(sealed_entry: String, encrypted_private_key: String, vault_state: State<VaultKeyState>) -> Result<String, String> {
    let mut my_key = vault_state.get().ok_or_else(|| "Coffre verrouillé".to_string())?;
    let private_key_result = crypto::decrypt_field(&my_key, &encrypted_private_key);
    my_key.zeroize();
    let mut private_key_b64 = private_key_result?;

    // CORRECTIF SÉCURITÉ : private_key_b64 (clé privée X25519 en clair) ne sert plus une fois le
    // descellement fait, quel qu'en soit le résultat.
    let result = sharing::unseal_share(&sealed_entry, &private_key_b64);
    private_key_b64.zeroize();
    result
}

// =========================================================================
// COFFRES PARTAGÉS FAMILIAUX (voir shared_vault.rs) — même contexte HKDF de séparation que le
// partage d'entrée ci-dessus (INFO_SHARED_VAULT_SEAL, distinct de INFO_SHARE_SEAL/INFO_SEAL),
// réutilise le même trousseau X25519 par utilisateur. Différence structurelle : la clé du coffre
// partagé est SYMÉTRIQUE (AES-256) et partagée par tous ses membres — les champs des entrées d'un
// coffre partagé sont donc chiffrés avec CETTE clé, jamais la clé du coffre PERSONNEL de
// l'utilisateur (State<VaultKeyState>) — d'où les commandes de chiffrement/déchiffrement de champ
// dédiées ci-dessous, qui prennent la clé en PARAMÈTRE plutôt que de la lire depuis l'état Tauri.
// =========================================================================

/// Génère une nouvelle clé symétrique pour un coffre partagé — appelée UNE SEULE FOIS, à sa
/// création (voir SettingsView/lib/sharedVault.ts côté frontend).
#[tauri::command]
fn generate_shared_vault_key() -> String {
    shared_vault::generate_vault_key()
}

/// Scelle la clé d'un coffre partagé (déjà en clair côté appelant — soit fraîchement générée par
/// le créateur, soit descellée via unseal_shared_vault_key ci-dessous) pour la clé publique d'un
/// membre (existant ou à inviter). Ne touche à AUCUN état.
#[tauri::command]
fn seal_shared_vault_key(vault_key_b64: String, recipient_public_key: String) -> Result<String, String> {
    shared_vault::seal_for_shared_vault(&vault_key_b64, &recipient_public_key)
}

/// Déchiffre la clé scellée d'un coffre partagé REÇUE (voir SharedVaultView::sealed_vault_key
/// côté backend) : déchiffre D'ABORD sa propre clé privée (avec SA clé de coffre PERSONNELLE
/// LOCALE, déjà déverrouillée normalement), puis s'en sert pour desceller la clé du coffre
/// partagé — renvoyée en clair, jamais stockée dans un état persistant (comme
/// unseal_shared_entry, dont cette commande est le pendant pour les coffres partagés).
#[tauri::command]
fn unseal_shared_vault_key(sealed_vault_key: String, encrypted_private_key: String, vault_state: State<VaultKeyState>) -> Result<String, String> {
    let mut my_key = vault_state.get().ok_or_else(|| "Coffre verrouillé".to_string())?;
    let private_key_result = crypto::decrypt_field(&my_key, &encrypted_private_key);
    my_key.zeroize();
    let mut private_key_b64 = private_key_result?;

    let result = shared_vault::unseal_shared_vault(&sealed_vault_key, &private_key_b64);
    private_key_b64.zeroize();
    result
}

/// Chiffre un champ d'entrée de coffre partagé avec SA clé symétrique (fournie en paramètre, PAS
/// lue depuis State<VaultKeyState> — contrairement à encrypt_vault_field, qui chiffre TOUJOURS
/// avec la clé du coffre PERSONNEL actuellement déverrouillé).
#[tauri::command]
fn encrypt_shared_vault_field(plaintext: String, vault_key_b64: String) -> Result<String, String> {
    let mut key_bytes = BASE64.decode(&vault_key_b64).map_err(|_| "Clé de coffre partagé invalide (base64)".to_string())?;
    let mut key: [u8; crypto::KEY_LEN] = key_bytes.as_slice().try_into().map_err(|_| "Clé de coffre partagé invalide (longueur)".to_string())?;
    key_bytes.zeroize();
    let result = crypto::encrypt_field(&key, &plaintext);
    key.zeroize();
    result
}

/// Déchiffre un champ d'entrée de coffre partagé avec SA clé symétrique — pendant de
/// encrypt_shared_vault_field ci-dessus.
#[tauri::command]
fn decrypt_shared_vault_field(ciphertext: String, vault_key_b64: String) -> Result<String, String> {
    let mut key_bytes = BASE64.decode(&vault_key_b64).map_err(|_| "Clé de coffre partagé invalide (base64)".to_string())?;
    let mut key: [u8; crypto::KEY_LEN] = key_bytes.as_slice().try_into().map_err(|_| "Clé de coffre partagé invalide (longueur)".to_string())?;
    key_bytes.zeroize();
    let result = crypto::decrypt_field(&key, &ciphertext);
    key.zeroize();
    result
}

/// Version GROUPÉE de encrypt_shared_vault_field() ci-dessus — CORRECTIF PERF (retour utilisateur,
/// 2026-09-02), même raisonnement que encrypt_vault_fields() plus haut (voir son commentaire) :
/// une entrée de coffre partagé a jusqu'à 9 champs chiffrés séparément (voir lib/sharedVault.ts),
/// un seul appel groupé ici — la clé n'est décodée/zeroizée qu'UNE FOIS pour tout le lot au lieu
/// d'une fois par champ.
#[tauri::command]
fn encrypt_shared_vault_fields(plaintexts: Vec<String>, vault_key_b64: String) -> Result<Vec<String>, String> {
    let mut key_bytes = BASE64.decode(&vault_key_b64).map_err(|_| "Clé de coffre partagé invalide (base64)".to_string())?;
    let mut key: [u8; crypto::KEY_LEN] = key_bytes.as_slice().try_into().map_err(|_| "Clé de coffre partagé invalide (longueur)".to_string())?;
    key_bytes.zeroize();
    let result = plaintexts.iter().map(|p| crypto::encrypt_field(&key, p)).collect();
    key.zeroize();
    result
}

/// Version GROUPÉE de decrypt_shared_vault_field() ci-dessus — même raisonnement que
/// encrypt_shared_vault_fields() juste au-dessus.
#[tauri::command]
fn decrypt_shared_vault_fields(ciphertexts: Vec<String>, vault_key_b64: String) -> Result<Vec<String>, String> {
    let mut key_bytes = BASE64.decode(&vault_key_b64).map_err(|_| "Clé de coffre partagé invalide (base64)".to_string())?;
    let mut key: [u8; crypto::KEY_LEN] = key_bytes.as_slice().try_into().map_err(|_| "Clé de coffre partagé invalide (longueur)".to_string())?;
    key_bytes.zeroize();
    let result = ciphertexts.iter().map(|c| crypto::decrypt_field(&key, c)).collect();
    key.zeroize();
    result
}

// =========================================================================
// PARTAGE À USAGE LIMITÉ ("AVEUGLE", voir blind_share.rs) — même contexte HKDF de séparation que
// les trois autres usages (INFO_BLIND_SHARE_SEAL). Le destinataire ne voit jamais l'identifiant ni
// le mot de passe en clair dans l'UI (voir lib/blindShare.ts côté frontend, qui ne renvoie jamais
// la valeur descellée à l'appelant de sa fonction "use" — seulement un succès/échec) : ces deux
// commandes se contentent de sceller/desceller, comme pour le partage classique ci-dessus.
// =========================================================================

/// Scelle `plaintext` (le nom du site EN CLAIR, ou le JSON des identifiants — deux appels
/// distincts, voir lib/blindShare.ts) pour le détenteur de `recipient_public_key`.
#[tauri::command]
fn seal_for_blind_share(plaintext: String, recipient_public_key: String) -> Result<String, String> {
    blind_share::seal_for_blind_share(&plaintext, &recipient_public_key)
}

/// Déchiffre un blob de partage à usage limité reçu — déchiffre D'ABORD sa propre clé privée
/// (avec SA clé de coffre LOCALE, déjà déverrouillée), puis descelle le contenu, renvoyé
/// directement en clair. C'est la RESPONSABILITÉ DE L'APPELANT (lib/blindShare.ts) de ne jamais
/// exposer cette valeur à l'UI au-delà de l'action de remplissage/copie immédiate.
#[tauri::command]
fn unseal_blind_share(sealed_b64: String, encrypted_private_key: String, vault_state: State<VaultKeyState>) -> Result<String, String> {
    let mut my_key = vault_state.get().ok_or_else(|| "Coffre verrouillé".to_string())?;
    let private_key_result = crypto::decrypt_field(&my_key, &encrypted_private_key);
    my_key.zeroize();
    let mut private_key_b64 = private_key_result?;

    let result = blind_share::unseal_blind_share(&sealed_b64, &private_key_b64);
    private_key_b64.zeroize();
    result
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        // Voir Cargo.toml et lib/mobileUpdateCheck.ts (app) — client HTTP natif, immunisé au CORS
        // du navigateur/WebView, contrairement au `fetch()` natif du navigateur.
        .plugin(tauri_plugin_http::init());

    // Mise à jour automatique : DESKTOP UNIQUEMENT (voir Cargo.toml — le plugin lui-même n'est
    // même pas compilé sur Android/iOS, une app mobile se met à jour via son store). `#[cfg(desktop)]`
    // est fourni nativement par Tauri (vrai sur Windows/macOS/Linux, faux sur Android/iOS) — même
    // logique que `#[cfg_attr(mobile, tauri::mobile_entry_point)]` juste au-dessus.
    #[cfg(desktop)]
    let builder = builder.plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init());

    builder
        .manage(VaultKeyState::default())
        .manage(EmergencyVaultKeyState::default())
        .invoke_handler(tauri::generate_handler![
            derive_keys,
            compute_auth_hash,
            lock_vault,
            is_vault_unlocked,
            encrypt_vault_field,
            decrypt_vault_field,
            encrypt_vault_fields,
            decrypt_vault_fields,
            prepare_password_change,
            encrypt_export_content,
            decrypt_export_content,
            sha1_hex,
            is_quick_unlock_available,
            enable_quick_unlock,
            disable_quick_unlock,
            try_quick_unlock,
            generate_emergency_keypair,
            seal_vault_key_for_contact,
            unlock_emergency_vault,
            lock_emergency_vault,
            is_emergency_vault_unlocked,
            decrypt_emergency_field,
            decrypt_emergency_fields,
            seal_entry_for_recipient,
            unseal_shared_entry,
            generate_shared_vault_key,
            seal_shared_vault_key,
            unseal_shared_vault_key,
            encrypt_shared_vault_field,
            decrypt_shared_vault_field,
            encrypt_shared_vault_fields,
            decrypt_shared_vault_fields,
            seal_for_blind_share,
            unseal_blind_share,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

// =========================================================================
// TESTS
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// RÉGRESSION CRITIQUE : un blob chiffré avec l'ANCIEN mot de passe doit, après
    /// prepare_password_change(), redevenir lisible avec le NOUVEAU mot de passe — c'est le cœur
    /// de tout le mécanisme de changement de mot de passe maître (voir la doc de la fonction).
    #[test]
    fn test_prepare_password_change_reencrypts_correctly() {
        let email = "user@example.com";
        let old_password = "ancien_mot_de_passe";
        let new_password = "nouveau_mot_de_passe";

        let old_keys = crypto::derive_keys(email, old_password);
        let original_plaintexts = ["https://example.com", "mon_identifiant", "secret_du_compte"];
        let ciphertexts: Vec<String> = original_plaintexts
            .iter()
            .map(|p| crypto::encrypt_field(&old_keys.vault_key, p).unwrap())
            .collect();

        let result = prepare_password_change(
            email.to_string(),
            old_password.to_string(),
            new_password.to_string(),
            ciphertexts,
        )
        .expect("le re-chiffrement avec le bon ancien mot de passe doit réussir");

        assert_eq!(result.reencrypted_ciphertexts.len(), original_plaintexts.len());

        let new_keys = crypto::derive_keys(email, new_password);
        for (ciphertext, expected_plaintext) in result.reencrypted_ciphertexts.iter().zip(original_plaintexts.iter()) {
            let decrypted = crypto::decrypt_field(&new_keys.vault_key, ciphertext)
                .expect("le blob re-chiffré doit se déchiffrer avec la NOUVELLE clé");
            assert_eq!(&decrypted, expected_plaintext);
        }

        // Les deux hash d'authentification doivent correspondre exactement à ce que
        // derive_keys() produirait indépendamment pour chaque mot de passe (cohérence avec le
        // reste du flux de connexion côté frontend).
        assert_eq!(result.old_auth_hash, old_keys.auth_hash_hex);
        assert_eq!(result.new_auth_hash, new_keys.auth_hash_hex);
    }

    /// GARDE-FOU : un mauvais ancien mot de passe (donc une mauvaise ancienne clé) doit faire
    /// échouer TOUTE l'opération — jamais un résultat partiellement re-chiffré ou silencieusement
    /// corrompu.
    #[test]
    fn test_prepare_password_change_fails_with_wrong_old_password() {
        let email = "user@example.com";
        let real_old_password = "bon_ancien_mot_de_passe";
        let wrong_old_password = "mauvais_ancien_mot_de_passe";

        let real_old_keys = crypto::derive_keys(email, real_old_password);
        let ciphertext = crypto::encrypt_field(&real_old_keys.vault_key, "contenu_secret").unwrap();

        let result = prepare_password_change(
            email.to_string(),
            wrong_old_password.to_string(),
            "nouveau_mot_de_passe".to_string(),
            vec![ciphertext],
        );

        assert!(result.is_err(), "un mauvais ancien mot de passe doit faire échouer tout le re-chiffrement");
    }

    /// Une liste de ciphertexts vide (compte sans aucune entrée) est un cas valide, pas une
    /// erreur — le changement de mot de passe doit fonctionner même pour un coffre vide.
    #[test]
    fn test_prepare_password_change_handles_empty_vault() {
        let result = prepare_password_change(
            "user@example.com".to_string(),
            "ancien_mot_de_passe".to_string(),
            "nouveau_mot_de_passe".to_string(),
            vec![],
        )
        .expect("un coffre vide ne doit jamais faire échouer le changement de mot de passe");

        assert!(result.reencrypted_ciphertexts.is_empty());
        assert_ne!(result.old_auth_hash, result.new_auth_hash);
    }
}
