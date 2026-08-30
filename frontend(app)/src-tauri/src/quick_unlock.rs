// =========================================================================
// DÉVERROUILLAGE RAPIDE (Windows uniquement) — voir dpapi.rs pour la protection DPAPI du blob de
// clé, et VaultLockScreen.tsx côté frontend pour le bouton "Déverrouiller avec Windows Hello".
// =========================================================================
// Le flux complet :
//   1. enable() : depuis un coffre DÉJÀ déverrouillé (mot de passe maître saisi normalement),
//      protège la clé actuellement en mémoire via DPAPI et l'écrit dans un fichier local.
//   2. try_unlock() : demande une vérification Windows Hello (empreinte/visage/code PIN — un
//      geste RÉEL est redemandé à CHAQUE tentative, ce n'est PAS juste "le compte Windows est déjà
//      connecté") PUIS, seulement si elle réussit, lit et déchiffre ce fichier pour recharger la
//      clé en mémoire — sans jamais redemander le mot de passe maître.
//   3. disable() : supprime le fichier — appelé automatiquement à la déconnexion et à tout
//      changement de mot de passe maître (la clé change, l'ancien blob deviendrait trompeur).
//
// Le mot de passe maître reste TOUJOURS utilisable en repli (voir unlockVault() côté
// AuthContext.tsx) : ce mécanisme ne le remplace jamais, il ne fait qu'éviter d'avoir à le
// ressaisir dans le cas courant.
#![cfg(target_os = "windows")]

use crate::{crypto::KEY_LEN, dpapi, state::VaultKeyState};
use tauri::{AppHandle, Manager};
use windows::core::HSTRING;
use windows::Security::Credentials::UI::{UserConsentVerificationResult, UserConsentVerifier};
use zeroize::Zeroize;

const FILE_NAME: &str = "quick_unlock.bin";

fn file_path(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|_| "Impossible de localiser le dossier de données de l'application".to_string())?;
    std::fs::create_dir_all(&dir).map_err(|_| "Impossible de créer le dossier de données de l'application".to_string())?;
    Ok(dir.join(FILE_NAME))
}

/// Le déverrouillage rapide est-il activé (le fichier existe) ? Le fichier lui-même fait foi —
/// pas un simple drapeau côté frontend qui pourrait se désynchroniser (ex: fichier supprimé
/// manuellement en dehors de l'app).
pub fn is_available(app: &AppHandle) -> bool {
    file_path(app).map(|p| p.exists()).unwrap_or(false)
}

/// Protège la clé ACTUELLEMENT en mémoire (le coffre doit déjà être déverrouillé, via le mot de
/// passe maître saisi normalement) et l'écrit sur disque.
pub fn enable(app: &AppHandle, vault_state: &VaultKeyState) -> Result<(), String> {
    let mut key = vault_state
        .get()
        .ok_or_else(|| "Le coffre doit être déverrouillé pour activer le déverrouillage rapide".to_string())?;
    let protected = dpapi::protect(&key);
    key.zeroize();
    let protected = protected?;

    let path = file_path(app)?;
    std::fs::write(&path, &protected).map_err(|_| "Impossible d'écrire le fichier de déverrouillage rapide".to_string())
}

/// Supprime le fichier — best-effort (une absence de fichier n'est pas une erreur, ex: déjà
/// désactivé, ou jamais activé).
pub fn disable(app: &AppHandle) {
    if let Ok(path) = file_path(app) {
        let _ = std::fs::remove_file(path);
    }
}

/// Demande une vérification Windows Hello, PUIS recharge la clé du coffre en mémoire si elle
/// réussit. `message` est le texte affiché dans l'invite système.
pub async fn try_unlock(app: &AppHandle, vault_state: &VaultKeyState, message: &str) -> Result<(), String> {
    let path = file_path(app)?;
    let protected = std::fs::read(&path).map_err(|_| "Déverrouillage rapide non configuré sur cet appareil".to_string())?;

    let result = UserConsentVerifier::RequestVerificationAsync(&HSTRING::from(message))
        .map_err(|_| "Windows Hello n'est pas disponible sur cet appareil".to_string())?
        .await
        .map_err(|_| "Échec de la vérification Windows Hello".to_string())?;

    if result != UserConsentVerificationResult::Verified {
        return Err(describe_failure(result));
    }

    // AUTO-RÉPARATION : si le blob ne se déchiffre pas (compte Windows différent, fichier
    // corrompu, OU — vécu en pratique — un ancien blob scellé avant un changement de format DPAPI
    // comme l'ajout de pbOptionalEntropy, voir dpapi.rs) ou a la mauvaise taille, ce fichier ne
    // redeviendra JAMAIS valide tout seul : le supprimer immédiatement fait disparaître le bouton
    // "Déverrouiller avec Windows Hello" au prochain écran de verrouillage (is_available() se fie
    // à l'existence du fichier) plutôt que de le re-proposer indéfiniment en échec. L'utilisateur
    // peut toujours réactiver le déverrouillage rapide depuis Réglages une fois le coffre
    // déverrouillé normalement (mot de passe maître, toujours utilisable en repli).
    let mut decrypted = match dpapi::unprotect(&protected) {
        Ok(d) => d,
        Err(e) => {
            disable(app);
            return Err(e);
        }
    };
    if decrypted.len() != KEY_LEN {
        decrypted.zeroize();
        disable(app);
        return Err("Fichier de déverrouillage rapide corrompu".to_string());
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&decrypted);
    decrypted.zeroize();

    vault_state.set(key);
    Ok(())
}

fn describe_failure(result: UserConsentVerificationResult) -> String {
    match result {
        UserConsentVerificationResult::Canceled => "Vérification annulée".to_string(),
        UserConsentVerificationResult::DeviceNotPresent => "Aucun capteur Windows Hello disponible sur cet appareil".to_string(),
        UserConsentVerificationResult::NotConfiguredForUser => "Windows Hello n'est pas configuré pour ce compte Windows".to_string(),
        UserConsentVerificationResult::DisabledByPolicy => "Windows Hello est désactivé par une stratégie système".to_string(),
        UserConsentVerificationResult::DeviceBusy => "Le capteur Windows Hello est occupé, réessaie dans un instant".to_string(),
        UserConsentVerificationResult::RetriesExhausted => "Trop de tentatives échouées, réessaie plus tard".to_string(),
        _ => "Vérification Windows Hello refusée".to_string(),
    }
}
