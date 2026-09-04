// =========================================================================
// ÉTAT EN MÉMOIRE DU COFFRE (CLÉ DE CHIFFREMENT)
// =========================================================================
// Géré par Tauri (voir lib.rs::run() -> .manage(...)), injecté dans chaque commande qui en a
// besoin. C'est le SEUL endroit où la clé de chiffrement du coffre existe une fois dérivée —
// jamais transmise au JS, jamais écrite sur disque. `None` = coffre verrouillé (état initial au
// démarrage, et après logout/verrouillage explicite).

use std::sync::Mutex;
use zeroize::Zeroize;
use crate::crypto::KEY_LEN;

#[derive(Default)]
pub struct VaultKeyState(Mutex<Option<[u8; KEY_LEN]>>);

// CORRECTIF SÉCURITÉ/ROBUSTESSE : `.lock().expect(...)` paniquait auparavant si le mutex était
// empoisonné (un panic survenu PENDANT que le verrou était tenu, même par du code ajouté plus
// tard/sans rapport). Une fois empoisonné, TOUS les appels suivants — verrouiller, déverrouiller,
// chiffrer, déchiffrer — paniquaient à leur tour, pour le reste de la durée de vie du processus :
// un déni de service auto-infligé et irréversible sur le coffre entier (redémarrage obligatoire),
// et un risque accru qu'une terminaison brutale laisse la clé en mémoire sans passage par
// zeroize(). `unwrap_or_else(PoisonError::into_inner)` récupère la valeur malgré l'empoisonnement
// plutôt que de propager la panique — sûr ici car chaque opération sur `Option<[u8; KEY_LEN]>` est
// une simple affectation/lecture, jamais un état partiellement écrit observable de l'extérieur.
fn lock_recovering_from_poison(mutex: &Mutex<Option<[u8; KEY_LEN]>>) -> std::sync::MutexGuard<'_, Option<[u8; KEY_LEN]>> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl VaultKeyState {
    /// Déverrouille le coffre avec une clé fraîchement dérivée (voir crypto::derive_keys()).
    pub fn set(&self, key: [u8; KEY_LEN]) {
        let mut guard = lock_recovering_from_poison(&self.0);
        *guard = Some(key);
    }

    /// Copie la clé actuellement en mémoire, si le coffre est déverrouillé. L'appelant est
    /// responsable d'effacer (zeroize) sa copie locale une fois l'opération terminée — voir les
    /// commandes encrypt_vault_field()/decrypt_vault_field() dans lib.rs.
    pub fn get(&self) -> Option<[u8; KEY_LEN]> {
        *lock_recovering_from_poison(&self.0)
    }

    /// Verrouille le coffre : efface la clé de la mémoire (zeroize, pas juste `= None`, pour ne
    /// pas laisser les octets de la clé traîner dans une page mémoire déjà libérée).
    pub fn clear(&self) {
        let mut guard = lock_recovering_from_poison(&self.0);
        if let Some(mut key) = guard.take() {
            key.zeroize();
        }
    }

    pub fn is_unlocked(&self) -> bool {
        lock_recovering_from_poison(&self.0).is_some()
    }
}

/// Pendant de VaultKeyState, mais pour la clé d'un coffre D'AUTRUI consultée via l'accès
/// d'urgence (voir emergency.rs) — un type DISTINCT (Tauri route les commandes par type d'état,
/// voir lib.rs::run() -> .manage()) pour ne JAMAIS pouvoir confondre "la clé de mon coffre" et "la
/// clé du coffre de quelqu'un d'autre que je consulte en urgence", même par erreur de câblage
/// d'une commande. `None` = pas de consultation d'urgence en cours (état initial, et après
/// lock_emergency_vault()).
/// Pendant de VaultKeyState pour la clé retrouvée via le KIT DE RÉCUPÉRATION (voir
/// crypto-core/src/recovery.rs). Type DISTINCT pour la même raison qu'EmergencyVaultKeyState
/// ci-dessous : Tauri route les commandes par TYPE d'état, si bien qu'une commande de récupération
/// ne peut pas, même par erreur de câblage, recevoir la clé du coffre local — ni l'inverse.
///
/// La distinction compte particulièrement ici : pendant une récupération, le coffre LOCAL est
/// verrouillé (l'utilisateur a justement oublié son mot de passe), alors que cette clé-là, elle,
/// est déverrouillée. Les confondre re-chiffrerait le coffre avec la mauvaise clé.
#[derive(Default)]
pub struct RecoveryVaultKeyState(VaultKeyState);

impl RecoveryVaultKeyState {
    pub fn set(&self, key: [u8; KEY_LEN]) {
        self.0.set(key);
    }
    pub fn get(&self) -> Option<[u8; KEY_LEN]> {
        self.0.get()
    }
    pub fn clear(&self) {
        self.0.clear();
    }
}

#[derive(Default)]
pub struct EmergencyVaultKeyState(VaultKeyState);

impl EmergencyVaultKeyState {
    pub fn set(&self, key: [u8; KEY_LEN]) {
        self.0.set(key);
    }
    pub fn get(&self) -> Option<[u8; KEY_LEN]> {
        self.0.get()
    }
    pub fn clear(&self) {
        self.0.clear();
    }
    pub fn is_unlocked(&self) -> bool {
        self.0.is_unlocked()
    }
}
