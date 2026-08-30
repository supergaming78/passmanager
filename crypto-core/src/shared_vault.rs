// =========================================================================
// COFFRE PARTAGÉ FAMILIAL — boîte scellée, même primitive que l'accès d'urgence/le partage
// =========================================================================
// Scelle la CLÉ SYMÉTRIQUE d'un coffre partagé (générée une fois à sa création, voir
// lib/sharedVault.ts côté frontend) pour un membre donné — chaque membre reçoit ainsi sa PROPRE
// copie chiffrée de la MÊME clé sous-jacente, via son trousseau X25519 personnel (le même que
// l'accès d'urgence/le partage d'entrée, table `user_keys` côté backend). C'est ce qui permet à
// n'importe quel membre de déchiffrer n'importe quelle entrée du coffre partagé — une modification
// par un membre est donc visible IMMÉDIATEMENT par tous les autres, sans re-partage individuel
// (contrairement à sharing.rs, qui scelle le CONTENU d'une entrée, une fois par destinataire).
//
// Contexte HKDF DIFFÉRENT des deux autres usages (INFO_SEAL pour l'accès d'urgence,
// INFO_SHARE_SEAL pour le partage d'entrée) — voir emergency::derive_key_or_reject() pour le
// raisonnement complet sur la séparation par domaine d'un trousseau partagé entre plusieurs
// usages. Voir handlers/shared_vault.rs côté backend pour le flux complet.

use crate::crypto::KEY_LEN;
use crate::emergency;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

const INFO_SHARED_VAULT_SEAL: &[u8] = b"passmanager-shared-vault-seal-v1";

/// Génère une nouvelle clé symétrique AES-256 aléatoire pour un coffre partagé — appelée UNE
/// SEULE FOIS, à la création du coffre (voir lib/sharedVault.ts côté frontend). Contrairement à
/// la clé du coffre PERSONNEL (dérivée du mot de passe maître, voir crypto::derive_keys), cette
/// clé n'est dérivée de RIEN : elle doit être scellée pour chaque membre (voir
/// seal_for_shared_vault ci-dessous) au moment même de sa génération, sous peine d'être perdue
/// définitivement (aucun mot de passe ne permet de la retrouver). Renvoyée encodée en base64,
/// prête à être passée telle quelle à seal_for_shared_vault()/crypto::encrypt_field.
pub fn generate_vault_key() -> String {
    let mut key = [0u8; KEY_LEN];
    rand::fill(&mut key);
    BASE64.encode(key)
}

/// Scelle `plaintext` (typiquement la clé symétrique du coffre partagé, encodée en base64) pour
/// le détenteur de `recipient_public_key_b64`.
pub fn seal_for_shared_vault(plaintext: &str, recipient_public_key_b64: &str) -> Result<String, String> {
    emergency::seal_with_info(plaintext, recipient_public_key_b64, INFO_SHARED_VAULT_SEAL)
}

/// Déchiffre un blob produit par seal_for_shared_vault(), avec la clé privée du destinataire.
pub fn unseal_shared_vault(sealed_b64: &str, recipient_private_key_b64: &str) -> Result<String, String> {
    emergency::unseal_with_info(sealed_b64, recipient_private_key_b64, INFO_SHARED_VAULT_SEAL)
}

// =========================================================================
// TESTS
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_vault_key_produces_distinct_full_length_keys() {
        let a = generate_vault_key();
        let b = generate_vault_key();
        assert_ne!(a, b, "deux appels ne doivent jamais produire la même clé");
        assert_eq!(BASE64.decode(&a).unwrap().len(), 32, "la clé doit faire exactement 32 octets une fois décodée");
    }

    #[test]
    fn test_seal_unseal_roundtrip() {
        let (public_key, private_key) = emergency::generate_keypair();
        let vault_key_b64 = "dGhpcyBpcyBhIGZha2Uga2V5IGZvciB0ZXN0aW5nIQ=="; // clé factice, 32 octets encodés

        let sealed = seal_for_shared_vault(vault_key_b64, &public_key).expect("le scellement doit réussir");
        assert_ne!(sealed, vault_key_b64, "le blob scellé ne doit jamais contenir la clé en clair telle quelle");

        let recovered = unseal_shared_vault(&sealed, &private_key).expect("le descellement avec la bonne clé privée doit réussir");
        assert_eq!(recovered, vault_key_b64);
    }

    #[test]
    fn test_unseal_fails_with_wrong_private_key() {
        let (public_key, _) = emergency::generate_keypair();
        let (_, wrong_private_key) = emergency::generate_keypair();

        let sealed = seal_for_shared_vault("clé de coffre partagé", &public_key).unwrap();
        let result = unseal_shared_vault(&sealed, &wrong_private_key);
        assert!(result.is_err(), "descellement avec la MAUVAISE clé privée doit échouer, jamais renvoyer un contenu incorrect silencieusement");
    }

    /// RÉGRESSION CRITIQUE, même principe que le test équivalent dans sharing.rs : un blob scellé
    /// pour un usage (accès d'urgence, partage d'entrée, coffre partagé) ne doit JAMAIS pouvoir se
    /// desceller comme appartenant à un AUTRE usage, même avec la même paire de clés (le trousseau
    /// est partagé entre les TROIS usages).
    #[test]
    fn test_shared_vault_seal_is_isolated_from_emergency_and_entry_sharing() {
        let (public_key, private_key) = emergency::generate_keypair();

        let sealed_for_emergency = emergency::seal("clé de coffre personnel", &public_key).unwrap();
        assert!(
            unseal_shared_vault(&sealed_for_emergency, &private_key).is_err(),
            "un blob scellé pour l'accès d'urgence ne doit jamais se desceller comme une clé de coffre partagé"
        );

        let sealed_for_share = crate::sharing::seal_for_share("contenu d'entrée partagée", &public_key).unwrap();
        assert!(
            unseal_shared_vault(&sealed_for_share, &private_key).is_err(),
            "un blob scellé pour un partage d'entrée ne doit jamais se desceller comme une clé de coffre partagé"
        );

        let sealed_for_shared_vault = seal_for_shared_vault("clé de coffre partagé", &public_key).unwrap();
        assert!(
            emergency::unseal(&sealed_for_shared_vault, &private_key).is_err(),
            "un blob scellé pour un coffre partagé ne doit jamais se desceller comme un accès d'urgence"
        );
        assert!(
            crate::sharing::unseal_share(&sealed_for_shared_vault, &private_key).is_err(),
            "un blob scellé pour un coffre partagé ne doit jamais se desceller comme un partage d'entrée"
        );
    }

    #[test]
    fn test_seal_produces_different_output_each_time() {
        let (public_key, _) = emergency::generate_keypair();
        let a = seal_for_shared_vault("meme_contenu", &public_key).unwrap();
        let b = seal_for_shared_vault("meme_contenu", &public_key).unwrap();
        assert_ne!(a, b, "clé éphémère + nonce aléatoires à chaque appel : jamais le même blob deux fois");
    }

    #[test]
    fn test_unseal_rejects_tampered_blob() {
        let (public_key, private_key) = emergency::generate_keypair();
        let sealed = seal_for_shared_vault("contenu original", &public_key).unwrap();

        let mut tampered: Vec<u8> = BASE64.decode(&sealed).unwrap();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        let tampered_b64 = BASE64.encode(tampered);

        let result = unseal_shared_vault(&tampered_b64, &private_key);
        assert!(result.is_err(), "un blob altéré doit être rejeté par l'authentification GCM");
    }
}
