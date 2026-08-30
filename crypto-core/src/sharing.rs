// =========================================================================
// PARTAGE SÉCURISÉ D'UNE ENTRÉE — boîte scellée, même primitive que l'accès d'urgence
// =========================================================================
// Permet à l'OWNER d'une entrée du coffre de la partager INSTANTANÉMENT avec un autre utilisateur
// (pas de délai d'attente, contrairement à l'accès d'urgence — voir emergency.rs) : il chiffre le
// contenu en clair de l'entrée (JSON) à destination de la clé publique X25519 du destinataire,
// sans avoir besoin d'une paire de clés lui-même. Réutilise le MÊME trousseau de clés X25519 par
// utilisateur que l'accès d'urgence (table `user_keys` côté backend, voir
// EmergencyRepository::get_public_key/get_own_keys) — un seul trousseau par compte, pour les deux
// usages — mais avec un contexte HKDF DIFFÉRENT (INFO_SHARE_SEAL, ci-dessous), pour que les deux
// usages restent cryptographiquement étanches l'un de l'autre (voir
// emergency::derive_key_or_reject() pour le raisonnement complet). Voir handlers/sharing.rs côté
// backend pour le flux complet (création, révocation).
//
// Pas de nouvel état Tauri persistant nécessaire (contrairement à EmergencyVaultKeyState) : chaque
// opération est ponctuelle — sceller un texte déjà en clair côté appelant, ou desceller un blob
// pour l'afficher une fois — jamais une session "déverrouillée" qui reste ouverte entre-temps.

use crate::emergency;

const INFO_SHARE_SEAL: &[u8] = b"passmanager-share-seal-v1";

/// Chiffre `plaintext` (typiquement le JSON d'une entrée en clair, voir lib/entrySharing.ts côté
/// frontend) pour le détenteur de `recipient_public_key_b64`.
pub fn seal_for_share(plaintext: &str, recipient_public_key_b64: &str) -> Result<String, String> {
    emergency::seal_with_info(plaintext, recipient_public_key_b64, INFO_SHARE_SEAL)
}

/// Déchiffre un blob produit par seal_for_share(), avec la clé privée du destinataire.
pub fn unseal_share(sealed_b64: &str, recipient_private_key_b64: &str) -> Result<String, String> {
    emergency::unseal_with_info(sealed_b64, recipient_private_key_b64, INFO_SHARE_SEAL)
}

// =========================================================================
// TESTS
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    #[test]
    fn test_seal_unseal_roundtrip() {
        let (public_key, private_key) = emergency::generate_keypair();
        let plaintext = r#"{"siteName":"Netflix","password":"hunter2"}"#;

        let sealed = seal_for_share(plaintext, &public_key).expect("le scellement doit réussir");
        assert_ne!(sealed, plaintext, "le blob scellé ne doit jamais contenir le texte en clair tel quel");

        let recovered = unseal_share(&sealed, &private_key).expect("le descellement avec la bonne clé privée doit réussir");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_unseal_fails_with_wrong_private_key() {
        let (public_key, _) = emergency::generate_keypair();
        let (_, wrong_private_key) = emergency::generate_keypair();

        let sealed = seal_for_share("secret", &public_key).unwrap();
        let result = unseal_share(&sealed, &wrong_private_key);
        assert!(result.is_err(), "descellement avec la MAUVAISE clé privée doit échouer, jamais renvoyer un contenu incorrect silencieusement");
    }

    /// RÉGRESSION CRITIQUE : un blob scellé pour l'accès d'urgence (emergency::seal, INFO_SEAL) ne
    /// doit JAMAIS pouvoir se desceller comme un partage d'entrée (unseal_share, INFO_SHARE_SEAL),
    /// et réciproquement — même avec la MÊME paire de clés (le trousseau est partagé entre les deux
    /// usages). Prouve que la séparation par contexte HKDF fonctionne réellement, pas juste en
    /// théorie : sans elle, un blob scellé pour un usage pourrait se retrouver interprété comme
    /// appartenant à l'autre si jamais l'un des deux flux venait à mal border son propre type de
    /// contenu (ex: JSON d'entrée VS clé de coffre encodée en base64, toutes deux de simples
    /// chaînes du point de vue du chiffrement).
    #[test]
    fn test_share_and_emergency_seals_are_cryptographically_isolated() {
        let (public_key, private_key) = emergency::generate_keypair();

        let sealed_for_emergency = emergency::seal("clé de coffre", &public_key).unwrap();
        assert!(
            unseal_share(&sealed_for_emergency, &private_key).is_err(),
            "un blob scellé pour l'accès d'urgence ne doit jamais se desceller comme un partage d'entrée"
        );

        let sealed_for_share = seal_for_share("contenu d'entrée partagée", &public_key).unwrap();
        assert!(
            emergency::unseal(&sealed_for_share, &private_key).is_err(),
            "un blob scellé pour un partage d'entrée ne doit jamais se desceller comme un accès d'urgence"
        );
    }

    #[test]
    fn test_seal_produces_different_output_each_time() {
        let (public_key, _) = emergency::generate_keypair();
        let a = seal_for_share("meme_contenu", &public_key).unwrap();
        let b = seal_for_share("meme_contenu", &public_key).unwrap();
        assert_ne!(a, b, "clé éphémère + nonce aléatoires à chaque appel : jamais le même blob deux fois");
    }

    #[test]
    fn test_unseal_rejects_tampered_blob() {
        let (public_key, private_key) = emergency::generate_keypair();
        let sealed = seal_for_share("contenu original", &public_key).unwrap();

        let mut tampered: Vec<u8> = BASE64.decode(&sealed).unwrap();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        let tampered_b64 = BASE64.encode(tampered);

        let result = unseal_share(&tampered_b64, &private_key);
        assert!(result.is_err(), "un blob altéré doit être rejeté par l'authentification GCM");
    }
}
