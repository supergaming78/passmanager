// =========================================================================
// PARTAGE À USAGE LIMITÉ ("AVEUGLE") — boîte scellée, même primitive que les deux autres modes de
// partage
// =========================================================================
// Le destinataire ne voit JAMAIS l'identifiant ni le mot de passe — seulement le nom du site — et
// ne peut déclencher un "usage" (remplissage automatique) qu'un nombre de fois limité choisi par
// l'expéditeur. Deux scellements SÉPARÉS (voir handlers/blind_share.rs côté backend pour le détail
// du pourquoi) : le nom du site (librement consultable) et les identifiants (gardés derrière le
// compteur d'usages, décrémenté atomiquement côté serveur) — mais tous deux passent par les MÊMES
// fonctions ci-dessous, seul le contenu scellé diffère selon l'appelant.
//
// Contexte HKDF ENCORE différent des trois autres usages (INFO_SEAL pour l'accès d'urgence,
// INFO_SHARE_SEAL pour le partage classique, INFO_SHARED_VAULT_SEAL pour les coffres partagés) —
// voir emergency::derive_key_or_reject() pour le raisonnement complet sur la séparation par
// domaine d'un trousseau partagé entre plusieurs usages.

use crate::emergency;

const INFO_BLIND_SHARE_SEAL: &[u8] = b"passmanager-blind-share-seal-v1";

/// Scelle `plaintext` (le nom du site EN CLAIR, ou le JSON des identifiants — voir
/// lib/blindShare.ts côté frontend pour les deux usages distincts) pour le détenteur de
/// `recipient_public_key_b64`.
pub fn seal_for_blind_share(plaintext: &str, recipient_public_key_b64: &str) -> Result<String, String> {
    emergency::seal_with_info(plaintext, recipient_public_key_b64, INFO_BLIND_SHARE_SEAL)
}

/// Déchiffre un blob produit par seal_for_blind_share(), avec la clé privée du destinataire.
pub fn unseal_blind_share(sealed_b64: &str, recipient_private_key_b64: &str) -> Result<String, String> {
    emergency::unseal_with_info(sealed_b64, recipient_private_key_b64, INFO_BLIND_SHARE_SEAL)
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
        let plaintext = r#"{"username":"jean","password":"hunter2"}"#;

        let sealed = seal_for_blind_share(plaintext, &public_key).expect("le scellement doit réussir");
        assert_ne!(sealed, plaintext, "le blob scellé ne doit jamais contenir le texte en clair tel quel");

        let recovered = unseal_blind_share(&sealed, &private_key).expect("le descellement avec la bonne clé privée doit réussir");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_unseal_fails_with_wrong_private_key() {
        let (public_key, _) = emergency::generate_keypair();
        let (_, wrong_private_key) = emergency::generate_keypair();

        let sealed = seal_for_blind_share("secret", &public_key).unwrap();
        let result = unseal_blind_share(&sealed, &wrong_private_key);
        assert!(result.is_err(), "descellement avec la MAUVAISE clé privée doit échouer, jamais renvoyer un contenu incorrect silencieusement");
    }

    /// RÉGRESSION CRITIQUE, même principe que les tests équivalents dans sharing.rs/shared_vault.rs :
    /// un blob scellé pour un usage ne doit jamais se desceller comme appartenant à un AUTRE usage,
    /// même avec la même paire de clés (le trousseau est partagé entre les QUATRE usages).
    #[test]
    fn test_blind_share_seal_is_isolated_from_other_usages() {
        let (public_key, private_key) = emergency::generate_keypair();

        let sealed_for_emergency = emergency::seal("clé de coffre", &public_key).unwrap();
        assert!(unseal_blind_share(&sealed_for_emergency, &private_key).is_err());

        let sealed_for_share = crate::sharing::seal_for_share("contenu d'entrée partagée", &public_key).unwrap();
        assert!(unseal_blind_share(&sealed_for_share, &private_key).is_err());

        let sealed_for_shared_vault = crate::shared_vault::seal_for_shared_vault("clé de coffre partagé", &public_key).unwrap();
        assert!(unseal_blind_share(&sealed_for_shared_vault, &private_key).is_err());

        let sealed_for_blind = seal_for_blind_share("identifiants", &public_key).unwrap();
        assert!(emergency::unseal(&sealed_for_blind, &private_key).is_err());
        assert!(crate::sharing::unseal_share(&sealed_for_blind, &private_key).is_err());
        assert!(crate::shared_vault::unseal_shared_vault(&sealed_for_blind, &private_key).is_err());
    }

    #[test]
    fn test_seal_produces_different_output_each_time() {
        let (public_key, _) = emergency::generate_keypair();
        let a = seal_for_blind_share("meme_contenu", &public_key).unwrap();
        let b = seal_for_blind_share("meme_contenu", &public_key).unwrap();
        assert_ne!(a, b, "clé éphémère + nonce aléatoires à chaque appel : jamais le même blob deux fois");
    }

    #[test]
    fn test_unseal_rejects_tampered_blob() {
        let (public_key, private_key) = emergency::generate_keypair();
        let sealed = seal_for_blind_share("contenu original", &public_key).unwrap();

        let mut tampered: Vec<u8> = BASE64.decode(&sealed).unwrap();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        let tampered_b64 = BASE64.encode(tampered);

        let result = unseal_blind_share(&tampered_b64, &private_key);
        assert!(result.is_err(), "un blob altéré doit être rejeté par l'authentification GCM");
    }
}
