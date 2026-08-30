// =========================================================================
// ACCÈS D'URGENCE — boîte scellée (chiffrement anonyme vers une clé publique)
// =========================================================================
// Permet au PROPRIÉTAIRE d'un coffre de chiffrer sa clé de coffre à destination d'un contact de
// confiance, de façon à ce que SEUL ce contact (détenteur de la clé privée correspondante) puisse
// la déchiffrer plus tard — ni l'expéditeur, ni le serveur qui relaie/stocke le blob, ni un tiers
// qui l'intercepterait ne peuvent le lire. C'est ce qui permet à un accès d'urgence de fonctionner
// SANS que le propriétaire n'ait jamais à révéler son mot de passe maître au contact : il chiffre
// une seule fois sa clé de coffre pour ce contact, et c'est tout — voir handlers/emergency.rs côté
// backend pour le flux complet (invitation, délai d'attente, approbation/refus).
//
// Construction inspirée de crypto_box_seal (libsodium), mais avec les primitives déjà utilisées
// ailleurs dans cette app (X25519 + HKDF-SHA256 + AES-256-GCM) plutôt que XSalsa20-Poly1305 — pour
// rester cohérent avec crypto.rs plutôt que d'introduire une famille d'algorithmes de plus.
//
// FORMAT du blob scellé (avant base64) :
//   clé publique ÉPHÉMÈRE (32 octets) || nonce AES-GCM (12 octets) || ciphertext+tag GCM
//
// L'expéditeur n'a besoin QUE de la clé publique du destinataire pour chiffrer (chiffrement
// "anonyme" : pas de paire de clés à lui côté expéditeur) — une nouvelle paire de clés ÉPHÉMÈRE
// est générée à CHAQUE appel de seal(), le secret partagé Diffie-Hellman n'est donc jamais
// réutilisé d'un appel à l'autre, même vers le même destinataire.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};
use zeroize::Zeroize;

const INFO_SEAL: &[u8] = b"passmanager-emergency-seal-v1";

/// Garde-fou : un secret partagé "non contributif" (point à l'infini) peut survenir si une des
/// deux clés publiques impliquées est dégénérée (ex: falsifiée par un serveur compromis qui
/// relaierait une clé publique malveillante) — dans ce cas, le secret partagé résultant devient
/// prévisible/nul, ce qui casserait toute la sécurité du chiffrement qui en dépend. Recommandé par
/// la documentation de x25519-dalek pour les protocoles qui en dépendent, comme celui-ci.
///
/// `info` : contexte HKDF — voir seal_with_info()/unseal_with_info() ci-dessous. DEUX usages
/// différents (accès d'urgence ICI, partage d'entrée voir sharing.rs) réutilisent le MÊME
/// trousseau de clés X25519 par utilisateur ; `info` les sépare cryptographiquement l'un de
/// l'autre — un blob scellé pour l'un ne peut jamais se desceller comme appartenant à l'autre,
/// même si le même échange Diffie-Hellman était rejoué (il ne l'est jamais ici, chaque seal()
/// génère une clé éphémère fraîche, mais la séparation par contexte reste la bonne hygiène
/// cryptographique dès que plusieurs usages partagent un même trousseau de clés statiques).
fn derive_key_or_reject(shared: &SharedSecret, info: &[u8]) -> Result<[u8; 32], String> {
    if !shared.was_contributory() {
        return Err("Échange de clé invalide (clé publique dégénérée)".to_string());
    }
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared.as_bytes())
        .expand(info, &mut key)
        .map_err(|_| "Échec de la dérivation de clé".to_string())?;
    Ok(key)
}

fn decode_public_key(b64: &str) -> Result<PublicKey, String> {
    let bytes: [u8; 32] = BASE64
        .decode(b64)
        .map_err(|_| "Clé publique invalide (base64)".to_string())?
        .try_into()
        .map_err(|_| "Clé publique invalide (longueur)".to_string())?;
    Ok(PublicKey::from(bytes))
}

/// Génère une nouvelle paire de clés X25519 — appelée une fois par utilisateur, à la première
/// configuration de l'accès d'urgence. Renvoie (clé publique base64, clé privée base64). La clé
/// privée doit être CHIFFRÉE par l'appelant (avec la clé du coffre, voir crypto::encrypt_field)
/// avant d'être envoyée au serveur : cette fonction ne fait QUE générer la paire, jamais l'envoi.
pub fn generate_keypair() -> (String, String) {
    let secret = StaticSecret::random();
    let public = PublicKey::from(&secret);
    let public_b64 = BASE64.encode(public.to_bytes());
    let private_b64 = BASE64.encode(secret.to_bytes());
    (public_b64, private_b64)
}

/// Chiffre `plaintext` pour le détenteur de `recipient_public_key_b64`, sans avoir besoin d'une
/// paire de clés côté expéditeur (chiffrement anonyme, comme crypto_box_seal). `info` : contexte
/// HKDF de séparation cryptographique — voir derive_key_or_reject(). Pas `pub` : les appelants
/// externes à ce crate passent par seal() (accès d'urgence) ou sharing::seal_for_share() (partage
/// d'entrée), jamais directement, pour ne jamais risquer un `info` incohérent avec l'usage réel.
pub(crate) fn seal_with_info(plaintext: &str, recipient_public_key_b64: &str, info: &[u8]) -> Result<String, String> {
    let recipient_public = decode_public_key(recipient_public_key_b64)?;

    let ephemeral_secret = EphemeralSecret::random();
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(&recipient_public);
    let mut key = derive_key_or_reject(&shared, info)?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    key.zeroize();

    let mut nonce_bytes = [0u8; 12];
    rand::fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| "Échec du chiffrement".to_string())?;

    let mut blob = Vec::with_capacity(32 + 12 + ciphertext.len());
    blob.extend_from_slice(ephemeral_public.as_bytes());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(blob))
}

/// Déchiffre un blob produit par seal_with_info(), avec la clé privée du destinataire — `info`
/// DOIT être celui utilisé au scellement, sinon la dérivation de clé échoue (donnée par le GCM tag
/// invalide, jamais une confusion silencieuse entre les deux usages). Pas `pub`, même raison que
/// seal_with_info() ci-dessus.
pub(crate) fn unseal_with_info(sealed_b64: &str, recipient_private_key_b64: &str, info: &[u8]) -> Result<String, String> {
    let private_bytes: [u8; 32] = BASE64
        .decode(recipient_private_key_b64)
        .map_err(|_| "Clé privée invalide (base64)".to_string())?
        .try_into()
        .map_err(|_| "Clé privée invalide (longueur)".to_string())?;
    let recipient_secret = StaticSecret::from(private_bytes);

    let blob = BASE64.decode(sealed_b64).map_err(|_| "Blob scellé invalide (base64)".to_string())?;
    if blob.len() < 32 + 12 {
        return Err("Blob scellé trop court".to_string());
    }
    let (ephemeral_public_bytes, rest) = blob.split_at(32);
    let (nonce_bytes, ciphertext) = rest.split_at(12);

    // Taille garantie par le split_at(32) ci-dessus (la vérification de longueur globale plus
    // haut assure qu'il y a bien au moins 32 octets disponibles pour cette tranche).
    let ephemeral_public = PublicKey::from(<[u8; 32]>::try_from(ephemeral_public_bytes).unwrap());
    let shared = recipient_secret.diffie_hellman(&ephemeral_public);
    let mut key = derive_key_or_reject(&shared, info)?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    key.zeroize();
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Échec du déchiffrement (mauvaise clé ou donnée corrompue)".to_string())?;

    String::from_utf8(plaintext).map_err(|_| "Contenu déchiffré invalide (UTF-8)".to_string())
}

/// Chiffre `plaintext` pour le détenteur de `recipient_public_key_b64`, dans le contexte de
/// l'accès d'urgence (voir INFO_SEAL). Signature/comportement inchangés — voir seal_with_info().
pub fn seal(plaintext: &str, recipient_public_key_b64: &str) -> Result<String, String> {
    seal_with_info(plaintext, recipient_public_key_b64, INFO_SEAL)
}

/// Déchiffre un blob produit par seal(), avec la clé privée du destinataire. Signature/comportement
/// inchangés — voir unseal_with_info().
pub fn unseal(sealed_b64: &str, recipient_private_key_b64: &str) -> Result<String, String> {
    unseal_with_info(sealed_b64, recipient_private_key_b64, INFO_SEAL)
}

// =========================================================================
// TESTS
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_unseal_roundtrip() {
        let (public_key, private_key) = generate_keypair();
        let plaintext = "clé de coffre en base64, ou n'importe quel secret";

        let sealed = seal(plaintext, &public_key).expect("le scellement doit réussir");
        assert_ne!(sealed, plaintext, "le blob scellé ne doit jamais contenir le texte en clair tel quel");

        let recovered = unseal(&sealed, &private_key).expect("le descellement avec la bonne clé privée doit réussir");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_unseal_fails_with_wrong_private_key() {
        let (public_key, _) = generate_keypair();
        let (_, wrong_private_key) = generate_keypair();

        let sealed = seal("secret", &public_key).unwrap();
        let result = unseal(&sealed, &wrong_private_key);
        assert!(result.is_err(), "descellement avec la MAUVAISE clé privée doit échouer, jamais renvoyer un contenu incorrect silencieusement");
    }

    #[test]
    fn test_seal_produces_different_output_each_time() {
        let (public_key, _) = generate_keypair();
        let a = seal("meme_contenu", &public_key).unwrap();
        let b = seal("meme_contenu", &public_key).unwrap();
        assert_ne!(a, b, "clé éphémère + nonce aléatoires à chaque appel : jamais le même blob deux fois");
    }

    #[test]
    fn test_generate_keypair_produces_valid_x25519_keys() {
        let (public_key, private_key) = generate_keypair();
        // Vérifie qu'un aller-retour DH complet fonctionne avec CETTE paire précisément — pas
        // juste que les chaînes ont la bonne forme.
        let sealed = seal("test", &public_key).unwrap();
        assert!(unseal(&sealed, &private_key).is_ok());
    }

    #[test]
    fn test_seal_rejects_invalid_public_key() {
        let result = seal("secret", "!!!pas du base64 valide!!!");
        assert!(result.is_err());

        let result = seal("secret", &BASE64.encode(b"trop court"));
        assert!(result.is_err(), "une clé publique d'une mauvaise longueur doit être rejetée proprement");
    }

    #[test]
    fn test_unseal_rejects_tampered_blob() {
        let (public_key, private_key) = generate_keypair();
        let sealed = seal("contenu original", &public_key).unwrap();

        let mut tampered: Vec<u8> = BASE64.decode(&sealed).unwrap();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        let tampered_b64 = BASE64.encode(tampered);

        let result = unseal(&tampered_b64, &private_key);
        assert!(result.is_err(), "un blob altéré doit être rejeté par l'authentification GCM");
    }

    #[test]
    fn test_unseal_rejects_too_short_blob() {
        let (_, private_key) = generate_keypair();
        let result = unseal(&BASE64.encode(b"trop court"), &private_key);
        assert!(result.is_err(), "un blob plus court que clé éphémère + nonce doit être rejeté proprement, jamais paniquer");
    }
}
