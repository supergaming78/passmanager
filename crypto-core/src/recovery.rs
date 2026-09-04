// =========================================================================
// KIT DE RÉCUPÉRATION — retrouver son coffre après un mot de passe maître oublié
// =========================================================================
// LE PROBLÈME : la clé qui chiffre le coffre est DÉRIVÉE du mot de passe maître (voir
// crypto.rs::derive_keys). L'oublier revenait donc à perdre le coffre : /auth/reset-password ne
// pouvait que le vider intégralement, faute de la moindre clé pour re-chiffrer quoi que ce soit.
// L'accès d'urgence (emergency.rs) répond à un besoin voisin, mais suppose d'avoir désigné
// quelqu'un À L'AVANCE, et fait intervenir un tiers.
//
// LA RÉPONSE : un code de récupération aléatoire, généré une fois, à imprimer et ranger
// physiquement. La clé du coffre est scellée avec ce code (Argon2id + AES-256-GCM, voir
// crypto::seal_with_password) et le blob obtenu est confié au serveur — qui ne peut rien en faire :
// il ne voit jamais le code, seulement des octets scellés. Le modèle Zero-Knowledge est intact.
//
// À LA RÉCUPÉRATION, le code descelle la clé du coffre, ce qui permet de tout re-chiffrer avec la
// clé dérivée d'un NOUVEAU mot de passe maître — exactement la même mécanique qu'un changement de
// mot de passe volontaire (voir handlers/auth/account.rs::update_password côté serveur), sans rien
// perdre.
//
// CE QUE CE MÉCANISME N'EST PAS : une porte dérobée. Le serveur ne peut pas ouvrir le blob, et le
// code n'est stocké nulle part — s'il est perdu EN MÊME TEMPS que le mot de passe maître, le coffre
// reste définitivement irrécupérable. C'est le prix du Zero-Knowledge, et c'est voulu.

use crate::crypto::{open_with_password, seal_with_password, KEY_LEN};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use zeroize::Zeroize;

/// Alphabet du code de récupération. Volontairement AMPUTÉ des caractères qu'on confond en
/// recopiant depuis une feuille imprimée : ni `I`/`1`/`L`, ni `O`/`0`, ni `U` (trop proche de `V`
/// dans certaines polices). Ce code sera transcrit à la main, parfois des mois plus tard, peut-être
/// par quelqu'un d'autre — l'ambiguïté y coûte plus cher que quelques bits d'entropie.
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTVWXYZ23456789";

/// 5 groupes de 5 caractères, soit 25 symboles parmi 30 possibles : environ 122 bits d'entropie
/// (25 × log2(30)). Très largement au-delà de ce qu'un attaquant peut parcourir, d'autant que
/// chaque tentative coûte un Argon2id complet (~46 Mo, voir crypto.rs::argon2_params).
const CODE_GROUPS: usize = 5;
const CODE_GROUP_LEN: usize = 5;

/// Engendre un code de récupération, présenté en groupes séparés par des tirets pour la lisibilité
/// (ex: `ABCDE-FGHJK-...`). Les tirets sont purement cosmétiques : ils sont ignorés à la saisie
/// (voir normalize_code), donc l'utilisateur peut les omettre ou se tromper d'espacement.
pub fn generate_recovery_code() -> String {
    let mut raw = [0u8; CODE_GROUPS * CODE_GROUP_LEN];
    rand::fill(&mut raw);

    let mut groups: Vec<String> = Vec::with_capacity(CODE_GROUPS);
    for group in raw.chunks(CODE_GROUP_LEN) {
        let chars: String = group
            .iter()
            // Le modulo introduit un biais théorique (256 n'est pas multiple de 30), négligeable
            // ici : il réduit l'entropie d'une fraction de bit sur les ~122 disponibles, sans
            // rapport avec ce qu'il faudrait pour rendre une recherche exhaustive envisageable.
            .map(|byte| CODE_ALPHABET[*byte as usize % CODE_ALPHABET.len()] as char)
            .collect();
        groups.push(chars);
    }
    raw.zeroize();
    groups.join("-")
}

/// Met un code saisi sous sa forme canonique : majuscules, sans tiret ni espace. Indispensable —
/// un code recopié d'une feuille arrive avec des séparateurs et une casse imprévisibles, et le
/// moindre écart produirait une clé Argon2id différente, donc un échec incompréhensible.
fn normalize_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Scelle la clé du coffre avec le code de récupération. Le blob renvoyé est celui à confier au
/// serveur ; il embarque son propre sel et son propre nonce (voir crypto::seal_with_password),
/// donc rien d'autre n'est à conserver à côté.
pub fn seal_vault_key(vault_key: &[u8; KEY_LEN], recovery_code: &str) -> Result<String, String> {
    let normalized = normalize_code(recovery_code);
    if normalized.is_empty() {
        return Err("Code de récupération vide".to_string());
    }
    seal_with_password(vault_key, &normalized)
}

/// Descelle la clé du coffre à partir du blob et du code saisi par l'utilisateur.
/// Échoue si le code est faux, si le blob a été altéré, ou si son contenu n'a pas la longueur d'une
/// clé — ce dernier cas ne devrait jamais survenir (GCM authentifie le contenu), mais on préfère un
/// refus explicite à une clé tronquée qui déchiffrerait tout en charabia.
pub fn unseal_vault_key(sealed_b64: &str, recovery_code: &str) -> Result<[u8; KEY_LEN], String> {
    let normalized = normalize_code(recovery_code);
    if normalized.is_empty() {
        return Err("Code de récupération vide".to_string());
    }

    let mut plaintext = open_with_password(sealed_b64, &normalized)
        .map_err(|_| "Code de récupération incorrect.".to_string())?;

    if plaintext.len() != KEY_LEN {
        plaintext.zeroize();
        return Err("Kit de récupération corrompu.".to_string());
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(key)
}

/// Encode la clé du coffre en base64 — forme sous laquelle elle transite vers le JS quand il faut
/// la remettre en jeu (voir src-tauri/src/lib.rs). Isolée ici pour que l'appelant n'ait pas à
/// réimplémenter l'encodage.
pub fn vault_key_to_base64(vault_key: &[u8; KEY_LEN]) -> String {
    BASE64.encode(vault_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_then_unseal_recovers_the_exact_key() {
        let key = [7u8; KEY_LEN];
        let code = generate_recovery_code();
        let sealed = seal_vault_key(&key, &code).expect("le scellement doit réussir");
        let recovered = unseal_vault_key(&sealed, &code).expect("le descellement doit réussir");
        assert_eq!(recovered, key, "la clé descellée doit être identique à l'originale");
    }

    #[test]
    fn test_wrong_code_is_rejected() {
        let key = [7u8; KEY_LEN];
        let sealed = seal_vault_key(&key, "ABCDE-FGHJK-MNPQR-STVWX-YZ234").unwrap();
        assert!(
            unseal_vault_key(&sealed, "ABCDE-FGHJK-MNPQR-STVWX-YZ235").is_err(),
            "un code faux d'un seul caractère doit être rejeté"
        );
    }

    /// Le code doit rester valable quelle que soit la façon dont il est RECOPIÉ : c'est le cas
    /// d'usage réel (transcription depuis une feuille imprimée, des mois plus tard).
    #[test]
    fn test_code_normalization_tolerates_transcription() {
        let key = [42u8; KEY_LEN];
        let code = "ABCDE-FGHJK-MNPQR-STVWX-YZ234";
        let sealed = seal_vault_key(&key, code).unwrap();

        for variant in [
            "abcde-fghjk-mnpqr-stvwx-yz234",   // minuscules
            "ABCDEFGHJKMNPQRSTVWXYZ234",       // sans séparateur
            "ABCDE FGHJK MNPQR STVWX YZ234",   // espaces au lieu de tirets
            "  ABCDE-FGHJK-MNPQR-STVWX-YZ234 ", // espaces parasites
        ] {
            assert_eq!(
                unseal_vault_key(&sealed, variant).expect(variant),
                key,
                "la variante de saisie {variant:?} doit être acceptée"
            );
        }
    }

    #[test]
    fn test_generated_code_has_expected_shape_and_alphabet() {
        let code = generate_recovery_code();
        let groups: Vec<&str> = code.split('-').collect();
        assert_eq!(groups.len(), CODE_GROUPS, "code : {code}");
        for group in &groups {
            assert_eq!(group.len(), CODE_GROUP_LEN, "code : {code}");
        }
        // Aucun caractère ambigu à la transcription (voir CODE_ALPHABET).
        for c in code.chars().filter(|c| *c != '-') {
            assert!(
                CODE_ALPHABET.contains(&(c as u8)),
                "caractère {c:?} hors alphabet (ambigu à recopier) dans {code}"
            );
        }
    }

    #[test]
    fn test_two_codes_differ() {
        assert_ne!(
            generate_recovery_code(),
            generate_recovery_code(),
            "deux codes tirés au hasard ne doivent pas coïncider"
        );
    }

    #[test]
    fn test_empty_code_is_rejected_on_both_sides() {
        let key = [1u8; KEY_LEN];
        assert!(seal_vault_key(&key, "   ").is_err());
        let sealed = seal_vault_key(&key, "ABCDE-FGHJK-MNPQR-STVWX-YZ234").unwrap();
        assert!(unseal_vault_key(&sealed, "").is_err());
    }

    #[test]
    fn test_tampered_blob_is_rejected() {
        let key = [3u8; KEY_LEN];
        let code = "ABCDE-FGHJK-MNPQR-STVWX-YZ234";
        let sealed = seal_vault_key(&key, code).unwrap();
        // Altère le dernier caractère base64 — GCM doit le détecter.
        let mut bytes = sealed.into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();
        assert!(unseal_vault_key(&tampered, code).is_err(), "un blob altéré doit être rejeté");
    }
}
