// =========================================================================
// DPAPI (Windows uniquement) — pour le "déverrouillage rapide" (voir lib.rs::enable_quick_unlock/
// try_quick_unlock). Protège le blob de clé du coffre en le liant au compte Windows de la session
// en cours via CryptProtectData/CryptUnprotectData (crypt32.dll) : personne d'autre que CE compte
// Windows ne peut déchiffrer ce blob, quel que soit le fichier récupéré (copié sur une clé USB,
// etc.).
//
// CE N'EST PAS un chiffrement supplémentaire au sens cryptographique fort de cette app — la
// protection DPAPI dépend de secrets internes gérés par Windows (dérivés du mot de passe de
// session), entièrement hors du contrôle de cette app. C'est un compromis délibéré
// confort/sécurité, STRICTEMENT OPT-IN (voir Réglages côté frontend), qui ne remplace jamais le
// mot de passe maître : celui-ci reste toujours utilisable en repli (voir VaultLockScreen.tsx).
#![cfg(target_os = "windows")]

use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

// CORRECTIF SÉCURITÉ : `pbOptionalEntropy` (le paramètre "entropie" de CryptProtectData/
// CryptUnprotectData) était auparavant omis (`None`). Sans lui, DPAPI ne lie le blob QU'au compte
// Windows courant — n'IMPORTE QUEL AUTRE programme tournant sous ce même compte (un malware, un
// script, une autre app compromise) peut lire quick_unlock.bin et appeler CryptUnprotectData
// directement, SANS jamais déclencher la vérification Windows Hello ci-dessus (qui est un
// mécanisme purement applicatif, complètement séparé de DPAPI côté OS) : la clé du coffre serait
// alors récupérable sans aucun geste biométrique.
//
// En fournissant cette entropie fixe et propre à l'app (elle n'a PAS besoin d'être un secret —
// n'importe qui peut la lire en désassemblant ce binaire — son rôle est seulement d'empêcher un
// appel DPAPI générique/naïf de fonctionner sur ce blob), on force un attaquant à cibler
// spécifiquement cette app plutôt que d'utiliser une technique universelle de vol de blob DPAPI.
// AVERTISSEMENT HONNÊTE : ceci reste une défense en profondeur, pas une garantie absolue — un
// attaquant qui a déjà extrait cette constante du binaire ET qui exécute du code sous le même
// compte Windows pourrait toujours la rejouer. Aucun mécanisme purement OS (DPAPI) ne peut lier
// cryptographiquement un déchiffrement à "Windows Hello vient de réussir" sans passer par les API
// NGC/TPM bien plus lourdes de Windows Hello lui-même — hors de portée de ce correctif ciblé.
const ENTROPY: &[u8] = b"passmanager-quick-unlock-dpapi-entropy-v1";

fn entropy_blob() -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: ENTROPY.len() as u32,
        pbData: ENTROPY.as_ptr() as *mut u8,
    }
}

/// Chiffre `data` via DPAPI. CRYPTPROTECT_UI_FORBIDDEN : échoue plutôt que de laisser Windows
/// afficher une éventuelle invite système — cette app gère elle-même toute interaction
/// utilisateur (le prompt Windows Hello, via UserConsentVerifier, est un mécanisme SÉPARÉ de
/// DPAPI lui-même, voir lib.rs). Voir ENTROPY ci-dessus pour pbOptionalEntropy.
pub fn protect(data: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let entropy = entropy_blob();
        let mut output = CRYPT_INTEGER_BLOB::default();

        CryptProtectData(&input, PCWSTR::null(), Some(&entropy), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            .map_err(|_| "Échec de la protection DPAPI".to_string())?;

        let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(output.pbData as *mut core::ffi::c_void)));
        Ok(result)
    }
}

/// Déchiffre un blob produit par protect() — échoue si le blob provient d'un AUTRE compte
/// Windows, a été altéré/corrompu, ou n'a pas été scellé avec la même ENTROPY (voir ci-dessus).
pub fn unprotect(data: &[u8]) -> Result<Vec<u8>, String> {
    unsafe {
        let input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let entropy = entropy_blob();
        let mut output = CRYPT_INTEGER_BLOB::default();

        CryptUnprotectData(&input, None, Some(&entropy), None, None, CRYPTPROTECT_UI_FORBIDDEN, &mut output)
            .map_err(|_| "Échec du déverrouillage rapide (compte Windows différent, ou donnée corrompue)".to_string())?;

        let result = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(Some(HLOCAL(output.pbData as *mut core::ffi::c_void)));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protect_unprotect_roundtrip() {
        let original = b"donnee secrete de test";
        let protected = protect(original).expect("la protection DPAPI doit reussir sur ce compte Windows");
        assert_ne!(protected, original, "le blob protege ne doit jamais contenir la donnee en clair telle quelle");

        let recovered = unprotect(&protected).expect("le dechiffrement avec le meme compte Windows doit reussir");
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_unprotect_rejects_garbage() {
        let result = unprotect(b"pas un vrai blob DPAPI");
        assert!(result.is_err(), "un blob invalide doit etre rejete proprement, jamais paniquer");
    }

    #[test]
    fn test_protect_produces_different_output_for_different_input() {
        let a = protect(b"contenu A").unwrap();
        let b = protect(b"contenu B").unwrap();
        assert_ne!(a, b);
    }
}
