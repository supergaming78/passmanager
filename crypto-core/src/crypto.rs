// =========================================================================
// CRYPTOGRAPHIE CLIENT — ZERO-KNOWLEDGE
// =========================================================================
// Tout ce qui touche à la clé de chiffrement du coffre vit ICI, côté Rust natif (processus
// Tauri), jamais côté JS/WebView. C'est l'avantage concret de Tauri par rapport à une app web
// classique : le frontend appelle des commandes Tauri (voir lib.rs) qui prennent du texte en
// clair en entrée et renvoient du texte chiffré en sortie (ou l'inverse) — il ne reçoit et ne
// manipule jamais la clé de chiffrement du coffre elle-même.
//
// SCHÉMA DE DÉRIVATION (voir derive_keys()) :
//   (email, mot de passe maître)
//        │  Argon2id (mêmes paramètres que le serveur, voir backend/src/crypto.rs)
//        ▼
//   clé maîtresse (32 octets, jamais stockée ni transmise)
//        │  HKDF-SHA256, deux contextes ("info") distincts
//        ├──▶ hash d'authentification (envoyé au serveur, re-haché par lui — voir /auth/register)
//        └──▶ clé de chiffrement du coffre (reste ici, jamais transmise)
//
// La séparation par HKDF garantit qu'une fuite du hash d'authentification stocké côté serveur
// (même après son propre re-hachage Argon2id+pepper) ne permet PAS de retrouver la clé qui
// chiffre le coffre — les deux sont dérivées indépendamment de la même clé maîtresse, jamais
// l'une à partir de l'autre.

use argon2::Argon2;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use zeroize::Zeroize;

/// Taille (en octets) de toutes les clés manipulées ici : clé maîtresse, hash d'authentification
/// avant encodage hex, clé de chiffrement du coffre (AES-256 = 32 octets de clé).
pub const KEY_LEN: usize = 32;

/// Contextes HKDF distincts par usage — voir le schéma en tête de fichier. Les valeurs exactes
/// n'ont pas besoin d'être secrètes (elles sont dans le binaire), seulement DISTINCTES entre
/// elles pour garantir l'indépendance cryptographique des deux sous-clés produites.
const INFO_AUTH: &[u8] = b"passmanager-auth-hash-v1";
const INFO_VAULT: &[u8] = b"passmanager-vault-key-v1";

/// Paramètres Argon2id — IDENTIQUES à ceux du serveur (voir backend/src/crypto.rs::hash_password,
/// m=47104 KiB soit ~46 Mo, t=1, p=1) : même barème de coût, appliqué ici côté client sur le mot
/// de passe maître EN CLAIR (jamais transmis), alors que le serveur applique le sien sur le hash
/// d'authentification déjà dérivé (double hachage, comme documenté côté backend). Le calcul n'a
/// lieu qu'à l'inscription/connexion/changement de mot de passe — jamais dans une boucle chaude —
/// donc ce coût (~1s sur un poste moderne) reste sans impact perceptible pour l'utilisateur.
fn argon2_params() -> argon2::Params {
    argon2::Params::new(47104, 1, 1, Some(KEY_LEN)).expect("paramètres Argon2id statiques et valides")
}

/// Résultat de derive_keys() : le hash d'authentification à envoyer au serveur (chaîne hex, voir
/// AuthPayload::master_password_hash côté backend) et la clé de chiffrement du coffre (reste en
/// Rust — voir state.rs pour son cycle de vie en mémoire).
pub struct DerivedKeys {
    pub auth_hash_hex: String,
    pub vault_key: [u8; KEY_LEN],
}

/// Dérive la clé MAÎTRESSE (32 octets) à partir de l'email et du mot de passe maître.
/// Sel = SHA-256(email normalisé en minuscules) : DÉTERMINISTE (pas de sel aléatoire stocké nulle
/// part) — impératif Zero-Knowledge, le serveur ne voyant jamais le mot de passe maître, il ne
/// peut par définition fournir aucun sel à l'avance. La même clé doit pouvoir se re-dériver sur
/// N'IMPORTE QUEL appareil à partir des deux seules informations que l'utilisateur connaît
/// (email + mot de passe maître). Ce sel n'a pas besoin d'être secret (l'email n'en est pas un) :
/// son seul rôle est d'empêcher que deux comptes avec le même mot de passe produisent la même
/// clé — la résistance au bruteforce vient uniquement du coût d'Argon2id lui-même, pas du sel.
/// Email passé par SHA-256 (32 octets fixes) plutôt qu'en clair : garantit une longueur de sel
/// toujours valide pour Argon2id (minimum 8 octets), quelle que soit la longueur de l'email.
fn derive_master_key(email: &str, master_password: &str) -> [u8; KEY_LEN] {
    let salt = Sha256::digest(email.trim().to_lowercase().as_bytes());

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon2_params());
    let mut master_key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(master_password.as_bytes(), &salt, &mut master_key)
        .expect("la dérivation Argon2id ne doit jamais échouer avec des paramètres statiques valides");
    master_key
}

/// Dérive une sous-clé de KEY_LEN octets à partir de la clé maîtresse, via HKDF-SHA256, avec un
/// contexte ("info") distinct par usage. Pas de sel HKDF explicite (`None`) : la clé maîtresse
/// elle-même a déjà l'entropie voulue (sortie d'Argon2id), HKDF ne sert ici qu'à la séparer en
/// sous-clés indépendantes, pas à renforcer une entropie qui existe déjà.
fn derive_subkey(master_key: &[u8; KEY_LEN], info: &[u8]) -> [u8; KEY_LEN] {
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut output = [0u8; KEY_LEN];
    hkdf.expand(info, &mut output)
        .expect("KEY_LEN est une longueur de sortie HKDF-SHA256 valide (largement sous la limite de 255 blocs)");
    output
}

/// Point d'entrée : dérive les DEUX sous-clés à partir de (email, mot de passe maître).
/// Appelée à l'inscription, à chaque connexion, et lors d'un changement de mot de passe (une fois
/// avec l'ancien mot de passe pour déchiffrer le coffre existant, une fois avec le nouveau pour
/// le re-chiffrer — voir handlers/auth/account.rs côté backend pour le flux complet).
pub fn derive_keys(email: &str, master_password: &str) -> DerivedKeys {
    let mut master_key = derive_master_key(email, master_password);
    let mut auth_key = derive_subkey(&master_key, INFO_AUTH);
    let vault_key = derive_subkey(&master_key, INFO_VAULT);
    master_key.zeroize(); // Ne sert plus une fois les deux sous-clés dérivées — effacée immédiatement.

    let auth_hash_hex = hex_encode(&auth_key);
    // Même raison que master_key juste au-dessus : `auth_key` ne sert plus une fois encodée en
    // hexadécimal. Elle était auparavant laissée telle quelle sur la pile jusqu'à la fin de la
    // fonction — un oubli, pas un choix : c'est un secret d'authentification (le hash envoyé au
    // serveur en dérive directement), et tout le reste de ce fichier efface systématiquement ce
    // genre de matériel dès qu'il devient inutile.
    auth_key.zeroize();

    DerivedKeys { auth_hash_hex, vault_key }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Chiffre un champ en clair du coffre (AES-256-GCM) et renvoie un blob base64 auto-suffisant :
/// nonce (12 octets) suivi du texte chiffré (incluant le tag d'authentification GCM, 16 octets) —
/// pas besoin de stocker/transmettre le nonce séparément, il voyage avec le reste du blob.
/// Nonce ALÉATOIRE à chaque appel (jamais réutilisé avec la même clé, condition de sécurité
/// stricte d'AES-GCM) : chiffrer deux fois le même contenu produit donc deux blobs différents.
pub fn encrypt_field(vault_key: &[u8; KEY_LEN], plaintext: &str) -> Result<String, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(vault_key));

    let mut nonce_bytes = [0u8; 12];
    rand::fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| "Échec du chiffrement".to_string())?;

    let mut blob = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(blob))
}

/// Déchiffre un blob produit par encrypt_field(). Échoue si le blob est trop court, mal formé, ou
/// si l'authentification GCM échoue (donnée corrompue, blob altéré, ou mauvaise clé — ex: un
/// mauvais mot de passe maître saisi ne produit JAMAIS un déchiffrement erroné silencieux, GCM
/// le détecte et rejette).
pub fn decrypt_field(vault_key: &[u8; KEY_LEN], blob_b64: &str) -> Result<String, String> {
    let blob = BASE64.decode(blob_b64).map_err(|_| "Blob chiffré invalide (base64)".to_string())?;
    if blob.len() < 12 {
        return Err("Blob chiffré trop court".to_string());
    }
    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(vault_key));
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Échec du déchiffrement (mauvaise clé ou donnée corrompue)".to_string())?;

    String::from_utf8(plaintext).map_err(|_| "Contenu déchiffré invalide (UTF-8)".to_string())
}

// =========================================================================
// EXPORT/IMPORT CHIFFRÉ — fichier de sauvegarde protégé par un mot de passe SÉPARÉ du mot de
// passe maître (voir components/ImportExportBar.tsx côté frontend). Contrairement à
// encrypt_field()/decrypt_field() ci-dessus, il n'y a ici NI email NI clé de coffre déjà dérivée
// disponibles pour fixer un sel déterministe — juste un mot de passe choisi au moment de
// l'export. Un sel ALÉATOIRE (stocké EN CLAIR dans le fichier, ce n'est pas un secret : son seul
// rôle est d'empêcher deux exports avec le même mot de passe de partager la même clé) est donc
// généré à chaque export et embarqué dans le fichier produit.
// =========================================================================

/// Marqueur en tête de fichier : permet à l'import de reconnaître un export chiffré (par
/// opposition à un JSON/TXT/CSV en clair) SANS avoir à deviner ou demander le format à l'avance —
/// voir lib/vaultFile.ts côté frontend, qui route vers decrypt_export_content() dès qu'il
/// reconnaît ce préfixe.
pub const ENCRYPTED_EXPORT_MAGIC: &str = "PMVAULT-ENC-V1";

/// Chiffre le contenu d'un export (JSON ou TXT déjà formaté par lib/vaultFile.ts) avec un mot de
/// passe choisi par l'utilisateur au moment de l'export — indépendant du mot de passe maître.
/// Renvoie le contenu prêt à écrire tel quel dans le fichier : une ligne de marqueur, puis le blob
/// base64 (sel Argon2id 16 octets || nonce AES-GCM 12 octets || texte chiffré+tag).
/// Scelle des octets quelconques avec un MOT DE PASSE (pas une clé déjà dérivée) : Argon2id sur un
/// sel aléatoire, puis AES-256-GCM. Le blob renvoyé est auto-suffisant — `sel(16) || nonce(12) ||
/// chiffré+tag`, en base64 — donc rien d'autre n'est à stocker à côté.
///
/// Extrait de encrypt_export_content() pour être partagé avec le KIT DE RÉCUPÉRATION (voir
/// recovery.rs), qui a besoin exactement de la même construction : sceller la clé du coffre avec un
/// code que seul l'utilisateur détient. Factorisé plutôt que recopié — deux implémentations
/// parallèles de la même cryptographie finissent toujours par diverger.
///
/// Le FORMAT est inchangé par rapport à ce que produisait encrypt_export_content avant cette
/// extraction : les fichiers d'export déjà créés restent lisibles.
pub fn seal_with_password(plaintext: &[u8], password: &str) -> Result<String, String> {
    let mut salt = [0u8; 16];
    rand::fill(&mut salt);

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon2_params());
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|_| "Échec de la dérivation de clé".to_string())?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    key.zeroize();

    let mut nonce_bytes = [0u8; 12];
    rand::fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| "Échec du chiffrement".to_string())?;

    let mut blob = Vec::with_capacity(salt.len() + nonce_bytes.len() + ciphertext.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(blob))
}

/// Pendant de seal_with_password(). Message d'erreur volontairement identique pour "mauvais mot de
/// passe" et "données corrompues" : GCM ne permet pas de les distinguer, et prétendre le contraire
/// induirait l'utilisateur en erreur.
pub fn open_with_password(blob_b64: &str, password: &str) -> Result<Vec<u8>, String> {
    let blob = BASE64.decode(blob_b64).map_err(|_| "Contenu chiffré invalide (base64)".to_string())?;
    if blob.len() < 16 + 12 {
        return Err("Contenu chiffré trop court".to_string());
    }
    let (salt, rest) = blob.split_at(16);
    let (nonce_bytes, ciphertext) = rest.split_at(12);

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, argon2_params());
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|_| "Échec de la dérivation de clé".to_string())?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    key.zeroize();
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Mot de passe incorrect, ou données corrompues".to_string())
}

pub fn encrypt_export_content(plaintext: &str, password: &str) -> Result<String, String> {
    let blob_b64 = seal_with_password(plaintext.as_bytes(), password)?;
    Ok(format!("{ENCRYPTED_EXPORT_MAGIC}\n{blob_b64}"))
}

/// Déchiffre un contenu produit par encrypt_export_content(). `content` doit commencer par
/// ENCRYPTED_EXPORT_MAGIC (à vérifier par l'appelant AVANT — voir lib/vaultFile.ts — pour pouvoir
/// distinguer "mauvais mot de passe" d'"pas un export chiffré du tout").
pub fn decrypt_export_content(content: &str, password: &str) -> Result<String, String> {
    let body = content
        .strip_prefix(ENCRYPTED_EXPORT_MAGIC)
        .ok_or_else(|| "Ce fichier n'est pas un export chiffré reconnu".to_string())?
        .trim_start_matches('\r')
        .trim_start_matches('\n')
        .trim_start_matches('\r');

    let plaintext = open_with_password(body, password)?;
    String::from_utf8(plaintext).map_err(|_| "Contenu déchiffré invalide (UTF-8)".to_string())
}

// =========================================================================
// VÉRIFICATION DES MOTS DE PASSE COMPROMIS (k-anonymat HaveIBeenPwned)
// =========================================================================
// SHA-1 n'est PAS un choix cryptographique de cette app — c'est le format imposé par l'API
// "Pwned Passwords" de HaveIBeenPwned, qui n'a rien à voir avec la sécurité du coffre (voir
// lib/breachCheck.ts côté frontend, qui fait la requête réseau elle-même : cette fonction ne
// calcule QUE le hash, jamais de connexion sortante ici). Le hachage lui-même reste en Rust,
// jamais en JS, par cohérence avec le reste de cette app — même si SHA-1 seul n'a ici aucune
// vocation à protéger un secret : ce n'est qu'une clé de recherche dans une base publique.

/// SHA-1 en hexadécimal MAJUSCULE (format attendu par l'API Pwned Passwords, voir
/// https://haveibeenpwned.com/API/v3#PwnedPasswords) — jamais utilisé pour dériver une clé ou
/// authentifier quoi que ce soit dans cette app.
pub fn sha1_hex(plaintext: &str) -> String {
    use sha1::{Digest as _, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(plaintext.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02X}")).collect()
}

// =========================================================================
// TESTS
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_keys_is_deterministic() {
        let a = derive_keys("user@example.com", "mon_mot_de_passe");
        let b = derive_keys("user@example.com", "mon_mot_de_passe");
        assert_eq!(a.auth_hash_hex, b.auth_hash_hex, "la dérivation doit être déterministe (même résultat sur n'importe quel appareil)");
        assert_eq!(a.vault_key, b.vault_key);
    }

    /// Le serveur normalise toujours les emails en minuscules (voir backend/src/handlers/auth) :
    /// la dérivation côté client doit faire pareil, sinon un utilisateur qui saisit son email
    /// avec une casse différente d'une connexion à l'autre ne retrouverait jamais sa vraie clé.
    #[test]
    fn test_derive_keys_is_case_insensitive_on_email() {
        let a = derive_keys("User@Example.com", "mon_mot_de_passe");
        let b = derive_keys("user@example.com", "mon_mot_de_passe");
        assert_eq!(a.auth_hash_hex, b.auth_hash_hex, "la casse de l'email ne doit pas changer la clé dérivée");
        assert_eq!(a.vault_key, b.vault_key);
    }

    #[test]
    fn test_different_passwords_produce_different_keys() {
        let a = derive_keys("user@example.com", "mot_de_passe_1");
        let b = derive_keys("user@example.com", "mot_de_passe_2");
        assert_ne!(a.auth_hash_hex, b.auth_hash_hex);
        assert_ne!(a.vault_key, b.vault_key);
    }

    #[test]
    fn test_different_emails_produce_different_keys_for_same_password() {
        let a = derive_keys("alice@example.com", "meme_mot_de_passe");
        let b = derive_keys("bob@example.com", "meme_mot_de_passe");
        assert_ne!(a.auth_hash_hex, b.auth_hash_hex, "deux comptes avec le même mot de passe ne doivent jamais partager la même clé");
        assert_ne!(a.vault_key, b.vault_key);
    }

    /// GARDE-FOU CRITIQUE : le hash d'authentification (envoyé au serveur) et la clé du coffre
    /// (jamais envoyée) doivent être cryptographiquement DIFFÉRENTS — sinon une fuite de la BDD
    /// serveur exposerait indirectement de quoi déchiffrer le coffre de tout le monde.
    #[test]
    fn test_auth_hash_and_vault_key_are_different() {
        let keys = derive_keys("user@example.com", "mon_mot_de_passe");
        let vault_key_hex = hex_encode(&keys.vault_key);
        assert_ne!(keys.auth_hash_hex, vault_key_hex, "le hash d'authentification et la clé du coffre ne doivent jamais être identiques");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let keys = derive_keys("user@example.com", "mon_mot_de_passe");
        let plaintext = "https://example.com identifiant secret";

        let ciphertext = encrypt_field(&keys.vault_key, plaintext).expect("le chiffrement doit réussir");
        assert_ne!(ciphertext, plaintext, "le blob chiffré ne doit jamais contenir le texte en clair tel quel");

        let decrypted = decrypt_field(&keys.vault_key, &ciphertext).expect("le déchiffrement avec la bonne clé doit réussir");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext_each_time() {
        let keys = derive_keys("user@example.com", "mon_mot_de_passe");
        let a = encrypt_field(&keys.vault_key, "meme_contenu").unwrap();
        let b = encrypt_field(&keys.vault_key, "meme_contenu").unwrap();
        assert_ne!(a, b, "chiffrer deux fois la même donnée ne doit jamais produire le même blob (nonce aléatoire à chaque appel)");
    }

    #[test]
    fn test_decrypt_fails_with_wrong_key() {
        let keys_a = derive_keys("user@example.com", "bon_mot_de_passe");
        let keys_b = derive_keys("user@example.com", "mauvais_mot_de_passe");

        let ciphertext = encrypt_field(&keys_a.vault_key, "secret").unwrap();
        let result = decrypt_field(&keys_b.vault_key, &ciphertext);
        assert!(result.is_err(), "déchiffrer avec la mauvaise clé doit échouer, jamais renvoyer un contenu incorrect silencieusement");
    }

    #[test]
    fn test_decrypt_fails_on_tampered_ciphertext() {
        let keys = derive_keys("user@example.com", "mon_mot_de_passe");
        let ciphertext = encrypt_field(&keys.vault_key, "secret").unwrap();

        // Modifie un caractère du blob base64 (en dehors du nonce, dans la partie chiffrée) ->
        // doit casser l'authentification GCM.
        let mut tampered: Vec<char> = ciphertext.chars().collect();
        let idx = tampered.len() - 5;
        tampered[idx] = if tampered[idx] == 'A' { 'B' } else { 'A' };
        let tampered: String = tampered.into_iter().collect();

        let result = decrypt_field(&keys.vault_key, &tampered);
        assert!(result.is_err(), "un blob altéré doit être rejeté par l'authentification GCM, jamais déchiffré silencieusement");
    }

    #[test]
    fn test_decrypt_rejects_too_short_blob() {
        let keys = derive_keys("user@example.com", "mon_mot_de_passe");
        let result = decrypt_field(&keys.vault_key, &BASE64.encode(b"trop_court"));
        assert!(result.is_err(), "un blob plus court que la taille du nonce seul doit être rejeté proprement, jamais paniquer");
    }

    #[test]
    fn test_decrypt_rejects_invalid_base64() {
        let keys = derive_keys("user@example.com", "mon_mot_de_passe");
        let result = decrypt_field(&keys.vault_key, "!!!pas du base64 valide!!!");
        assert!(result.is_err(), "un blob qui n'est même pas du base64 valide doit être rejeté proprement");
    }

    #[test]
    fn test_encrypted_export_roundtrip() {
        let plaintext = r#"[{"siteName":"GitHub","password":"hunter2"}]"#;
        let encrypted = encrypt_export_content(plaintext, "mot_de_passe_export").expect("le chiffrement doit réussir");
        assert!(encrypted.starts_with(ENCRYPTED_EXPORT_MAGIC), "le fichier chiffré doit commencer par le marqueur");
        assert!(!encrypted.contains("hunter2"), "le contenu en clair ne doit apparaître nulle part dans le fichier chiffré");

        let decrypted = decrypt_export_content(&encrypted, "mot_de_passe_export").expect("le déchiffrement avec le bon mot de passe doit réussir");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypted_export_wrong_password_fails() {
        let encrypted = encrypt_export_content("contenu quelconque", "bon_mot_de_passe").unwrap();
        let result = decrypt_export_content(&encrypted, "mauvais_mot_de_passe");
        assert!(result.is_err(), "un mauvais mot de passe d'export doit échouer, jamais renvoyer un contenu incorrect silencieusement");
    }

    #[test]
    fn test_encrypted_export_produces_different_output_each_time() {
        let a = encrypt_export_content("meme_contenu", "meme_mot_de_passe").unwrap();
        let b = encrypt_export_content("meme_contenu", "meme_mot_de_passe").unwrap();
        assert_ne!(a, b, "sel et nonce aléatoires à chaque export : jamais le même fichier deux fois, même à contenu/mot de passe identiques");
    }

    #[test]
    fn test_decrypt_export_rejects_content_without_magic() {
        let result = decrypt_export_content("juste du JSON normal, pas un export chiffré", "peu importe");
        assert!(result.is_err(), "un contenu sans le marqueur d'export chiffré doit être rejeté clairement, pas planter");
    }

    #[test]
    fn test_decrypt_export_rejects_tampered_content() {
        let encrypted = encrypt_export_content("contenu original", "mot_de_passe").unwrap();
        let mut tampered = encrypted.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });

        let result = decrypt_export_content(&tampered, "mot_de_passe");
        assert!(result.is_err(), "un fichier chiffré altéré doit être rejeté par l'authentification GCM");
    }

    /// Vecteur de test connu (recalculé indépendamment via `hashlib.sha1` en Python, pas de
    /// mémoire) : SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8 — garantit que le
    /// format (hexa MAJUSCULE, 40 caractères = 20 octets) est bien celui attendu par l'API Pwned
    /// Passwords, pas juste "un" hash SHA-1 valide.
    #[test]
    fn test_sha1_hex_matches_known_vector() {
        let hash = sha1_hex("password");
        assert_eq!(hash.len(), 40, "un hash SHA-1 fait toujours 20 octets = 40 caractères hexa");
        assert_eq!(hash, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn test_sha1_hex_is_deterministic() {
        assert_eq!(sha1_hex("mon_mot_de_passe"), sha1_hex("mon_mot_de_passe"));
    }

    #[test]
    fn test_sha1_hex_differs_for_different_input() {
        assert_ne!(sha1_hex("mot_de_passe_1"), sha1_hex("mot_de_passe_2"));
    }

    /// PREUVE D'INTEROPÉRABILITÉ DESKTOP ↔ WASM (voir extension/wasm-bindings/test-node.js, qui
    /// exécute EXACTEMENT le même calcul via le module WASM compilé depuis CE MÊME code source,
    /// et vérifie qu'il produit ces MÊMES valeurs hexadécimales). derive_keys() est déterministe
    /// (voir test_derive_keys_is_deterministic ci-dessus) : ces valeurs, une fois calculées ici et
    /// figées, doivent rester identiques quelle que soit la cible de compilation — n'importe quel
    /// changement dans ce test (autre qu'un changement délibéré du schéma de dérivation, auquel
    /// cas le test Node.js correspondant DOIT être mis à jour à l'identique) est un signal
    /// d'alerte sérieux : cela signifierait que desktop et extension chiffreraient différemment
    /// pour les mêmes email/mot de passe, rendant leurs coffres mutuellement illisibles.
    #[test]
    fn test_known_vector_matches_wasm_build() {
        let keys = derive_keys("cross-target-test@example.com", "cross-target-test-password");
        assert_eq!(keys.auth_hash_hex, "4f7d8a8473865a465ece3c58a0da6bc1b24e84d3237d739789bfea540d55e84d");
        assert_eq!(hex_encode(&keys.vault_key), "a281ad7fe9b9d7e1a10f272f52bf8133addf206f9a5a74748083d9b0320a1ea6");
    }
}
