// =========================================================================
// CRYPTOGRAPHIE : MOTS DE PASSE, JETONS JWT & REFRESH TOKENS
// =========================================================================
// Anciennement regroupé avec l'envoi d'e-mails dans un seul `security.rs` — séparé en deux
// fichiers pour que chacun reflète une SEULE responsabilité : ce fichier ne fait que du calcul
// (hachage, signature, comparaison), aucune E/S réseau. Voir mailer.rs pour l'envoi de mails.

use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{
    password_hash::{phc::PasswordHash, PasswordVerifier, PasswordHasher},
    Argon2,
};

use jsonwebtoken::{encode, Header, EncodingKey};

use serde::{Serialize, Deserialize};

// =========================================================================
// STRUCTURE DES DONNÉES DU JETON (JWT CLAIMS)
// =========================================================================

/// Représente les données embarquées (Payload) à l'intérieur du jeton JWT.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // "Subject" : Identifiant unique de l'utilisateur (ex: son email)
    pub exp: usize,  // "Expiration" : Date d'expiration du jeton (Timestamp Unix)
    pub iat: usize,  // "Issued At" : Date de création du jeton (Timestamp Unix)
    pub iss: String, // "Issuer" : Le nom du serveur qui a émis le jeton
    pub aud: String, // "Audience" : Le destinataire prévu du jeton (ex: l'application cliente)
}

// =========================================================================
// FONCTIONS DE SÉCURITÉ (MOTS DE PASSE & SELS)
// =========================================================================

/// Hache (Argon2id + pepper serveur) le hash d'authentification REÇU du client.
/// ZERO-KNOWLEDGE TOTAL : depuis le passage à ce modèle, `password` ici n'est PLUS le mot de
/// passe maître en clair — le client l'a déjà transformé localement (Argon2id/PBKDF2) en un
/// hash d'authentification distinct de la clé qui chiffre le coffre. Cette fonction rehache
/// simplement CE hash côté serveur, pour se protéger contre une fuite de la BDD (le serveur
/// n'a jamais connaissance du mot de passe maître original).
///
/// CORRECTIF PERF/CRITIQUE (retour utilisateur, 2026-09-02 : connexion parfois jusqu'à 10
/// secondes) : cette fonction (et verify_password() ci-dessous) était SYNCHRONE, appelée
/// DIRECTEMENT depuis du code async (les handlers Axum) sans `spawn_blocking` — le calcul Argon2id
/// (46 Mo de mémoire, volontairement coûteux, voir plus bas) bloquait donc entièrement le thread
/// du runtime Tokio pendant toute sa durée. Sur une machine à peu de cœurs CPU partagés entre
/// plusieurs services (voir la conversation du 2026-09-02), Tokio n'a qu'un petit nombre de
/// threads async — un seul calcul Argon2 en cours suffisait à mettre TOUTES les autres requêtes
/// en attente derrière lui (y compris d'autres logins, la synchro WebSocket, etc.), la latence
/// s'accumulant si plusieurs requêtes coûteuses arrivaient en même temps. `tokio::task::
/// spawn_blocking` déplace le calcul sur le pool de threads DÉDIÉ de Tokio (séparé des threads
/// async, dimensionné bien plus largement) — le runtime async reste entièrement disponible
/// pendant le calcul, quelle que soit sa durée.
pub async fn hash_password(password: &str, pepper: &str) -> Result<String, argon2::password_hash::Error> {
    let password = password.to_string();
    let pepper = pepper.to_string();
    tokio::task::spawn_blocking(move || hash_password_blocking(&password, &pepper))
        .await
        .expect("le calcul Argon2 (hash_password) ne devrait jamais paniquer")
}

/// Calcul RÉEL, synchrone — jamais appelé directement en dehors de hash_password() ci-dessus
/// (qui le déplace sur le pool bloquant de Tokio) et des tests unitaires plus bas (exécutés hors
/// runtime async, aucun risque d'y bloquer quoi que ce soit).
fn hash_password_blocking(password: &str, pepper: &str) -> Result<String, argon2::password_hash::Error> {
    // Paramètres Argon2id explicites (au lieu de Params::default() = m=19456,t=2,p=1).
    // Note : le défaut du crate était déjà l'une des options recommandées par l'OWASP,
    // donc ce n'était pas un problème de sécurité en soi. On prend ici l'option la PLUS
    // forte de leur barème (m=47104 KiB soit ~46 Mo, t=1, p=1), pertinent pour un mot de
    // passe MAÎTRE dont le hachage n'a lieu qu'une fois par login (déjà rate-limité).
    // IMPORTANT : ceci n'affecte QUE les nouveaux hachages. Les mots de passe déjà hachés
    // avec les anciens paramètres restent vérifiables normalement (verify_password lit les
    // paramètres embarqués dans le hash stocké, pas ceux de cette fonction).
    let params = argon2::Params::new(47104, 1, 1, None)
        .map_err(|_| argon2::password_hash::Error::Crypto)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    // Concatène (colle) le mot de passe de l'utilisateur avec la clé secrète du serveur (le poivre/pepper)
    let combined = format!("{}{}", password, pepper);

    // Depuis argon2 0.6, hash_password() ne prend plus le sel en argument manuel : elle le génère
    // elle-même via un CSPRNG système (feature "getrandom", activée par défaut) — plus besoin de
    // gérer nous-mêmes un SaltString comme avant. Le format PHC produit ($argon2id$v=19$...) est
    // inchangé, donc les hashs déjà en base restent vérifiables normalement par verify_password().
    Ok(argon2.hash_password(combined.as_bytes())?.to_string())
}

/// Vérifie si le hash d'authentification soumis par le client correspond au hash stocké en BDD.
/// Même remarque que hash_password() : `password` est le hash d'authentification dérivé côté
/// client, jamais le mot de passe maître lui-même.
///
/// CORRECTIF PERF/CRITIQUE : voir le commentaire de hash_password() ci-dessus — même correctif
/// (spawn_blocking), pour la même raison (appelée à CHAQUE login, en plus des changements de mot
/// de passe/email, donc la fonction la plus fréquemment invoquée des deux).
pub async fn verify_password(password: &str, hash: &str, pepper: &str) -> bool {
    let password = password.to_string();
    let hash = hash.to_string();
    let pepper = pepper.to_string();
    // `.unwrap_or(false)` plutôt que `.expect(...)` comme hash_password() ci-dessus : en cas de
    // panique improbable dans le calcul (thread bloquant tué/JoinError), on préfère un échec de
    // vérification "propre" (mot de passe refusé) à un crash de toute la requête — cette
    // fonction-ci est sur le chemin critique de l'authentification, une dégradation silencieuse
    // vers "refusé" reste le comportement le plus sûr par défaut.
    tokio::task::spawn_blocking(move || verify_password_blocking(&password, &hash, &pepper))
        .await
        .unwrap_or(false)
}

/// Calcul RÉEL, synchrone — même principe que hash_password_blocking() ci-dessus.
fn verify_password_blocking(password: &str, hash: &str, pepper: &str) -> bool {
    // Faux hash valide utilisé pour simuler un calcul si l'utilisateur n'existe pas en BDD.
    // ATTENTION : ce hash doit être syntaxiquement valide (parsable par Argon2), sinon
    // PasswordHash::new() échoue immédiatement plus bas et la protection anti-timing-attack
    // ne sert à rien (le calcul Argon2 ne serait jamais réellement exécuté).
    //
    // CORRECTIF SÉCURITÉ : ce dummy DOIT utiliser EXACTEMENT les mêmes paramètres Argon2id
    // (m=47104,t=1,p=1) que hash_password() ci-dessus — sinon la vérification contre un compte
    // INCONNU (ce dummy) coûte un temps CPU/mémoire différent de la vérification contre un compte
    // CONNU créé après le passage à ces paramètres renforcés, ce qui réintroduit exactement la
    // fuite temporelle (énumération de comptes) que ce mécanisme est censé empêcher. Générée une
    // seule fois via hash_password(), puis figée ici en dur (même principe que legacy_hash dans
    // les tests plus bas) — son contenu réel n'a aucune importance, seuls ses paramètres comptent.
    let dummy_hash = "$argon2id$v=19$m=47104,t=1,p=1$1zmGBompBdrviT44CFTH9g$83znW1S8794qLlrF3GBdVnAWdsTr6C1lLCiZirENHM0";

    // Contre-mesure aux attaques temporelles : Si le hash fourni est vide (utilisateur inconnu),
    // on utilise le dummy_hash pour forcer le processeur à travailler et masquer le temps de traitement.
    let hash_to_use = if hash.is_empty() { dummy_hash } else { hash };

    // Tente de parser la chaîne de caractères du hash pour que l'algorithme puisse la lire
    if let Ok(parsed_hash) = PasswordHash::new(hash_to_use) {
        // Recrée la combinaison mot de passe + poivre secret
        let combined = format!("{}{}", password, pepper);

        // Exécute la vérification d'Argon2 et retourne 'true' si ça correspond
        return Argon2::default()
            .verify_password(combined.as_bytes(), &parsed_hash)
            .is_ok();
    }
    // Si le parsing du hash a échoué, on retourne false
    false
}

// =========================================================================
// GÉNÉRATION DES JETONS DE SESSION (JWT & REFRESH)
// =========================================================================

/// Génère un nouveau jeton d'accès JWT pour un utilisateur donné.
pub fn create_jwt(email: &str, encoding_key: &EncodingKey, duration_secs: u64) -> Result<String, jsonwebtoken::errors::Error> {
    // Récupère le timestamp actuel en secondes depuis le 1er janvier 1970
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

    // Construit les données qui seront chiffrées dans le jeton
    let claims = Claims {
        sub: email.to_owned(),
        iss: "mon-app-backend".to_string(),
        aud: "mon-app-client".to_string(),
        exp: (now + duration_secs) as usize, // Temps actuel + durée de validité demandée
        iat: now as usize,
    };

    // Encode et signe le jeton à l'aide de la clé secrète de cryptage
    encode(&Header::default(), &claims, encoding_key)
}

/// Crée un jeton de rafraîchissement (Refresh Token) aléatoire et hautement sécurisé sous forme hexadécimale.
pub fn create_refresh_token() -> String {
    let mut key = [0u8; 32];

    // Remplissage aléatoire direct avec rand 0.10
    rand::fill(&mut key);

    hex::encode(key)
}

/// Hache un refresh token avec SHA-256 avant stockage en base de données.
/// Le CLIENT continue de recevoir/envoyer le token en clair (c'est lui qui doit le connaître
/// pour prouver sa session) ; seul le SERVEUR ne stocke jamais que son empreinte. Ainsi, une
/// fuite de la base de données (sauvegarde volée, accès admin compromis...) ne donne pas
/// directement accès à des sessions valides — l'attaquant devrait retrouver le token original
/// à partir de son hash, infaisable pour un secret de 256 bits même avec un hash rapide comme
/// SHA-256 (contrairement à un mot de passe, la résistance au bruteforce n'est pas le sujet ici :
/// le token est déjà à haute entropie, donc pas besoin d'un hachage volontairement lent).
pub fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compare deux chaînes en temps constant (le temps d'exécution ne dépend pas de l'endroit où
/// les chaînes diffèrent), pour éviter qu'un attaquant ne devine un code de vérification à 6
/// chiffres octet par octet en mesurant de minuscules différences de latence réseau.
/// Volontairement une implémentation maison plutôt qu'une dépendance externe (ex: `subtle`) :
/// l'opération est simple (XOR + OU logique sur des chaînes courtes), pas besoin d'une crate
/// dédiée pour ce cas d'usage précis.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// =========================================================================
// TESTS
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// Test unitaire vérifiant la validité du hachage et de la vérification des mots de passe.
    /// Appelle les variantes _blocking directement (logique pure, testée hors runtime async) —
    /// hash_password()/verify_password() elles-mêmes ne sont que le déplacement sur
    /// spawn_blocking, voir leur commentaire, pas testable depuis un #[test] synchrone sans
    /// runtime Tokio actif.
    #[test]
    fn test_password_hashing() {
        let password = "mon_super_password_123";
        let pepper = "test_pepper_secret"; // Simule la variable d'environnement secrète du serveur

        // Test de la génération du hash
        let hash = hash_password_blocking(password, pepper).expect("Le hachage a échoué");

        // Vérifie qu'un bon mot de passe avec le bon pepper renvoie bien true
        assert!(verify_password_blocking(password, &hash, pepper));

        // Vérifie qu'un mauvais mot de passe renvoie bien false
        assert!(!verify_password_blocking("mauvais_password", &hash, pepper));
    }

    /// RÉGRESSION CRITIQUE (migration argon2 0.5.x -> 0.6.0, voir Cargo.toml) : un hash produit
    /// par l'ANCIENNE version de hash_password() (sel généré manuellement via SaltString, avant
    /// migration) doit rester vérifiable normalement par la NOUVELLE version. Le format PHC
    /// textuel ($argon2id$v=19$...) n'a pas changé entre les deux versions de la crate — seule
    /// l'API Rust de hash_password() a bougé (elle ne prend plus le sel en argument) — donc tous
    /// les comptes existants doivent continuer à se connecter sans réinitialisation forcée.
    /// Ce hash a été capturé une seule fois avec l'ancien code, pour "mot_de_passe_test123" +
    /// "peppertest1234567890123456789012", puis figé ici en dur.
    #[test]
    fn test_verify_password_accepts_hash_from_before_argon2_0_6_0_migration() {
        let legacy_hash = "$argon2id$v=19$m=47104,t=1,p=1$cvTBGFk8DCuRoFl54W8kag$A3sGU1UMavkRaHh6mFQxmwMSTId326dTYdJBBZt3EcE";
        let password = "motdepassetest123";
        let pepper = "peppertest1234567890123456789012";

        assert!(
            verify_password_blocking(password, legacy_hash, pepper),
            "un hash produit avant la migration argon2 0.6.0 doit rester vérifiable après coup"
        );
        assert!(
            !verify_password_blocking("mauvais_password", legacy_hash, pepper),
            "un mauvais mot de passe contre un hash pré-migration doit toujours être rejeté"
        );
    }

    /// Test unitaire vérifiant le bon déroulement de la génération d'un JWT.
    #[test]
    fn test_jwt_creation_and_claims() {
        // Clé de test arbitraire de 32 caractères
        let key = EncodingKey::from_secret(b"secret_de_test_au_moins_32_chars_");
        let email = "test@example.com";

        // Génère un jeton valable 600 secondes (10 minutes)
        let token = create_jwt(email, &key, 600).expect("Échec création JWT");

        // Vérifie simplement que la chaîne générée n'est pas vide
        assert!(!token.is_empty());
    }

    /// Un jeton créé avec une durée de validité déjà écoulée doit être rejeté au décodage
    /// (le champ `exp` du JWT doit être respecté par jsonwebtoken::decode).
    /// ATTENTION : `jsonwebtoken::Validation::default()` applique une tolérance ("leeway") de
    /// 60 secondes sur `exp` — un jeton expiré depuis 1 seconde serait donc encore accepté.
    /// On construit ici un jeton dont `exp` est largement au-delà de cette tolérance (120s),
    /// pour un test rapide et déterministe (pas de sleep).
    #[test]
    fn test_jwt_expired_token_is_rejected_on_decode() {
        let secret = b"secret_de_test_au_moins_32_chars_";
        let encoding_key = EncodingKey::from_secret(secret);
        let decoding_key = jsonwebtoken::DecodingKey::from_secret(secret);
        let email = "expiration@example.com";

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let claims = Claims {
            sub: email.to_string(),
            iss: "mon-app-backend".to_string(),
            aud: "mon-app-client".to_string(),
            exp: (now - 120) as usize, // expiré depuis 120s, bien au-delà des 60s de leeway
            iat: (now - 130) as usize,
        };
        let token = jsonwebtoken::encode(&Header::default(), &claims, &encoding_key)
            .expect("Échec création JWT expiré");

        let mut validation = jsonwebtoken::Validation::default();
        validation.set_audience(&["mon-app-client"]);
        validation.set_issuer(&["mon-app-backend"]);

        let result = jsonwebtoken::decode::<Claims>(&token, &decoding_key, &validation);
        assert!(result.is_err(), "un jeton expiré doit être rejeté au décodage");
    }

    /// Quand le hash stocké est vide (utilisateur inconnu), verify_password() doit basculer
    /// sur le dummy_hash de secours et renvoyer `false` de manière fiable (jamais de panique,
    /// jamais un faux positif), tout en exécutant quand même un calcul Argon2 complet
    /// (protection anti-timing-attack).
    #[test]
    fn test_verify_password_with_empty_hash_uses_dummy_and_returns_false() {
        let result = verify_password_blocking("peu_importe_le_mot_de_passe", "", "un_pepper_quelconque");
        assert!(!result, "un hash vide (utilisateur inconnu) ne doit jamais valider un mot de passe");
    }

    /// hash_token() doit être déterministe (même entrée -> même hash) et sensible à la moindre
    /// différence (deux tokens différents -> hashs différents).
    #[test]
    fn test_hash_token_is_deterministic_and_collision_resistant_for_similar_inputs() {
        let token = "abc123def456";
        let hash1 = hash_token(token);
        let hash2 = hash_token(token);
        assert_eq!(hash1, hash2, "hacher deux fois le même token doit donner le même résultat");

        let different_hash = hash_token("abc123def457"); // un seul caractère différent
        assert_ne!(hash1, different_hash, "des tokens différents doivent produire des hashs différents");

        // Le hash ne doit jamais être égal au token en clair (sinon ça ne sert à rien de le hacher)
        assert_ne!(hash1, token);
    }

    #[test]
    fn test_constant_time_eq_matches_identical_strings() {
        assert!(constant_time_eq("123456", "123456"));
    }

    #[test]
    fn test_constant_time_eq_rejects_different_strings() {
        assert!(!constant_time_eq("123456", "654321"));
        assert!(!constant_time_eq("123456", "12345")); // longueur différente
        assert!(!constant_time_eq("123456", ""));
    }
}
