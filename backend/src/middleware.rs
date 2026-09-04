use axum::{
    extract::{FromRequestParts, FromRef},
    http::{request::Parts, StatusCode},
};
use std::sync::Arc;
use crate::{AppState, crypto::Claims};

// =========================================================================
// 1. STRUCTURE DE L'UTILISATEUR AUTHENTIFIÉ
// =========================================================================

/// Cette structure encapsule les informations de l'utilisateur qui a été
/// validé avec succès par le middleware. Elle peut être injectée directement
/// en paramètre de vos fonctions de routes d'API pour savoir "qui" appelle.
#[derive(Debug)]
pub struct AuthUser {
    pub email: String,        // L'adresse e-mail de l'utilisateur identifié
    pub is_moderator: bool,   // Indique si l'utilisateur possède les droits de modérateur
}

impl AuthUser {
    /// Vrai UNIQUEMENT pour le compte configuré via `ADMIN_EMAIL` — le seul "Admin" de
    /// l'application (voir maintenance.rs::promote_configured_admin). Calculé à chaque appel,
    /// jamais stocké en base : contrairement à `is_moderator` (une colonne, attribuable par
    /// l'Admin à n'importe qui), il ne peut jamais y avoir qu'UN SEUL compte pour lequel ceci
    /// renvoie `true`, déterminé uniquement par la configuration du déploiement.
    pub fn is_admin(&self, state: &AppState) -> bool {
        state.config.admin_email.as_deref() == Some(self.email.as_str())
    }
}

// =========================================================================
// 2. EXTRACTION ET VÉRIFICATION DE LA SESSION (TRAIT FROMREQUESTPARTS)
// =========================================================================

/// Implémentation du mécanisme d'extraction d'Axum (`FromRequestParts`).
/// Cela permet à Axum d'analyser automatiquement les en-têtes (headers) de chaque
/// requête HTTP entrante pour y chercher et valider le jeton de session.
impl<S> FromRequestParts<S> for AuthUser 
where
    // On exige que l'état global de l'application (`AppState`) soit accessible
    Arc<AppState>: FromRef<S>,
    S: Send + Sync,
{
    // En cas d'échec (pas de token, token expiré, etc.), le middleware rejette la requête
    // en renvoyant un code statut HTTP associé à un message textuel explicatif.
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Récupération de l'état global de l'application (contient la clé de décodage et l'accès BDD)
        let state = Arc::<AppState>::from_ref(state);

        // 1. Extraction de l'en-tête HTTP 'Authorization' (ex: "Authorization: Bearer <votre_token>")
        let auth_header = parts.headers.get("Authorization")
            .and_then(|h| h.to_str().ok())
            // Si l'en-tête est manquant, on stoppe immédiatement avec une erreur 401 (Unauthorized)
            .ok_or((StatusCode::UNAUTHORIZED, "Authentification requise".to_string()))?;

        // 2. Vérification du format du jeton : il doit impérativement commencer par "Bearer "
        let token = auth_header.strip_prefix("Bearer ")
            // Si le préfixe est absent, le format est invalide (Erreur 401)
            .ok_or((StatusCode::UNAUTHORIZED, "Format de jeton invalide".to_string()))?;

        // 3. Configuration des règles de validation du JSON Web Token (JWT)
        let mut validation = jsonwebtoken::Validation::default();
        // Le jeton doit cibler spécifiquement l'application cliente
        validation.set_audience(&["mon-app-client"]);
        // Le jeton doit provenir obligatoirement de notre serveur backend
        validation.set_issuer(&["mon-app-backend"]);

        // 4. Décodage et vérification de l'intégrité cryptographique du jeton
        // La fonction `decode` vérifie la signature, l'audience, l'émetteur et la date d'expiration (exp).
        let token_data = jsonwebtoken::decode::<Claims>(token, &state.decoding_key, &validation)
            // Si la signature est fausse ou le temps expiré, on rejette l'accès
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Session expirée".to_string()))?;

        // 5. Double vérification de sécurité en Base de Données
        // Même si le jeton est valide, on s'assure que le compte n'a pas été supprimé ou banni entre-temps.
        // On récupère au passage son statut de modérateur (`is_moderator`) et le plus récent de
        // DEUX événements qui doivent invalider les access tokens déjà émis (voir point 6) : un
        // changement de mot de passe (`password_changed_at`) OU une déconnexion globale
        // volontaire (`sessions_revoked_at`, voir handlers/devices.rs::logout_all_devices()).
        // `MAX(a, b)` avec 2 arguments est la forme SCALAIRE (par ligne) de SQLite, pas la forme
        // agrégat à un seul argument — exactement ce qu'il faut ici.
        let user_row = sqlx::query_as::<_, (String, bool, chrono::NaiveDateTime, bool)>(
            "SELECT email, is_moderator, MAX(password_changed_at, sessions_revoked_at), is_suspended FROM users WHERE email = ?"
        )
            // Le sujet (`sub`) du token contient l'email de l'utilisateur
            .bind(&token_data.claims.sub)
            // Exécute la requête sur le pool de connexion de l'application
            .fetch_optional(&state.db)
            .await
            // Si la base de données est inaccessible, on lève une erreur interne 500
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Erreur serveur".to_string()))?
            // Si la requête ne renvoie aucune ligne, le compte n'existe pas ou plus (Erreur 401)
            .ok_or((StatusCode::UNAUTHORIZED, "Compte introuvable".to_string()))?;

        // 6. Un jeton émis AVANT le dernier changement de mot de passe OU la dernière
        // déconnexion globale volontaire ne doit plus être valide. Sans ce contrôle, ces deux
        // actions révoquent bien les refresh tokens, mais un access token déjà émis restait
        // valide jusqu'à ~10 minutes de plus (sa propre expiration) malgré tout — l'attaquant
        // (ou l'appareil perdu) gardait l'accès pendant cette fenêtre résiduelle.
        // `<=` et non `<` : CURRENT_TIMESTAMP (SQLite) et `iat` (JWT) ont tous deux une
        // résolution à la SECONDE — un jeton émis pile la même seconde que le changement de mot
        // de passe est indiscernable de l'ordre réel. On tranche du côté strict (on invalide
        // aussi les égalités) : au pire, un utilisateur qui se reconnecte immédiatement après un
        // changement de mot de passe doit réessayer une fois, ce qui reste un bien meilleur
        // compromis qu'un token potentiellement compromis qui resterait accepté.
        // COMPTE SUSPENDU (voir handlers/admin.rs::update_suspended) : refusé ICI, au même endroit
        // que la révocation par changement de mot de passe. La suspension supprime déjà les refresh
        // tokens, mais un ACCESS token déjà émis resterait sinon valable jusqu'à sa propre
        // expiration — soit une fenêtre résiduelle de plusieurs minutes pendant laquelle un compte
        // suspendu continuerait d'agir. Le contrôle a lieu à CHAQUE requête, donc une suspension
        // prend effet immédiatement.
        if user_row.3 {
            return Err((StatusCode::UNAUTHORIZED, "Ce compte est suspendu.".to_string()));
        }

        let issued_at = chrono::DateTime::from_timestamp(token_data.claims.iat as i64, 0)
            .map(|dt| dt.naive_utc())
            .ok_or((StatusCode::UNAUTHORIZED, "Jeton invalide".to_string()))?;
        if issued_at <= user_row.2 {
            return Err((StatusCode::UNAUTHORIZED, "Session expirée : le mot de passe a été modifié, veuillez vous reconnecter".to_string()));
        }

        // 7. Succès : On construit et on retourne l'objet `AuthUser` contenant les données validées.
        // Axum va maintenant autoriser l'accès à la route demandée et lui transmettre cet objet.
        Ok(AuthUser {
            email: user_row.0,        // Récupère l'email issu du tuple de la BDD
            is_moderator: user_row.1  // Récupère le booléen is_moderator issu du tuple de la BDD
        })
    }
}

// =========================================================================
// TESTS SUR L'EXTRACTEUR AuthUser (cœur de l'authentification de chaque requête)
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use sqlx::sqlite::SqlitePoolOptions;
    use axum::http::Request;

    async fn build_test_state() -> Arc<AppState> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connexion à la BDD de test");

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("échec des migrations sur la BDD de test");

        let config = Config {
            database_url: "sqlite::memory:".to_string(),
            jwt_secret: "test_jwt_secret_au_moins_32_caracteres_ici".to_string(),
            port: 0,
            app_env: "test".to_string(),
            access_token_seconds: 600,
            refresh_token_hours: 24,
            refresh_token_short_seconds: 5,
            password_pepper: "test_password_pepper_au_moins_32_caracteres".to_string(),
            smtp_host: "localhost".to_string(),
            smtp_user: "test@example.com".to_string(),
            smtp_pass: "unused".to_string(),
            allowed_origins: vec!["http://localhost:5173".to_string()],
            admin_email: None,
            trust_proxy_headers: false,
        };

        Arc::new(AppState {
            encoding_key: jsonwebtoken::EncodingKey::from_secret(config.jwt_secret.as_bytes()),
            decoding_key: jsonwebtoken::DecodingKey::from_secret(config.jwt_secret.as_bytes()),
            app_env: config.app_env.clone(),
            db: pool,
            config,
            sync_tx: tokio::sync::broadcast::channel(16).0,
            shutdown_tx: tokio::sync::broadcast::channel(1).0,
            ws_connections: Default::default(),
        })
    }

    /// Construit des `Parts` de requête HTTP avec (ou sans) un en-tête Authorization donné,
    /// pour pouvoir appeler l'extracteur directement sans passer par un vrai serveur HTTP.
    fn parts_with_header(header_value: Option<&str>) -> axum::http::request::Parts {
        let mut builder = Request::builder();
        if let Some(value) = header_value {
            builder = builder.header("Authorization", value);
        }
        let (parts, _) = builder.body(()).unwrap().into_parts();
        parts
    }

    /// Un jeton valide, pour un utilisateur existant en BDD, doit être accepté et renvoyer
    /// les bonnes informations (email, statut admin).
    #[tokio::test]
    async fn test_auth_user_valid_token_succeeds() {
        let state = build_test_state().await;
        let email = "validtoken@example.com";
        sqlx::query("INSERT INTO users (email, password_hash, is_moderator) VALUES (?, ?, ?)")
            .bind(email)
            .bind("hash_non_pertinent")
            .bind(true)
            .execute(&state.db)
            .await
            .unwrap();

        let token = crate::crypto::create_jwt(email, &state.encoding_key, 600).unwrap();
        let mut parts = parts_with_header(Some(&format!("Bearer {token}")));

        let result = AuthUser::from_request_parts(&mut parts, &state).await;
        let user = result.expect("un jeton valide doit être accepté");
        assert_eq!(user.email, email);
        assert!(user.is_moderator, "le statut modérateur en BDD doit être correctement reporté");
    }

    /// Aucun en-tête Authorization du tout -> 401.
    #[tokio::test]
    async fn test_auth_user_missing_header_rejected() {
        let state = build_test_state().await;
        let mut parts = parts_with_header(None);

        let result = AuthUser::from_request_parts(&mut parts, &state).await;
        match result {
            Err((status, _)) => assert_eq!(status, StatusCode::UNAUTHORIZED),
            Ok(_) => panic!("une requête sans en-tête Authorization ne doit jamais être acceptée"),
        }
    }

    /// En-tête présent mais sans le préfixe "Bearer " -> 401 (format invalide).
    #[tokio::test]
    async fn test_auth_user_malformed_header_rejected() {
        let state = build_test_state().await;
        let mut parts = parts_with_header(Some("un_token_sans_prefixe_bearer"));

        let result = AuthUser::from_request_parts(&mut parts, &state).await;
        match result {
            Err((status, _)) => assert_eq!(status, StatusCode::UNAUTHORIZED),
            Ok(_) => panic!("un en-tête sans préfixe 'Bearer ' ne doit jamais être accepté"),
        }
    }

    /// Un jeton syntaxiquement invalide (n'importe quelle chaîne) doit être rejeté.
    #[tokio::test]
    async fn test_auth_user_invalid_token_rejected() {
        let state = build_test_state().await;
        let mut parts = parts_with_header(Some("Bearer ceci.nest.pas.un.jwt.valide"));

        let result = AuthUser::from_request_parts(&mut parts, &state).await;
        match result {
            Err((status, _)) => assert_eq!(status, StatusCode::UNAUTHORIZED),
            Ok(_) => panic!("un jeton invalide ne doit jamais être accepté"),
        }
    }

    /// Un jeton dont la signature est valide mais dont l'expiration (`exp`) est déjà passée
    /// doit être rejeté.
    /// ATTENTION : `jsonwebtoken::Validation::default()` (utilisée dans l'extracteur) applique
    /// une tolérance ("leeway") de 60 secondes sur `exp` — on construit donc directement un
    /// jeton expiré depuis 120s (bien au-delà), pour un test rapide et déterministe (pas de sleep).
    #[tokio::test]
    async fn test_auth_user_expired_token_rejected() {
        let state = build_test_state().await;
        let email = "expiredtoken@example.com";
        sqlx::query("INSERT INTO users (email, password_hash) VALUES (?, ?)")
            .bind(email)
            .bind("hash_non_pertinent")
            .execute(&state.db)
            .await
            .unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = crate::crypto::Claims {
            sub: email.to_string(),
            iss: "mon-app-backend".to_string(),
            aud: "mon-app-client".to_string(),
            exp: (now - 120) as usize, // expiré depuis 120s, bien au-delà des 60s de leeway
            iat: (now - 130) as usize,
        };
        let expired_token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &state.encoding_key,
        ).expect("Échec création JWT expiré");

        let mut parts = parts_with_header(Some(&format!("Bearer {expired_token}")));
        let result = AuthUser::from_request_parts(&mut parts, &state).await;
        match result {
            Err((status, _)) => assert_eq!(status, StatusCode::UNAUTHORIZED),
            Ok(_) => panic!("un jeton expiré ne doit jamais être accepté"),
        }
    }

    /// Un jeton valide pour un compte qui a ENTRE-TEMPS été supprimé de la BDD doit être rejeté
    /// (double vérification en base, pas seulement la signature du jeton).
    #[tokio::test]
    async fn test_auth_user_deleted_account_rejected() {
        let state = build_test_state().await;
        let email = "willbedeleted@example.com";
        sqlx::query("INSERT INTO users (email, password_hash) VALUES (?, ?)")
            .bind(email)
            .bind("hash_non_pertinent")
            .execute(&state.db)
            .await
            .unwrap();

        let token = crate::crypto::create_jwt(email, &state.encoding_key, 600).unwrap();

        // Le compte est supprimé APRÈS l'émission du jeton
        sqlx::query("DELETE FROM users WHERE email = ?")
            .bind(email)
            .execute(&state.db)
            .await
            .unwrap();

        let mut parts = parts_with_header(Some(&format!("Bearer {token}")));
        let result = AuthUser::from_request_parts(&mut parts, &state).await;
        match result {
            Err((status, _)) => assert_eq!(status, StatusCode::UNAUTHORIZED),
            Ok(_) => panic!("un jeton valide pour un compte supprimé ne doit jamais être accepté"),
        }
    }

    /// Un jeton valide et non expiré, mais émis AVANT le dernier changement de mot de passe,
    /// ne doit plus être accepté — ferme la fenêtre résiduelle laissée par la seule révocation
    /// des refresh tokens (voir update_password()/confirm_password_reset() dans handlers/auth.rs).
    #[tokio::test]
    async fn test_auth_user_token_issued_before_password_change_rejected() {
        let state = build_test_state().await;
        let email = "pwchanged@example.com";
        sqlx::query("INSERT INTO users (email, password_hash) VALUES (?, ?)")
            .bind(email)
            .bind("hash_non_pertinent")
            .execute(&state.db)
            .await
            .unwrap();

        // Jeton émis "maintenant"
        let token = crate::crypto::create_jwt(email, &state.encoding_key, 600).unwrap();

        // Le mot de passe est changé APRÈS l'émission du jeton (poussé dans le futur proche
        // pour un test rapide et déterministe, sans sleep).
        sqlx::query("UPDATE users SET password_changed_at = DATETIME('now', '+1 hour') WHERE email = ?")
            .bind(email)
            .execute(&state.db)
            .await
            .unwrap();

        let mut parts = parts_with_header(Some(&format!("Bearer {token}")));
        let result = AuthUser::from_request_parts(&mut parts, &state).await;
        match result {
            Err((status, _)) => assert_eq!(status, StatusCode::UNAUTHORIZED),
            Ok(_) => panic!("un jeton émis avant un changement de mot de passe ne doit plus être accepté"),
        }
    }

    /// À l'inverse, un compte dont le mot de passe n'a JAMAIS été changé (valeur par défaut
    /// '1970-01-01 00:00:00' posée par la migration) ne doit jamais rejeter un jeton légitime
    /// à cause de ce nouveau contrôle — non-régression du comportement par défaut.
    #[tokio::test]
    async fn test_auth_user_accepts_token_when_password_never_changed() {
        let state = build_test_state().await;
        let email = "neverchanged@example.com";
        sqlx::query("INSERT INTO users (email, password_hash) VALUES (?, ?)")
            .bind(email)
            .bind("hash_non_pertinent")
            .execute(&state.db)
            .await
            .unwrap();

        let token = crate::crypto::create_jwt(email, &state.encoding_key, 600).unwrap();
        let mut parts = parts_with_header(Some(&format!("Bearer {token}")));
        let result = AuthUser::from_request_parts(&mut parts, &state).await;
        assert!(result.is_ok(), "un jeton légitime pour un compte n'ayant jamais changé de mot de passe doit être accepté");
    }
}