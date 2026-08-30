use axum::{extract::State, http::{StatusCode, header, HeaderMap}, response::IntoResponse, Json};
use std::sync::Arc;
use crate::AppState;
use serde_json::json;

// --- FONCTIONS UTILITAIRES PARTAGÉES ---

/// Extrait proprement la chaîne 'User-Agent' depuis les en-têtes HTTP (Headers)
/// Utile pour identifier l'application ou le navigateur qui effectue la requête.
/// `pub(crate)` : utilisée par les autres sous-modules de `handlers` (auth, vault, devices),
/// pas besoin qu'elle soit publique au-delà du crate.
pub(crate) fn get_user_agent(headers: &HeaderMap) -> Option<String> {
    headers.get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Détecte si la requête vient d'une extension de navigateur (Chrome/Firefox) plutôt que de l'app
/// desktop ou d'un appel API direct — voir handlers/auth/account.rs::update_email(), qui restreint
/// le changement d'email aux comptes explicitement autorisés (`can_change_email_via_extension`)
/// UNIQUEMENT quand l'appel vient de là. La couche CORS (voir main.rs) ne consomme jamais l'en-tête
/// `Origin` de la requête entrante — seulement lu ici pour construire la réponse CORS — donc il
/// reste lisible normalement par un handler.
/// ATTENTION : PAS une frontière de sécurité dure — un appelant non-navigateur peut omettre ou
/// forger cet en-tête. C'est un garde-fou de politique produit, en complément (jamais à la place)
/// de la vérification de mot de passe déjà obligatoire pour tout changement d'email.
pub(crate) fn is_extension_origin(headers: &HeaderMap) -> bool {
    headers.get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|origin| origin.starts_with("chrome-extension://") || origin.starts_with("moz-extension://"))
}

/// Endpoint de santé pour un load balancer / orchestrateur (Docker healthcheck, k8s liveness/readiness...).
/// Vérifie aussi que la BDD répond (pas juste que le process tourne), sinon un load balancer
/// continuerait à envoyer du trafic vers une instance dont la BDD est injoignable.
pub async fn health_check(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "status": "db_unreachable" }))),
    }
}

// =========================================================================
// TESTS SUR LES UTILITAIRES COMMUNS
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use sqlx::sqlite::SqlitePoolOptions;

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

    #[test]
    fn test_get_user_agent_extracts_present_header() {
        let mut headers = HeaderMap::new();
        headers.insert(header::USER_AGENT, "TestClient/1.0".parse().unwrap());
        assert_eq!(get_user_agent(&headers), Some("TestClient/1.0".to_string()));
    }

    #[test]
    fn test_get_user_agent_returns_none_when_absent() {
        let headers = HeaderMap::new();
        assert_eq!(get_user_agent(&headers), None);
    }

    #[test]
    fn test_is_extension_origin_detects_chrome_and_firefox() {
        let mut chrome = HeaderMap::new();
        chrome.insert(header::ORIGIN, "chrome-extension://hcggmibfhgjcamfehjjdmagbecbkljdj".parse().unwrap());
        assert!(is_extension_origin(&chrome));

        let mut firefox = HeaderMap::new();
        firefox.insert(header::ORIGIN, "moz-extension://some-uuid".parse().unwrap());
        assert!(is_extension_origin(&firefox));
    }

    #[test]
    fn test_is_extension_origin_false_for_desktop_or_absent() {
        let mut desktop = HeaderMap::new();
        desktop.insert(header::ORIGIN, "http://localhost:1420".parse().unwrap());
        assert!(!is_extension_origin(&desktop));

        assert!(!is_extension_origin(&HeaderMap::new()));
    }

    /// La BDD étant joignable (cas normal), le healthcheck doit renvoyer 200 OK.
    #[tokio::test]
    async fn test_health_check_returns_ok_when_db_reachable() {
        let state = build_test_state().await;
        let response = health_check(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }
}