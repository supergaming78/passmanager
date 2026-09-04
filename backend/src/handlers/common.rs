use axum::{extract::State, http::{StatusCode, header, HeaderMap}, response::IntoResponse, Json};
use std::sync::{Arc, Mutex};
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

// CORRECTIF PERF (retour utilisateur, 2026-09-02) : /public-config (juste en dessous) est appelée
// à CHAQUE ouverture de l'app/l'extension, AVANT toute authentification — l'une des routes les
// plus fréquemment invoquées de toute l'API. La valeur qu'elle lit ne change quasiment jamais (un
// réglage Admin, voir update_server_choice_at_login() dans admin.rs, qui appelle
// set_server_choice_at_login_cache() juste après chaque modification pour garder ce cache à jour).
// Singleton process-global plutôt qu'un champ dans AppState : AppState est construit "en dur",
// champ par champ, dans une VINGTAINE d'endroits différents (surtout des helpers de test) — y
// ajouter un champ aurait forcé à modifier chacun d'eux pour un gain qui ne concerne qu'une seule
// route. Sûr ici PRÉCISÉMENT parce que la donnée est un simple booléen de config PUBLIQUE par
// nature (voir le commentaire de get_public_config ci-dessous) — jamais rien de sensible/
// spécifique à un utilisateur, qui ne devrait, lui, jamais vivre dans un singleton partagé.
//
// `Mutex<Option<bool>>` plutôt qu'un `OnceLock` (qui semblait plus simple au premier abord) :
// `cargo test` exécute TOUS les tests dans le MÊME process, souvent en parallèle — un `OnceLock`,
// une fois rempli par le PREMIER test à appeler get_public_config(), resterait figé sur CETTE
// valeur pour TOUS les tests suivants, même ceux utilisant leur propre base de données isolée
// avec une valeur différente (voir test_get_public_config_reflects_server_choice_at_login_default
// vs ..._once_enabled plus bas : le second échouerait en lisant la valeur mise en cache par le
// premier, un faux négatif introduit PAR ce correctif). `Mutex<Option<bool>>` reste réinitialisable
// via reset_server_choice_at_login_cache_for_tests() (uniquement compilée en `#[cfg(test)]`),
// appelée en tout début de chaque test concerné pour restaurer l'isolation entre eux.
static SERVER_CHOICE_AT_LOGIN_CACHE: Mutex<Option<bool>> = Mutex::new(None);

/// Met à jour (ou initialise) le cache ci-dessus. Appelée par get_public_config() elle-même (pour
/// se remplir au tout premier appel après démarrage) ET par
/// handlers/admin.rs::update_server_choice_at_login() (pour rester à jour immédiatement après une
/// modification, sans attendre une quelconque expiration — ce cache n'expire jamais tout seul,
/// aucun intérêt vu la fréquence de modification quasi nulle de ce réglage).
pub(crate) fn set_server_choice_at_login_cache(value: bool) {
    *SERVER_CHOICE_AT_LOGIN_CACHE.lock().expect("le mutex du cache ne devrait jamais être empoisonné") = Some(value);
}

/// UNIQUEMENT pour les tests (voir le commentaire du cache ci-dessus) : restaure l'isolation entre
/// deux tests qui s'attendent chacun à une valeur différente, dans le même process de test partagé.
#[cfg(test)]
pub(crate) fn reset_server_choice_at_login_cache_for_tests() {
    *SERVER_CHOICE_AT_LOGIN_CACHE.lock().expect("le mutex du cache ne devrait jamais être empoisonné") = None;
}

/// Petits réglages GLOBAUX lisibles SANS AUTHENTIFICATION, PAR NATURE (l'écran de connexion
/// n'a encore identifié aucun compte) — voir handlers/admin.rs::update_server_choice_at_login()
/// pour qui peut modifier ce réglage (Admin seul), et pages/Login.tsx côté app pour son usage :
/// affiche (ou non) le lien "Configurer le serveur" avant toute connexion. Volontairement séparé
/// de /health (rôles différents : orchestrateur/load balancer d'un côté, config produit de
/// l'autre) plutôt que d'y ajouter ce champ.
pub async fn get_public_config(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, crate::error::AppError> {
    let cached = *SERVER_CHOICE_AT_LOGIN_CACHE.lock().expect("le mutex du cache ne devrait jamais être empoisonné");
    let server_choice_at_login_enabled = match cached {
        Some(value) => value,
        None => {
            let value: bool = sqlx::query_scalar(
                "SELECT server_choice_at_login_enabled FROM app_settings WHERE id = 1"
            )
                .fetch_one(&state.db)
                .await?;
            set_server_choice_at_login_cache(value);
            value
        }
    };

    // `registration_open` est lu À CHAQUE APPEL, volontairement SANS cache — contrairement au
    // réglage ci-dessus. Le cache y est un correctif de performance qui impose, en contrepartie,
    // de penser à l'invalider à chaque écriture (voir set_server_choice_at_login_cache) : c'est un
    // piège à bug de valeur périmée. Ici le coût évité serait une lecture indexée d'une seule
    // ligne, sur une route appelée à l'ouverture de l'écran de connexion — négligeable. Mieux vaut
    // une valeur toujours juste qu'un cache à maintenir.
    let registration_open: bool = sqlx::query_scalar("SELECT registration_open FROM app_settings WHERE id = 1")
        .fetch_one(&state.db)
        .await?;

    Ok(Json(json!({
        "server_choice_at_login_enabled": server_choice_at_login_enabled,
        "registration_open": registration_open,
    })))
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
            geoip_database_path: None,
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
            geoip: Arc::new(crate::geoip::GeoIpResolver::load(None)),
            started_at: std::time::Instant::now(),
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

    /// get_public_config() : accessible SANS le moindre AuthUser en paramètre (contrairement à
    /// tout le reste du fichier admin.rs) — c'est tout le sens de ce endpoint (voir
    /// pages/Login.tsx côté app, appelé AVANT toute connexion). Doit refléter
    /// server_choice_at_login_enabled à false par défaut (voir la migration), PUIS true une fois
    /// modifié — voir handlers/admin.rs::update_server_choice_at_login().
    ///
    /// CORRECTIF (voir le commentaire du cache dans get_public_config()) : les deux scénarios
    /// (par défaut / une fois activé) vivaient auparavant dans deux tests `#[tokio::test]`
    /// SÉPARÉS — `cargo test` les exécute potentiellement EN PARALLÈLE, dans des THREADS
    /// différents du MÊME process : rien n'empêchait le second de démarrer avant que le premier
    /// n'ait fini de lire le cache (partagé, process-global), l'un pouvant alors lire la valeur
    /// tout juste posée par l'autre — un test intermittent (flaky), qui n'aurait rien eu à voir
    /// avec un vrai bug. Fusionnés en un seul test séquentiel : aucune interaction entre threads
    /// possible, le cache est réinitialisé UNE SEULE FOIS en tout début, jamais entre les deux
    /// vérifications (exactement comme en production, où set_server_choice_at_login_cache() —
    /// appelée par le handler d'admin après chaque modification — le garde à jour sans jamais
    /// avoir besoin d'être vidé entre deux lectures).
    #[tokio::test]
    async fn test_get_public_config_reflects_server_choice_at_login() {
        reset_server_choice_at_login_cache_for_tests();
        let state = build_test_state().await;

        let response = get_public_config(State(state.clone())).await.unwrap().into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["server_choice_at_login_enabled"], false, "désactivé par défaut (voir la migration)");

        // Simule ce que fait réellement handlers/admin.rs::update_server_choice_at_login() : une
        // modification en base SUIVIE d'une mise à jour explicite du cache (jamais une expiration
        // automatique, voir le commentaire du cache) — sans cet appel, get_public_config()
        // continuerait de refléter l'ANCIENNE valeur déjà en cache, comme en production.
        sqlx::query("UPDATE app_settings SET server_choice_at_login_enabled = 1 WHERE id = 1")
            .execute(&state.db)
            .await
            .unwrap();
        set_server_choice_at_login_cache(true);

        let response = get_public_config(State(state)).await.unwrap().into_response();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["server_choice_at_login_enabled"], true, "doit refléter le changement une fois le cache mis à jour");
    }
}