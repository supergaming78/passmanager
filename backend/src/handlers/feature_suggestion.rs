// =========================================================================
// SUGGESTION DE FONCTIONNALITÉ — app DESKTOP uniquement, compte CONNECTÉ requis (voir migration
// 20260902000002_feature_suggestions.sql et models.rs pour le détail du modèle). Retour
// utilisateur (2026-09-02) : "un peu comme le signalement de bug" (voir handlers/bug_report.rs,
// dont ce fichier reprend la structure), mais toutes les routes ICI exigent un `AuthUser` — pas de
// route publique/anonyme comme POST /bug-reports, une suggestion de fonctionnalité n'a pas
// l'urgence d'un bug qui empêche justement de se connecter.
// =========================================================================
use axum::{
    extract::{State, Path},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use tracing::warn;
use crate::{AppState, error::AppError, mailer, middleware::AuthUser, repository::FeatureSuggestionRepository, models::CreateFeatureSuggestionPayload};
use validator::Validate;

/// N'IMPORTE QUEL compte connecté peut suggérer une fonctionnalité (pas réservé aux
/// modérateurs/à l'Admin, contrairement à la lecture/suppression ci-dessous) — `author_email` vient
/// de `user.email` (AuthUser), jamais d'un champ du payload : impossible de suggérer au nom de
/// quelqu'un d'autre, contrairement à reporter_email dans un signalement de bug (qui n'est qu'une
/// information de contact facultative, sur une route sans compte du tout).
pub async fn create_feature_suggestion(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(payload): Json<CreateFeatureSuggestionPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;

    let id = FeatureSuggestionRepository::create(&state.db, &user.email, &payload).await?;

    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id }))))
}

/// Réservé au SEUL Admin (`user.is_admin(&state)`, vrai uniquement pour le compte `ADMIN_EMAIL` —
/// voir middleware.rs), même raisonnement que list_bug_reports : décider quoi ajouter au produit
/// reste une décision qu'il préfère garder pour lui, même vis-à-vis de modérateurs de confiance.
pub async fn list_feature_suggestions(State(state): State<Arc<AppState>>, user: AuthUser) -> Result<impl IntoResponse, AppError> {
    if !user.is_admin(&state) {
        warn!("Tentative d'accès non autorisé aux suggestions de fonctionnalité par {} (pas l'Admin)", user.email);
        return Err(AppError::Forbidden);
    }

    let suggestions = FeatureSuggestionRepository::list_all(&state.db).await?;
    Ok(Json(suggestions))
}

/// Réservé au SEUL Admin (voir list_feature_suggestions ci-dessus) — supprime la suggestion (pas de
/// statut "examinée" séparé, la suppression EST la façon de marquer "traité", même choix que les
/// signalements de bug). Prévient TOUJOURS l'auteur par email (contrairement à
/// delete_bug_report — reporter_email peut y être NULL/non vérifié, alors qu'ici author_email est
/// TOUJOURS un compte réel authentifié au moment de l'envoi) — best-effort en `let _ =`, un échec
/// d'envoi ne doit jamais faire échouer la suppression elle-même.
pub async fn delete_feature_suggestion(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_admin(&state) {
        warn!("Tentative de suppression non autorisée d'une suggestion de fonctionnalité par {} (pas l'Admin)", user.email);
        return Err(AppError::Forbidden);
    }

    let deleted = FeatureSuggestionRepository::delete(&state.db, &id).await?;

    // Tronqué à 200 caractères, même choix que send_bug_report_resolved — pas la peine de renvoyer
    // les 4000 caractères possibles d'une description dans un simple rappel de courtoisie.
    let snippet: String = deleted.description.chars().take(200).collect();
    let _ = mailer::send_feature_suggestion_reviewed(&deleted.author_email, &snippet, &state.config).await;

    Ok(StatusCode::NO_CONTENT)
}

// =========================================================================
// TESTS
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

    fn auth(email: &str, is_moderator: bool) -> AuthUser {
        AuthUser { email: email.to_string(), is_moderator }
    }

    /// Même pattern que handlers/bug_report.rs::build_test_state_with_admin_email — nécessaire ici
    /// puisque list_feature_suggestions/delete_feature_suggestion sont réservés au SEUL Admin,
    /// calculé depuis cette config, jamais depuis is_moderator.
    async fn build_test_state_with_admin_email(admin_email: &str) -> Arc<AppState> {
        let state = build_test_state().await;
        Arc::new(AppState {
            encoding_key: state.encoding_key.clone(),
            decoding_key: state.decoding_key.clone(),
            app_env: state.app_env.clone(),
            db: state.db.clone(),
            config: Config { admin_email: Some(admin_email.to_lowercase()), ..state.config.clone() },
            sync_tx: state.sync_tx.clone(),
            shutdown_tx: state.shutdown_tx.clone(),
            ws_connections: state.ws_connections.clone(),
            geoip: state.geoip.clone(),
            started_at: state.started_at,
        })
    }

    async fn read_json_body(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).expect("le corps doit être du JSON valide")
    }

    fn sample_payload(description: &str) -> CreateFeatureSuggestionPayload {
        CreateFeatureSuggestionPayload { description: description.to_string() }
    }

    /// RÉGRESSION : contrairement au signalement de bug, `author_email` doit TOUJOURS venir du
    /// compte authentifié, jamais d'un champ du payload — vérifié en relisant la suggestion via
    /// list_feature_suggestions (le payload lui-même n'a pas de champ email du tout, ce test prouve
    /// surtout que l'email du bon compte atterrit bien en base).
    #[tokio::test]
    async fn test_author_email_comes_from_authenticated_user() {
        let state = build_test_state_with_admin_email("admin@example.com").await;

        create_feature_suggestion(State(state.clone()), auth("membre@example.com", false), Json(sample_payload("Un mode sombre plus profond")))
            .await
            .expect("un compte ordinaire doit pouvoir suggérer une fonctionnalité");

        let list = read_json_body(list_feature_suggestions(State(state.clone()), auth("admin@example.com", true)).await.unwrap().into_response()).await;
        let suggestions = list.as_array().unwrap();
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0]["author_email"], "membre@example.com");
    }

    /// RÉGRESSION : réservé au SEUL Admin — ni un compte ordinaire, NI un modérateur (même promu)
    /// ne doit pouvoir consulter les suggestions (même garde-fou que les signalements de bug).
    #[tokio::test]
    async fn test_only_admin_can_list_feature_suggestions() {
        let state = build_test_state_with_admin_email("admin2@example.com").await;
        create_feature_suggestion(State(state.clone()), auth("membre2@example.com", false), Json(sample_payload("Idée visible"))).await.unwrap();

        let stranger_attempt = list_feature_suggestions(State(state.clone()), auth("stranger@example.com", false)).await;
        assert!(matches!(stranger_attempt, Err(AppError::Forbidden)), "un compte ordinaire ne doit jamais voir les suggestions");

        let moderator_attempt = list_feature_suggestions(State(state.clone()), auth("mod@example.com", true)).await;
        assert!(matches!(moderator_attempt, Err(AppError::Forbidden)), "un modérateur (même promu, pas l'Admin) ne doit PAS voir les suggestions");

        let admin_list = read_json_body(list_feature_suggestions(State(state.clone()), auth("admin2@example.com", true)).await.unwrap().into_response()).await;
        assert_eq!(admin_list.as_array().unwrap().len(), 1, "seul l'Admin doit voir les suggestions");
    }

    /// RÉGRESSION : même garde-fou que ci-dessus, côté suppression.
    #[tokio::test]
    async fn test_only_admin_can_delete_feature_suggestion() {
        let state = build_test_state_with_admin_email("admin3@example.com").await;
        let create_result = create_feature_suggestion(State(state.clone()), auth("membre3@example.com", false), Json(sample_payload("À examiner"))).await.unwrap();
        let id = read_json_body(create_result.into_response()).await["id"].as_str().unwrap().to_string();

        let stranger_attempt = delete_feature_suggestion(State(state.clone()), auth("stranger3@example.com", false), Path(id.clone())).await;
        assert!(matches!(stranger_attempt, Err(AppError::Forbidden)));

        let moderator_attempt = delete_feature_suggestion(State(state.clone()), auth("mod3@example.com", true), Path(id.clone())).await;
        assert!(matches!(moderator_attempt, Err(AppError::Forbidden)), "un modérateur (même promu, pas l'Admin) ne doit PAS pouvoir supprimer une suggestion");

        delete_feature_suggestion(State(state.clone()), auth("admin3@example.com", true), Path(id)).await
            .expect("seul l'Admin doit pouvoir supprimer/marquer traitée une suggestion");
    }

    #[tokio::test]
    async fn test_flooding_feature_suggestions_is_capped_per_author() {
        let state = build_test_state().await;
        for i in 0..crate::repository::MAX_FEATURE_SUGGESTIONS_PER_USER {
            create_feature_suggestion(State(state.clone()), auth("flooder@example.com", false), Json(sample_payload(&format!("Idée {i}")))).await.unwrap();
        }
        let over_the_limit = create_feature_suggestion(State(state.clone()), auth("flooder@example.com", false), Json(sample_payload("Une de trop"))).await;
        assert!(matches!(over_the_limit, Err(AppError::ValidationError(_))), "au-delà de la limite PAR AUTEUR, une nouvelle suggestion doit être refusée");

        // RÉGRESSION : le plafond est PAR AUTEUR, pas global — un autre compte doit pouvoir
        // suggérer normalement même si "flooder" a atteint sa propre limite.
        let other_author = create_feature_suggestion(State(state.clone()), auth("autre@example.com", false), Json(sample_payload("Idée d'un autre compte"))).await;
        assert!(other_author.is_ok(), "le plafond par auteur ne doit jamais bloquer un AUTRE compte");
    }
}
