// =========================================================================
// SIGNALEMENT DE BUG — desktop/Android (voir migration 20260901000000_bug_reports.sql et
// models.rs pour le détail du modèle). PAS chiffré, contrairement au coffre : un texte technique
// destiné à être lu directement par un modérateur, pas une donnée du coffre. `create_bug_report`
// est la SEULE route publique de ce fichier (accessible même sans connexion, voir la garde
// sensitive_governor dans main.rs) — un bug qui empêche justement de se connecter doit pouvoir
// être signalé depuis l'app elle-même.
// =========================================================================
use axum::{
    extract::{State, Path},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use tracing::warn;
use crate::{AppState, error::AppError, middleware::AuthUser, repository::BugReportRepository, models::CreateBugReportPayload};
use validator::Validate;

/// Route PUBLIQUE — aucun `AuthUser` en paramètre, volontairement (voir le commentaire en tête de
/// fichier). `reporter_email` dans le payload est une simple information de contact facultative,
/// jamais vérifiée contre un compte réel.
pub async fn create_bug_report(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateBugReportPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;

    let id = BugReportRepository::create(&state.db, &payload).await?;

    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id }))))
}

/// Réservé au modérateur.
pub async fn list_bug_reports(State(state): State<Arc<AppState>>, user: AuthUser) -> Result<impl IntoResponse, AppError> {
    if !user.is_moderator {
        warn!("Tentative d'accès non autorisé aux signalements de bug par {}", user.email);
        return Err(AppError::Forbidden);
    }

    let reports = BugReportRepository::list_all(&state.db).await?;
    Ok(Json(reports))
}

/// Réservé au modérateur — supprime le signalement (voir BugReportRepository::delete, pas de
/// statut "résolu" séparé dans cette première version : la suppression EST la façon de marquer
/// "traité").
pub async fn delete_bug_report(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_moderator {
        warn!("Tentative de suppression non autorisée d'un signalement de bug par {}", user.email);
        return Err(AppError::Forbidden);
    }

    BugReportRepository::delete(&state.db, &id).await?;
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

    fn auth(email: &str, is_moderator: bool) -> AuthUser {
        AuthUser { email: email.to_string(), is_moderator }
    }

    async fn read_json_body(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).expect("le corps doit être du JSON valide")
    }

    fn sample_payload(description: &str) -> CreateBugReportPayload {
        CreateBugReportPayload {
            description: description.to_string(),
            reporter_email: Some("quelqu-un@example.com".to_string()),
            app_version: "0.1.0".to_string(),
            platform: "Windows".to_string(),
        }
    }

    /// RÉGRESSION CRITIQUE : create_bug_report doit fonctionner SANS AuthUser du tout — c'est tout
    /// l'intérêt de cette route (signaler un bug qui empêche justement de se connecter).
    #[tokio::test]
    async fn test_create_bug_report_works_without_authentication() {
        let state = build_test_state().await;

        let result = create_bug_report(State(state.clone()), Json(sample_payload("Le bouton casse tout"))).await;
        assert!(result.is_ok(), "signaler un bug ne doit JAMAIS exiger d'être connecté");
    }

    #[tokio::test]
    async fn test_reporter_email_is_optional() {
        let state = build_test_state().await;
        let mut payload = sample_payload("Bug sans email de contact");
        payload.reporter_email = None;

        let result = create_bug_report(State(state.clone()), Json(payload)).await;
        assert!(result.is_ok(), "l'email de contact doit rester facultatif");
    }

    #[tokio::test]
    async fn test_only_moderator_can_list_bug_reports() {
        let state = build_test_state().await;
        create_bug_report(State(state.clone()), Json(sample_payload("Bug visible"))).await.unwrap();

        let stranger_attempt = list_bug_reports(State(state.clone()), auth("stranger@example.com", false)).await;
        assert!(matches!(stranger_attempt, Err(AppError::Forbidden)), "un compte non-modérateur ne doit jamais voir les signalements");

        let moderator_list = read_json_body(list_bug_reports(State(state.clone()), auth("mod@example.com", true)).await.unwrap().into_response()).await;
        assert_eq!(moderator_list.as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_only_moderator_can_delete_bug_report() {
        let state = build_test_state().await;
        let create_result = create_bug_report(State(state.clone()), Json(sample_payload("À supprimer"))).await.unwrap();
        let id = read_json_body(create_result.into_response()).await["id"].as_str().unwrap().to_string();

        let stranger_attempt = delete_bug_report(State(state.clone()), auth("stranger2@example.com", false), Path(id.clone())).await;
        assert!(matches!(stranger_attempt, Err(AppError::Forbidden)));

        delete_bug_report(State(state.clone()), auth("mod2@example.com", true), Path(id)).await
            .expect("un modérateur doit pouvoir supprimer un signalement traité");
    }

    #[tokio::test]
    async fn test_flooding_bug_reports_is_capped() {
        let state = build_test_state().await;
        for i in 0..crate::repository::MAX_BUG_REPORTS_TOTAL {
            create_bug_report(State(state.clone()), Json(sample_payload(&format!("Bug {i}")))).await.unwrap();
        }
        let over_the_limit = create_bug_report(State(state.clone()), Json(sample_payload("Un de trop"))).await;
        assert!(matches!(over_the_limit, Err(AppError::ValidationError(_))), "au-delà de la limite globale, un nouveau signalement doit être refusé");
    }
}
