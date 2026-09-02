// =========================================================================
// PERSONNALISATION DE THÈME — synchronisée par COMPTE (retour utilisateur, 2026-09-03), voir
// migration 20260903000000_user_theme_customization.sql et models.rs pour le détail du modèle.
// Contrairement au reste du panneau Administration/aux autres fichiers de ce module, ce n'est PAS
// une ressource administrée : chaque compte gère UNIQUEMENT sa propre personnalisation (email
// tiré de `AuthUser`, jamais d'un paramètre d'URL/du payload) — aucune vérification de rôle
// nécessaire au-delà d'être connecté.
// =========================================================================
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use std::sync::Arc;
use crate::{AppState, error::AppError, middleware::AuthUser, repository::ThemeCustomizationRepository, models::UpdateThemeCustomizationPayload};
use validator::Validate;

/// `null` (pas d'erreur) si le compte n'a jamais enregistré de personnalisation — voir le
/// commentaire de models.rs::ThemeCustomizationView. Le client applique alors un thème preset.
pub async fn get_theme_customization(State(state): State<Arc<AppState>>, user: AuthUser) -> Result<impl IntoResponse, AppError> {
    let customization = ThemeCustomizationRepository::get(&state.db, &user.email).await?;
    Ok(Json(customization))
}

/// Enregistre/remplace la personnalisation du compte connecté (UPSERT, voir
/// ThemeCustomizationRepository::set — jamais plusieurs lignes pour un même compte). `mode` validé
/// à la main ici (juste deux valeurs possibles) — le reste (teintes 0-359) via
/// `payload.validate()`, voir models.rs.
pub async fn update_theme_customization(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(payload): Json<UpdateThemeCustomizationPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    if payload.mode != "dark" && payload.mode != "light" {
        return Err(AppError::ValidationError("Le mode doit être \"dark\" ou \"light\".".to_string()));
    }

    ThemeCustomizationRepository::set(&state.db, &user.email, &payload).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Revient au thème preset — supprime la personnalisation enregistrée (voir
/// ThemeCustomizationRepository::delete). Jamais d'erreur si aucune personnalisation n'existait
/// déjà (idempotent, comme une déconnexion d'un appareil déjà déconnecté ailleurs dans ce projet).
pub async fn delete_theme_customization(State(state): State<Arc<AppState>>, user: AuthUser) -> Result<impl IntoResponse, AppError> {
    ThemeCustomizationRepository::delete(&state.db, &user.email).await?;
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

    fn auth(email: &str) -> AuthUser {
        AuthUser { email: email.to_string(), is_moderator: false }
    }

    /// `user_theme_customization.user_email` a une vraie contrainte FOREIGN KEY vers `users(email)`
    /// (voir la migration) — contrairement à bug_reports/feature_suggestions, qui acceptent
    /// n'importe quel email sans compte réel derrière. Un compte "connecté" (AuthUser) correspond
    /// TOUJOURS à une ligne réelle dans `users` en usage normal, donc ces tests doivent en insérer
    /// une pour de vrai plutôt que de fabriquer juste un AuthUser (même pattern que
    /// handlers/shared_vault.rs::register_test_user).
    async fn register_test_user(state: &Arc<AppState>, email: &str) {
        sqlx::query("INSERT INTO users (email, password_hash) VALUES (?, ?)")
            .bind(email)
            .bind("hash_non_pertinent_pour_ce_test")
            .execute(&state.db)
            .await
            .expect("l'insertion de l'utilisateur de test doit réussir");
    }

    async fn read_json_body(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).expect("le corps doit être du JSON valide")
    }

    fn sample_payload() -> UpdateThemeCustomizationPayload {
        UpdateThemeCustomizationPayload {
            mode: "dark".to_string(),
            accent_hue: 180,
            background_tinted: true,
            danger_hue: 20,
            success_hue: 150,
            favorite_hue: 60,
        }
    }

    /// RÉGRESSION : un compte sans personnalisation enregistrée doit voir `null`, pas une erreur.
    #[tokio::test]
    async fn test_get_returns_null_when_never_configured() {
        let state = build_test_state().await;
        let response = get_theme_customization(State(state), auth("jamais-configure@example.com")).await.unwrap();
        let body = read_json_body(response.into_response()).await;
        assert!(body.is_null());
    }

    /// Enregistrement puis relecture — round-trip complet.
    #[tokio::test]
    async fn test_update_then_get_round_trips() {
        let state = build_test_state().await;
        let email = "user@example.com";
        register_test_user(&state, email).await;

        update_theme_customization(State(state.clone()), auth(email), Json(sample_payload())).await.unwrap();

        let response = get_theme_customization(State(state.clone()), auth(email)).await.unwrap();
        let body = read_json_body(response.into_response()).await;
        assert_eq!(body["mode"], "dark");
        assert_eq!(body["accent_hue"], 180);
        assert_eq!(body["background_tinted"], true);
        assert_eq!(body["danger_hue"], 20);
        assert_eq!(body["success_hue"], 150);
        assert_eq!(body["favorite_hue"], 60);
    }

    /// RÉGRESSION : un second enregistrement REMPLACE le premier (UPSERT), ne s'accumule jamais en
    /// plusieurs lignes pour le même compte.
    #[tokio::test]
    async fn test_update_replaces_previous_customization() {
        let state = build_test_state().await;
        let email = "user2@example.com";
        register_test_user(&state, email).await;

        update_theme_customization(State(state.clone()), auth(email), Json(sample_payload())).await.unwrap();

        let mut second = sample_payload();
        second.accent_hue = 300;
        second.mode = "light".to_string();
        update_theme_customization(State(state.clone()), auth(email), Json(second)).await.unwrap();

        let response = get_theme_customization(State(state.clone()), auth(email)).await.unwrap();
        let body = read_json_body(response.into_response()).await;
        assert_eq!(body["accent_hue"], 300);
        assert_eq!(body["mode"], "light");
    }

    /// RÉGRESSION SÉCURITÉ : la personnalisation d'un compte ne doit jamais fuiter vers un autre.
    #[tokio::test]
    async fn test_customization_is_isolated_between_accounts() {
        let state = build_test_state().await;
        register_test_user(&state, "a@example.com").await;
        register_test_user(&state, "b@example.com").await;
        update_theme_customization(State(state.clone()), auth("a@example.com"), Json(sample_payload())).await.unwrap();

        let response = get_theme_customization(State(state.clone()), auth("b@example.com")).await.unwrap();
        let body = read_json_body(response.into_response()).await;
        assert!(body.is_null(), "le compte b ne doit jamais voir la personnalisation du compte a");
    }

    #[tokio::test]
    async fn test_update_rejects_out_of_range_hue() {
        let state = build_test_state().await;
        let mut payload = sample_payload();
        payload.accent_hue = 400;
        let result = update_theme_customization(State(state), auth("user3@example.com"), Json(payload)).await;
        assert!(matches!(result, Err(AppError::ValidationError(_))));
    }

    #[tokio::test]
    async fn test_update_rejects_invalid_mode() {
        let state = build_test_state().await;
        let mut payload = sample_payload();
        payload.mode = "sepia".to_string();
        let result = update_theme_customization(State(state), auth("user4@example.com"), Json(payload)).await;
        assert!(matches!(result, Err(AppError::ValidationError(_))));
    }

    /// RÉGRESSION : DELETE doit fonctionner même si aucune personnalisation n'existait déjà
    /// (idempotent), et retirer bien la ligne existante sinon.
    #[tokio::test]
    async fn test_delete_reverts_to_preset() {
        let state = build_test_state().await;
        let email = "user5@example.com";
        register_test_user(&state, email).await;

        // Idempotent sans rien à supprimer.
        delete_theme_customization(State(state.clone()), auth(email)).await.unwrap();

        update_theme_customization(State(state.clone()), auth(email), Json(sample_payload())).await.unwrap();
        delete_theme_customization(State(state.clone()), auth(email)).await.unwrap();

        let response = get_theme_customization(State(state.clone()), auth(email)).await.unwrap();
        let body = read_json_body(response.into_response()).await;
        assert!(body.is_null());
    }
}
