// =========================================================================
// PERSONNALISATION DE THÈME — PROFILS synchronisés par COMPTE (retour utilisateur, 2026-09-03,
// voir migration 20260903000000_theme_customization_profiles.sql et models.rs pour le détail du
// modèle). Chaque compte gère UNIQUEMENT ses propres profils (email tiré de `AuthUser`, jamais
// d'un paramètre d'URL/du payload) — aucune vérification de rôle nécessaire au-delà d'être
// connecté, SAUF pour le plafond de création (3 profils max, illimité pour l'Admin uniquement, via
// `user.is_admin(&state)` — voir ThemeProfileRepository::create).
// =========================================================================
use axum::{
    extract::{State, Path},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use crate::{AppState, error::AppError, middleware::AuthUser, repository::ThemeProfileRepository, models::ThemeProfilePayload};
use validator::Validate;

/// Tous les profils du compte connecté (voir ThemeProfileView pour `is_active`) — liste vide, pas
/// une erreur, si le compte n'en a jamais créé (thème preset actif côté client dans ce cas).
pub async fn list_theme_profiles(State(state): State<Arc<AppState>>, user: AuthUser) -> Result<impl IntoResponse, AppError> {
    let profiles = ThemeProfileRepository::list(&state.db, &user.email).await?;
    Ok(Json(profiles))
}

/// Crée un nouveau profil (jamais actif à la création, voir activate_theme_profile) — plafonné à
/// 3 par compte SAUF pour l'Admin (voir le commentaire d'en-tête), qui n'a aucune limite.
pub async fn create_theme_profile(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(payload): Json<ThemeProfilePayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    let is_admin = user.is_admin(&state);
    let profile = ThemeProfileRepository::create(&state.db, &user.email, &payload, is_admin).await?;
    Ok((StatusCode::CREATED, Json(profile)))
}

/// Modifie un profil existant (nom + toutes les teintes/luminosités) — 404 si l'id n'appartient
/// pas au compte connecté (voir ThemeProfileRepository::update, jamais un profil d'un autre
/// compte). N'affecte PAS `is_active` (voir activate_theme_profile, une action séparée).
pub async fn update_theme_profile(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(payload): Json<ThemeProfilePayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    let updated = ThemeProfileRepository::update(&state.db, &user.email, &id, &payload).await?;
    if !updated {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Supprime un profil — idempotent au sens où retenter avec un id déjà supprimé renvoie 404 (pas
/// une erreur serveur), comme le reste de cette API. Si le profil supprimé était actif, plus AUCUN
/// profil n'est actif ensuite (le client retombe sur un thème preset) — jamais réactivé
/// automatiquement un autre profil à sa place.
pub async fn delete_theme_profile(State(state): State<Arc<AppState>>, user: AuthUser, Path(id): Path<String>) -> Result<impl IntoResponse, AppError> {
    let deleted = ThemeProfileRepository::delete(&state.db, &user.email, &id).await?;
    if !deleted {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Active ce profil (et désactive tous les autres du compte, voir
/// ThemeProfileRepository::activate — transaction atomique, jamais deux profils actifs à la fois).
pub async fn activate_theme_profile(State(state): State<Arc<AppState>>, user: AuthUser, Path(id): Path<String>) -> Result<impl IntoResponse, AppError> {
    let activated = ThemeProfileRepository::activate(&state.db, &user.email, &id).await?;
    if !activated {
        return Err(AppError::NotFound);
    }
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

    async fn build_test_state(admin_email: Option<String>) -> Arc<AppState> {
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
            admin_email,
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

    /// `theme_customization_profiles.user_email` a une vraie contrainte FOREIGN KEY vers
    /// `users(email)` (voir la migration) — même pattern que
    /// handlers/shared_vault.rs::register_test_user.
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

    fn sample_payload(name: &str) -> ThemeProfilePayload {
        ThemeProfilePayload {
            name: name.to_string(),
            background_hue: 220,
            background_lightness: 12,
            accent_hue: 180,
            accent_lightness: 55,
            danger_hue: 20,
            danger_lightness: 60,
            success_hue: 150,
            success_lightness: 65,
            favorite_hue: 60,
            favorite_lightness: 75,
        }
    }

    #[tokio::test]
    async fn test_list_is_empty_when_never_configured() {
        let state = build_test_state(None).await;
        let response = list_theme_profiles(State(state), auth("jamais-configure@example.com")).await.unwrap();
        let body = read_json_body(response.into_response()).await;
        assert_eq!(body.as_array().unwrap().len(), 0);
    }

    /// Création puis relecture — round-trip complet, profil jamais actif à la création.
    #[tokio::test]
    async fn test_create_then_list_round_trips() {
        let state = build_test_state(None).await;
        let email = "user@example.com";
        register_test_user(&state, email).await;

        create_theme_profile(State(state.clone()), auth(email), Json(sample_payload("Mon profil"))).await.unwrap();

        let response = list_theme_profiles(State(state.clone()), auth(email)).await.unwrap();
        let body = read_json_body(response.into_response()).await;
        let profiles = body.as_array().unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0]["name"], "Mon profil");
        assert_eq!(profiles[0]["accent_hue"], 180);
        assert_eq!(profiles[0]["is_active"], false);
    }

    /// RÉGRESSION : un compte normal ne peut pas dépasser 3 profils.
    #[tokio::test]
    async fn test_non_admin_capped_at_three_profiles() {
        let state = build_test_state(Some("admin@example.com".to_string())).await;
        let email = "user2@example.com";
        register_test_user(&state, email).await;

        for i in 0..3 {
            create_theme_profile(State(state.clone()), auth(email), Json(sample_payload(&format!("Profil {i}")))).await.unwrap();
        }
        let result = create_theme_profile(State(state.clone()), auth(email), Json(sample_payload("Profil 4"))).await;
        assert!(matches!(result, Err(AppError::ValidationError(_))));
    }

    /// RÉGRESSION : l'Admin (ADMIN_EMAIL) n'a lui AUCUNE limite.
    #[tokio::test]
    async fn test_admin_has_no_profile_limit() {
        let admin_email = "admin@example.com";
        let state = build_test_state(Some(admin_email.to_string())).await;
        register_test_user(&state, admin_email).await;

        for i in 0..5 {
            create_theme_profile(State(state.clone()), auth(admin_email), Json(sample_payload(&format!("Profil {i}")))).await.unwrap();
        }

        let response = list_theme_profiles(State(state.clone()), auth(admin_email)).await.unwrap();
        let body = read_json_body(response.into_response()).await;
        assert_eq!(body.as_array().unwrap().len(), 5);
    }

    /// RÉGRESSION SÉCURITÉ : les profils d'un compte ne doivent jamais fuiter vers un autre.
    #[tokio::test]
    async fn test_profiles_are_isolated_between_accounts() {
        let state = build_test_state(None).await;
        register_test_user(&state, "a@example.com").await;
        register_test_user(&state, "b@example.com").await;
        create_theme_profile(State(state.clone()), auth("a@example.com"), Json(sample_payload("Profil A"))).await.unwrap();

        let response = list_theme_profiles(State(state.clone()), auth("b@example.com")).await.unwrap();
        let body = read_json_body(response.into_response()).await;
        assert_eq!(body.as_array().unwrap().len(), 0, "le compte b ne doit jamais voir les profils du compte a");
    }

    #[tokio::test]
    async fn test_create_rejects_out_of_range_hue() {
        let state = build_test_state(None).await;
        let mut payload = sample_payload("Invalide");
        payload.accent_hue = 400;
        let result = create_theme_profile(State(state), auth("user3@example.com"), Json(payload)).await;
        assert!(matches!(result, Err(AppError::ValidationError(_))));
    }

    #[tokio::test]
    async fn test_create_rejects_out_of_range_lightness() {
        let state = build_test_state(None).await;
        let mut payload = sample_payload("Invalide");
        payload.background_lightness = 150;
        let result = create_theme_profile(State(state), auth("user4@example.com"), Json(payload)).await;
        assert!(matches!(result, Err(AppError::ValidationError(_))));
    }

    /// Activer un profil le marque actif ET désactive tous les autres du même compte.
    #[tokio::test]
    async fn test_activate_deactivates_other_profiles() {
        let state = build_test_state(None).await;
        let email = "user5@example.com";
        register_test_user(&state, email).await;

        let r1 = create_theme_profile(State(state.clone()), auth(email), Json(sample_payload("Profil 1"))).await.unwrap();
        let body1 = read_json_body(r1.into_response()).await;
        let id1 = body1["id"].as_str().unwrap().to_string();

        let r2 = create_theme_profile(State(state.clone()), auth(email), Json(sample_payload("Profil 2"))).await.unwrap();
        let body2 = read_json_body(r2.into_response()).await;
        let id2 = body2["id"].as_str().unwrap().to_string();

        activate_theme_profile(State(state.clone()), auth(email), Path(id1.clone())).await.unwrap();
        activate_theme_profile(State(state.clone()), auth(email), Path(id2.clone())).await.unwrap();

        let response = list_theme_profiles(State(state.clone()), auth(email)).await.unwrap();
        let body = read_json_body(response.into_response()).await;
        let profiles = body.as_array().unwrap();
        let active: Vec<&serde_json::Value> = profiles.iter().filter(|p| p["is_active"] == true).collect();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0]["id"], id2);
    }

    /// RÉGRESSION SÉCURITÉ : impossible d'activer/modifier/supprimer le profil d'un AUTRE compte.
    #[tokio::test]
    async fn test_cannot_activate_update_or_delete_another_accounts_profile() {
        let state = build_test_state(None).await;
        register_test_user(&state, "a2@example.com").await;
        register_test_user(&state, "b2@example.com").await;
        let created = create_theme_profile(State(state.clone()), auth("a2@example.com"), Json(sample_payload("Profil A"))).await.unwrap();
        let body = read_json_body(created.into_response()).await;
        let id = body["id"].as_str().unwrap().to_string();

        let activate_result = activate_theme_profile(State(state.clone()), auth("b2@example.com"), Path(id.clone())).await;
        assert!(matches!(activate_result, Err(AppError::NotFound)));

        let update_result = update_theme_profile(State(state.clone()), auth("b2@example.com"), Path(id.clone()), Json(sample_payload("Piraté"))).await;
        assert!(matches!(update_result, Err(AppError::NotFound)));

        let delete_result = delete_theme_profile(State(state.clone()), auth("b2@example.com"), Path(id.clone())).await;
        assert!(matches!(delete_result, Err(AppError::NotFound)));
    }

    #[tokio::test]
    async fn test_delete_nonexistent_profile_returns_not_found() {
        let state = build_test_state(None).await;
        let result = delete_theme_profile(State(state), auth("user6@example.com"), Path("id-inexistant".to_string())).await;
        assert!(matches!(result, Err(AppError::NotFound)));
    }
}
