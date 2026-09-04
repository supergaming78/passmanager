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
use crate::{AppState, error::AppError, middleware::AuthUser, repository::{ThemeProfileRepository, ThemeShareRepository}, models::{ThemeProfilePayload, ShareThemeProfilePayload, UpdatePreferredThemePayload, VALID_THEMES}};
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
// PARTAGE AVEC UN AUTRE UTILISATEUR — retour utilisateur : "au lieu de uniquement copier le code,
// il faudrait plutôt savoir le partager avec d'autres utilisateurs". PAS de crypto (voir
// repository.rs::ThemeShareRepository) — une personnalisation de thème n'a rien à protéger.
// =========================================================================

/// Partage UN des profils du compte connecté avec un autre utilisateur — copie ses valeurs telles
/// quelles au moment du partage (voir ThemeShareRepository::share, pas un lien live). `false`
/// (renvoyé comme 404) si `id` n'appartient pas au compte connecté OU si l'email destinataire ne
/// correspond à aucun compte de ce serveur.
pub async fn share_theme_profile(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(payload): Json<ShareThemeProfilePayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    let shared_with_email = payload.shared_with_email.to_lowercase();
    if shared_with_email == user.email {
        return Err(AppError::ValidationError("Impossible de partager un profil avec soi-même.".to_string()));
    }

    let shared_id = ThemeShareRepository::share(&state.db, &user.email, &id, &shared_with_email).await?;
    let Some(shared_id) = shared_id else {
        return Err(AppError::NotFound);
    };
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": shared_id }))))
}

/// Tous les partages EN ATTENTE reçus par le compte connecté (à afficher/accepter/refuser côté
/// client) — liste vide, pas une erreur, si personne n'a rien partagé avec ce compte.
pub async fn list_shared_theme_profiles(State(state): State<Arc<AppState>>, user: AuthUser) -> Result<impl IntoResponse, AppError> {
    let shares = ThemeShareRepository::list_received(&state.db, &user.email).await?;
    Ok(Json(shares))
}

/// Accepte un partage reçu — le copie dans les PROPRES profils du compte connecté (soumis au même
/// plafond que create_theme_profile) puis retire le partage de la liste d'attente. `404` si le
/// partage n'existe pas / n'est pas adressé à ce compte (voir ThemeShareRepository::accept).
pub async fn accept_shared_theme_profile(State(state): State<Arc<AppState>>, user: AuthUser, Path(id): Path<String>) -> Result<impl IntoResponse, AppError> {
    let is_admin = user.is_admin(&state);
    let created = ThemeShareRepository::accept(&state.db, &id, &user.email, is_admin).await?;
    let Some(created) = created else {
        return Err(AppError::NotFound);
    };
    Ok((StatusCode::CREATED, Json(created)))
}

/// Refuse/retire un partage — l'expéditeur peut annuler AVANT acceptation, le destinataire peut
/// décliner (voir ThemeShareRepository::decline, les deux côtés confondus). `404` si `id` n'existe
/// pas ou n'implique le compte connecté ni comme expéditeur ni comme destinataire.
pub async fn decline_shared_theme_profile(State(state): State<Arc<AppState>>, user: AuthUser, Path(id): Path<String>) -> Result<impl IntoResponse, AppError> {
    let declined = ThemeShareRepository::decline(&state.db, &id, &user.email).await?;
    if !declined {
        return Err(AppError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

// =========================================================================
// CHOIX DU THÈME LUI-MÊME (preset ou "custom") — retour utilisateur : "je veux que lorsqu'on
// choisit un thème ce soit pour partout (aussi l'extension) que le thème soit appliqué partout".
// Distinct de tout ce qui précède (qui gère les COULEURS d'un profil "Personnalisé…") : ce champ
// dit simplement LEQUEL des thèmes disponibles est actuellement choisi sur le compte, y compris un
// simple preset (Sombre/Minuit/Océan/...) qui restait jusqu'ici purement local à chaque appareil
// (voir la migration 20260903070000_users_preferred_theme.sql).
// =========================================================================

/// Met à jour le thème actuellement choisi par le compte connecté. Aucune vérification de rôle
/// au-delà d'être connecté (même raisonnement que le reste de ce fichier) : une préférence
/// d'affichage n'a rien à protéger.
pub async fn update_preferred_theme(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(payload): Json<UpdatePreferredThemePayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    if !VALID_THEMES.contains(&payload.theme.as_str()) {
        return Err(AppError::ValidationError("Thème inconnu.".to_string()));
    }

    sqlx::query("UPDATE users SET preferred_theme = ? WHERE email = ?")
        .bind(&payload.theme)
        .bind(&user.email)
        .execute(&state.db)
        .await?;

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
            vacuum_in_progress: Default::default(),
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
            background_saturation: 80,
            accent_hue: 180,
            accent_lightness: 55,
            accent_saturation: 100,
            danger_hue: 20,
            danger_lightness: 60,
            danger_saturation: 100,
            success_hue: 150,
            success_lightness: 65,
            success_saturation: 100,
            favorite_hue: 60,
            favorite_lightness: 75,
            favorite_saturation: 100,
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
        assert_eq!(profiles[0]["background_saturation"], 80);
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

    #[tokio::test]
    async fn test_create_rejects_out_of_range_saturation() {
        let state = build_test_state(None).await;
        let mut payload = sample_payload("Invalide");
        payload.background_saturation = 150;
        let result = create_theme_profile(State(state), auth("user7@example.com"), Json(payload)).await;
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

    // -----------------------------------------------------------------
    // PARTAGE AVEC UN AUTRE UTILISATEUR
    // -----------------------------------------------------------------

    /// Cycle de vie complet : partage -> visible côté destinataire -> acceptation -> devient un
    /// profil à part entière chez le destinataire -> le partage en attente a disparu.
    #[tokio::test]
    async fn test_share_accept_lifecycle() {
        let state = build_test_state(None).await;
        register_test_user(&state, "sender@example.com").await;
        register_test_user(&state, "recipient@example.com").await;

        let created = create_theme_profile(State(state.clone()), auth("sender@example.com"), Json(sample_payload("Mon thème"))).await.unwrap();
        let profile_id = read_json_body(created.into_response()).await["id"].as_str().unwrap().to_string();

        let share_result = share_theme_profile(
            State(state.clone()),
            auth("sender@example.com"),
            Path(profile_id),
            Json(ShareThemeProfilePayload { shared_with_email: "recipient@example.com".to_string() }),
        )
        .await
        .expect("le partage doit réussir");
        let share_id = read_json_body(share_result.into_response()).await["id"].as_str().unwrap().to_string();

        // Visible côté destinataire.
        let received = list_shared_theme_profiles(State(state.clone()), auth("recipient@example.com")).await.unwrap();
        let received_body = read_json_body(received.into_response()).await;
        let received_rows = received_body.as_array().unwrap();
        assert_eq!(received_rows.len(), 1);
        assert_eq!(received_rows[0]["from_email"], "sender@example.com");
        assert_eq!(received_rows[0]["name"], "Mon thème");

        // Acceptation -> devient un profil chez le destinataire.
        let accepted = accept_shared_theme_profile(State(state.clone()), auth("recipient@example.com"), Path(share_id)).await.unwrap();
        let accepted_body = read_json_body(accepted.into_response()).await;
        assert_eq!(accepted_body["name"], "Mon thème");
        assert_eq!(accepted_body["accent_hue"], 180);

        let recipient_profiles = list_theme_profiles(State(state.clone()), auth("recipient@example.com")).await.unwrap();
        let recipient_body = read_json_body(recipient_profiles.into_response()).await;
        assert_eq!(recipient_body.as_array().unwrap().len(), 1, "le partage accepté doit apparaître dans les propres profils du destinataire");

        // Le partage en attente a disparu après acceptation.
        let received_after = list_shared_theme_profiles(State(state.clone()), auth("recipient@example.com")).await.unwrap();
        let received_after_body = read_json_body(received_after.into_response()).await;
        assert_eq!(received_after_body.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_cannot_share_with_self() {
        let state = build_test_state(None).await;
        register_test_user(&state, "solo@example.com").await;
        let created = create_theme_profile(State(state.clone()), auth("solo@example.com"), Json(sample_payload("Profil"))).await.unwrap();
        let profile_id = read_json_body(created.into_response()).await["id"].as_str().unwrap().to_string();

        let result = share_theme_profile(
            State(state.clone()),
            auth("solo@example.com"),
            Path(profile_id),
            Json(ShareThemeProfilePayload { shared_with_email: "solo@example.com".to_string() }),
        )
        .await;
        assert!(matches!(result, Err(AppError::ValidationError(_))));
    }

    /// RÉGRESSION SÉCURITÉ : impossible de partager le profil d'un AUTRE utilisateur.
    #[tokio::test]
    async fn test_cannot_share_another_users_profile() {
        let state = build_test_state(None).await;
        register_test_user(&state, "realowner3@example.com").await;
        register_test_user(&state, "attacker3@example.com").await;
        register_test_user(&state, "victim3@example.com").await;
        let created = create_theme_profile(State(state.clone()), auth("realowner3@example.com"), Json(sample_payload("Profil"))).await.unwrap();
        let profile_id = read_json_body(created.into_response()).await["id"].as_str().unwrap().to_string();

        let result = share_theme_profile(
            State(state.clone()),
            auth("attacker3@example.com"),
            Path(profile_id),
            Json(ShareThemeProfilePayload { shared_with_email: "victim3@example.com".to_string() }),
        )
        .await;
        assert!(matches!(result, Err(AppError::NotFound)));
    }

    #[tokio::test]
    async fn test_share_with_nonexistent_recipient_fails() {
        let state = build_test_state(None).await;
        register_test_user(&state, "sender2@example.com").await;
        let created = create_theme_profile(State(state.clone()), auth("sender2@example.com"), Json(sample_payload("Profil"))).await.unwrap();
        let profile_id = read_json_body(created.into_response()).await["id"].as_str().unwrap().to_string();

        let result = share_theme_profile(
            State(state.clone()),
            auth("sender2@example.com"),
            Path(profile_id),
            Json(ShareThemeProfilePayload { shared_with_email: "personne@example.com".to_string() }),
        )
        .await;
        assert!(matches!(result, Err(AppError::NotFound)));
    }

    /// RÉGRESSION SÉCURITÉ : ni un tiers étranger, ni même l'expéditeur, ne peuvent ACCEPTER un
    /// partage qui ne leur est pas adressé (seul le destinataire désigné le peut).
    #[tokio::test]
    async fn test_only_recipient_can_accept_share() {
        let state = build_test_state(None).await;
        register_test_user(&state, "sender3@example.com").await;
        register_test_user(&state, "recipient3@example.com").await;
        register_test_user(&state, "stranger3@example.com").await;
        let created = create_theme_profile(State(state.clone()), auth("sender3@example.com"), Json(sample_payload("Profil"))).await.unwrap();
        let profile_id = read_json_body(created.into_response()).await["id"].as_str().unwrap().to_string();
        let share_result = share_theme_profile(
            State(state.clone()),
            auth("sender3@example.com"),
            Path(profile_id),
            Json(ShareThemeProfilePayload { shared_with_email: "recipient3@example.com".to_string() }),
        )
        .await
        .unwrap();
        let share_id = read_json_body(share_result.into_response()).await["id"].as_str().unwrap().to_string();

        let stranger_attempt = accept_shared_theme_profile(State(state.clone()), auth("stranger3@example.com"), Path(share_id.clone())).await;
        assert!(matches!(stranger_attempt, Err(AppError::NotFound)));

        let sender_attempt = accept_shared_theme_profile(State(state.clone()), auth("sender3@example.com"), Path(share_id)).await;
        assert!(matches!(sender_attempt, Err(AppError::NotFound)));
    }

    /// L'expéditeur ET le destinataire peuvent tous les deux décliner/annuler un partage en
    /// attente — mais pas un tiers étranger.
    #[tokio::test]
    async fn test_decline_share_either_side() {
        let state = build_test_state(None).await;
        register_test_user(&state, "sender4@example.com").await;
        register_test_user(&state, "recipient4@example.com").await;
        register_test_user(&state, "stranger4@example.com").await;
        let created = create_theme_profile(State(state.clone()), auth("sender4@example.com"), Json(sample_payload("Profil"))).await.unwrap();
        let profile_id = read_json_body(created.into_response()).await["id"].as_str().unwrap().to_string();

        async fn make_share(state: &Arc<AppState>, profile_id: &str) -> String {
            let result = share_theme_profile(
                State(state.clone()),
                auth("sender4@example.com"),
                Path(profile_id.to_string()),
                Json(ShareThemeProfilePayload { shared_with_email: "recipient4@example.com".to_string() }),
            )
            .await
            .unwrap();
            read_json_body(result.into_response()).await["id"].as_str().unwrap().to_string()
        }

        // Un tiers étranger ne peut pas décliner.
        let share_id_1 = make_share(&state, &profile_id).await;
        let stranger_attempt = decline_shared_theme_profile(State(state.clone()), auth("stranger4@example.com"), Path(share_id_1.clone())).await;
        assert!(matches!(stranger_attempt, Err(AppError::NotFound)));

        // Le destinataire peut décliner.
        decline_shared_theme_profile(State(state.clone()), auth("recipient4@example.com"), Path(share_id_1)).await.unwrap();

        // L'expéditeur peut annuler.
        let share_id_2 = make_share(&state, &profile_id).await;
        decline_shared_theme_profile(State(state.clone()), auth("sender4@example.com"), Path(share_id_2)).await.unwrap();

        let received = list_shared_theme_profiles(State(state.clone()), auth("recipient4@example.com")).await.unwrap();
        let received_body = read_json_body(received.into_response()).await;
        assert_eq!(received_body.as_array().unwrap().len(), 0, "les deux partages déclinés/annulés ne doivent plus apparaître");
    }

    /// RÉGRESSION : accepter un partage alors que le destinataire a déjà 3 profils (plafond non-
    /// admin) échoue — le partage reste EN ATTENTE (pas perdu), le destinataire peut réessayer
    /// après avoir supprimé un profil.
    #[tokio::test]
    async fn test_accept_share_respects_profile_limit() {
        let state = build_test_state(None).await;
        register_test_user(&state, "sender5@example.com").await;
        register_test_user(&state, "recipient5@example.com").await;
        for i in 0..3 {
            create_theme_profile(State(state.clone()), auth("recipient5@example.com"), Json(sample_payload(&format!("Profil {i}")))).await.unwrap();
        }
        let created = create_theme_profile(State(state.clone()), auth("sender5@example.com"), Json(sample_payload("Cadeau"))).await.unwrap();
        let profile_id = read_json_body(created.into_response()).await["id"].as_str().unwrap().to_string();
        let share_result = share_theme_profile(
            State(state.clone()),
            auth("sender5@example.com"),
            Path(profile_id),
            Json(ShareThemeProfilePayload { shared_with_email: "recipient5@example.com".to_string() }),
        )
        .await
        .unwrap();
        let share_id = read_json_body(share_result.into_response()).await["id"].as_str().unwrap().to_string();

        let accept_result = accept_shared_theme_profile(State(state.clone()), auth("recipient5@example.com"), Path(share_id.clone())).await;
        assert!(matches!(accept_result, Err(AppError::ValidationError(_))));

        // Toujours en attente, pas perdu.
        let received = list_shared_theme_profiles(State(state.clone()), auth("recipient5@example.com")).await.unwrap();
        let received_body = read_json_body(received.into_response()).await;
        assert_eq!(received_body.as_array().unwrap().len(), 1);
    }

    /// RÉGRESSION : le thème choisi (preset ou "custom") doit être persisté et relisible via
    /// GET /me (voir handlers/auth/account.rs::get_me) — c'est tout l'intérêt de ce champ (retour
    /// utilisateur : "que le thème soit appliqué partout").
    #[tokio::test]
    async fn test_update_preferred_theme_persists_and_is_readable_via_get_me() {
        let state = build_test_state(None).await;
        let email = "themepref@example.com";
        register_test_user(&state, email).await;

        update_preferred_theme(State(state.clone()), auth(email), Json(UpdatePreferredThemePayload { theme: "midnight".to_string() }))
            .await
            .expect("un thème valide doit être accepté");

        let stored: (String,) = sqlx::query_as("SELECT preferred_theme FROM users WHERE email = ?")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(stored.0, "midnight");
    }

    /// RÉGRESSION : une valeur hors de VALID_THEMES doit être rejetée (400), jamais stockée telle
    /// quelle — sinon un client buggé pourrait laisser un compte dans un état que ni l'app ni
    /// l'extension ne savent interpréter (repli silencieux sur "dark" des deux côtés, mais mieux
    /// vaut refuser à la source).
    #[tokio::test]
    async fn test_update_preferred_theme_rejects_unknown_value() {
        let state = build_test_state(None).await;
        let email = "badtheme@example.com";
        register_test_user(&state, email).await;

        let result = update_preferred_theme(State(state.clone()), auth(email), Json(UpdatePreferredThemePayload { theme: "not-a-real-theme".to_string() })).await;
        assert!(matches!(result, Err(AppError::ValidationError(_))));

        let stored: (String,) = sqlx::query_as("SELECT preferred_theme FROM users WHERE email = ?")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(stored.0, "dark", "la valeur par défaut ne doit pas avoir été écrasée par une valeur invalide");
    }

    /// Défaut ('dark') pour un compte qui n'a jamais touché ce réglage — non-régression du
    /// comportement précédent (voir le commentaire de la migration).
    #[tokio::test]
    async fn test_preferred_theme_defaults_to_dark() {
        let state = build_test_state(None).await;
        let email = "neverset@example.com";
        register_test_user(&state, email).await;

        let stored: (String,) = sqlx::query_as("SELECT preferred_theme FROM users WHERE email = ?")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(stored.0, "dark");
    }
}
