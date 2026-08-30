// =========================================================================
// PARTAGE SÉCURISÉ D'UNE ENTRÉE
// =========================================================================
// Permet au PROPRIÉTAIRE d'une entrée du coffre de la partager INSTANTANÉMENT avec un autre
// utilisateur de ce même serveur — contrairement à l'accès d'urgence (voir handlers/emergency.rs),
// pas de délai d'attente ni de machine à états : un partage existe ou n'existe pas.
//
// ZERO-KNOWLEDGE DE BOUT EN BOUT, même construction que l'accès d'urgence : le serveur ne voit et
// ne déchiffre JAMAIS le contenu de l'entrée partagée. Le propriétaire chiffre (JSON) les champs
// en clair de l'entrée avec la clé PUBLIQUE X25519 du destinataire (voir
// src-tauri/src/sharing.rs::seal_for_share), un blob que SEULE la clé PRIVÉE du destinataire peut
// déchiffrer. Réutilise le MÊME trousseau de clés X25519 par utilisateur que l'accès d'urgence
// (table `user_keys`, voir EmergencyRepository::get_public_key/get_own_keys) — un seul trousseau
// par compte pour les deux usages, mais avec un contexte HKDF différent côté client (voir
// sharing::INFO_SHARE_SEAL), qui les garde cryptographiquement étanches l'un de l'autre.
use axum::{
    extract::{State, Path},
    http::{StatusCode, HeaderMap},
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use crate::{AppState, error::AppError, mailer, middleware::AuthUser, repository::SharingRepository, models::*};
use validator::Validate;
use std::net::SocketAddr;
use axum::extract::ConnectInfo;
use super::common::get_user_agent;

/// Le PROPRIÉTAIRE partage (ou re-partage, après une modification de l'entrée — voir
/// lib/entrySharing.ts::reseedEntryShares côté frontend) une entrée avec un autre utilisateur.
/// Le CLIENT a déjà résolu la clé publique du destinataire (GET /emergency/keys/{email}, réutilisé
/// tel quel — voir SharingRepository) et scellé le contenu AVANT d'appeler cette route : le
/// serveur ne fait que stocker le blob déjà scellé.
pub async fn share_entry(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(vault_id): Path<String>,
    Json(payload): Json<ShareEntryPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    let shared_with_email = payload.shared_with_email.to_lowercase();
    if shared_with_email == user.email {
        return Err(AppError::ValidationError("Impossible de partager une entrée avec soi-même.".to_string()));
    }

    let id = SharingRepository::share_entry(&state.db, &vault_id, &user.email, &shared_with_email, &payload.sealed_entry).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "VAULT_SHARE_ENTRY", addr.to_string(), agent).await;

    let _ = mailer::send_security_alert(
        &shared_with_email,
        &format!("{} a partagé une entrée de son coffre avec vous. Connectez-vous pour la consulter.", user.email),
        &state.config,
    ).await;

    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id }))))
}

/// Les partages actifs d'UNE entrée, vus par son PROPRIÉTAIRE — pour l'écran de gestion (qui a
/// accès à cette entrée, révoquer), et pour reseedEntryShares() côté client (savoir à qui
/// re-sceller après une modification).
pub async fn list_shares_for_entry(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(vault_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let shares = SharingRepository::list_shares_for_entry(&state.db, &vault_id, &user.email).await?;
    Ok(Json(shares))
}

/// Tout ce qui a été partagé AVEC l'utilisateur connecté, tous propriétaires confondus.
pub async fn list_shared_with_me(State(state): State<Arc<AppState>>, user: AuthUser) -> Result<impl IntoResponse, AppError> {
    let shares = SharingRepository::list_shared_with_me(&state.db, &user.email).await?;
    Ok(Json(shares))
}

/// Le DESTINATAIRE récupère le blob scellé d'UN partage précis, pour le desceller côté client
/// (voir src-tauri/src/sharing.rs::unseal_share) et afficher l'entrée en lecture seule.
pub async fn get_shared_entry(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let view = SharingRepository::get_shared_entry(&state.db, &id, &user.email).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "VAULT_SHARE_VIEW", addr.to_string(), agent).await;

    Ok(Json(view))
}

/// Révoque un partage — l'un OU l'autre côté peut y mettre fin (le propriétaire retire l'accès, ou
/// le destinataire quitte le partage).
pub async fn revoke_share(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    SharingRepository::revoke_share(&state.db, &id, &user.email).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "VAULT_SHARE_REVOKE", addr.to_string(), agent).await;

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
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;
    use crate::models::{VaultEntryInput, UserKeysInput};
    use crate::repository::{VaultRepository, EmergencyRepository};

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

    async fn register_test_user(state: &Arc<AppState>, email: &str) {
        sqlx::query("INSERT INTO users (email, password_hash) VALUES (?, ?)")
            .bind(email)
            .bind("hash_non_pertinent_pour_ce_test")
            .execute(&state.db)
            .await
            .expect("l'insertion de l'utilisateur de test doit réussir");
    }

    fn test_addr() -> ConnectInfo<SocketAddr> {
        ConnectInfo("127.0.0.1:1".parse().unwrap())
    }

    fn auth(email: &str) -> AuthUser {
        AuthUser { email: email.to_string(), is_moderator: false }
    }

    async fn read_json_body(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).expect("le corps doit être du JSON valide")
    }

    async fn setup_keys(state: &Arc<AppState>, email: &str) {
        EmergencyRepository::upsert_user_keys(
            &state.db,
            email,
            &UserKeysInput { public_key: format!("pubkey_{email}"), encrypted_private_key: format!("privkey_chiffre_{email}") },
        )
        .await
        .expect("l'enregistrement des clés doit réussir");
    }

    async fn add_test_entry(state: &Arc<AppState>, owner_email: &str) -> String {
        VaultRepository::add(
            &state.db,
            owner_email,
            VaultEntryInput {
                encrypted_site_name: "chiffre_site".to_string(), encrypted_username: None, encrypted_login_email: None,
                encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
                entry_type: "login".to_string(), encrypted_extra_fields: None,
                encrypted_password: "chiffre_mdp".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
            },
        ).await.unwrap();
        sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(owner_email)
            .fetch_one(&state.db)
            .await
            .unwrap()
    }

    /// Cycle de vie complet : partage -> visible côté destinataire -> blob scellé récupérable
    /// UNIQUEMENT par lui -> révocation par le propriétaire -> plus rien n'est accessible.
    #[tokio::test]
    async fn test_share_lifecycle() {
        let state = build_test_state().await;
        register_test_user(&state, "owner@example.com").await;
        register_test_user(&state, "friend@example.com").await;
        setup_keys(&state, "friend@example.com").await;
        let vault_id = add_test_entry(&state, "owner@example.com").await;

        let share_result = share_entry(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner@example.com"),
            Path(vault_id.clone()),
            Json(ShareEntryPayload { shared_with_email: "friend@example.com".to_string(), sealed_entry: "blob_scelle".to_string() }),
        ).await.expect("le partage doit réussir");
        let id = read_json_body(share_result.into_response()).await["id"].as_str().unwrap().to_string();

        // Le destinataire voit le partage dans sa liste "partagé avec moi".
        let shared_with_me = list_shared_with_me(State(state.clone()), auth("friend@example.com")).await.unwrap();
        let value = read_json_body(shared_with_me.into_response()).await;
        let rows = value.as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["owner_email"].as_str(), Some("owner@example.com"));
        assert!(rows[0].get("sealed_entry").is_none(), "le listing ne doit JAMAIS exposer le blob scellé");

        // Le destinataire peut récupérer le blob scellé via le fetch unique.
        let view_result = get_shared_entry(State(state.clone()), test_addr(), HeaderMap::new(), auth("friend@example.com"), Path(id.clone()))
            .await.expect("la récupération du blob scellé doit réussir pour le destinataire");
        let view_value = read_json_body(view_result.into_response()).await;
        assert_eq!(view_value["sealed_entry"].as_str(), Some("blob_scelle"));
        assert_eq!(view_value["owner_email"].as_str(), Some("owner@example.com"));

        // Le propriétaire révoque -> plus rien n'est accessible côté destinataire.
        revoke_share(State(state.clone()), test_addr(), HeaderMap::new(), auth("owner@example.com"), Path(id.clone()))
            .await.expect("la révocation doit réussir");
        let after_revoke = get_shared_entry(State(state.clone()), test_addr(), HeaderMap::new(), auth("friend@example.com"), Path(id)).await;
        assert!(matches!(after_revoke, Err(AppError::NotFound)), "après révocation, plus aucun accès ne doit être possible");
    }

    /// GARDE-FOU CRITIQUE : seul le DESTINATAIRE désigné peut récupérer sealed_entry — ni le
    /// propriétaire lui-même (qui n'a pas besoin de repasser par cette route, il a déjà l'entrée en
    /// clair), ni surtout un tiers étranger au partage.
    #[tokio::test]
    async fn test_sealed_entry_only_accessible_to_recipient() {
        let state = build_test_state().await;
        register_test_user(&state, "owner2@example.com").await;
        register_test_user(&state, "friend2@example.com").await;
        register_test_user(&state, "stranger@example.com").await;
        setup_keys(&state, "friend2@example.com").await;
        let vault_id = add_test_entry(&state, "owner2@example.com").await;

        let share_result = share_entry(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner2@example.com"),
            Path(vault_id),
            Json(ShareEntryPayload { shared_with_email: "friend2@example.com".to_string(), sealed_entry: "secret".to_string() }),
        ).await.unwrap();
        let id = read_json_body(share_result.into_response()).await["id"].as_str().unwrap().to_string();

        let stranger_attempt = get_shared_entry(State(state.clone()), test_addr(), HeaderMap::new(), auth("stranger@example.com"), Path(id.clone())).await;
        assert!(matches!(stranger_attempt, Err(AppError::NotFound)), "un tiers étranger au partage ne doit jamais pouvoir lire le blob scellé");

        let owner_attempt = get_shared_entry(State(state.clone()), test_addr(), HeaderMap::new(), auth("owner2@example.com"), Path(id)).await;
        assert!(matches!(owner_attempt, Err(AppError::NotFound)), "même le propriétaire ne doit pas pouvoir lire via CETTE route, réservée au destinataire");
    }

    #[tokio::test]
    async fn test_cannot_share_with_self() {
        let state = build_test_state().await;
        register_test_user(&state, "solo@example.com").await;
        let vault_id = add_test_entry(&state, "solo@example.com").await;

        let result = share_entry(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("solo@example.com"),
            Path(vault_id),
            Json(ShareEntryPayload { shared_with_email: "solo@example.com".to_string(), sealed_entry: "x".to_string() }),
        ).await;
        assert!(matches!(result, Err(AppError::ValidationError(_))));
    }

    /// Impossible de partager l'entrée d'un AUTRE utilisateur — même si l'id d'entrée est valide,
    /// l'appartenance est vérifiée dans SharingRepository::share_entry.
    #[tokio::test]
    async fn test_cannot_share_entry_belonging_to_another_user() {
        let state = build_test_state().await;
        register_test_user(&state, "realowner@example.com").await;
        register_test_user(&state, "attacker@example.com").await;
        register_test_user(&state, "victim@example.com").await;
        let vault_id = add_test_entry(&state, "realowner@example.com").await;

        let result = share_entry(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("attacker@example.com"),
            Path(vault_id),
            Json(ShareEntryPayload { shared_with_email: "victim@example.com".to_string(), sealed_entry: "x".to_string() }),
        ).await;
        assert!(matches!(result, Err(AppError::NotFound)), "partager l'entrée d'un AUTRE utilisateur doit échouer en 404, jamais réussir");
    }

    /// Re-partager la même entrée avec la même personne (ex: après modification de l'entrée, voir
    /// reseedEntryShares côté client) doit METTRE À JOUR le blob existant, jamais créer un doublon.
    #[tokio::test]
    async fn test_resharing_same_recipient_updates_existing_share() {
        let state = build_test_state().await;
        register_test_user(&state, "owner3@example.com").await;
        register_test_user(&state, "friend3@example.com").await;
        setup_keys(&state, "friend3@example.com").await;
        let vault_id = add_test_entry(&state, "owner3@example.com").await;

        let first = share_entry(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner3@example.com"),
            Path(vault_id.clone()),
            Json(ShareEntryPayload { shared_with_email: "friend3@example.com".to_string(), sealed_entry: "ancien_blob".to_string() }),
        ).await.unwrap();
        let first_id = read_json_body(first.into_response()).await["id"].as_str().unwrap().to_string();

        let second = share_entry(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner3@example.com"),
            Path(vault_id.clone()),
            Json(ShareEntryPayload { shared_with_email: "friend3@example.com".to_string(), sealed_entry: "nouveau_blob".to_string() }),
        ).await.unwrap();
        let second_id = read_json_body(second.into_response()).await["id"].as_str().unwrap().to_string();

        assert_eq!(first_id, second_id, "re-partager avec le même destinataire doit réutiliser le même id de partage");

        let owner_shares = list_shares_for_entry(State(state.clone()), auth("owner3@example.com"), Path(vault_id)).await.unwrap();
        let owner_value = read_json_body(owner_shares.into_response()).await;
        assert_eq!(owner_value.as_array().unwrap().len(), 1, "re-partager ne doit jamais créer une seconde ligne pour le même couple (entrée, destinataire)");

        let view = get_shared_entry(State(state.clone()), test_addr(), HeaderMap::new(), auth("friend3@example.com"), Path(second_id))
            .await.unwrap();
        let value = read_json_body(view.into_response()).await;
        assert_eq!(value["sealed_entry"].as_str(), Some("nouveau_blob"), "le blob doit avoir été remplacé par le nouveau, pas dupliqué à côté");
    }

    /// Supprimer définitivement l'entrée source (purge de la corbeille) doit faire disparaître ses
    /// partages — via ON DELETE CASCADE sur vault_id (voir la migration).
    #[tokio::test]
    async fn test_purging_entry_cascades_to_shares() {
        let state = build_test_state().await;
        register_test_user(&state, "owner4@example.com").await;
        register_test_user(&state, "friend4@example.com").await;
        setup_keys(&state, "friend4@example.com").await;
        let vault_id = add_test_entry(&state, "owner4@example.com").await;

        share_entry(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner4@example.com"),
            Path(vault_id.clone()),
            Json(ShareEntryPayload { shared_with_email: "friend4@example.com".to_string(), sealed_entry: "blob".to_string() }),
        ).await.unwrap();

        VaultRepository::delete(&state.db, "owner4@example.com", &vault_id).await.unwrap();
        VaultRepository::purge(&state.db, "owner4@example.com", &vault_id).await.unwrap();

        let shared_with_me = list_shared_with_me(State(state.clone()), auth("friend4@example.com")).await.unwrap();
        let value = read_json_body(shared_with_me.into_response()).await;
        assert_eq!(value.as_array().unwrap().len(), 0, "la purge de l'entrée doit faire disparaître ses partages (ON DELETE CASCADE)");
    }
}
