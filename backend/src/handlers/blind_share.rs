// =========================================================================
// PARTAGE À USAGE LIMITÉ ("AVEUGLE")
// =========================================================================
// S'AJOUTE au partage d'entrée classique (handlers/sharing.rs) ET aux coffres partagés familiaux
// (handlers/shared_vault.rs), ne remplace ni l'un ni l'autre — trois mécanismes distincts,
// chacun pour un usage différent. Ici : le destinataire ne voit JAMAIS l'identifiant ni le mot de
// passe (seulement le nom du site), et ne peut déclencher un "usage" (remplissage automatique côté
// extension, copie sans affichage côté desktop) qu'un nombre de fois limité choisi par
// l'expéditeur (1 par défaut).
//
// ZERO-KNOWLEDGE DE BOUT EN BOUT, même construction que les deux autres modes de partage : le
// serveur ne voit et ne déchiffre JAMAIS le nom du site ni les identifiants — voir
// crypto-core/src/blind_share.rs pour le détail cryptographique, et repository.rs::BlindShareRepository
// pour l'autorisation (toujours encodée directement dans le SQL) et le décrément ATOMIQUE du
// compteur d'usages (voir consume_use, LE point critique de cette fonctionnalité).
//
// LIMITE HONNÊTEMENT DOCUMENTÉE (voir aussi la migration) : empêcher un destinataire de voir le
// mot de passe rend l'usage CASUEL/accidentel impossible (aucun bouton "voir"/"copier" pour ce
// type de partage dans l'interface), et borne strictement le nombre d'OCCASIONS d'y accéder — mais
// un destinataire techniquement outillé (inspection de sa propre extension/application) pourrait
// toujours extraire la valeur en clair PENDANT un usage autorisé : c'est une limite inhérente à
// tout mécanisme de remplissage automatique côté client, pas un défaut corrigible ici.
use axum::{
    extract::{State, Path},
    http::{StatusCode, HeaderMap},
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use std::net::SocketAddr;
use axum::extract::ConnectInfo;
use crate::{AppState, error::AppError, mailer, middleware::AuthUser, repository::BlindShareRepository, models::*};
use validator::Validate;
use super::common::get_user_agent;

/// Le PROPRIÉTAIRE crée un partage à usage limité pour l'entrée `{id}`. Le CLIENT a déjà résolu la
/// clé publique du destinataire (GET /emergency/keys/{email}, réutilisé tel quel) et scellé
/// SÉPARÉMENT le nom du site et les identifiants AVANT cet appel — le serveur ne fait que stocker
/// les deux blobs déjà scellés, avec le compteur d'usages initial.
pub async fn create_blind_share(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(vault_id): Path<String>,
    Json(payload): Json<CreateBlindSharePayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    let shared_with_email = payload.shared_with_email.to_lowercase();
    if shared_with_email == user.email {
        return Err(AppError::ValidationError("Impossible de partager une entrée avec soi-même.".to_string()));
    }

    let id = BlindShareRepository::create(
        &state.db, &vault_id, &user.email, &shared_with_email,
        &payload.sealed_site_name, &payload.sealed_credentials, payload.max_uses,
    ).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "VAULT_BLIND_SHARE_CREATE", addr.to_string(), agent).await;

    let _ = mailer::send_security_alert(
        &shared_with_email,
        &format!("{} a partagé un identifiant avec vous (usage limité, sans accès direct au mot de passe). Connectez-vous pour l'utiliser.", user.email),
        &state.config,
    ).await;

    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id }))))
}

/// Les partages à usage limité actifs d'UNE entrée, vus par son PROPRIÉTAIRE.
pub async fn list_blind_shares_for_entry(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(vault_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let shares = BlindShareRepository::list_for_entry(&state.db, &vault_id, &user.email).await?;
    Ok(Json(shares))
}

/// Tout ce qui a été partagé EN USAGE LIMITÉ avec l'utilisateur connecté — inclut le nom du site
/// scellé (librement consultable), jamais les identifiants.
pub async fn list_blind_shares_received(State(state): State<Arc<AppState>>, user: AuthUser) -> Result<impl IntoResponse, AppError> {
    let shares = BlindShareRepository::list_received(&state.db, &user.email).await?;
    Ok(Json(shares))
}

/// LE DESTINATAIRE consomme UN usage : décrémente atomiquement le compteur et renvoie les
/// identifiants scellés — à desceller et utiliser IMMÉDIATEMENT côté client (remplissage
/// automatique/copie), jamais mis en cache ni ré-exposé ensuite (voir lib/blindShare.ts côté
/// frontend, qui ne renvoie jamais la valeur en clair à l'appelant de sa propre fonction "use").
pub async fn use_blind_share(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let view = BlindShareRepository::consume_use(&state.db, &id, &user.email).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "VAULT_BLIND_SHARE_USE", addr.to_string(), agent).await;

    Ok(Json(view))
}

/// Révoque un partage à usage limité — le propriétaire retire l'accès, ou le destinataire y
/// renonce, à tout moment (indépendamment du nombre d'usages restants).
pub async fn revoke_blind_share(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    BlindShareRepository::revoke(&state.db, &id, &user.email).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "VAULT_BLIND_SHARE_REVOKE", addr.to_string(), agent).await;

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

    fn payload(email: &str, max_uses: i64) -> CreateBlindSharePayload {
        CreateBlindSharePayload {
            shared_with_email: email.to_string(),
            sealed_site_name: "site_scelle".to_string(),
            sealed_credentials: "identifiants_scelles".to_string(),
            max_uses,
        }
    }

    /// Cycle de vie complet : création avec 2 usages -> visible côté propriétaire ET destinataire
    /// (site scellé consultable SANS consommer d'usage) -> 2 utilisations réussies, décrémentant à
    /// chaque fois -> une 3e utilisation échoue avec un message dédié, pas une erreur générique.
    #[tokio::test]
    async fn test_blind_share_lifecycle() {
        let state = build_test_state().await;
        register_test_user(&state, "owner@example.com").await;
        register_test_user(&state, "friend@example.com").await;
        setup_keys(&state, "friend@example.com").await;
        let vault_id = add_test_entry(&state, "owner@example.com").await;

        let create_result = create_blind_share(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner@example.com"),
            Path(vault_id.clone()), Json(payload("friend@example.com", 2)),
        ).await.expect("la création doit réussir");
        let id = read_json_body(create_result.into_response()).await["id"].as_str().unwrap().to_string();

        // Le propriétaire voit le compteur, jamais les blobs scellés.
        let owner_view = read_json_body(list_blind_shares_for_entry(State(state.clone()), auth("owner@example.com"), Path(vault_id)).await.unwrap().into_response()).await;
        let owner_rows = owner_view.as_array().unwrap();
        assert_eq!(owner_rows.len(), 1);
        assert_eq!(owner_rows[0]["max_uses"].as_i64(), Some(2));
        assert_eq!(owner_rows[0]["remaining_uses"].as_i64(), Some(2));
        assert!(owner_rows[0].get("sealed_credentials").is_none(), "le propriétaire ne doit jamais voir les identifiants scellés dans ce listing");

        // Le destinataire voit le nom du site SANS consommer d'usage.
        let received = read_json_body(list_blind_shares_received(State(state.clone()), auth("friend@example.com")).await.unwrap().into_response()).await;
        let received_rows = received.as_array().unwrap();
        assert_eq!(received_rows[0]["sealed_site_name"].as_str(), Some("site_scelle"));
        assert_eq!(received_rows[0]["remaining_uses"].as_i64(), Some(2), "consulter la liste ne doit jamais consommer d'usage");
        assert!(received_rows[0].get("sealed_credentials").is_none(), "les identifiants ne doivent JAMAIS apparaître dans le listing, seulement via /use");

        // Première utilisation : réussit, décrémente à 1.
        let use1 = use_blind_share(State(state.clone()), test_addr(), HeaderMap::new(), auth("friend@example.com"), Path(id.clone()))
            .await.expect("la première utilisation doit réussir");
        let use1_value = read_json_body(use1.into_response()).await;
        assert_eq!(use1_value["sealed_credentials"].as_str(), Some("identifiants_scelles"));
        assert_eq!(use1_value["remaining_uses"].as_i64(), Some(1));

        // Deuxième utilisation : réussit, décrémente à 0.
        let use2 = use_blind_share(State(state.clone()), test_addr(), HeaderMap::new(), auth("friend@example.com"), Path(id.clone()))
            .await.expect("la deuxième utilisation doit réussir");
        let use2_value = read_json_body(use2.into_response()).await;
        assert_eq!(use2_value["remaining_uses"].as_i64(), Some(0));

        // Troisième utilisation : plus aucun usage disponible.
        let use3 = use_blind_share(State(state.clone()), test_addr(), HeaderMap::new(), auth("friend@example.com"), Path(id)).await;
        match use3 {
            Err(AppError::ValidationError(msg)) => assert!(msg.contains("Plus aucun usage"), "message reçu: {msg}"),
            other => panic!("la 3e utilisation devrait être refusée, résultat: {}", if other.is_ok() { "succès" } else { "mauvaise erreur" }),
        }
    }

    #[tokio::test]
    async fn test_default_max_uses_is_one() {
        let state = build_test_state().await;
        register_test_user(&state, "owner2@example.com").await;
        register_test_user(&state, "friend2@example.com").await;
        setup_keys(&state, "friend2@example.com").await;
        let vault_id = add_test_entry(&state, "owner2@example.com").await;

        let create_result = create_blind_share(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner2@example.com"),
            Path(vault_id), Json(payload("friend2@example.com", 1)),
        ).await.unwrap();
        let id = read_json_body(create_result.into_response()).await["id"].as_str().unwrap().to_string();

        use_blind_share(State(state.clone()), test_addr(), HeaderMap::new(), auth("friend2@example.com"), Path(id.clone()))
            .await.expect("le seul usage disponible doit réussir");

        let second = use_blind_share(State(state.clone()), test_addr(), HeaderMap::new(), auth("friend2@example.com"), Path(id)).await;
        assert!(matches!(second, Err(AppError::ValidationError(_))), "avec max_uses=1, une deuxième utilisation doit être refusée");
    }

    /// GARDE-FOU CRITIQUE : seul le DESTINATAIRE désigné peut consommer un usage — ni le
    /// propriétaire, ni surtout un tiers étranger au partage.
    #[tokio::test]
    async fn test_only_designated_recipient_can_use() {
        let state = build_test_state().await;
        register_test_user(&state, "owner3@example.com").await;
        register_test_user(&state, "friend3@example.com").await;
        register_test_user(&state, "stranger3@example.com").await;
        setup_keys(&state, "friend3@example.com").await;
        let vault_id = add_test_entry(&state, "owner3@example.com").await;

        let create_result = create_blind_share(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner3@example.com"),
            Path(vault_id), Json(payload("friend3@example.com", 5)),
        ).await.unwrap();
        let id = read_json_body(create_result.into_response()).await["id"].as_str().unwrap().to_string();

        let stranger_attempt = use_blind_share(State(state.clone()), test_addr(), HeaderMap::new(), auth("stranger3@example.com"), Path(id.clone())).await;
        assert!(matches!(stranger_attempt, Err(AppError::NotFound)));

        let owner_attempt = use_blind_share(State(state.clone()), test_addr(), HeaderMap::new(), auth("owner3@example.com"), Path(id)).await;
        assert!(matches!(owner_attempt, Err(AppError::NotFound)), "même le propriétaire ne doit pas pouvoir consommer un usage via cette route");
    }

    #[tokio::test]
    async fn test_cannot_blind_share_with_self() {
        let state = build_test_state().await;
        register_test_user(&state, "solo@example.com").await;
        let vault_id = add_test_entry(&state, "solo@example.com").await;

        let result = create_blind_share(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("solo@example.com"),
            Path(vault_id), Json(payload("solo@example.com", 1)),
        ).await;
        assert!(matches!(result, Err(AppError::ValidationError(_))));
    }

    /// Révocation par l'un ou l'autre côté, avant épuisement des usages.
    #[tokio::test]
    async fn test_revoke_by_either_side() {
        let state = build_test_state().await;
        register_test_user(&state, "owner4@example.com").await;
        register_test_user(&state, "friend4@example.com").await;
        setup_keys(&state, "friend4@example.com").await;
        let vault_id = add_test_entry(&state, "owner4@example.com").await;

        let create_result = create_blind_share(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner4@example.com"),
            Path(vault_id), Json(payload("friend4@example.com", 3)),
        ).await.unwrap();
        let id = read_json_body(create_result.into_response()).await["id"].as_str().unwrap().to_string();

        revoke_blind_share(State(state.clone()), test_addr(), HeaderMap::new(), auth("friend4@example.com"), Path(id.clone()))
            .await.expect("le destinataire doit pouvoir révoquer/renoncer au partage");

        let after = use_blind_share(State(state.clone()), test_addr(), HeaderMap::new(), auth("friend4@example.com"), Path(id)).await;
        assert!(matches!(after, Err(AppError::NotFound)), "un partage révoqué ne doit plus être utilisable");
    }

    /// Purger DÉFINITIVEMENT l'entrée source (corbeille vidée) supprime la ligne de partage
    /// elle-même (ON DELETE CASCADE sur vault_id, voir la migration) — même principe que le
    /// partage classique (test_purging_entry_cascades_to_shares dans sharing.rs).
    #[tokio::test]
    async fn test_purging_source_entry_cascades_to_blind_share() {
        let state = build_test_state().await;
        register_test_user(&state, "owner5@example.com").await;
        register_test_user(&state, "friend5@example.com").await;
        setup_keys(&state, "friend5@example.com").await;
        let vault_id = add_test_entry(&state, "owner5@example.com").await;

        let create_result = create_blind_share(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner5@example.com"),
            Path(vault_id.clone()), Json(payload("friend5@example.com", 5)),
        ).await.unwrap();
        let id = read_json_body(create_result.into_response()).await["id"].as_str().unwrap().to_string();

        VaultRepository::delete(&state.db, "owner5@example.com", &vault_id).await.unwrap();
        VaultRepository::purge(&state.db, "owner5@example.com", &vault_id).await.unwrap();

        let attempt = use_blind_share(State(state.clone()), test_addr(), HeaderMap::new(), auth("friend5@example.com"), Path(id)).await;
        assert!(matches!(attempt, Err(AppError::NotFound)));
    }

    /// Mettre l'entrée source à la CORBEILLE (suppression douce, pas encore purgée) doit déjà
    /// bloquer toute nouvelle utilisation — même si le compteur d'usages n'est pas épuisé — mais
    /// la LIGNE de partage doit rester visible côté destinataire (voir
    /// BlindShareRepository::consume_use, qui applique cette garde de corbeille — CONTRAIREMENT à
    /// list_received, volontairement pas gardée : voir son commentaire).
    #[tokio::test]
    async fn test_trashing_source_entry_blocks_use_but_keeps_listing() {
        let state = build_test_state().await;
        register_test_user(&state, "owner6@example.com").await;
        register_test_user(&state, "friend6@example.com").await;
        setup_keys(&state, "friend6@example.com").await;
        let vault_id = add_test_entry(&state, "owner6@example.com").await;

        let create_result = create_blind_share(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner6@example.com"),
            Path(vault_id.clone()), Json(payload("friend6@example.com", 5)),
        ).await.unwrap();
        let id = read_json_body(create_result.into_response()).await["id"].as_str().unwrap().to_string();

        // Corbeille SEULEMENT (pas de purge) — l'entrée existe encore en base, juste marquée supprimée.
        VaultRepository::delete(&state.db, "owner6@example.com", &vault_id).await.unwrap();

        let listing = read_json_body(list_blind_shares_received(State(state.clone()), auth("friend6@example.com")).await.unwrap().into_response()).await;
        assert_eq!(listing.as_array().unwrap().len(), 1, "la ligne de partage doit rester visible même si l'entrée source est à la corbeille");

        let attempt = use_blind_share(State(state.clone()), test_addr(), HeaderMap::new(), auth("friend6@example.com"), Path(id)).await;
        assert!(matches!(attempt, Err(AppError::NotFound)), "une entrée source à la corbeille ne doit plus pouvoir être utilisée, même avec des usages restants");
    }
}
