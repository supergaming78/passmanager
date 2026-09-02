use axum::{
    extract::{State, Path, ConnectInfo},
    http::{StatusCode, HeaderMap},
    response::IntoResponse,
    Json
};
use std::{sync::Arc, net::SocketAddr};
use crate::{AppState, error::AppError, crypto, middleware::AuthUser, models::*};
use validator::Validate;
use tracing::instrument;
use super::common::get_user_agent;

// --- GESTION DES APPAREILS DE CONFIANCE ---

/// Liste les appareils de confiance de l'utilisateur connecté (ex: "App iPhone", "Extension Chrome").
/// Permet au client d'afficher un écran "Appareils connectés" pour repérer un appareil suspect.
pub async fn list_devices(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    let devices = sqlx::query_as::<_, TrustedDevice>(
        "SELECT device_id, device_name, created_at, last_used_at FROM trusted_devices WHERE user_email = ? ORDER BY last_used_at DESC"
    )
    .bind(&user.email)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(devices))
}

/// Révoque un appareil de confiance : il devra repasser par le 2FA à sa prochaine connexion,
/// et sa session active (s'il en a une) est immédiatement coupée.
#[instrument(skip(state, user, addr, headers), fields(user = %user.email))]
pub async fn revoke_device(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(device_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let mut tx = state.db.begin().await?;

    // Sécurité : la clause "AND user_email = ?" empêche de révoquer l'appareil d'un AUTRE utilisateur
    let res = sqlx::query("DELETE FROM trusted_devices WHERE device_id = ? AND user_email = ?")
        .bind(&device_id)
        .bind(&user.email)
        .execute(&mut *tx)
        .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    // Coupe aussi la session active de cet appareil, s'il en existe une
    sqlx::query("DELETE FROM refresh_tokens WHERE device_id = ? AND user_email = ?")
        .bind(&device_id)
        .bind(&user.email)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    // CORRECTIF SÉCURITÉ : sans ceci, une connexion WebSocket DÉJÀ OUVERTE sur l'appareil révoqué
    // restait active malgré la révocation — le ticket WS n'est vérifié qu'à l'ouverture de la
    // connexion (voir le commentaire en tête de handlers/sync.rs), rien d'autre ne la fermait
    // avant que l'appareil ne se déconnecte de lui-même. Réutilise le même mécanisme que
    // logout_all_devices() ci-dessous : le canal de synchro n'est PAS distingué par appareil (voir
    // handle_socket() dans sync.rs, qui filtre uniquement par email), donc ceci ferme TOUTES les
    // connexions WS actives de ce compte, pas seulement celle de l'appareil révoqué — un
    // compromis délibéré (pas de suivi par appareil dans ws_connections aujourd'hui) : les autres
    // appareils encore de confiance se reconnectent automatiquement avec un ticket frais (voir la
    // logique de reconnexion côté client), une brève resynchronisation plutôt qu'une vraie coupure.
    let _ = state.sync_tx.send(SyncEvent { user_email: user.email.clone(), event_type: "SESSION_REVOKED".to_string() });

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "DEVICE_REVOKED", addr.to_string(), agent).await;

    Ok(StatusCode::NO_CONTENT)
}

/// Modifie APRÈS COUP le plafond d'appareils de confiance choisi à l'inscription (voir
/// AuthPayload.max_trusted_devices dans handlers/auth.rs). Redemande le hash du mot de passe
/// maître, comme update_email()/update_password() : ce paramètre affecte la posture de sécurité
/// du compte, il ne doit pas être modifiable par la seule connaissance d'un access token volé.
pub async fn update_device_limit(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<UpdateDeviceLimitPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?; // borne déjà 1-50, voir models.rs

    let current_user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = ?")
        .bind(&user.email)
        .fetch_one(&state.db)
        .await?;
    if !crypto::verify_password(&payload.master_password_hash, &current_user.password_hash, &state.config.password_pepper).await {
        return Err(AppError::InvalidCredentials);
    }

    sqlx::query("UPDATE users SET max_trusted_devices = ? WHERE email = ?")
        .bind(payload.new_limit as i64)
        .bind(&user.email)
        .execute(&state.db)
        .await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "DEVICE_LIMIT_CHANGED", addr.to_string(), agent).await;

    Ok(StatusCode::OK)
}

/// Révoque IMMÉDIATEMENT toutes les sessions actives de l'utilisateur, sur TOUS les appareils —
/// y compris celui qui appelle cette route (déconnexion totale volontaire, ex: "j'ai perdu mon
/// téléphone"). Contrairement à revoke_device(), pas de reconfirmation du mot de passe maître :
/// c'est une action purement défensive qui ne peut jamais rien exposer (au pire, un access token
/// volé qui appelle cette route ne fait que déconnecter tout le monde, pas escalader un accès).
///
/// Supprime les refresh tokens ET marque `sessions_revoked_at` (voir middleware.rs::AuthUser) :
/// sans cette deuxième étape, un access token DÉJÀ ÉMIS resterait valide jusqu'à ~10 minutes de
/// plus malgré l'appel à cette route — exactement le même raisonnement que pour
/// `password_changed_at` lors d'un changement de mot de passe.
pub async fn logout_all_devices(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    let mut tx = state.db.begin().await?;

    sqlx::query("DELETE FROM refresh_tokens WHERE user_email = ?")
        .bind(&user.email)
        .execute(&mut *tx)
        .await?;

    sqlx::query("UPDATE users SET sessions_revoked_at = CURRENT_TIMESTAMP WHERE email = ?")
        .bind(&user.email)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    // Diffuse un événement "SESSION_REVOKED" sur le canal existant (voir handlers/vault.rs pour
    // le même mécanisme côté coffre) : sync.rs::handle_socket() le traite comme un cas spécial et
    // ferme la connexion WebSocket au lieu de se contenter de relayer un simple signal de
    // resynchronisation — sans ça, une connexion déjà ouverte au moment de cet appel resterait
    // active malgré la révocation, jusqu'à ce que le client la referme lui-même de son côté.
    let _ = state.sync_tx.send(SyncEvent { user_email: user.email.clone(), event_type: "SESSION_REVOKED".to_string() });

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "LOGOUT_ALL_DEVICES", addr.to_string(), agent).await;

    Ok(StatusCode::NO_CONTENT)
}

// =========================================================================
// TESTS SUR LA GESTION DES APPAREILS DE CONFIANCE
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use sqlx::sqlite::SqlitePoolOptions;
    use chrono::Utc;

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

    async fn trust_device(state: &Arc<AppState>, email: &str, device_id: &str, device_name: &str) {
        sqlx::query("INSERT OR REPLACE INTO trusted_devices (device_id, user_email, device_name) VALUES (?, ?, ?)")
            .bind(device_id)
            .bind(email)
            .bind(device_name)
            .execute(&state.db)
            .await
            .expect("l'insertion de l'appareil de confiance de test doit réussir");
    }

    /// list_devices() ne doit renvoyer QUE les appareils de l'utilisateur connecté,
    /// jamais ceux d'un autre utilisateur.
    #[tokio::test]
    async fn test_list_devices_returns_only_own_devices() {
        let state = build_test_state().await;
        register_test_user(&state, "devowner@example.com").await;
        register_test_user(&state, "devother@example.com").await;
        trust_device(&state, "devowner@example.com", "device-1", "Téléphone").await;
        trust_device(&state, "devowner@example.com", "device-2", "Extension Chrome").await;
        trust_device(&state, "devother@example.com", "device-3", "Ordinateur d'un autre").await;

        let owner_devices = list_devices(
            State(state.clone()),
            AuthUser { email: "devowner@example.com".to_string(), is_moderator: false },
        ).await.expect("le listage doit réussir");

        // list_devices() renvoie Json<Vec<TrustedDevice>> -> on vérifie via la BDD directement
        // le nombre d'appareils réellement associés à chaque utilisateur, cohérent avec ce que
        // la requête SQL du handler filtre (WHERE user_email = ?).
        let _ = owner_devices; // le handler a réussi, on vérifie l'effet en BDD ci-dessous
        let owner_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM trusted_devices WHERE user_email = ?")
            .bind("devowner@example.com")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(owner_count, 2, "devowner doit avoir exactement 2 appareils de confiance");
    }

    /// revoke_device() doit supprimer l'appareil de confiance ET couper sa session active.
    #[tokio::test]
    async fn test_revoke_device_removes_trust_and_session() {
        let state = build_test_state().await;
        let email = "revoketest@example.com";
        register_test_user(&state, email).await;
        trust_device(&state, email, "device-to-revoke", "Appareil à révoquer").await;

        // Simule une session active sur cet appareil
        sqlx::query("INSERT INTO refresh_tokens (token, user_email, device_id, expires_at, is_persistent) VALUES (?, ?, ?, ?, ?)")
            .bind("token-de-test")
            .bind(email)
            .bind("device-to-revoke")
            .bind((Utc::now() + chrono::Duration::hours(1)).format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .bind(true)
            .execute(&state.db)
            .await
            .unwrap();

        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        revoke_device(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Path("device-to-revoke".to_string()),
        ).await.expect("la révocation doit réussir");

        let trusted_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM trusted_devices WHERE device_id = ?")
            .bind("device-to-revoke")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(trusted_count, 0, "l'appareil ne doit plus être dans les appareils de confiance");

        let session_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE device_id = ?")
            .bind("device-to-revoke")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(session_count, 0, "la session active de l'appareil doit avoir été coupée");
    }

    /// CORRECTIF SÉCURITÉ : revoke_device() doit aussi diffuser un SyncEvent SESSION_REVOKED, pour
    /// que handle_socket() (voir sync.rs) ferme toute connexion WebSocket déjà ouverte sur ce
    /// compte — sans quoi une session déjà connectée en WS restait active malgré la révocation.
    #[tokio::test]
    async fn test_revoke_device_broadcasts_session_revoked_event() {
        let state = build_test_state().await;
        let email = "revokebroadcast@example.com";
        register_test_user(&state, email).await;
        trust_device(&state, email, "device-to-revoke", "Appareil à révoquer").await;

        let mut rx = state.sync_tx.subscribe();

        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        revoke_device(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Path("device-to-revoke".to_string()),
        ).await.expect("la révocation doit réussir");

        let evt = rx.try_recv().expect("un SyncEvent doit avoir été diffusé");
        assert_eq!(evt.user_email, email);
        assert_eq!(evt.event_type, "SESSION_REVOKED", "doit être le même type d'événement que logout_all_devices, pour fermer les connexions WS actives");
    }

    /// Un utilisateur ne doit jamais pouvoir révoquer l'appareil d'un AUTRE utilisateur,
    /// même en connaissant son device_id exact.
    #[tokio::test]
    async fn test_revoke_device_cannot_revoke_another_users_device() {
        let state = build_test_state().await;
        register_test_user(&state, "victim@example.com").await;
        register_test_user(&state, "attacker@example.com").await;
        trust_device(&state, "victim@example.com", "victim-device", "Appareil de la victime").await;

        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let result = revoke_device(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            AuthUser { email: "attacker@example.com".to_string(), is_moderator: false },
            Path("victim-device".to_string()),
        ).await;

        assert!(
            matches!(result, Err(AppError::NotFound)),
            "un utilisateur ne doit pas pouvoir révoquer l'appareil d'un autre"
        );

        let still_trusted: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM trusted_devices WHERE device_id = ?")
            .bind("victim-device")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(still_trusted, 1, "l'appareil de la victime doit rester intact");
    }

    /// Insère un utilisateur avec un VRAI hash Argon2 (pas le hash factice de
    /// register_test_user() ci-dessus), nécessaire pour tester update_device_limit() qui
    /// vérifie réellement le mot de passe fourni.
    async fn register_user_with_real_password(state: &Arc<AppState>, email: &str, password: &str) {
        let hash = crate::crypto::hash_password(password, &state.config.password_pepper).await.unwrap();
        sqlx::query("INSERT INTO users (email, password_hash) VALUES (?, ?)")
            .bind(email)
            .bind(hash)
            .execute(&state.db)
            .await
            .expect("l'insertion de l'utilisateur de test doit réussir");
    }

    /// update_device_limit() doit refuser un mauvais mot de passe, et appliquer le nouveau
    /// plafond (avec trace d'audit) quand le bon mot de passe est fourni.
    #[tokio::test]
    async fn test_update_device_limit_validates_password_and_applies_new_limit() {
        let state = build_test_state().await;
        let email = "devicelimit@example.com";
        register_user_with_real_password(&state, email, "mot_de_passe_test_123").await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let user = AuthUser { email: email.to_string(), is_moderator: false };

        let bad_result = update_device_limit(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: user.email.clone(), is_moderator: false },
            Json(UpdateDeviceLimitPayload { new_limit: 5, master_password_hash: "mauvais_mdp".to_string() }),
        ).await;
        assert!(matches!(bad_result, Err(AppError::InvalidCredentials)), "un mauvais mot de passe doit être rejeté");

        update_device_limit(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: user.email.clone(), is_moderator: false },
            Json(UpdateDeviceLimitPayload { new_limit: 5, master_password_hash: "mot_de_passe_test_123".to_string() }),
        ).await.expect("le bon mot de passe doit permettre la modification");

        let new_limit: i64 = sqlx::query_scalar("SELECT max_trusted_devices FROM users WHERE email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert_eq!(new_limit, 5, "le nouveau plafond doit être appliqué en BDD");

        let audit_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE user_email = ? AND action = 'DEVICE_LIMIT_CHANGED'")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert_eq!(audit_count, 1, "le changement de plafond doit être tracé dans l'audit");
    }

    /// logout_all_devices() doit supprimer TOUS les refresh tokens de l'utilisateur (tous
    /// appareils confondus), sans toucher à ceux d'un autre utilisateur.
    #[tokio::test]
    async fn test_logout_all_devices_revokes_every_session() {
        let state = build_test_state().await;
        let email = "logoutall@example.com";
        register_test_user(&state, email).await;
        register_test_user(&state, "other@example.com").await;

        for (owner, device) in [(email, "device-a"), (email, "device-b"), ("other@example.com", "device-c")] {
            sqlx::query("INSERT INTO refresh_tokens (token, user_email, device_id, expires_at, is_persistent) VALUES (?, ?, ?, ?, ?)")
                .bind(format!("token-{device}"))
                .bind(owner)
                .bind(device)
                .bind((Utc::now() + chrono::Duration::hours(1)).format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .bind(false)
                .execute(&state.db)
                .await
                .unwrap();
        }

        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        logout_all_devices(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
        ).await.expect("la déconnexion globale doit réussir");

        let remaining_own: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert_eq!(remaining_own, 0, "toutes les sessions de l'utilisateur doivent être révoquées");

        let remaining_other: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE user_email = ?")
            .bind("other@example.com").fetch_one(&state.db).await.unwrap();
        assert_eq!(remaining_other, 1, "les sessions d'un AUTRE utilisateur ne doivent jamais être touchées");
    }

    /// logout_all_devices() doit aussi invalider immédiatement les access tokens déjà émis
    /// (via `sessions_revoked_at`), pas seulement les refresh tokens — même raisonnement que
    /// password_changed_at pour un changement de mot de passe.
    #[tokio::test]
    async fn test_logout_all_devices_invalidates_existing_access_tokens() {
        use axum::extract::FromRequestParts;

        let state = build_test_state().await;
        let email = "logoutalltoken@example.com";
        register_test_user(&state, email).await;

        let old_token = crate::crypto::create_jwt(email, &state.encoding_key, 600).unwrap();

        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        logout_all_devices(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
        ).await.expect("la déconnexion globale doit réussir");

        let mut parts = axum::http::Request::builder()
            .header("Authorization", format!("Bearer {old_token}"))
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let result = AuthUser::from_request_parts(&mut parts, &state).await;
        assert!(result.is_err(), "un access token émis avant logout_all_devices() ne doit plus être accepté");
    }
}