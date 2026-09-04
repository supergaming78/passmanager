// =========================================================================
// COFFRES PARTAGÉS FAMILIAUX
// =========================================================================
// S'AJOUTE au partage d'entrée 1-vers-1 existant (voir handlers/sharing.rs), ne le remplace pas :
// les deux systèmes coexistent pour deux usages différents — partager UNE entrée ponctuellement
// (sharing.rs) VS un ensemble d'entrées qui reste à jour EN DIRECT pour plusieurs membres (ici).
//
// ZERO-KNOWLEDGE DE BOUT EN BOUT, même famille de primitives que le partage d'entrée et l'accès
// d'urgence : le serveur ne voit et ne déchiffre JAMAIS le nom du coffre ni le contenu de ses
// entrées, ni la clé symétrique qui les protège — voir crypto-core/src/shared_vault.rs pour le
// détail cryptographique complet, et repository.rs::SharedVaultRepository pour l'autorisation
// (toujours encodée directement dans le SQL, jamais vérifiée séparément ici).
use axum::{
    extract::{State, Path},
    http::{StatusCode, HeaderMap},
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use std::net::SocketAddr;
use axum::extract::ConnectInfo;
use crate::{AppState, error::AppError, mailer, middleware::AuthUser, repository::SharedVaultRepository, models::*};
use validator::Validate;
use super::common::get_user_agent;

/// Diffuse un SyncEvent à CHAQUE membre actuel du coffre partagé (pas juste l'appelant) — c'est ce
/// qui permet aux autres appareils connectés des AUTRES membres de recharger en direct, comme pour
/// le coffre personnel (voir handlers/vault.rs), mais multiplié par le nombre de membres puisque
/// plusieurs comptes différents sont concernés ici. `SharedVaultRepository::list_all_members`
/// (SANS vérification d'autorisation, contrairement à list_members) : ce n'est pas un appelant HTTP
/// qui demande "qui sont les membres", c'est le serveur qui a besoin de savoir qui notifier après
/// sa propre action. `let _ =` volontaire sur `send()` : échoue seulement si personne n'écoute
/// actuellement pour CE membre (aucune connexion WebSocket ouverte), ce n'est jamais une erreur.
async fn broadcast_to_members(state: &Arc<AppState>, shared_vault_id: &str, event_type: &str) {
    if let Ok(members) = SharedVaultRepository::list_all_members(&state.db, shared_vault_id).await {
        for member in members {
            let _ = state.sync_tx.send(SyncEvent { user_email: member.member_email, event_type: event_type.to_string() });
        }
    }
}

/// Crée un nouveau coffre partagé — l'appelant devient automatiquement son premier membre,
/// propriétaire (voir SharedVaultRepository::create). Le CLIENT a déjà généré la clé symétrique du
/// coffre, chiffré `encrypted_name` avec elle, et scellé cette même clé pour SA PROPRE clé
/// publique (`sealed_vault_key`) AVANT cet appel — voir crypto-core::shared_vault::generate_vault_key.
pub async fn create_shared_vault(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<CreateSharedVaultPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;

    let id = SharedVaultRepository::create(&state.db, &user.email, &payload.encrypted_name, &payload.sealed_vault_key).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "SHARED_VAULT_CREATE", addr.to_string(), agent).await;

    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id }))))
}

/// Liste les coffres partagés dont l'appelant est membre.
pub async fn list_shared_vaults(State(state): State<Arc<AppState>>, user: AuthUser) -> Result<impl IntoResponse, AppError> {
    let vaults = SharedVaultRepository::list_for_member(&state.db, &user.email).await?;
    Ok(Json(vaults))
}

/// Supprime DÉFINITIVEMENT un coffre partagé entier — réservé au créateur (voir
/// SharedVaultRepository::delete_vault). Diffuse l'événement AVANT la suppression : après coup,
/// list_members() (utilisée par broadcast_to_members) ne trouverait plus personne à notifier.
pub async fn delete_shared_vault(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    broadcast_to_members(&state, &id, "SHARED_VAULT_DELETED").await;
    SharedVaultRepository::delete_vault(&state.db, &id, &user.email).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "SHARED_VAULT_DELETE", addr.to_string(), agent).await;

    Ok(StatusCode::NO_CONTENT)
}

/// Invite un nouveau membre — réservé au propriétaire du coffre. Le CLIENT a déjà résolu la clé
/// publique du futur membre (GET /emergency/keys/{email}) et scellé la clé du coffre pour lui
/// AVANT cet appel.
pub async fn invite_shared_vault_member(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<String>,
    Json(payload): Json<InviteSharedVaultMemberPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    let member_email = payload.member_email.to_lowercase();
    if member_email == user.email {
        return Err(AppError::ValidationError("Impossible de s'inviter soi-même.".to_string()));
    }

    SharedVaultRepository::invite_member(&state.db, &id, &user.email, &member_email, &payload.sealed_vault_key).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "SHARED_VAULT_MEMBER_ADD", addr.to_string(), agent).await;

    let _ = mailer::send_security_alert(
        &member_email,
        &format!("{} vous a ajouté à un coffre partagé. Connectez-vous pour le consulter.", user.email),
        &state.config,
    ).await;

    Ok(StatusCode::CREATED)
}

/// Liste les membres d'un coffre partagé — n'importe quel membre peut la consulter.
pub async fn list_shared_vault_members(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let members = SharedVaultRepository::list_members(&state.db, &id, &user.email).await?;
    Ok(Json(members))
}

/// Retire un membre — soit l'appelant se retire LUI-MÊME ("quitter", jamais permis pour le
/// propriétaire, voir SharedVaultRepository::leave), soit le PROPRIÉTAIRE retire quelqu'un
/// d'autre (voir SharedVaultRepository::remove_member). Le choix entre les deux est déterminé
/// SEULEMENT par la comparaison des emails, jamais par un paramètre fourni par le client.
pub async fn remove_shared_vault_member(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path((id, target_email)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    let target_email = target_email.to_lowercase();

    if target_email == user.email {
        SharedVaultRepository::leave(&state.db, &id, &user.email).await?;
        let agent = get_user_agent(&headers);
        state.log_audit(&user.email, "SHARED_VAULT_MEMBER_LEAVE", addr.to_string(), agent).await;
    } else {
        SharedVaultRepository::remove_member(&state.db, &id, &user.email, &target_email).await?;
        let agent = get_user_agent(&headers);
        state.log_audit(&user.email, "SHARED_VAULT_MEMBER_REMOVE", addr.to_string(), agent).await;
        // Prévient la personne retirée sur son PROCHAIN chargement (elle ne peut plus recevoir
        // l'événement WebSocket : list_members() ne la retourne déjà plus après la suppression).
        let _ = state.sync_tx.send(SyncEvent { user_email: target_email, event_type: "SHARED_VAULT_DELETED".to_string() });
    }

    broadcast_to_members(&state, &id, "SHARED_VAULT_MEMBERS_CHANGED").await;
    Ok(StatusCode::NO_CONTENT)
}

/// Liste les entrées d'un coffre partagé.
pub async fn list_shared_vault_entries(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let entries = SharedVaultRepository::list_entries(&state.db, &id, &user.email).await?;
    Ok(Json(entries))
}

/// Ajoute une entrée au coffre partagé — visible IMMÉDIATEMENT par tous les membres (même clé
/// symétrique partagée par tous, voir crypto-core/src/shared_vault.rs), notifiés en direct via
/// WebSocket.
pub async fn add_shared_vault_entry(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<String>,
    Json(payload): Json<SharedVaultEntryInput>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;

    let entry_id = SharedVaultRepository::add_entry(&state.db, &id, &user.email, &payload).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "SHARED_VAULT_ENTRY_ADD", addr.to_string(), agent).await;
    broadcast_to_members(&state, &id, "SHARED_VAULT_UPDATE").await;

    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": entry_id }))))
}

/// Modifie une entrée du coffre partagé — réservé aux membres (n'importe lequel).
pub async fn update_shared_vault_entry(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path((id, entry_id)): Path<(String, String)>,
    Json(payload): Json<SharedVaultEntryInput>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;

    SharedVaultRepository::update_entry(&state.db, &id, &entry_id, &user.email, &payload).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "SHARED_VAULT_ENTRY_UPDATE", addr.to_string(), agent).await;
    broadcast_to_members(&state, &id, "SHARED_VAULT_UPDATE").await;

    Ok(StatusCode::OK)
}

/// Supprime DÉFINITIVEMENT une entrée du coffre partagé (pas de corbeille, voir la migration).
pub async fn delete_shared_vault_entry(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path((id, entry_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    SharedVaultRepository::delete_entry(&state.db, &id, &entry_id, &user.email).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "SHARED_VAULT_ENTRY_DELETE", addr.to_string(), agent).await;
    broadcast_to_members(&state, &id, "SHARED_VAULT_UPDATE").await;

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

    fn sample_entry_input() -> SharedVaultEntryInput {
        SharedVaultEntryInput {
            encrypted_site_name: "site_chiffre".to_string(),
            encrypted_username: None,
            encrypted_login_email: None,
            encrypted_password: "mdp_chiffre".to_string(),
            encrypted_preferred_login_type: "email".to_string(),
            encrypted_notes: None,
            encrypted_url: None,
            entry_type: "login".to_string(),
            encrypted_extra_fields: None,
            expected_version: None,
        }
    }

    /// Cycle de vie complet : création -> visible côté propriétaire ET membre invité, chacun avec
    /// SA PROPRE clé scellée -> une entrée ajoutée par un membre est immédiatement visible par
    /// l'autre (même clé symétrique partagée) -> suppression du coffre par le propriétaire fait
    /// disparaître le coffre et ses entrées pour tout le monde.
    #[tokio::test]
    async fn test_shared_vault_lifecycle() {
        let state = build_test_state().await;
        register_test_user(&state, "parent@example.com").await;
        register_test_user(&state, "enfant@example.com").await;

        let create_result = create_shared_vault(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("parent@example.com"),
            Json(CreateSharedVaultPayload { encrypted_name: "nom_chiffre".to_string(), sealed_vault_key: "cle_scellee_pour_parent".to_string() }),
        ).await.expect("la création doit réussir");
        let vault_id = read_json_body(create_result.into_response()).await["id"].as_str().unwrap().to_string();

        // Le propriétaire se voit lui-même dans la liste, avec SA clé scellée et is_owner=true.
        let owner_list = read_json_body(list_shared_vaults(State(state.clone()), auth("parent@example.com")).await.unwrap().into_response()).await;
        let owner_rows = owner_list.as_array().unwrap();
        assert_eq!(owner_rows.len(), 1);
        assert_eq!(owner_rows[0]["sealed_vault_key"].as_str(), Some("cle_scellee_pour_parent"));
        assert_eq!(owner_rows[0]["is_owner"].as_bool(), Some(true));

        // Invite un membre.
        invite_shared_vault_member(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("parent@example.com"),
            Path(vault_id.clone()),
            Json(InviteSharedVaultMemberPayload { member_email: "enfant@example.com".to_string(), sealed_vault_key: "cle_scellee_pour_enfant".to_string() }),
        ).await.expect("l'invitation doit réussir");

        // Le membre invité voit désormais le coffre, avec SA PROPRE clé scellée (différente de
        // celle du propriétaire) et is_owner=false.
        let member_list = read_json_body(list_shared_vaults(State(state.clone()), auth("enfant@example.com")).await.unwrap().into_response()).await;
        let member_rows = member_list.as_array().unwrap();
        assert_eq!(member_rows.len(), 1);
        assert_eq!(member_rows[0]["sealed_vault_key"].as_str(), Some("cle_scellee_pour_enfant"));
        assert_eq!(member_rows[0]["is_owner"].as_bool(), Some(false));

        // Le membre (pas le propriétaire) ajoute une entrée.
        let add_result = add_shared_vault_entry(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("enfant@example.com"),
            Path(vault_id.clone()), Json(sample_entry_input()),
        ).await.expect("un membre non-propriétaire doit pouvoir ajouter une entrée");
        let entry_id = read_json_body(add_result.into_response()).await["id"].as_str().unwrap().to_string();

        // Le propriétaire la voit immédiatement (même clé symétrique partagée, pas de re-partage).
        let owner_entries = read_json_body(list_shared_vault_entries(State(state.clone()), auth("parent@example.com"), Path(vault_id.clone())).await.unwrap().into_response()).await;
        let owner_entry_rows = owner_entries.as_array().unwrap();
        assert_eq!(owner_entry_rows.len(), 1);
        assert_eq!(owner_entry_rows[0]["id"].as_str(), Some(entry_id.as_str()));
        assert_eq!(owner_entry_rows[0]["created_by"].as_str(), Some("enfant@example.com"));

        // Suppression du coffre par le propriétaire -> plus rien pour personne.
        delete_shared_vault(State(state.clone()), test_addr(), HeaderMap::new(), auth("parent@example.com"), Path(vault_id.clone()))
            .await.expect("la suppression doit réussir");

        let owner_after = read_json_body(list_shared_vaults(State(state.clone()), auth("parent@example.com")).await.unwrap().into_response()).await;
        assert_eq!(owner_after.as_array().unwrap().len(), 0);
        let member_entries_after = list_shared_vault_entries(State(state.clone()), auth("enfant@example.com"), Path(vault_id)).await;
        assert!(matches!(member_entries_after, Err(AppError::NotFound)), "le coffre supprimé ne doit plus être accessible à personne");
    }

    #[tokio::test]
    async fn test_only_owner_can_invite_members() {
        let state = build_test_state().await;
        register_test_user(&state, "owner5@example.com").await;
        register_test_user(&state, "member5@example.com").await;
        register_test_user(&state, "outsider5@example.com").await;

        let create_result = create_shared_vault(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner5@example.com"),
            Json(CreateSharedVaultPayload { encrypted_name: "nom".to_string(), sealed_vault_key: "cle".to_string() }),
        ).await.unwrap();
        let vault_id = read_json_body(create_result.into_response()).await["id"].as_str().unwrap().to_string();

        invite_shared_vault_member(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner5@example.com"),
            Path(vault_id.clone()),
            Json(InviteSharedVaultMemberPayload { member_email: "member5@example.com".to_string(), sealed_vault_key: "cle_membre".to_string() }),
        ).await.unwrap();

        // Un membre SIMPLE (non-propriétaire) ne peut pas inviter quelqu'un d'autre.
        let result = invite_shared_vault_member(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("member5@example.com"),
            Path(vault_id),
            Json(InviteSharedVaultMemberPayload { member_email: "outsider5@example.com".to_string(), sealed_vault_key: "x".to_string() }),
        ).await;
        assert!(matches!(result, Err(AppError::Forbidden)), "seul le propriétaire doit pouvoir inviter de nouveaux membres");
    }

    #[tokio::test]
    async fn test_non_member_cannot_access_shared_vault_entries() {
        let state = build_test_state().await;
        register_test_user(&state, "owner6@example.com").await;
        register_test_user(&state, "stranger6@example.com").await;

        let create_result = create_shared_vault(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner6@example.com"),
            Json(CreateSharedVaultPayload { encrypted_name: "nom".to_string(), sealed_vault_key: "cle".to_string() }),
        ).await.unwrap();
        let vault_id = read_json_body(create_result.into_response()).await["id"].as_str().unwrap().to_string();

        let list_attempt = list_shared_vault_entries(State(state.clone()), auth("stranger6@example.com"), Path(vault_id.clone())).await;
        assert!(matches!(list_attempt, Err(AppError::NotFound)), "un non-membre ne doit jamais pouvoir lister les entrées d'un coffre partagé");

        let add_attempt = add_shared_vault_entry(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("stranger6@example.com"),
            Path(vault_id), Json(sample_entry_input()),
        ).await;
        assert!(matches!(add_attempt, Err(AppError::NotFound)), "un non-membre ne doit jamais pouvoir ajouter une entrée");
    }

    #[tokio::test]
    async fn test_member_can_leave_but_owner_cannot() {
        let state = build_test_state().await;
        register_test_user(&state, "owner7@example.com").await;
        register_test_user(&state, "member7@example.com").await;

        let create_result = create_shared_vault(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner7@example.com"),
            Json(CreateSharedVaultPayload { encrypted_name: "nom".to_string(), sealed_vault_key: "cle".to_string() }),
        ).await.unwrap();
        let vault_id = read_json_body(create_result.into_response()).await["id"].as_str().unwrap().to_string();

        invite_shared_vault_member(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner7@example.com"),
            Path(vault_id.clone()),
            Json(InviteSharedVaultMemberPayload { member_email: "member7@example.com".to_string(), sealed_vault_key: "cle_membre".to_string() }),
        ).await.unwrap();

        // Le propriétaire ne peut pas se retirer lui-même (doit supprimer le coffre entier à la place).
        let owner_leave_attempt = remove_shared_vault_member(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner7@example.com"),
            Path((vault_id.clone(), "owner7@example.com".to_string())),
        ).await;
        assert!(owner_leave_attempt.is_err(), "le propriétaire ne doit pas pouvoir quitter son propre coffre partagé");

        // Le membre simple peut quitter de lui-même.
        remove_shared_vault_member(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("member7@example.com"),
            Path((vault_id.clone(), "member7@example.com".to_string())),
        ).await.expect("un membre simple doit pouvoir quitter de lui-même");

        let members_after = read_json_body(list_shared_vault_members(State(state.clone()), auth("owner7@example.com"), Path(vault_id)).await.unwrap().into_response()).await;
        assert_eq!(members_after.as_array().unwrap().len(), 1, "après son départ, seul le propriétaire doit rester membre");
    }

    #[tokio::test]
    async fn test_owner_can_remove_another_member() {
        let state = build_test_state().await;
        register_test_user(&state, "owner8@example.com").await;
        register_test_user(&state, "member8@example.com").await;

        let create_result = create_shared_vault(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner8@example.com"),
            Json(CreateSharedVaultPayload { encrypted_name: "nom".to_string(), sealed_vault_key: "cle".to_string() }),
        ).await.unwrap();
        let vault_id = read_json_body(create_result.into_response()).await["id"].as_str().unwrap().to_string();

        invite_shared_vault_member(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner8@example.com"),
            Path(vault_id.clone()),
            Json(InviteSharedVaultMemberPayload { member_email: "member8@example.com".to_string(), sealed_vault_key: "cle_membre".to_string() }),
        ).await.unwrap();

        remove_shared_vault_member(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner8@example.com"),
            Path((vault_id.clone(), "member8@example.com".to_string())),
        ).await.expect("le propriétaire doit pouvoir retirer un autre membre");

        // Le membre retiré n'a plus accès.
        let access_attempt = list_shared_vault_entries(State(state.clone()), auth("member8@example.com"), Path(vault_id)).await;
        assert!(matches!(access_attempt, Err(AppError::NotFound)), "un membre retiré ne doit plus avoir accès au coffre");
    }

    /// Détection de conflit d'édition : deux membres qui chargent la même entrée puis la modifient
    /// tous les deux, le second doit être rejeté (409) plutôt qu'écraser silencieusement le premier.
    #[tokio::test]
    async fn test_entry_update_rejects_stale_expected_version() {
        let state = build_test_state().await;
        register_test_user(&state, "owner9@example.com").await;

        let create_result = create_shared_vault(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner9@example.com"),
            Json(CreateSharedVaultPayload { encrypted_name: "nom".to_string(), sealed_vault_key: "cle".to_string() }),
        ).await.unwrap();
        let vault_id = read_json_body(create_result.into_response()).await["id"].as_str().unwrap().to_string();

        let add_result = add_shared_vault_entry(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner9@example.com"),
            Path(vault_id.clone()), Json(sample_entry_input()),
        ).await.unwrap();
        let entry_id = read_json_body(add_result.into_response()).await["id"].as_str().unwrap().to_string();

        // Première modification, avec expected_version=1 (valeur initiale) : doit réussir.
        let mut first_update = sample_entry_input();
        first_update.expected_version = Some(1);
        update_shared_vault_entry(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner9@example.com"),
            Path((vault_id.clone(), entry_id.clone())), Json(first_update),
        ).await.expect("la première modification doit réussir");

        // Seconde modification, avec le MÊME expected_version=1 (désormais périmé, la version
        // réelle est passée à 2) : doit être rejetée avec un conflit.
        let mut stale_update = sample_entry_input();
        stale_update.expected_version = Some(1);
        let result = update_shared_vault_entry(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner9@example.com"),
            Path((vault_id, entry_id)), Json(stale_update),
        ).await;
        assert!(matches!(result, Err(AppError::Conflict(_))), "une modification basée sur une version périmée doit être rejetée");
    }

    #[tokio::test]
    async fn test_cannot_invite_self() {
        let state = build_test_state().await;
        register_test_user(&state, "solo10@example.com").await;

        let create_result = create_shared_vault(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("solo10@example.com"),
            Json(CreateSharedVaultPayload { encrypted_name: "nom".to_string(), sealed_vault_key: "cle".to_string() }),
        ).await.unwrap();
        let vault_id = read_json_body(create_result.into_response()).await["id"].as_str().unwrap().to_string();

        let result = invite_shared_vault_member(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("solo10@example.com"),
            Path(vault_id),
            Json(InviteSharedVaultMemberPayload { member_email: "solo10@example.com".to_string(), sealed_vault_key: "x".to_string() }),
        ).await;
        assert!(matches!(result, Err(AppError::ValidationError(_))));
    }

    /// RÉGRESSION : un coffre partagé ne doit jamais pouvoir accumuler un nombre de membres non
    /// borné (voir MAX_MEMBERS_PER_SHARED_VAULT dans repository.rs — protège contre l'épuisement
    /// de ressources via `broadcast_to_members`, qui notifie CHAQUE membre à chaque modification).
    #[tokio::test]
    async fn test_shared_vault_member_limit_is_enforced() {
        let state = build_test_state().await;
        register_test_user(&state, "owner11@example.com").await;

        let create_result = create_shared_vault(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner11@example.com"),
            Json(CreateSharedVaultPayload { encrypted_name: "nom".to_string(), sealed_vault_key: "cle".to_string() }),
        ).await.unwrap();
        let vault_id = read_json_body(create_result.into_response()).await["id"].as_str().unwrap().to_string();

        // Remplit le coffre jusqu'à la limite (24 membres invités + le propriétaire = 25 = la limite).
        for i in 0..24 {
            let email = format!("member11-{i}@example.com");
            register_test_user(&state, &email).await;
            invite_shared_vault_member(
                State(state.clone()), test_addr(), HeaderMap::new(), auth("owner11@example.com"),
                Path(vault_id.clone()),
                Json(InviteSharedVaultMemberPayload { member_email: email, sealed_vault_key: "cle".to_string() }),
            ).await.expect("chaque invitation jusqu'à la limite doit réussir");
        }

        // La 26e personne (limite déjà atteinte) doit être refusée.
        register_test_user(&state, "over-the-limit@example.com").await;
        let result = invite_shared_vault_member(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner11@example.com"),
            Path(vault_id),
            Json(InviteSharedVaultMemberPayload { member_email: "over-the-limit@example.com".to_string(), sealed_vault_key: "x".to_string() }),
        ).await;
        assert!(matches!(result, Err(AppError::ValidationError(_))), "au-delà de la limite de membres, l'invitation doit être refusée");
    }
}
