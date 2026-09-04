// =========================================================================
// ACCÈS D'URGENCE
// =========================================================================
// Permet à un utilisateur (le PROPRIÉTAIRE) de désigner un autre compte de ce même serveur (le
// CONTACT) comme contact de confiance : en cas d'urgence, ce contact peut demander l'accès en
// LECTURE SEULE au coffre du propriétaire, accordé automatiquement après un délai d'attente
// configurable (sauf refus explicite du propriétaire pendant ce délai).
//
// ZERO-KNOWLEDGE DE BOUT EN BOUT : le serveur ne voit et ne déchiffre JAMAIS ni la clé de coffre
// du propriétaire, ni le contenu du coffre lui-même. Tout repose sur une "boîte scellée" X25519
// calculée CÔTÉ CLIENT (voir src-tauri/src/emergency.rs) : le propriétaire chiffre sa clé de
// coffre avec la clé PUBLIQUE du contact (récupérée ici), un blob que SEULE la clé PRIVÉE du
// contact peut déchiffrer — cette clé privée est elle-même chiffrée avec SA PROPRE clé de coffre,
// jamais lisible par le serveur. Ce module ne fait que stocker/relayer des clés publiques et des
// blobs déjà scellés, exactement comme il relaie les champs `encrypted_*` du reste du coffre.
use axum::{
    extract::{State, Path},
    http::{StatusCode, HeaderMap},
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use crate::{AppState, error::AppError, mailer, middleware::AuthUser, repository::{EmergencyRepository, VaultRepository}, models::*};
use validator::Validate;
use std::net::SocketAddr;
use axum::extract::ConnectInfo;
use super::common::get_user_agent;

/// Nombre maximum d'entrées renvoyées par la vue d'urgence — même plafond que le reste du coffre
/// (voir MAX_VAULT_ENTRIES_PER_USER dans handlers/vault.rs), un propriétaire ne peut de toute
/// façon jamais avoir plus d'entrées actives que ça.
const MAX_VAULT_ENTRIES: i64 = 5000;

/// Enregistre OU remplace la paire de clés X25519 de l'utilisateur connecté (voir
/// src-tauri/src/emergency.rs::generate_keypair — la clé privée arrive déjà chiffrée).
pub async fn upsert_keys(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Json(payload): Json<UserKeysInput>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    EmergencyRepository::upsert_user_keys(&state.db, &user.email, &payload).await?;
    Ok(StatusCode::OK)
}

/// Récupère UNIQUEMENT la clé publique d'un autre utilisateur — ce qu'il faut pour lui sceller
/// quelque chose (voir POST .../seed ci-dessous), jamais sa clé privée.
pub async fn get_public_key(
    State(state): State<Arc<AppState>>,
    _user: AuthUser,
    Path(email): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    // CORRECTIF : chaque email est stocké en minuscules partout ailleurs dans ce projet
    // (inscription, connexion, ajout de contact, partage...) — sans ce .to_lowercase() ici, un
    // appelant passant un email dans une casse différente de celle enregistrée obtenait un 404
    // silencieux même si la cible avait bien configuré ses clés.
    let email = email.to_lowercase();
    let key = EmergencyRepository::get_public_key(&state.db, &email).await?;
    Ok(Json(key))
}

/// Récupère SES PROPRES clés (publique ET privée CHIFFRÉE) — nécessaire côté client pour
/// déchiffrer sa propre clé privée (avec SA clé de coffre, déjà déverrouillée normalement) puis
/// s'en servir pour desceller la clé de coffre d'un propriétaire (voir
/// src-tauri/src/emergency.rs::unseal, appelée via unlock_emergency_vault). Volontairement une
/// route SÉPARÉE de GET /emergency/keys/{email} (qui ne renvoie QUE des clés publiques, pour
/// N'IMPORTE quel email) : jamais la même route ne doit pouvoir renvoyer une clé privée, même la
/// sienne, selon le paramètre fourni.
pub async fn get_own_keys(State(state): State<Arc<AppState>>, user: AuthUser) -> Result<impl IntoResponse, AppError> {
    let keys = EmergencyRepository::get_own_keys(&state.db, &user.email).await?;
    Ok(Json(keys))
}

/// Désigne un nouveau contact de confiance — envoie une invitation par email, qui doit être
/// explicitement acceptée (voir accept_contact ci-dessous) avant que quoi que ce soit ne devienne
/// utilisable : personne ne peut être désigné contact à son insu.
pub async fn add_contact(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<AddEmergencyContactPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    let contact_email = payload.contact_email.to_lowercase();
    if contact_email == user.email {
        return Err(AppError::ValidationError("Impossible de se désigner soi-même comme contact de confiance.".to_string()));
    }

    let id = EmergencyRepository::add_contact(&state.db, &user.email, &contact_email, payload.waiting_period_days).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "EMERGENCY_CONTACT_ADD", addr.to_string(), agent).await;

    let _ = mailer::send_security_alert(
        &contact_email,
        &format!("{} vous a désigné comme contact de confiance pour un accès d'urgence à son coffre. Connectez-vous pour accepter ou refuser.", user.email),
        &state.config,
    ).await;

    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id }))))
}

/// Contacts désignés par l'utilisateur connecté ("les gens en qui j'ai confiance").
pub async fn list_contacts_as_owner(State(state): State<Arc<AppState>>, user: AuthUser) -> Result<impl IntoResponse, AppError> {
    let contacts = EmergencyRepository::list_as_owner(&state.db, &user.email).await?;
    Ok(Json(contacts))
}

/// Relations où l'utilisateur connecté est LE CONTACT désigné ("les comptes où on m'a fait
/// confiance").
pub async fn list_granted_to_me(State(state): State<Arc<AppState>>, user: AuthUser) -> Result<impl IntoResponse, AppError> {
    let contacts = EmergencyRepository::list_as_contact(&state.db, &user.email).await?;
    Ok(Json(contacts))
}

/// Le CONTACT accepte l'invitation.
pub async fn accept_contact(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    EmergencyRepository::accept(&state.db, &id, &user.email).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "EMERGENCY_CONTACT_ACCEPT", addr.to_string(), agent).await;

    Ok(StatusCode::OK)
}

/// Le CONTACT décline l'invitation (supprime la relation).
pub async fn decline_contact(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    EmergencyRepository::decline(&state.db, &id, &user.email).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Le PROPRIÉTAIRE chiffre (scelle) sa clé de coffre pour ce contact précis — voir
/// src-tauri/src/emergency.rs::seal. Peut être rappelé à tout moment (ex: après un changement de
/// mot de passe maître, qui invalide l'ancien blob scellé, voir AuthContext.tsx côté frontend).
pub async fn seed_contact(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
    Json(payload): Json<SeedEmergencyKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    EmergencyRepository::seed(&state.db, &id, &user.email, &payload.sealed_vault_key).await?;
    Ok(StatusCode::OK)
}

/// Le CONTACT demande l'accès d'urgence — démarre le délai d'attente configuré par le
/// propriétaire ; celui-ci reçoit une notification et peut approuver immédiatement ou refuser
/// pendant ce délai (voir approve_access/reject_access ci-dessous). Sans décision de sa part,
/// l'accès s'accorde automatiquement une fois le délai écoulé (voir maybe_auto_grant, appelé
/// paresseusement dans get_emergency_vault).
pub async fn request_access(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let contact = EmergencyRepository::get_by_id(&state.db, &id).await?;
    if contact.contact_email != user.email {
        return Err(AppError::NotFound);
    }

    let requested_at = chrono::Utc::now().naive_utc();
    let available_at = requested_at + chrono::Duration::days(contact.waiting_period_days);
    EmergencyRepository::request_access(&state.db, &id, &user.email, requested_at, available_at).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "EMERGENCY_ACCESS_REQUEST", addr.to_string(), agent).await;

    let _ = mailer::send_security_alert(
        &contact.owner_email,
        &format!(
            "{} a demandé un accès d'urgence à votre coffre. Sans action de votre part, l'accès sera accordé automatiquement dans {} jour(s). Connectez-vous pour approuver immédiatement ou refuser.",
            user.email, contact.waiting_period_days
        ),
        &state.config,
    ).await;

    Ok(StatusCode::OK)
}

/// Le PROPRIÉTAIRE approuve immédiatement une demande en cours, sans attendre la fin du délai.
pub async fn approve_access(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    EmergencyRepository::approve(&state.db, &id, &user.email).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "EMERGENCY_ACCESS_APPROVE", addr.to_string(), agent).await;

    Ok(StatusCode::OK)
}

/// Le PROPRIÉTAIRE refuse une demande en cours — la relation reste active (le contact reste
/// désigné), seule cette demande précise est annulée.
pub async fn reject_access(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    EmergencyRepository::reject(&state.db, &id, &user.email).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "EMERGENCY_ACCESS_REJECT", addr.to_string(), agent).await;

    Ok(StatusCode::OK)
}

/// Le CONTACT consulte le coffre du propriétaire — UNIQUEMENT si l'accès est effectivement
/// accordé (promotion paresseuse du délai écoulé effectuée ICI, juste avant la vérification, voir
/// EmergencyRepository::maybe_auto_grant). Renvoie le coffre complet du propriétaire (comme
/// GET /vault, sans pagination — même raisonnement que /vault/export) ainsi que le blob scellé à
/// desceller côté client pour en obtenir la clé de déchiffrement.
pub async fn get_emergency_vault(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    EmergencyRepository::maybe_auto_grant(&state.db, &id, &user.email).await?;

    let (owner_email, sealed_vault_key) = EmergencyRepository::get_granted_vault_key(&state.db, &id, &user.email).await?;
    let entries = VaultRepository::get_all(&state.db, &owner_email, MAX_VAULT_ENTRIES, 0).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "EMERGENCY_VAULT_VIEW", addr.to_string(), agent).await;
    // Le PROPRIÉTAIRE est aussi averti à chaque consultation effective de son coffre — pas
    // uniquement à la demande initiale d'accès (voir request_access ci-dessus) : il doit savoir
    // quand son coffre est RÉELLEMENT lu, pas seulement quand l'accès a été demandé.
    let _ = mailer::send_security_alert(
        &owner_email,
        &format!("{} vient de consulter votre coffre via l'accès d'urgence.", user.email),
        &state.config,
    ).await;

    Ok(Json(EmergencyVaultView { sealed_vault_key, entries }))
}

/// Révoque une relation d'accès d'urgence — l'un OU l'autre côté peut y mettre fin à tout moment.
pub async fn revoke_contact(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    EmergencyRepository::revoke(&state.db, &id, &user.email).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "EMERGENCY_CONTACT_REVOKE", addr.to_string(), agent).await;

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

    /// Enregistre une paire de clés factice mais bien FORMÉE pour cet utilisateur — le contenu
    /// exact des clés n'a pas d'importance pour ces tests (qui portent sur la MACHINE À ÉTATS,
    /// pas sur le contenu cryptographique réel, déjà testé indépendamment dans
    /// src-tauri/src/emergency.rs), seule leur PRÉSENCE compte.
    async fn setup_keys(state: &Arc<AppState>, email: &str) {
        upsert_keys(
            State(state.clone()),
            auth(email),
            Json(UserKeysInput { public_key: format!("pubkey_{email}"), encrypted_private_key: format!("privkey_chiffre_{email}") }),
        )
        .await
        .expect("l'enregistrement des clés doit réussir");
    }

    /// Cycle de vie complet, sans intervention du propriétaire pendant le délai (auto-octroi) :
    /// invitation -> acceptation -> scellement -> demande d'accès -> délai écoulé -> consultation.
    #[tokio::test]
    async fn test_emergency_access_full_lifecycle_with_auto_grant() {
        let state = build_test_state().await;
        register_test_user(&state, "owner@example.com").await;
        register_test_user(&state, "contact@example.com").await;
        setup_keys(&state, "owner@example.com").await;
        setup_keys(&state, "contact@example.com").await;

        // Le propriétaire ajoute une entrée à son coffre, pour vérifier plus tard qu'elle est
        // bien visible via l'accès d'urgence.
        VaultRepository::add(
            &state.db,
            "owner@example.com",
            VaultEntryInput {
                encrypted_site_name: "chiffre_site".to_string(), encrypted_username: None, encrypted_login_email: None,
                encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
                entry_type: "login".to_string(), encrypted_extra_fields: None,
                encrypted_password: "chiffre_mdp".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
            },
        ).await.unwrap();

        // 0 jour d'attente : la demande d'accès doit pouvoir s'auto-accorder immédiatement.
        let add_result = add_contact(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner@example.com"),
            Json(AddEmergencyContactPayload { contact_email: "contact@example.com".to_string(), waiting_period_days: 0 }),
        ).await.expect("l'ajout du contact doit réussir");
        let id = read_json_body(add_result.into_response()).await["id"].as_str().unwrap().to_string();

        // Avant acceptation : le contact ne peut ni sceller (c'est le propriétaire qui scelle) ni
        // demander l'accès.
        let premature = request_access(State(state.clone()), test_addr(), HeaderMap::new(), auth("contact@example.com"), Path(id.clone())).await;
        assert!(premature.is_err(), "impossible de demander l'accès avant d'avoir accepté l'invitation");

        accept_contact(State(state.clone()), test_addr(), HeaderMap::new(), auth("contact@example.com"), Path(id.clone()))
            .await.expect("l'acceptation doit réussir");

        seed_contact(
            State(state.clone()), auth("owner@example.com"), Path(id.clone()),
            Json(SeedEmergencyKeyPayload { sealed_vault_key: "blob_scelle_pour_contact".to_string() }),
        ).await.expect("le scellement doit réussir");

        request_access(State(state.clone()), test_addr(), HeaderMap::new(), auth("contact@example.com"), Path(id.clone()))
            .await.expect("la demande d'accès doit réussir");

        // Personne n'approuve ni ne refuse : après le délai (ici 0 jour, donc immédiatement), la
        // consultation doit fonctionner grâce à la promotion paresseuse (maybe_auto_grant).
        let vault_result = get_emergency_vault(State(state.clone()), test_addr(), HeaderMap::new(), auth("contact@example.com"), Path(id.clone()))
            .await.expect("la consultation doit réussir une fois le délai (nul) écoulé");
        let value = read_json_body(vault_result.into_response()).await;
        assert_eq!(value["sealed_vault_key"].as_str(), Some("blob_scelle_pour_contact"));
        let entries = value["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["encrypted_site_name"].as_str(), Some("chiffre_site"));

        // La révocation, par n'importe lequel des deux côtés, met fin à tout.
        revoke_contact(State(state.clone()), test_addr(), HeaderMap::new(), auth("contact@example.com"), Path(id.clone()))
            .await.expect("la révocation doit réussir");
        let after_revoke = get_emergency_vault(State(state.clone()), test_addr(), HeaderMap::new(), auth("contact@example.com"), Path(id)).await;
        assert!(matches!(after_revoke, Err(AppError::NotFound)), "après révocation, plus aucun accès ne doit être possible");
    }

    /// GARDE-FOU CRITIQUE : tant que le propriétaire n'a pas explicitement approuvé (ou que le
    /// délai n'est pas écoulé), le contact ne doit JAMAIS pouvoir récupérer sealed_vault_key —
    /// sans quoi le délai d'attente et l'approbation ne seraient que des vérifications
    /// cosmétiques, contournables en asseyant le blob directement.
    #[tokio::test]
    async fn test_sealed_vault_key_not_exposed_before_access_granted() {
        let state = build_test_state().await;
        register_test_user(&state, "owner2@example.com").await;
        register_test_user(&state, "contact2@example.com").await;
        setup_keys(&state, "owner2@example.com").await;
        setup_keys(&state, "contact2@example.com").await;

        let add_result = add_contact(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner2@example.com"),
            // Délai long : la demande d'accès ne doit PAS pouvoir s'auto-accorder pendant ce test.
            Json(AddEmergencyContactPayload { contact_email: "contact2@example.com".to_string(), waiting_period_days: 30 }),
        ).await.unwrap();
        let id = read_json_body(add_result.into_response()).await["id"].as_str().unwrap().to_string();

        accept_contact(State(state.clone()), test_addr(), HeaderMap::new(), auth("contact2@example.com"), Path(id.clone())).await.unwrap();
        seed_contact(
            State(state.clone()), auth("owner2@example.com"), Path(id.clone()),
            Json(SeedEmergencyKeyPayload { sealed_vault_key: "secret_scelle".to_string() }),
        ).await.unwrap();

        // Ni juste après l'acceptation...
        let too_early = get_emergency_vault(State(state.clone()), test_addr(), HeaderMap::new(), auth("contact2@example.com"), Path(id.clone())).await;
        assert!(matches!(too_early, Err(AppError::NotFound)));

        // ...ni juste après avoir demandé l'accès (délai de 30 jours, pas encore écoulé).
        request_access(State(state.clone()), test_addr(), HeaderMap::new(), auth("contact2@example.com"), Path(id.clone())).await.unwrap();
        let still_too_early = get_emergency_vault(State(state.clone()), test_addr(), HeaderMap::new(), auth("contact2@example.com"), Path(id.clone())).await;
        assert!(matches!(still_too_early, Err(AppError::NotFound)), "le délai de 30 jours n'est pas écoulé, l'accès ne doit pas être accordé");

        // Le propriétaire approuve explicitement -> maintenant seulement, ça fonctionne.
        approve_access(State(state.clone()), test_addr(), HeaderMap::new(), auth("owner2@example.com"), Path(id.clone())).await.unwrap();
        let now_ok = get_emergency_vault(State(state.clone()), test_addr(), HeaderMap::new(), auth("contact2@example.com"), Path(id)).await;
        assert!(now_ok.is_ok(), "après approbation explicite du propriétaire, la consultation doit réussir");
    }

    /// Un refus pendant le délai d'attente doit bloquer l'accès (retour à 'active'), sans pour
    /// autant supprimer la relation de confiance elle-même.
    #[tokio::test]
    async fn test_reject_blocks_access_but_keeps_relationship() {
        let state = build_test_state().await;
        register_test_user(&state, "owner3@example.com").await;
        register_test_user(&state, "contact3@example.com").await;
        setup_keys(&state, "owner3@example.com").await;
        setup_keys(&state, "contact3@example.com").await;

        let add_result = add_contact(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner3@example.com"),
            Json(AddEmergencyContactPayload { contact_email: "contact3@example.com".to_string(), waiting_period_days: 7 }),
        ).await.unwrap();
        let id = read_json_body(add_result.into_response()).await["id"].as_str().unwrap().to_string();

        accept_contact(State(state.clone()), test_addr(), HeaderMap::new(), auth("contact3@example.com"), Path(id.clone())).await.unwrap();
        seed_contact(State(state.clone()), auth("owner3@example.com"), Path(id.clone()), Json(SeedEmergencyKeyPayload { sealed_vault_key: "blob".to_string() })).await.unwrap();
        request_access(State(state.clone()), test_addr(), HeaderMap::new(), auth("contact3@example.com"), Path(id.clone())).await.unwrap();

        reject_access(State(state.clone()), test_addr(), HeaderMap::new(), auth("owner3@example.com"), Path(id.clone()))
            .await.expect("le refus doit réussir");

        let denied = get_emergency_vault(State(state.clone()), test_addr(), HeaderMap::new(), auth("contact3@example.com"), Path(id.clone())).await;
        assert!(matches!(denied, Err(AppError::NotFound)), "après refus, la consultation doit échouer");

        // La relation existe toujours (juste plus de demande en cours) — le contact peut refaire
        // une demande plus tard.
        let contacts = list_contacts_as_owner(State(state.clone()), auth("owner3@example.com")).await.unwrap();
        let value = read_json_body(contacts.into_response()).await;
        assert_eq!(value.as_array().unwrap().len(), 1, "la relation ne doit pas avoir été supprimée par le refus");
    }

    /// Un utilisateur qui n'est ni le propriétaire ni le contact désigné ne doit jamais pouvoir
    /// agir sur une relation qui ne le concerne pas.
    #[tokio::test]
    async fn test_third_party_cannot_act_on_relationship() {
        let state = build_test_state().await;
        register_test_user(&state, "owner4@example.com").await;
        register_test_user(&state, "contact4@example.com").await;
        register_test_user(&state, "stranger@example.com").await;
        setup_keys(&state, "owner4@example.com").await;
        setup_keys(&state, "contact4@example.com").await;

        let add_result = add_contact(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner4@example.com"),
            Json(AddEmergencyContactPayload { contact_email: "contact4@example.com".to_string(), waiting_period_days: 1 }),
        ).await.unwrap();
        let id = read_json_body(add_result.into_response()).await["id"].as_str().unwrap().to_string();

        let wrong_accept = accept_contact(State(state.clone()), test_addr(), HeaderMap::new(), auth("stranger@example.com"), Path(id.clone())).await;
        assert!(matches!(wrong_accept, Err(AppError::NotFound)));

        let wrong_seed = seed_contact(
            State(state.clone()), auth("stranger@example.com"), Path(id.clone()),
            Json(SeedEmergencyKeyPayload { sealed_vault_key: "intrus".to_string() }),
        ).await;
        assert!(matches!(wrong_seed, Err(AppError::NotFound)));

        let wrong_revoke = revoke_contact(State(state.clone()), test_addr(), HeaderMap::new(), auth("stranger@example.com"), Path(id)).await;
        assert!(matches!(wrong_revoke, Err(AppError::NotFound)), "un tiers étranger à la relation ne doit jamais pouvoir la révoquer");
    }

    #[tokio::test]
    async fn test_cannot_add_self_as_contact() {
        let state = build_test_state().await;
        register_test_user(&state, "solo@example.com").await;

        let result = add_contact(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("solo@example.com"),
            Json(AddEmergencyContactPayload { contact_email: "solo@example.com".to_string(), waiting_period_days: 1 }),
        ).await;
        assert!(matches!(result, Err(AppError::ValidationError(_))));
    }

    #[tokio::test]
    async fn test_cannot_add_duplicate_contact() {
        let state = build_test_state().await;
        register_test_user(&state, "owner5@example.com").await;
        register_test_user(&state, "contact5@example.com").await;

        add_contact(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner5@example.com"),
            Json(AddEmergencyContactPayload { contact_email: "contact5@example.com".to_string(), waiting_period_days: 1 }),
        ).await.expect("le premier ajout doit réussir");

        let duplicate = add_contact(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner5@example.com"),
            Json(AddEmergencyContactPayload { contact_email: "contact5@example.com".to_string(), waiting_period_days: 5 }),
        ).await;
        assert!(matches!(duplicate, Err(AppError::Conflict(_))), "désigner deux fois le même contact doit être refusé");
    }

    #[tokio::test]
    async fn test_decline_removes_pending_invitation() {
        let state = build_test_state().await;
        register_test_user(&state, "owner6@example.com").await;
        register_test_user(&state, "contact6@example.com").await;

        let add_result = add_contact(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner6@example.com"),
            Json(AddEmergencyContactPayload { contact_email: "contact6@example.com".to_string(), waiting_period_days: 1 }),
        ).await.unwrap();
        let id = read_json_body(add_result.into_response()).await["id"].as_str().unwrap().to_string();

        decline_contact(State(state.clone()), auth("contact6@example.com"), Path(id)).await.expect("le refus de l'invitation doit réussir");

        let contacts = list_contacts_as_owner(State(state.clone()), auth("owner6@example.com")).await.unwrap();
        let value = read_json_body(contacts.into_response()).await;
        assert_eq!(value.as_array().unwrap().len(), 0, "une invitation déclinée ne doit laisser aucune trace");
    }

    #[tokio::test]
    async fn test_own_and_public_key_roundtrip() {
        let state = build_test_state().await;
        register_test_user(&state, "keyowner@example.com").await;
        register_test_user(&state, "viewer@example.com").await;
        setup_keys(&state, "keyowner@example.com").await;

        // N'importe quel utilisateur authentifié peut lire la clé PUBLIQUE d'un autre.
        let public_result = get_public_key(State(state.clone()), auth("viewer@example.com"), Path("keyowner@example.com".to_string()))
            .await.expect("la lecture de la clé publique doit réussir");
        let public_value = read_json_body(public_result.into_response()).await;
        assert_eq!(public_value["public_key"].as_str(), Some("pubkey_keyowner@example.com"));
        assert!(public_value.get("encrypted_private_key").is_none(), "la route publique ne doit JAMAIS exposer de clé privée, même chiffrée");

        // Seul le propriétaire peut lire SES PROPRES clés complètes (via son propre AuthUser, pas
        // un paramètre d'URL arbitraire).
        let own_result = get_own_keys(State(state.clone()), auth("keyowner@example.com")).await.expect("la lecture de ses propres clés doit réussir");
        let own_value = read_json_body(own_result.into_response()).await;
        assert_eq!(own_value["encrypted_private_key"].as_str(), Some("privkey_chiffre_keyowner@example.com"));
    }

    /// CORRECTIF : get_public_key() doit retrouver la cible même si l'appelant fournit son email
    /// dans une casse différente de celle enregistrée (ex: copié-collé depuis un autre contexte).
    #[tokio::test]
    async fn test_get_public_key_is_case_insensitive_on_target_email() {
        let state = build_test_state().await;
        register_test_user(&state, "keyowner2@example.com").await;
        register_test_user(&state, "viewer2@example.com").await;
        setup_keys(&state, "keyowner2@example.com").await;

        let result = get_public_key(State(state.clone()), auth("viewer2@example.com"), Path("KeyOwner2@Example.com".to_string()))
            .await.expect("la casse de l'email cible ne doit pas empêcher de trouver la clé publique");
        let value = read_json_body(result.into_response()).await;
        assert_eq!(value["public_key"].as_str(), Some("pubkey_keyowner2@example.com"));
    }

    #[tokio::test]
    async fn test_get_public_key_not_found_when_no_keys_configured() {
        let state = build_test_state().await;
        register_test_user(&state, "nokeys@example.com").await;
        register_test_user(&state, "asker@example.com").await;

        let result = get_public_key(State(state.clone()), auth("asker@example.com"), Path("nokeys@example.com".to_string())).await;
        assert!(matches!(result, Err(AppError::NotFound)), "un utilisateur qui n'a jamais configuré l'accès d'urgence ne doit avoir aucune clé publique");
    }

    /// list_granted_to_me() doit refléter le point de vue du CONTACT, symétrique à
    /// list_contacts_as_owner() côté propriétaire.
    #[tokio::test]
    async fn test_list_granted_to_me_reflects_contact_view() {
        let state = build_test_state().await;
        register_test_user(&state, "owner7@example.com").await;
        register_test_user(&state, "contact7@example.com").await;

        add_contact(
            State(state.clone()), test_addr(), HeaderMap::new(), auth("owner7@example.com"),
            Json(AddEmergencyContactPayload { contact_email: "contact7@example.com".to_string(), waiting_period_days: 3 }),
        ).await.unwrap();

        let granted = list_granted_to_me(State(state.clone()), auth("contact7@example.com")).await.unwrap();
        let value = read_json_body(granted.into_response()).await;
        let rows = value.as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["owner_email"].as_str(), Some("owner7@example.com"));

        // Le propriétaire, lui, n'apparaît pas dans SES PROPRES "granted-to-me".
        let owner_granted = list_granted_to_me(State(state.clone()), auth("owner7@example.com")).await.unwrap();
        let owner_value = read_json_body(owner_granted.into_response()).await;
        assert_eq!(owner_value.as_array().unwrap().len(), 0);
    }
}
