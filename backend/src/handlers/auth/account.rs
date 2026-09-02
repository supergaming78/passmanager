// =========================================================================
// COMPTE : MOT DE PASSE, EMAIL, PROFIL
// =========================================================================
// Tout ce qui concerne la gestion d'un compte DÉJÀ créé et vérifié : changement volontaire du
// mot de passe maître (avec re-chiffrement du coffre), réinitialisation en cas d'oubli (purge du
// coffre, Zero-Knowledge oblige), changement d'email, et consultation du profil. Voir register.rs
// pour la création de compte, session.rs pour login/2FA/refresh/logout.

use axum::{
    extract::State,
    http::{StatusCode, HeaderMap},
    response::IntoResponse,
    Json
};
use std::sync::Arc;
use crate::{AppState, crypto, mailer, error::AppError, middleware::AuthUser, repository::VaultRepository, models::*};
use validator::Validate;
use chrono::Utc;
use serde_json::json;
use tracing::{instrument, warn, info};
use rand::RngExt;
use super::{MAX_CODE_ATTEMPTS, PURPOSE_PASSWORD_RESET};
use super::super::common::is_extension_origin;

// --- ROUTE : MISE À JOUR DU MOT DE PASSE (PASSWORD UPDATE) ---

#[instrument(skip(state, user, payload))]
/// Permet à un utilisateur connecté de changer VOLONTAIREMENT son mot de passe maître.
/// ZERO-KNOWLEDGE TOTAL : contrairement à un simple changement de mot de passe "classique", ceci
/// DOIT s'accompagner du re-chiffrement de TOUTES les entrées actives du coffre — la clé qui
/// chiffre le coffre dérive du mot de passe maître (côté client, jamais côté serveur), donc la
/// changer sans re-chiffrer rendrait les entrées existantes définitivement indéchiffrables.
/// Le CLIENT doit donc : déchiffrer localement toutes ses entrées avec l'ancienne clé, les
/// re-chiffrer avec la nouvelle, et les envoyer ICI dans `reencrypted_entries`, EN MÊME TEMPS
/// que le changement de mot de passe — le tout dans une seule transaction atomique côté serveur
/// (soit tout réussit, soit rien n'est modifié, jamais d'état à moitié re-chiffré).
pub async fn update_password(
    State(state): State<Arc<AppState>>,
    user: AuthUser,                          // Middleware : extrait l'utilisateur connecté via son JWT
    Json(payload): Json<ChangeMasterPasswordPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    // Valide aussi chaque entrée re-chiffrée individuellement (la validation du crate `validator`
    // sur `Vec<T>` n'est pas fiable via la macro dérivée, on le fait donc explicitement ici).
    for entry in &payload.reencrypted_entries {
        entry.validate()?;
    }
    for entry in &payload.reencrypted_history {
        entry.validate()?;
    }
    for attachment in &payload.reencrypted_attachments {
        attachment.validate()?;
    }

    // 1. Récupération des informations actuelles de l'utilisateur en base
    let current_user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = ?")
        .bind(&user.email)
        .fetch_one(&state.db)
        .await?;

    // 2. Vérification que l'ANCIEN hash d'authentification fourni correspond bien au hash stocké
    if !crypto::verify_password(&payload.old_master_password_hash, &current_user.password_hash, &state.config.password_pepper).await {
        return Err(AppError::InvalidCredentials);
    }

    // 3. GARDE-FOU CRITIQUE : le client doit avoir re-chiffré TOUTES les entrées actives, ET TOUT
    // l'historique de mots de passe, sans exception — un oubli rendrait cette donnée
    // définitivement indéchiffrable (elle resterait chiffrée avec l'ANCIENNE clé, perdue à
    // jamais). On compare aux comptes réels en BDD, AVANT de toucher quoi que ce soit.
    //
    // CORRECTIF PERF (retour utilisateur, 2026-09-02) : ces trois COUNT() portent sur trois
    // TABLES DIFFÉRENTES et sont totalement INDÉPENDANTS les uns des autres (aucun n'a besoin du
    // résultat d'un autre) — auparavant enchaînés séquentiellement (un .await après l'autre) alors
    // qu'ils peuvent tourner EN PARALLÈLE sur des connexions différentes du pool (SQLite en mode
    // WAL gère bien plusieurs lectures concurrentes, voir main.rs). Les résultats sont ensuite
    // vérifiés dans le MÊME ORDRE qu'avant (entrées, puis historique, puis pièces jointes) : un
    // changement de mot de passe avec plusieurs incohérences à la fois affiche encore le même
    // message qu'avant, seule la phase de LECTURE est parallélisée.
    let (active_count, history_count, attachments_count) = tokio::try_join!(
        VaultRepository::count_active(&state.db, &user.email),
        VaultRepository::count_history_for_user(&state.db, &user.email),
        VaultRepository::count_attachments_for_user(&state.db, &user.email),
    )?;
    if payload.reencrypted_entries.len() as i64 != active_count {
        return Err(AppError::ValidationError(format!(
            "Re-chiffrement incomplet : {} entrée(s) active(s) en BDD, {} reçue(s). Le changement de mot de passe a été annulé pour éviter de perdre des données.",
            active_count, payload.reencrypted_entries.len()
        )));
    }
    if payload.reencrypted_history.len() as i64 != history_count {
        return Err(AppError::ValidationError(format!(
            "Re-chiffrement de l'historique incomplet : {} ligne(s) en BDD, {} reçue(s). Le changement de mot de passe a été annulé pour éviter de perdre des données.",
            history_count, payload.reencrypted_history.len()
        )));
    }
    if payload.reencrypted_attachments.len() as i64 != attachments_count {
        return Err(AppError::ValidationError(format!(
            "Re-chiffrement des pièces jointes incomplet : {} pièce(s) jointe(s) en BDD, {} reçue(s). Le changement de mot de passe a été annulé pour éviter de perdre des données.",
            attachments_count, payload.reencrypted_attachments.len()
        )));
    }

    // 4. Calcul du hachage du NOUVEAU hash d'authentification (double hachage, comme au login)
    let new_password_hash = crypto::hash_password(&payload.new_master_password_hash, &state.config.password_pepper).await?;

    // 5. TRANSACTION ATOMIQUE : mot de passe + TOUTES les entrées re-chiffrées + TOUT l'historique
    // re-chiffré + invalidation des sessions. Si UNE SEULE ligne échoue à se mettre à jour (ex: id
    // inconnu), tout est annulé — jamais de coffre à moitié re-chiffré avec deux clés différentes
    // en même temps.
    let mut tx = state.db.begin().await?;

    // `password_changed_at` : voir middleware.rs::AuthUser, qui rejette tout access token émis
    // avant cette date — ferme la fenêtre résiduelle où un token déjà émis restait valide malgré
    // la révocation des refresh tokens juste en dessous.
    sqlx::query("UPDATE users SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP WHERE email = ?")
        .bind(&new_password_hash)
        .bind(&user.email)
        .execute(&mut *tx)
        .await?;

    for entry in &payload.reencrypted_entries {
        VaultRepository::reencrypt(&mut tx, &user.email, entry).await?;
    }
    for entry in &payload.reencrypted_history {
        VaultRepository::reencrypt_history_row(&mut tx, &user.email, entry).await?;
    }
    for attachment in &payload.reencrypted_attachments {
        VaultRepository::reencrypt_attachment(&mut tx, &user.email, attachment).await?;
    }

    // MESURE DE SÉCURITÉ : Invalidation immédiate de TOUTES les sessions actives (déconnexion globale)
    sqlx::query("DELETE FROM refresh_tokens WHERE user_email = ?")
        .bind(&user.email)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    // 6. Envoi d'une alerte de sécurité par email à l'utilisateur
    let _ = mailer::send_security_alert(
        &user.email,
        "Votre mot de passe a été modifié. Si vous n'êtes pas à l'origine de cette action, sécurisez votre compte.",
        &state.config
    ).await;

    Ok(StatusCode::OK)
}

// --- ROUTE : MISE À JOUR DE L'EMAIL (EMAIL UPDATE) ---

/// Permet à l'utilisateur de modifier son adresse de messagerie principale.
/// RESTRICTION SPÉCIFIQUE À L'EXTENSION NAVIGATEUR : un changement d'email touche à l'identité du
/// compte — désactivé par défaut quand la requête vient d'une extension (voir
/// `common::is_extension_origin`), sauf pour un modérateur (ou l'Admin) ou un compte explicitement
/// autorisé (`can_change_email_via_extension`, activable un par un ou pour tout le monde via
/// handlers/admin.rs). L'app desktop n'est JAMAIS concernée par cette restriction.
pub async fn update_email(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<UpdateEmailPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;

    if is_extension_origin(&headers) && !user.is_moderator {
        let enabled: bool = sqlx::query_scalar("SELECT can_change_email_via_extension FROM users WHERE email = ?")
            .bind(&user.email)
            .fetch_one(&state.db)
            .await?;
        if !enabled {
            warn!("Changement d'email refusé depuis l'extension pour {} (non autorisé)", user.email);
            return Err(AppError::Forbidden);
        }
    }

    // 1. Récupération de l'utilisateur pour vérifier son mot de passe (Défense en profondeur)
    let current_user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = ?")
        .bind(&user.email)
        .fetch_one(&state.db)
        .await?;

    if !crypto::verify_password(&payload.master_password_hash, &current_user.password_hash, &state.config.password_pepper).await {
        return Err(AppError::InvalidCredentials);
    }

    let old_email = user.email.clone();
    let new_email = payload.new_email.to_lowercase();

    // 2. Transaction SQL
    let mut tx = state.db.begin().await?;

    // Mise à jour de l'email dans la table principale 'users'
    // Note : Le mécanisme 'ON UPDATE CASCADE' configuré au niveau de la base de données
    // répercute automatiquement ce changement d'email sur toutes les tables liées.
    sqlx::query("UPDATE users SET email = ? WHERE email = ?")
        .bind(&new_email)
        .bind(&old_email)
        .execute(&mut *tx)
        .await?;

    // Invalidation forcée des sessions pour obliger l'utilisateur à se reconnecter avec son nouvel email
    sqlx::query("DELETE FROM refresh_tokens WHERE user_email = ?")
        .bind(&new_email)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    // 3. ALERTE DE SÉCURITÉ : Envoyée exclusivement à l'ANCIENNE adresse pour notifier d'un éventuel piratage
    let _ = mailer::send_security_alert(
        &old_email,
        "Votre adresse e-mail a été modifiée. Cette boîte mail n'est plus associée à votre compte.",
        &state.config
    ).await;

    info!("Email mis à jour : {} remplacé par {}", old_email, new_email);
    Ok(StatusCode::OK)
}

/// Récupère le profil de l'utilisateur connecté (email, statut modérateur/admin, plafond
/// d'appareils actuel).
/// `is_moderator` : le JWT ne porte PAS ce champ (volontairement — AuthUser le revérifie en base à
/// chaque requête, voir middleware.rs, pour qu'une promotion/rétrogradation prenne effet
/// immédiatement sans attendre l'expiration du token). Ce endpoint est donc la seule façon fiable
/// pour un client de savoir s'il doit afficher une interface d'administration, sans avoir à
/// décoder le JWT lui-même (une décision d'autorisation ne doit jamais reposer sur une donnée
/// lue côté client) ni à sonder un endpoint admin à l'aveugle pour déduire la réponse d'un 403.
/// `is_admin` : calculé (voir `AuthUser::is_admin()`), vrai uniquement pour le compte `ADMIN_EMAIL`.
/// `max_trusted_devices` : sans ce champ ici, un utilisateur sans droits élevés n'avait AUCUN
/// moyen de connaître son propre plafond actuel avant de le modifier (voir update_device_limit()) —
/// PUT /devices/limit ne renvoie qu'un 200 vide, jamais la valeur en vigueur.
pub async fn get_me(State(state): State<Arc<AppState>>, user: AuthUser) -> Result<impl IntoResponse, AppError> {
    let (max_trusted_devices, can_change_email_via_extension, can_choose_server_in_settings): (i64, bool, bool) = sqlx::query_as(
        "SELECT max_trusted_devices, can_change_email_via_extension, can_choose_server_in_settings FROM users WHERE email = ?"
    )
        .bind(&user.email)
        .fetch_one(&state.db)
        .await?;

    Ok(Json(json!({
        "email": user.email,
        "is_moderator": user.is_moderator,
        "max_trusted_devices": max_trusted_devices,
        "can_change_email_via_extension": can_change_email_via_extension,
        // Valeur BRUTE de la colonne (PAS OR'ée avec is_admin) — même convention que le champ
        // ci-dessus : c'est au CLIENT de combiner `isAdmin || canChooseServerInSettings` pour
        // décider d'afficher la section (voir pages/Settings.tsx), is_admin étant déjà exposé
        // séparément juste en dessous.
        "can_choose_server_in_settings": can_choose_server_in_settings,
        // Voir handlers/admin.rs::update_user_role() : SEUL ce compte (ADMIN_EMAIL) peut changer
        // un rôle modérateur — exposé ici pour que l'écran Administration puisse masquer les
        // boutons promouvoir/rétrograder pour tout le monde d'autre, plutôt que de laisser un
        // bouton qui échouerait toujours avec 403.
        "is_admin": user.is_admin(&state),
    })))
}

/// Historique de sécurité SELF-SERVICE : contrairement à `GET /audit` (handlers/admin.rs, réservé
/// aux admins, TOUS les utilisateurs confondus), ce endpoint ne renvoie QUE les entrées d'audit de
/// L'UTILISATEUR CONNECTÉ (`WHERE user_email = ?`, jamais de vérification a posteriori en Rust —
/// même principe de sécurité que EmergencyRepository::get_granted_vault_key). Aucun contenu du
/// coffre là-dedans (voir log_audit dans state.rs) : juste action/IP/user-agent/date, en clair.
pub async fn get_my_audit_logs(State(state): State<Arc<AppState>>, user: AuthUser) -> Result<impl IntoResponse, AppError> {
    let logs: Vec<AuditLog> = sqlx::query_as(
        "SELECT * FROM audit_logs WHERE user_email = ? ORDER BY created_at DESC LIMIT 100",
    )
    .bind(&user.email)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(logs))
}

// --- RÉINITIALISATION DU COMPTE (PASSWORD RESET - STRATÉGIE ZERO-KNOWLEDGE) ---

/// Initie une demande de réinitialisation de mot de passe en générant et envoyant un code par e-mail.
pub async fn request_password_reset(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ForgotPasswordPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    let email = payload.email.to_lowercase();

    // 0. Vérifie si le compte existe AVANT toute action.
    // IMPORTANT : quel que soit le résultat, cette route doit TOUJOURS répondre 202,
    // sans quoi la différence de statut (202 vs 500 dû à la contrainte FK sur tfa_codes)
    // permettrait à un attaquant de deviner quels emails sont enregistrés (énumération de comptes).
    let user_exists = sqlx::query("SELECT 1 FROM users WHERE email = ?")
        .bind(&email)
        .fetch_optional(&state.db)
        .await?
        .is_some();

    if user_exists {
        // 1. Génère un code de sécurité temporaire à 6 chiffres
        let reset_code = format!("{:06}", rand::rng().random_range(0..1000000));
        let expires_at = (Utc::now() + chrono::Duration::minutes(15)).format("%Y-%m-%dT%H:%M:%SZ").to_string();

        // 2. Sauvegarde ou remplace le code en base pour cet email
        sqlx::query("INSERT OR REPLACE INTO tfa_codes (email, purpose, code, expires_at) VALUES (?, ?, ?, ?)")
            .bind(&email)
            .bind(PURPOSE_PASSWORD_RESET)
            .bind(&reset_code)
            .bind(expires_at)
            .execute(&state.db)
            .await?;

        // 3. Expédition de l'email contenant la clé de récupération
        // On journalise une éventuelle erreur d'envoi sans jamais la répercuter au client
        // (même raison : ne pas trahir si l'email existe ou non via une réponse d'erreur).
        if let Err(e) = mailer::send_reset_email(&email, &reset_code, &state.config).await {
            warn!("Échec envoi email de reset pour {} : {:?}", email, e);
        }
    } else {
        warn!("Demande de reset de mot de passe pour un email inconnu : {}", email);
    }

    // Réponse identique dans tous les cas (compte existant ou non)
    Ok(StatusCode::ACCEPTED)
}

/// Valide le code de récupération et applique le nouveau mot de passe.
/// /!\ ATTENTION /!\ : Conséquences critiques dues à la politique d'architecture Zero-Knowledge.
pub async fn confirm_password_reset(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ConfirmResetPayload>,
) -> Result<impl IntoResponse, AppError> {
    // CORRECTIF SÉCURITÉ : route NON authentifiée — sans ce .validate(), new_master_password_hash
    // (jusqu'à la limite globale de 256 Ko) atteignait directement crypto::hash_password() ->
    // Argon2, un vecteur d'amplification CPU/mémoire accessible à n'importe qui.
    payload.validate()?;

    // Même raison que dans verify_2fa_and_register_device (session.rs) : le code a été stocké
    // sous l'email en minuscules par request_password_reset(), donc on doit comparer avec la
    // même forme normalisée, sinon un email de casse différente ne retrouvera ni le code, ni la
    // ligne `users` à mettre à jour.
    let email = payload.email.to_lowercase();

    // 1. Recherche du code de réinitialisation associé
    let tfa: TfaCode = sqlx::query_as("SELECT * FROM tfa_codes WHERE email = ? AND purpose = ?")
        .bind(&email)
        .bind(PURPOSE_PASSWORD_RESET)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::ValidationError("Code invalide ou expiré".to_string()))?;

    // Verrouillage : trop de tentatives échouées sur ce code -> on le supprime
    if tfa.attempts >= MAX_CODE_ATTEMPTS {
        sqlx::query("DELETE FROM tfa_codes WHERE email = ? AND purpose = ?")
            .bind(&email)
            .bind(PURPOSE_PASSWORD_RESET)
            .execute(&state.db)
            .await?;
        warn!("Code de reset verrouillé après trop de tentatives pour {}", email);
        return Err(AppError::ValidationError("Trop de tentatives, veuillez redemander un code".to_string()));
    }

    // Vérification de la correspondance du code fourni (temps constant : voir crypto::constant_time_eq)
    if !crypto::constant_time_eq(&payload.code, &tfa.code) {
        // Tentative échouée : on incrémente le compteur avant de rejeter la requête
        sqlx::query("UPDATE tfa_codes SET attempts = attempts + 1 WHERE email = ? AND purpose = ?")
            .bind(&email)
            .bind(PURPOSE_PASSWORD_RESET)
            .execute(&state.db)
            .await?;
        return Err(AppError::ValidationError("Code incorrect".to_string()));
    }

    // Vérification de la validité de l'heure
    let expires_at = chrono::NaiveDateTime::parse_from_str(&tfa.expires_at, "%Y-%m-%dT%H:%M:%SZ")
        .map_err(|_| AppError::Internal("Erreur technique de date".to_string()))?;

    if Utc::now().naive_utc() > expires_at {
        return Err(AppError::ValidationError("Le code a expiré".to_string()));
    }

    // 2. Calcul du hash du nouveau mot de passe maître
    let new_hash = crypto::hash_password(&payload.new_master_password_hash, &state.config.password_pepper)
        .await
        .map_err(|_| AppError::HashError)?;

    // 3. TRANSACTION CRITIQUE MULTI-CIBLES
    let mut tx = state.db.begin().await?;

    // a. Changement effectif du mot de passe de l'utilisateur. `password_changed_at` : même
    // raison que dans update_password() (voir middleware.rs::AuthUser).
    sqlx::query("UPDATE users SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP WHERE email = ?")
        .bind(new_hash)
        .bind(&email)
        .execute(&mut *tx).await?;

    // b. PURGE INTÉGRALE DU COFFRE-FORT (Stratégie Zero-Knowledge) :
    // Dans une architecture Zero-Knowledge, les données du coffre sont chiffrées côté client
    // avec une clé dérivée de l'ancien mot de passe maître. Le serveur ne la possède pas.
    // Si l'utilisateur perd son mot de passe, ses données stockées deviennent définitivement indéchiffrables.
    // Par sécurité, le serveur supprime (purge) donc l'intégralité du coffre-fort ('vault').
    sqlx::query("DELETE FROM vault WHERE user_email = ?")
        .bind(&email)
        .execute(&mut *tx).await?;

    // c. Nettoyage des sessions actives et des codes émis pour ce compte. Volontairement SANS
    // filtre `purpose` ici (contrairement au reste de cette fonction) : une réinitialisation de
    // mot de passe est un événement majeur, on purge TOUS les codes en attente pour cet email,
    // même ceux d'un autre flux (2FA, vérification d'email) qui n'aurait plus de sens après ça.
    sqlx::query("DELETE FROM refresh_tokens WHERE user_email = ?").bind(&email).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM tfa_codes WHERE email = ?").bind(&email).execute(&mut *tx).await?;

    tx.commit().await?;

    info!("Réinitialisation totale du compte (MDP + Vault) pour : {}", email);
    Ok(StatusCode::OK)
}

// =========================================================================
// TESTS
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::handlers::auth::register::register;
    use crate::handlers::auth::session::{login, verify_2fa_and_register_device};
    use sqlx::sqlite::SqlitePoolOptions;
    use std::net::SocketAddr;
    use axum::extract::{ConnectInfo, Path};
    use axum::http::HeaderMap;

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

    /// Crée un utilisateur de test via le VRAI handler register() (donc avec le hachage réel),
    /// puis marque directement le compte comme vérifié en BDD (voir register.rs::tests pour
    /// l'explication détaillée — dupliqué ici volontairement, chaque module de tests reste autonome).
    async fn register_test_user(state: &Arc<AppState>, email: &str, password: &str) {
        let payload = AuthPayload {
            email: email.to_string(),
            master_password_hash: password.to_string(),
            device_id: "unused-at-registration".to_string(),
            remember_me: None,
            max_trusted_devices: None,
        };
        register(State(state.clone()), Json(payload))
            .await
            .expect("l'inscription doit réussir");

        sqlx::query("UPDATE users SET email_verified = 1 WHERE email = ?")
            .bind(email.to_lowercase())
            .execute(&state.db)
            .await
            .expect("le marquage du compte de test comme vérifié doit réussir");

        sqlx::query("DELETE FROM tfa_codes WHERE email = ?")
            .bind(email.to_lowercase())
            .execute(&state.db)
            .await
            .expect("le nettoyage du code de vérification de test doit réussir");
    }

    /// Fait passer un appareil en "appareil de confiance" SANS passer par l'envoi d'email réel.
    async fn trust_device(state: &Arc<AppState>, email: &str, device_id: &str) {
        let code = "111111";
        let expires_at = (Utc::now() + chrono::Duration::minutes(5))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        sqlx::query("INSERT OR REPLACE INTO tfa_codes (email, purpose, code, expires_at) VALUES (?, ?, ?, ?)")
            .bind(email)
            .bind(crate::handlers::auth::PURPOSE_LOGIN_2FA)
            .bind(code)
            .bind(expires_at)
            .execute(&state.db)
            .await
            .expect("insertion du code 2FA de test");

        let payload = VerifyTfaPayload {
            email: email.to_string(),
            code: code.to_string(),
            device_id: device_id.to_string(),
            device_name: Some("Appareil de test".to_string()),
        };
        verify_2fa_and_register_device(State(state.clone()), ConnectInfo("127.0.0.1:1".parse().unwrap()), Json(payload))
            .await
            .expect("la validation du code 2FA doit réussir");
    }

    /// Régression du bug de casse des emails : confirm_password_reset() doit retrouver le code
    /// même si le client envoie l'email dans une casse différente de celle stockée en BDD.
    #[tokio::test]
    async fn test_confirm_password_reset_is_case_insensitive_on_email() {
        let state = build_test_state().await;
        let email_lowercase = "casetest@example.com";
        register_test_user(&state, email_lowercase, "ancien_mot_de_passe").await;

        let code = "222222";
        let expires_at = (Utc::now() + chrono::Duration::minutes(15))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        sqlx::query("INSERT OR REPLACE INTO tfa_codes (email, purpose, code, expires_at) VALUES (?, ?, ?, ?)")
            .bind(email_lowercase) // stocké en minuscules, comme le ferait request_password_reset()
            .bind(PURPOSE_PASSWORD_RESET)
            .bind(code)
            .bind(expires_at)
            .execute(&state.db)
            .await
            .unwrap();

        // Le client envoie l'email avec une casse différente
        let payload = ConfirmResetPayload {
            email: "CaseTest@Example.com".to_string(),
            code: code.to_string(),
            new_master_password_hash: "nouveau_mot_de_passe_123".to_string(),
        };

        let result = confirm_password_reset(State(state.clone()), Json(payload)).await;
        if let Err(e) = &result {
            panic!("le reset doit réussir malgré la casse différente : {e:?}");
        }
    }

    /// update_password() doit refuser un mauvais ancien mot de passe, et en cas de succès,
    /// invalider TOUTES les sessions actives (déconnexion globale de sécurité).
    #[tokio::test]
    async fn test_update_password_validates_old_password_and_invalidates_sessions() {
        let state = build_test_state().await;
        let email = "updatepw@example.com";
        register_test_user(&state, email, "ancien_mot_de_passe_123").await;
        trust_device(&state, email, "device-a").await;

        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let login_payload = AuthPayload {
            email: email.to_string(),
            master_password_hash: "ancien_mot_de_passe_123".to_string(),
            device_id: "device-a".to_string(),
            remember_me: Some(true),
            max_trusted_devices: None,
        };
        login(State(state.clone()), ConnectInfo(addr), HeaderMap::new(), Json(login_payload))
            .await
            .expect("le login doit réussir");

        let user = AuthUser { email: email.to_string(), is_moderator: false };

        // Mauvais ancien hash -> doit échouer (coffre vide ici, reencrypted_entries vide aussi)
        let bad_payload = ChangeMasterPasswordPayload {
            old_master_password_hash: "mauvais_ancien_mdp".to_string(),
            new_master_password_hash: "nouveau_mot_de_passe_456".to_string(),
            reencrypted_entries: vec![],
            reencrypted_history: vec![],
            reencrypted_attachments: vec![],
        };
        let result = update_password(State(state.clone()), AuthUser { email: user.email.clone(), is_moderator: false }, Json(bad_payload)).await;
        assert!(
            matches!(result, Err(AppError::InvalidCredentials)),
            "un mauvais ancien hash d'authentification doit être rejeté"
        );

        // Bon ancien hash, coffre vide -> doit réussir sans aucune entrée à re-chiffrer
        let good_payload = ChangeMasterPasswordPayload {
            old_master_password_hash: "ancien_mot_de_passe_123".to_string(),
            new_master_password_hash: "nouveau_mot_de_passe_456".to_string(),
            reencrypted_entries: vec![],
            reencrypted_history: vec![],
            reencrypted_attachments: vec![],
        };
        update_password(State(state.clone()), AuthUser { email: user.email.clone(), is_moderator: false }, Json(good_payload))
            .await
            .expect("le changement de mot de passe doit réussir avec le bon ancien hash");

        // Toutes les sessions doivent avoir été invalidées
        let session_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE user_email = ?")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(session_count, 0, "toutes les sessions doivent être invalidées après un changement de mot de passe");
    }

    /// RÉGRESSION COMBLÉE : update_password() doit invalider immédiatement les access tokens
    /// déjà émis, pas seulement les refresh tokens — voir middleware.rs::AuthUser et la colonne
    /// `password_changed_at`. Avant ce correctif, un token émis avant le changement restait
    /// valide jusqu'à ~10 minutes de plus malgré le changement de mot de passe.
    #[tokio::test]
    async fn test_update_password_invalidates_existing_access_tokens() {
        use axum::extract::FromRequestParts;

        let state = build_test_state().await;
        let email = "tokeninvalidation@example.com";
        register_test_user(&state, email, "ancien_mot_de_passe_123").await;

        // Access token émis AVANT le changement de mot de passe
        let old_access_token = crypto::create_jwt(email, &state.encoding_key, 600).unwrap();

        let payload = ChangeMasterPasswordPayload {
            old_master_password_hash: "ancien_mot_de_passe_123".to_string(),
            new_master_password_hash: "nouveau_mot_de_passe_456".to_string(),
            reencrypted_entries: vec![],
            reencrypted_history: vec![],
            reencrypted_attachments: vec![],
        };
        update_password(State(state.clone()), AuthUser { email: email.to_string(), is_moderator: false }, Json(payload))
            .await
            .expect("le changement de mot de passe doit réussir");

        let mut parts = axum::http::Request::builder()
            .header("Authorization", format!("Bearer {old_access_token}"))
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let result = AuthUser::from_request_parts(&mut parts, &state).await;
        assert!(result.is_err(), "un access token émis AVANT le changement de mot de passe ne doit plus être accepté après coup");
    }

    /// GARDE-FOU CRITIQUE : si le client "oublie" de re-chiffrer une ou plusieurs entrées du
    /// coffre (reencrypted_entries incomplet par rapport au nombre d'entrées actives réelles),
    /// le changement de mot de passe entier doit être refusé — pour ne jamais laisser une
    /// entrée orpheline chiffrée avec l'ANCIENNE clé, donc perdue.
    #[tokio::test]
    async fn test_update_password_rejects_incomplete_reencryption() {
        let state = build_test_state().await;
        let email = "incompletereenc@example.com";
        register_test_user(&state, email, "mot_de_passe_actuel_123").await;

        // Deux entrées actives dans le coffre
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        for site in ["Site1", "Site2"] {
            let entry = VaultEntryInput {
                encrypted_site_name: site.to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
                entry_type: "login".to_string(), encrypted_extra_fields: None,
                encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
            };
            crate::handlers::vault::add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
                AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
                .await.expect("l'ajout doit réussir");
        }

        // Le client ne renvoie qu'UNE SEULE entrée re-chiffrée sur les deux -> doit être refusé
        let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_all(&state.db).await.unwrap();
        let incomplete_payload = ChangeMasterPasswordPayload {
            old_master_password_hash: "mot_de_passe_actuel_123".to_string(),
            new_master_password_hash: "nouveau_mot_de_passe_789".to_string(),
            reencrypted_entries: vec![crate::models::ReencryptedVaultEntry {
                id: ids[0].clone(),
                encrypted_site_name: "ReChiffre".to_string(),
                encrypted_username: None,
                encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None,
                encrypted_password: "nouveau_chiffre".to_string(),
                encrypted_preferred_login_type: "email".to_string(),
                encrypted_extra_fields: None,
            }],
            reencrypted_history: vec![],
            reencrypted_attachments: vec![],
        };
        let result = update_password(State(state.clone()), AuthUser { email: email.to_string(), is_moderator: false }, Json(incomplete_payload)).await;
        assert!(
            matches!(result, Err(AppError::ValidationError(_))),
            "un re-chiffrement incomplet doit être refusé"
        );

        // Le mot de passe ne doit PAS avoir changé (transaction annulée dans son ensemble)
        let current_user: User = sqlx::query_as("SELECT * FROM users WHERE email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert!(
            crypto::verify_password("mot_de_passe_actuel_123", &current_user.password_hash, &state.config.password_pepper).await,
            "l'ancien mot de passe doit rester valide, rien ne doit avoir changé"
        );
    }

    /// Vérifie que le changement de mot de passe applique effectivement le re-chiffrement reçu :
    /// les champs chiffrés de l'entrée en BDD doivent correspondre à ceux envoyés par le client.
    #[tokio::test]
    async fn test_update_password_applies_reencrypted_entries() {
        let state = build_test_state().await;
        let email = "reencapplied@example.com";
        register_test_user(&state, email, "mot_de_passe_initial_123").await;

        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let entry = VaultEntryInput {
            encrypted_site_name: "AncienChiffre".to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "ancien_chiffre_pw".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        crate::handlers::vault::add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");
        let id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        let payload = ChangeMasterPasswordPayload {
            old_master_password_hash: "mot_de_passe_initial_123".to_string(),
            new_master_password_hash: "mot_de_passe_final_456".to_string(),
            reencrypted_entries: vec![crate::models::ReencryptedVaultEntry {
                id: id.clone(),
                encrypted_site_name: "NouveauChiffre".to_string(),
                encrypted_username: None,
                encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None,
                encrypted_password: "nouveau_chiffre_pw".to_string(),
                encrypted_preferred_login_type: "email".to_string(),
                encrypted_extra_fields: None,
            }],
            reencrypted_history: vec![],
            reencrypted_attachments: vec![],
        };
        update_password(State(state.clone()), AuthUser { email: email.to_string(), is_moderator: false }, Json(payload))
            .await
            .expect("le changement de mot de passe avec re-chiffrement doit réussir");

        let stored_encrypted_password: String = sqlx::query_scalar("SELECT encrypted_password FROM vault WHERE id = ?")
            .bind(&id).fetch_one(&state.db).await.unwrap();
        assert_eq!(stored_encrypted_password, "nouveau_chiffre_pw", "le contenu re-chiffré envoyé par le client doit être appliqué en BDD");
    }

    /// Même garde-fou que pour reencrypted_entries (test_update_password_rejects_incomplete_reencryption),
    /// mais pour l'historique de mots de passe : un changement de mot de passe maître qui
    /// oublierait de re-chiffrer une ligne d'historique doit être intégralement annulé, pas
    /// appliqué partiellement (sinon cette ligne resterait indéchiffrable pour toujours).
    #[tokio::test]
    async fn test_update_password_rejects_incomplete_history_reencryption() {
        let state = build_test_state().await;
        let email = "historyincomplete@example.com";
        register_test_user(&state, email, "ancien_mot_de_passe_123").await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = VaultEntryInput {
            encrypted_site_name: "Site".to_string(), encrypted_username: None, encrypted_login_email: None,
            encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "v0".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        crate::handlers::vault::add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");
        let id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        // Un changement RÉEL de mot de passe crée une ligne d'historique à re-chiffrer plus tard.
        let updated = VaultEntryInput {
            encrypted_site_name: "Site".to_string(), encrypted_username: None, encrypted_login_email: None,
            encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: true, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "v1".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        crate::handlers::vault::update_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(id.clone()), Json(updated))
            .await.expect("la modification doit réussir");

        // reencrypted_entries est complet (1/1), mais reencrypted_history est vide alors qu'une
        // ligne existe (1 attendue, 0 fournie) : doit être refusé.
        let payload = ChangeMasterPasswordPayload {
            old_master_password_hash: "ancien_mot_de_passe_123".to_string(),
            new_master_password_hash: "nouveau_mot_de_passe_456".to_string(),
            reencrypted_entries: vec![crate::models::ReencryptedVaultEntry {
                id: id.clone(),
                encrypted_site_name: "Site".to_string(),
                encrypted_username: None,
                encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None,
                encrypted_password: "v1_rechiffre".to_string(),
                encrypted_preferred_login_type: "email".to_string(),
                encrypted_extra_fields: None,
            }],
            reencrypted_history: vec![],
            reencrypted_attachments: vec![],
        };
        let result = update_password(State(state.clone()), AuthUser { email: email.to_string(), is_moderator: false }, Json(payload)).await;
        assert!(
            matches!(result, Err(AppError::ValidationError(_))),
            "un historique re-chiffré incomplet doit être refusé"
        );

        // Rien ne doit avoir changé (transaction annulée) : l'ancien mot de passe maître reste valide.
        let current_user: User = sqlx::query_as("SELECT * FROM users WHERE email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert!(
            crypto::verify_password("ancien_mot_de_passe_123", &current_user.password_hash, &state.config.password_pepper).await,
            "l'ancien mot de passe doit rester valide, rien ne doit avoir changé"
        );
    }

    /// Vérifie que le changement de mot de passe maître applique effectivement le re-chiffrement
    /// de l'historique reçu — pendant du test analogue pour reencrypted_entries.
    #[tokio::test]
    async fn test_update_password_applies_reencrypted_history() {
        let state = build_test_state().await;
        let email = "historyapplied@example.com";
        register_test_user(&state, email, "mot_de_passe_initial_123").await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = VaultEntryInput {
            encrypted_site_name: "Site".to_string(), encrypted_username: None, encrypted_login_email: None,
            encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "v0".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        crate::handlers::vault::add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");
        let id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        let updated = VaultEntryInput {
            encrypted_site_name: "Site".to_string(), encrypted_username: None, encrypted_login_email: None,
            encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: true, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "v1".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        crate::handlers::vault::update_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(id.clone()), Json(updated))
            .await.expect("la modification doit réussir");

        let history_id: String = sqlx::query_scalar("SELECT id FROM vault_password_history WHERE vault_id = ?")
            .bind(&id).fetch_one(&state.db).await.unwrap();

        let payload = ChangeMasterPasswordPayload {
            old_master_password_hash: "mot_de_passe_initial_123".to_string(),
            new_master_password_hash: "mot_de_passe_final_456".to_string(),
            reencrypted_entries: vec![crate::models::ReencryptedVaultEntry {
                id: id.clone(),
                encrypted_site_name: "Site".to_string(),
                encrypted_username: None,
                encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None,
                encrypted_password: "v1_rechiffre".to_string(),
                encrypted_preferred_login_type: "email".to_string(),
                encrypted_extra_fields: None,
            }],
            reencrypted_history: vec![crate::models::ReencryptedHistoryEntry {
                id: history_id.clone(),
                encrypted_password: "v0_rechiffre".to_string(),
            }],
            reencrypted_attachments: vec![],
        };
        update_password(State(state.clone()), AuthUser { email: email.to_string(), is_moderator: false }, Json(payload))
            .await
            .expect("le changement de mot de passe avec historique complet doit réussir");

        let stored: String = sqlx::query_scalar("SELECT encrypted_password FROM vault_password_history WHERE id = ?")
            .bind(&history_id).fetch_one(&state.db).await.unwrap();
        assert_eq!(stored, "v0_rechiffre", "la ligne d'historique doit contenir le contenu re-chiffré envoyé par le client");
    }

    /// CORRECTIF : vérifie que le changement de mot de passe applique effectivement le
    /// re-chiffrement d'une pièce jointe reçue — pendant de test_update_password_applies_reencrypted_entries,
    /// pour vault_attachments. Avant ce correctif, les pièces jointes n'étaient jamais incluses
    /// dans ce flux et restaient chiffrées avec l'ANCIENNE clé après un changement de mot de passe.
    #[tokio::test]
    async fn test_update_password_applies_reencrypted_attachments() {
        let state = build_test_state().await;
        let email = "attachreencapplied@example.com";
        register_test_user(&state, email, "mot_de_passe_initial_123").await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = VaultEntryInput {
            encrypted_site_name: "Site".to_string(), encrypted_username: None, encrypted_login_email: None,
            encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        crate::handlers::vault::add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");
        let vault_id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        crate::handlers::vault::add_vault_attachment(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Path(vault_id.clone()),
            Json(VaultAttachmentInput {
                encrypted_filename: "ancien_nom_chiffre".to_string(),
                encrypted_content: "ancien_contenu_chiffre".to_string(),
                content_size: 42,
            }),
        ).await.expect("l'ajout de la pièce jointe doit réussir");
        let attachment_id: String = sqlx::query_scalar("SELECT id FROM vault_attachments WHERE vault_id = ?")
            .bind(&vault_id).fetch_one(&state.db).await.unwrap();

        let payload = ChangeMasterPasswordPayload {
            old_master_password_hash: "mot_de_passe_initial_123".to_string(),
            new_master_password_hash: "mot_de_passe_final_456".to_string(),
            reencrypted_entries: vec![crate::models::ReencryptedVaultEntry {
                id: vault_id.clone(),
                encrypted_site_name: "Site".to_string(),
                encrypted_username: None,
                encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None,
                encrypted_password: "chiffre_v2".to_string(),
                encrypted_preferred_login_type: "email".to_string(),
                encrypted_extra_fields: None,
            }],
            reencrypted_history: vec![],
            reencrypted_attachments: vec![crate::models::ReencryptedVaultAttachment {
                id: attachment_id.clone(),
                encrypted_filename: "nouveau_nom_chiffre".to_string(),
                encrypted_content: "nouveau_contenu_chiffre".to_string(),
            }],
        };
        update_password(State(state.clone()), AuthUser { email: email.to_string(), is_moderator: false }, Json(payload))
            .await
            .expect("le changement de mot de passe avec pièce jointe re-chiffrée doit réussir");

        let (stored_filename, stored_content): (String, String) = sqlx::query_as(
            "SELECT encrypted_filename, encrypted_content FROM vault_attachments WHERE id = ?",
        ).bind(&attachment_id).fetch_one(&state.db).await.unwrap();
        assert_eq!(stored_filename, "nouveau_nom_chiffre", "le nom de fichier re-chiffré envoyé par le client doit être appliqué en BDD");
        assert_eq!(stored_content, "nouveau_contenu_chiffre", "le contenu re-chiffré envoyé par le client doit être appliqué en BDD");
    }

    /// CORRECTIF : même garde-fou que pour reencrypted_entries/reencrypted_history, mais pour les
    /// pièces jointes — un changement de mot de passe maître qui oublierait de re-chiffrer une
    /// pièce jointe existante doit être intégralement refusé, jamais appliqué partiellement
    /// (sinon cette pièce jointe resterait indéchiffrable pour toujours, silencieusement).
    #[tokio::test]
    async fn test_update_password_rejects_incomplete_attachment_reencryption() {
        let state = build_test_state().await;
        let email = "attachincomplete@example.com";
        register_test_user(&state, email, "mot_de_passe_actuel_123").await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = VaultEntryInput {
            encrypted_site_name: "Site".to_string(), encrypted_username: None, encrypted_login_email: None,
            encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        crate::handlers::vault::add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");
        let vault_id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        crate::handlers::vault::add_vault_attachment(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Path(vault_id.clone()),
            Json(VaultAttachmentInput {
                encrypted_filename: "nom_chiffre".to_string(),
                encrypted_content: "contenu_chiffre".to_string(),
                content_size: 42,
            }),
        ).await.expect("l'ajout de la pièce jointe doit réussir");

        // reencrypted_entries est complet (1/1), mais reencrypted_attachments est vide alors
        // qu'une pièce jointe existe (1 attendue, 0 fournie) : doit être refusé.
        let payload = ChangeMasterPasswordPayload {
            old_master_password_hash: "mot_de_passe_actuel_123".to_string(),
            new_master_password_hash: "nouveau_mot_de_passe_789".to_string(),
            reencrypted_entries: vec![crate::models::ReencryptedVaultEntry {
                id: vault_id.clone(),
                encrypted_site_name: "Site".to_string(),
                encrypted_username: None,
                encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None,
                encrypted_password: "chiffre_v2".to_string(),
                encrypted_preferred_login_type: "email".to_string(),
                encrypted_extra_fields: None,
            }],
            reencrypted_history: vec![],
            reencrypted_attachments: vec![],
        };
        let result = update_password(State(state.clone()), AuthUser { email: email.to_string(), is_moderator: false }, Json(payload)).await;
        assert!(
            matches!(result, Err(AppError::ValidationError(_))),
            "un re-chiffrement de pièce jointe incomplet doit être refusé"
        );

        // Rien ne doit avoir changé (transaction annulée) : l'ancien mot de passe maître reste valide.
        let current_user: User = sqlx::query_as("SELECT * FROM users WHERE email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert!(
            crypto::verify_password("mot_de_passe_actuel_123", &current_user.password_hash, &state.config.password_pepper).await,
            "l'ancien mot de passe doit rester valide, rien ne doit avoir changé"
        );
    }

    /// update_email() doit changer l'email, et grâce à ON UPDATE CASCADE, les tables liées
    /// (refresh_tokens, vault, etc.) doivent suivre automatiquement le nouvel email.
    #[tokio::test]
    async fn test_update_email_changes_email_and_cascades() {
        let state = build_test_state().await;
        let old_email = "oldemail@example.com";
        let new_email = "newemail@example.com";
        register_test_user(&state, old_email, "mot_de_passe_test_123").await;

        // Une entrée de coffre AVANT le changement d'email : sert à vérifier que ON UPDATE
        // CASCADE propage réellement le changement à `vault`, pas seulement à `users` (sqlx
        // active `foreign_keys` par défaut sur chaque connexion, voir main.rs, mais on le
        // vérifie ici avec un vrai test bout en bout plutôt que de se fier uniquement au
        // comportement par défaut d'une lib tierce).
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let entry = VaultEntryInput {
            encrypted_site_name: "AvantRenommage".to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        crate::handlers::vault::add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: old_email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");

        let user = AuthUser { email: old_email.to_string(), is_moderator: false };
        let payload = UpdateEmailPayload {
            new_email: new_email.to_string(),
            master_password_hash: "mot_de_passe_test_123".to_string(),
        };
        update_email(State(state.clone()), HeaderMap::new(), user, Json(payload))
            .await
            .expect("le changement d'email doit réussir");

        let old_exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = ?")
            .bind(old_email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(old_exists, 0, "l'ancien email ne doit plus exister");

        let new_exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = ?")
            .bind(new_email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(new_exists, 1, "le nouvel email doit exister");

        // L'entrée de coffre doit être accessible sous le NOUVEL email (cascade réelle), et plus
        // du tout sous l'ancien — sinon l'utilisateur "perdrait" silencieusement son coffre.
        let entries_new_email = VaultRepository::get_all(&state.db, new_email, 50, 0).await.unwrap();
        assert_eq!(entries_new_email.len(), 1, "le coffre doit rester accessible sous le nouvel email grâce à ON UPDATE CASCADE");
        let entries_old_email = VaultRepository::get_all(&state.db, old_email, 50, 0).await.unwrap();
        assert!(entries_old_email.is_empty(), "plus aucune entrée ne doit rester associée à l'ancien email");
    }

    /// update_email() doit refuser un appel venant de l'extension (Origin chrome-extension://…)
    /// tant que `can_change_email_via_extension` vaut false pour ce compte, mais réussir sans
    /// condition pour l'app desktop (aucun en-tête Origin de ce type) même avec le flag à false —
    /// c'est LA garde-fou introduit en Phase 5, le plus important à couvrir par un test automatisé.
    #[tokio::test]
    async fn test_update_email_blocked_from_extension_unless_enabled() {
        let state = build_test_state().await;
        let email = "extension-user@example.com";
        register_test_user(&state, email, "mot_de_passe_test_123").await;

        let mut extension_headers = HeaderMap::new();
        extension_headers.insert("origin", "chrome-extension://hcggmibfhgjcamfehjjdmagbecbkljdj".parse().unwrap());

        let payload = || UpdateEmailPayload {
            new_email: "nouveau@example.com".to_string(),
            master_password_hash: "mot_de_passe_test_123".to_string(),
        };

        // 1. Depuis l'extension, flag désactivé (valeur par défaut) : refusé.
        let denied = update_email(
            State(state.clone()), extension_headers.clone(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(payload()),
        ).await;
        assert!(matches!(denied, Err(AppError::Forbidden)), "doit être refusé depuis l'extension tant que le flag est désactivé");

        // 2. Depuis le desktop (pas d'Origin d'extension) : autorisé malgré le flag désactivé.
        let user = AuthUser { email: email.to_string(), is_moderator: false };
        update_email(State(state.clone()), HeaderMap::new(), user, Json(payload()))
            .await
            .expect("le desktop ne doit jamais être concerné par cette restriction");

        // 3. Depuis l'extension, mais un admin : toujours autorisé, flag ou pas.
        let admin_email = "admin-ext@example.com";
        register_test_user(&state, admin_email, "mot_de_passe_test_123").await;
        sqlx::query("UPDATE users SET is_moderator = 1 WHERE email = ?").bind(admin_email).execute(&state.db).await.unwrap();
        let admin = AuthUser { email: admin_email.to_string(), is_moderator: true };
        update_email(
            State(state.clone()), extension_headers.clone(), admin,
            Json(UpdateEmailPayload { new_email: "admin-nouveau@example.com".to_string(), master_password_hash: "mot_de_passe_test_123".to_string() }),
        ).await.expect("un admin doit toujours pouvoir changer son email, même depuis l'extension");

        // 4. Depuis l'extension, flag explicitement activé pour ce compte : autorisé.
        let flagged_email = "flagged-user@example.com";
        register_test_user(&state, flagged_email, "mot_de_passe_test_123").await;
        sqlx::query("UPDATE users SET can_change_email_via_extension = 1 WHERE email = ?").bind(flagged_email).execute(&state.db).await.unwrap();
        let flagged_user = AuthUser { email: flagged_email.to_string(), is_moderator: false };
        update_email(
            State(state.clone()), extension_headers, flagged_user,
            Json(UpdateEmailPayload { new_email: "flagged-nouveau@example.com".to_string(), master_password_hash: "mot_de_passe_test_123".to_string() }),
        ).await.expect("un compte avec le flag activé doit pouvoir changer son email depuis l'extension");
    }

    /// request_password_reset() ne doit JAMAIS générer de code pour un email qui n'existe pas
    /// (sinon la simple présence/absence d'un code en BDD trahirait l'existence du compte).
    #[tokio::test]
    async fn test_request_password_reset_does_not_leak_account_existence() {
        let state = build_test_state().await;
        let known_email = "knownuser@example.com";
        let unknown_email = "unknown-account@example.com";
        register_test_user(&state, known_email, "mot_de_passe_test_123").await;

        // Email connu : un code doit être généré
        request_password_reset(State(state.clone()), Json(ForgotPasswordPayload { email: known_email.to_string() }))
            .await
            .expect("la demande doit réussir pour un email connu");
        let known_code_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tfa_codes WHERE email = ?")
            .bind(known_email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(known_code_count, 1, "un code doit être généré pour un email connu");

        // Email inconnu : la requête doit quand même "réussir" (202), mais SANS générer de code
        let result = request_password_reset(State(state.clone()), Json(ForgotPasswordPayload { email: unknown_email.to_string() })).await;
        assert!(result.is_ok(), "la requête doit répondre succès même pour un email inconnu (anti-énumération)");

        let unknown_code_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tfa_codes WHERE email = ?")
            .bind(unknown_email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(unknown_code_count, 0, "aucun code ne doit être généré pour un email inconnu");
    }

    /// get_me() doit renvoyer l'email ET le statut admin de l'utilisateur connecté — voir le
    /// commentaire sur get_me() : c'est la seule source fiable pour qu'un client sache s'il doit
    /// afficher une interface d'administration.
    #[tokio::test]
    async fn test_get_me_returns_email_admin_status_and_device_limit() {
        let state = build_test_state().await;
        sqlx::query("INSERT INTO users (email, password_hash, is_moderator, max_trusted_devices) VALUES (?, ?, ?, ?)")
            .bind("user@example.com").bind("hash_non_pertinent").bind(false).bind(15)
            .execute(&state.db).await.unwrap();
        sqlx::query("INSERT INTO users (email, password_hash, is_moderator) VALUES (?, ?, ?)")
            .bind("admin@example.com").bind("hash_non_pertinent").bind(true)
            .execute(&state.db).await.unwrap();

        let non_admin = get_me(State(state.clone()), AuthUser { email: "user@example.com".to_string(), is_moderator: false })
            .await.expect("get_me doit réussir").into_response();
        let bytes = axum::body::to_bytes(non_admin.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["email"], "user@example.com");
        assert_eq!(json["is_moderator"], false);
        assert_eq!(json["max_trusted_devices"], 15, "le plafond actuel doit refléter la valeur réellement stockée en BDD");
        assert_eq!(json["is_admin"], false, "sans ADMIN_EMAIL configuré, personne n'est le premier admin");

        let admin = get_me(State(state.clone()), AuthUser { email: "admin@example.com".to_string(), is_moderator: true })
            .await.expect("get_me doit réussir").into_response();
        let bytes = axum::body::to_bytes(admin.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["email"], "admin@example.com");
        assert_eq!(json["is_moderator"], true);
        assert_eq!(json["max_trusted_devices"], 10, "le plafond par défaut (schéma) doit être 10 si jamais modifié");
        assert_eq!(json["is_admin"], false, "un admin ordinaire (pas ADMIN_EMAIL) n'est pas le premier admin");
    }

    /// get_me() doit exposer is_admin=true UNIQUEMENT pour le compte qui correspond à
    /// ADMIN_EMAIL — c'est ce champ que l'écran Administration utilise pour savoir s'il doit
    /// afficher les boutons promouvoir/rétrograder (voir handlers/admin.rs::update_user_role()).
    #[tokio::test]
    async fn test_get_me_exposes_is_admin_only_for_the_configured_account() {
        let base_state = build_test_state().await;
        let state = Arc::new(AppState {
            encoding_key: base_state.encoding_key.clone(),
            decoding_key: base_state.decoding_key.clone(),
            app_env: base_state.app_env.clone(),
            db: base_state.db.clone(),
            config: crate::config::Config { admin_email: Some("owner@example.com".to_string()), ..base_state.config.clone() },
            sync_tx: base_state.sync_tx.clone(),
            shutdown_tx: base_state.shutdown_tx.clone(),
            ws_connections: base_state.ws_connections.clone(),
        });

        sqlx::query("INSERT INTO users (email, password_hash, is_moderator) VALUES (?, ?, ?)")
            .bind("owner@example.com").bind("hash_non_pertinent").bind(true)
            .execute(&state.db).await.unwrap();
        sqlx::query("INSERT INTO users (email, password_hash, is_moderator) VALUES (?, ?, ?)")
            .bind("other-admin@example.com").bind("hash_non_pertinent").bind(true)
            .execute(&state.db).await.unwrap();

        let owner = get_me(State(state.clone()), AuthUser { email: "owner@example.com".to_string(), is_moderator: true })
            .await.expect("get_me doit réussir").into_response();
        let bytes = axum::body::to_bytes(owner.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["is_admin"], true, "le compte ADMIN_EMAIL doit être identifié comme le premier admin");

        let other = get_me(State(state.clone()), AuthUser { email: "other-admin@example.com".to_string(), is_moderator: true })
            .await.expect("get_me doit réussir").into_response();
        let bytes = axum::body::to_bytes(other.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["is_admin"], false, "un autre admin, même avec is_moderator=true, n'est pas le premier admin");
    }

    /// get_my_audit_logs() ne doit renvoyer QUE les entrées d'audit de l'utilisateur connecté,
    /// jamais celles d'un autre compte — contrairement à get_audit_logs() (admin, tous comptes
    /// confondus). Vérifie aussi l'ordre (plus récent en premier, via ORDER BY created_at DESC).
    #[tokio::test]
    async fn test_get_my_audit_logs_only_returns_own_entries() {
        let state = build_test_state().await;
        register_test_user(&state, "user@example.com", "mot_de_passe_test_123").await;
        register_test_user(&state, "other@example.com", "mot_de_passe_test_123").await;

        state.log_audit("user@example.com", "VAULT_ADD", "127.0.0.1".to_string(), None).await;
        state.log_audit("user@example.com", "VAULT_UPDATE", "127.0.0.1".to_string(), None).await;
        state.log_audit("other@example.com", "VAULT_ADD", "10.0.0.1".to_string(), None).await;

        let response = get_my_audit_logs(State(state.clone()), AuthUser { email: "user@example.com".to_string(), is_moderator: false })
            .await.expect("get_my_audit_logs doit réussir").into_response();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let logs: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let logs = logs.as_array().expect("la réponse doit être un tableau");

        assert_eq!(logs.len(), 2, "seules les entrées de user@example.com doivent apparaître, jamais celles de other@example.com");
        assert!(logs.iter().all(|l| l["user_email"] == "user@example.com"));
        assert_eq!(logs[0]["action"], "VAULT_UPDATE", "la plus récente doit être en premier");
        assert_eq!(logs[1]["action"], "VAULT_ADD");
    }
}
