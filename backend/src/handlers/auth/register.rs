// =========================================================================
// INSCRIPTION & VÉRIFICATION D'EMAIL
// =========================================================================
// Tout ce qui concerne la CRÉATION d'un compte : inscription, confirmation du code envoyé par
// email, et renvoi de ce code s'il a expiré ou n'est jamais arrivé. Séparé de session.rs (login,
// 2FA, refresh, logout) et account.rs (mot de passe, email, profil) — trois responsabilités
// distinctes qui n'avaient plus grand-chose en commun une fois regroupées dans un seul auth.rs.

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json
};
use std::sync::Arc;
use crate::{AppState, crypto, mailer, error::AppError, models::*};
use validator::Validate;
use chrono::Utc;
use tracing::{instrument, warn, info, error};
use rand::RngExt;
use super::{MAX_CODE_ATTEMPTS, PURPOSE_EMAIL_VERIFICATION, VERIFICATION_CODE_LIFETIME_MINUTES, is_code_within_cooldown};
#[cfg(test)]
use super::PURPOSE_PASSWORD_RESET;

// --- ROUTE : INSCRIPTION (REGISTER) ---

/// Enregistre un nouvel utilisateur dans l'application.
/// #[instrument] génère automatiquement des logs Tracing en y incluant l'email.
#[instrument(skip(state, payload), fields(email = %payload.email))]
pub async fn register(
    State(state): State<Arc<AppState>>, // Accès à l'état global (DB, config...)
    Json(payload): Json<AuthPayload>     // Récupère le corps de la requête au format JSON
) -> Result<impl IntoResponse, AppError> {

    // 1. Valide les contraintes du payload (ex: email valide, taille mdp) via le crate 'validator'
    payload.validate()?;

    // 1bis. INSCRIPTIONS FERMÉES (voir handlers/admin.rs::update_registration_open) — vérifié
    // AVANT le hachage Argon2id ci-dessous, qui coûte volontairement ~46 Mo et plusieurs dizaines
    // de ms : sur une route publique, faire ce calcul pour le rejeter ensuite offrirait un vecteur
    // d'amplification à qui insisterait sur un serveur fermé.
    //
    // L'Admin (ADMIN_EMAIL) reste TOUJOURS autorisé à s'inscrire : sur un serveur neuf dont les
    // inscriptions seraient fermées, s'en exclure soi-même laisserait le déploiement sans aucun
    // compte administrateur possible, sans autre issue qu'une modification manuelle de la base.
    let email_for_gate = payload.email.to_lowercase();
    let is_configured_admin = state.config.admin_email.as_deref() == Some(email_for_gate.as_str());
    if !is_configured_admin {
        let registration_open: bool = sqlx::query_scalar("SELECT registration_open FROM app_settings WHERE id = 1")
            .fetch_one(&state.db)
            .await?;
        if !registration_open {
            warn!("Inscription refusée (inscriptions fermées) pour {}", email_for_gate);
            return Err(AppError::ValidationError(
                "Les inscriptions sont fermées sur ce serveur.".to_string(),
            ));
        }
    }

    // 2. Hache le mot de passe maître avec un "pepper" (grain de sel global) pour sécuriser le stockage
    let hash = crypto::hash_password(&payload.master_password_hash, &state.config.password_pepper)
        .await
        .map_err(|_| AppError::HashError)?;
    let email = payload.email.to_lowercase();

    // 2bis. Bootstrap admin (voir Config::admin_email / ADMIN_EMAIL) : si cet email correspond à
    // celui configuré au démarrage, le compte est créé directement administrateur — remplace le
    // besoin de modifier la BDD à la main. Comparaison sur des emails déjà normalisés en
    // minuscules des deux côtés (voir Config::from_env()).
    let is_bootstrap_admin = state.config.admin_email.as_deref() == Some(email.as_str());

    // 2ter. Plafond d'appareils de confiance choisi par l'utilisateur à l'inscription (borné à
    // 1-50 par la validation du payload ci-dessus), sinon la valeur par défaut du schéma (10).
    let max_trusted_devices = payload.max_trusted_devices.unwrap_or(10) as i64;

    // 3. Insère le nouvel utilisateur en base de données. `email_verified` vaut FAUX par défaut
    // (voir la migration) : le compte n'est pas encore utilisable pour login() tant que le code
    // ci-dessous n'a pas été confirmé via /auth/verify-email. Sans ça, n'importe qui pourrait
    // s'inscrire avec l'email de quelqu'un d'autre et bloquer sa vraie inscription (Conflict).
    sqlx::query("INSERT INTO users (email, password_hash, is_moderator, max_trusted_devices) VALUES (?, ?, ?, ?)")
        .bind(&email)
        .bind(hash)
        .bind(is_bootstrap_admin)
        .bind(max_trusted_devices)
        .execute(&state.db)
        .await?;

    if is_bootstrap_admin {
        info!("Compte admin créé via ADMIN_EMAIL à l'inscription : {}", email);
    }

    // 4. Génération et envoi du code de confirmation d'email (même mécanisme que le 2FA/reset,
    // réutilise la table `tfa_codes` et son verrouillage anti-bruteforce).
    let verification_code = format!("{:06}", rand::rng().random_range(0..1000000));
    let expires_at = (Utc::now() + chrono::Duration::minutes(30)).format("%Y-%m-%dT%H:%M:%SZ").to_string();
    sqlx::query("INSERT OR REPLACE INTO tfa_codes (email, purpose, code, expires_at) VALUES (?, ?, ?, ?)")
        .bind(&email)
        .bind(PURPOSE_EMAIL_VERIFICATION)
        .bind(&verification_code)
        .bind(expires_at)
        .execute(&state.db)
        .await?;

    // Best-effort comme les autres emails de notification (mailer::send_security_alert) : un
    // échec SMTP ne doit pas faire échouer l'inscription elle-même (le compte existe déjà en BDD
    // à ce stade, le faire échouer forcerait un retry qui buterait sur un conflit d'email déjà pris).
    if let Err(e) = mailer::send_verification_email(&email, &verification_code, &state.config).await {
        error!("Échec envoi email de vérification pour {} : {:?}", email, e);
    }

    // 5. Log de confirmation et retour d'un statut HTTP 201 Created
    info!("Nouvel utilisateur enregistré (email non vérifié) : {}", email);
    Ok((StatusCode::CREATED, "OK"))
}

// --- ROUTE : CONFIRMATION D'EMAIL (VERIFY EMAIL) ---

/// Confirme le code envoyé à l'inscription et marque le compte comme vérifié.
/// Tant que ce n'est pas fait, login() (voir session.rs) refuse la connexion.
pub async fn verify_email(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<VerifyEmailPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    let email = payload.email.to_lowercase();

    let tfa: TfaCode = sqlx::query_as("SELECT * FROM tfa_codes WHERE email = ? AND purpose = ?")
        .bind(&email)
        .bind(PURPOSE_EMAIL_VERIFICATION)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::ValidationError("Aucun code de vérification en attente pour cet email".to_string()))?;

    // Même verrouillage anti-bruteforce que le 2FA/reset (voir MAX_CODE_ATTEMPTS). Filtré par
    // `purpose` : ne touche jamais un code 2FA/reset éventuellement en cours pour le même email.
    if tfa.attempts >= MAX_CODE_ATTEMPTS {
        sqlx::query("DELETE FROM tfa_codes WHERE email = ? AND purpose = ?")
            .bind(&email)
            .bind(PURPOSE_EMAIL_VERIFICATION)
            .execute(&state.db)
            .await?;
        warn!("Code de vérification d'email verrouillé après trop de tentatives pour {}", email);
        return Err(AppError::ValidationError("Trop de tentatives, veuillez vous réinscrire pour recevoir un nouveau code".to_string()));
    }

    if !crypto::constant_time_eq(&payload.code, &tfa.code) {
        sqlx::query("UPDATE tfa_codes SET attempts = attempts + 1 WHERE email = ? AND purpose = ?")
            .bind(&email)
            .bind(PURPOSE_EMAIL_VERIFICATION)
            .execute(&state.db)
            .await?;
        return Err(AppError::ValidationError("Code de vérification incorrect".to_string()));
    }

    let expires_at = chrono::NaiveDateTime::parse_from_str(&tfa.expires_at, "%Y-%m-%dT%H:%M:%SZ")
        .map_err(|_| AppError::Internal("Erreur format date".to_string()))?;
    if Utc::now().naive_utc() > expires_at {
        return Err(AppError::ValidationError("Le code a expiré".to_string()));
    }

    let mut tx = state.db.begin().await?;

    sqlx::query("UPDATE users SET email_verified = 1 WHERE email = ?")
        .bind(&email)
        .execute(&mut *tx)
        .await?;

    // Consommation du code : il ne doit plus pouvoir servir une seconde fois.
    sqlx::query("DELETE FROM tfa_codes WHERE email = ? AND purpose = ?")
        .bind(&email)
        .bind(PURPOSE_EMAIL_VERIFICATION)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    info!("Email vérifié avec succès pour {}", email);
    Ok(StatusCode::OK)
}

/// Renvoie un nouveau code de confirmation d'email pour un compte pas encore vérifié.
/// NÉCESSAIRE car register() ne peut être appelé qu'une seule fois par email (une deuxième
/// tentative échoue en Conflict) : sans ce endpoint, un code expiré (30 min) ou un échec
/// d'envoi SMTP à l'inscription laisserait le compte définitivement bloqué jusqu'à sa purge
/// automatique 24h plus tard (maintenance.rs::cleanup_stale_unverified_accounts) — obligeant
/// l'utilisateur à tout recommencer depuis zéro (et à re-choisir un hash d'authentification,
/// puisque le client aurait besoin d'un nouveau mot de passe maître Zero-Knowledge).
/// Réutilise `ForgotPasswordPayload` (même forme : un simple email) plutôt qu'un doublon.
pub async fn resend_verification_email(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ForgotPasswordPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    let email = payload.email.to_lowercase();

    // Même stratégie anti-énumération que request_password_reset() (voir account.rs) : la
    // réponse est identique (202) que le compte soit inconnu, déjà vérifié, ou qu'un renvoi ait
    // réellement eu lieu — sinon la différence de comportement trahirait l'existence/l'état d'un compte.
    let email_verified: Option<bool> = sqlx::query_scalar("SELECT email_verified FROM users WHERE email = ?")
        .bind(&email)
        .fetch_optional(&state.db)
        .await?;

    // ANTI-EMAIL-BOMBING : voir is_code_within_cooldown() (handlers/auth.rs) — cette route expédie
    // un email vers une adresse choisie par l'appelant, et n'était protégée que PAR IP. Silencieux
    // (la réponse reste un 202 identique) pour ne pas trahir l'existence/l'état du compte, exactement
    // comme le reste de cette fonction s'y applique.
    let recently_sent = is_code_within_cooldown(&state, &email, PURPOSE_EMAIL_VERIFICATION, VERIFICATION_CODE_LIFETIME_MINUTES).await?;

    if let (Some(false), false) = (email_verified, recently_sent) {
        let code = format!("{:06}", rand::rng().random_range(0..1000000));
        let expires_at = (Utc::now() + chrono::Duration::minutes(VERIFICATION_CODE_LIFETIME_MINUTES)).format("%Y-%m-%dT%H:%M:%SZ").to_string();

        // INSERT OR REPLACE : remplace aussi le compteur `attempts` par sa valeur par défaut (0),
        // donc un renvoi donne bien un nouveau capital de MAX_CODE_ATTEMPTS tentatives. Filtré
        // par `purpose` : ne touche jamais un code 2FA/reset éventuellement en cours en parallèle.
        sqlx::query("INSERT OR REPLACE INTO tfa_codes (email, purpose, code, expires_at) VALUES (?, ?, ?, ?)")
            .bind(&email)
            .bind(PURPOSE_EMAIL_VERIFICATION)
            .bind(&code)
            .bind(expires_at)
            .execute(&state.db)
            .await?;

        if let Err(e) = mailer::send_verification_email(&email, &code, &state.config).await {
            warn!("Échec envoi email de vérification (renvoi) pour {} : {:?}", email, e);
        }
    }

    Ok(StatusCode::ACCEPTED)
}

// =========================================================================
// TESTS
// =========================================================================
// On appelle les handlers directement comme des fonctions Rust normales, sans passer par une
// vraie requête HTTP (voir le commentaire détaillé équivalent dans session.rs).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::handlers::auth::session::login;
    use sqlx::sqlite::SqlitePoolOptions;

    /// Construit un AppState de test : BDD SQLite en mémoire + migrations réelles + config factice.
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
        })
    }

    /// Variante de build_test_state() avec un ADMIN_EMAIL configuré, pour tester le bootstrap
    /// admin automatique à l'inscription (voir register()).
    async fn build_test_state_with_admin_email(admin_email: &str) -> Arc<AppState> {
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
            admin_email: Some(admin_email.to_lowercase()),
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
        })
    }

    /// Crée un utilisateur de test via le VRAI handler register() (donc avec le hachage réel),
    /// puis marque directement le compte comme vérifié en BDD : impossible d'envoyer un vrai
    /// email en test, donc on court-circuite le clic sur le lien de confirmation (même principe
    /// que trust_device() dans session.rs, qui court-circuite l'envoi réel du code 2FA).
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

        // verify_email() supprimerait normalement ce code en le consommant (voir plus haut) :
        // on reproduit le même effet de bord ici pour que l'état de test reflète fidèlement un
        // vrai compte vérifié (aucun code de vérification résiduel en BDD).
        sqlx::query("DELETE FROM tfa_codes WHERE email = ?")
            .bind(email.to_lowercase())
            .execute(&state.db)
            .await
            .expect("le nettoyage du code de vérification de test doit réussir");
    }

    /// Fait passer un appareil en "appareil de confiance" SANS passer par l'envoi d'email réel
    /// (impossible en test) : on insère directement le code 2FA en BDD, comme le ferait login(),
    /// puis on appelle le VRAI handler verify_2fa_and_register_device() pour le valider.
    /// Dupliqué dans session.rs/account.rs volontairement : chaque module de tests reste
    /// autonome, sans dépendance croisée entre modules de handlers juste pour les tests.
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
        crate::handlers::auth::session::verify_2fa_and_register_device(
            State(state.clone()),
            axum::extract::ConnectInfo("127.0.0.1:1".parse().unwrap()),
            Json(payload),
        )
            .await
            .expect("la validation du code 2FA doit réussir");
    }

    /// register() doit refuser un email déjà utilisé (conflit d'unicité en BDD).
    #[tokio::test]
    async fn test_register_duplicate_email_conflicts() {
        let state = build_test_state().await;
        let email = "duplicate@example.com";
        register_test_user(&state, email, "mot_de_passe_test_123").await;

        // Deuxième inscription avec le même email -> doit échouer
        let payload = AuthPayload {
            email: email.to_string(),
            master_password_hash: "un_autre_mot_de_passe".to_string(),
            device_id: "unused".to_string(),
            remember_me: None,
            max_trusted_devices: None,
        };
        let result = register(State(state.clone()), Json(payload)).await;
        assert!(result.is_err(), "une deuxième inscription avec le même email doit échouer");

        // Un seul utilisateur doit exister en BDD malgré la tentative
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = ?")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(count, 1, "l'email ne doit être enregistré qu'une seule fois");
    }

    /// Le cycle complet : inscription -> confirmation du bon code via verify_email() -> login()
    /// qui réussit enfin (sur un appareil de confiance, pour isoler du flux 2FA séparé).
    #[tokio::test]
    async fn test_verify_email_then_login_succeeds() {
        let state = build_test_state().await;
        let email = "toverify@example.com";
        let password = "mot_de_passe_test_123";

        let payload = AuthPayload {
            email: email.to_string(),
            master_password_hash: password.to_string(),
            device_id: "device-verify".to_string(),
            remember_me: None,
            max_trusted_devices: None,
        };
        register(State(state.clone()), Json(payload))
            .await
            .expect("l'inscription doit réussir");

        let code: String = sqlx::query_scalar("SELECT code FROM tfa_codes WHERE email = ? AND purpose = ?")
            .bind(email)
            .bind(PURPOSE_EMAIL_VERIFICATION)
            .fetch_one(&state.db)
            .await
            .expect("un code de vérification doit avoir été généré à l'inscription");

        verify_email(State(state.clone()), Json(VerifyEmailPayload { email: email.to_string(), code }))
            .await
            .expect("la vérification avec le bon code doit réussir");

        let verified: bool = sqlx::query_scalar("SELECT email_verified FROM users WHERE email = ?")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert!(verified, "le compte doit être marqué vérifié après verify_email()");

        trust_device(&state, email, "device-verify").await;
        let addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let login_payload = AuthPayload {
            email: email.to_string(),
            master_password_hash: password.to_string(),
            device_id: "device-verify".to_string(),
            remember_me: None,
            max_trusted_devices: None,
        };
        login(State(state.clone()), axum::extract::ConnectInfo(addr), axum::http::HeaderMap::new(), Json(login_payload))
            .await
            .expect("login() doit maintenant réussir, le compte étant vérifié et l'appareil de confiance");
    }

    /// verify_email() doit rejeter un mauvais code sans marquer le compte comme vérifié.
    #[tokio::test]
    async fn test_verify_email_rejects_wrong_code() {
        let state = build_test_state().await;
        let email = "wrongcode@example.com";
        let payload = AuthPayload {
            email: email.to_string(),
            master_password_hash: "mot_de_passe_test_123".to_string(),
            device_id: "device-x".to_string(),
            remember_me: None,
            max_trusted_devices: None,
        };
        register(State(state.clone()), Json(payload))
            .await
            .expect("l'inscription doit réussir");

        let result = verify_email(State(state.clone()), Json(VerifyEmailPayload {
            email: email.to_string(),
            code: "000000".to_string(), // presque certainement pas le bon code généré
        })).await;
        // Le seul cas où ce test flakerait est un tirage aléatoire de "000000" à l'inscription
        // (1 chance sur 1 000 000) — négligeable.
        assert!(matches!(result, Err(AppError::ValidationError(_))), "un mauvais code doit être rejeté");

        let verified: bool = sqlx::query_scalar("SELECT email_verified FROM users WHERE email = ?")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert!(!verified, "un mauvais code ne doit jamais vérifier le compte");
    }

    /// resend_verification_email() doit générer un NOUVEAU code (différent de l'original, avec
    /// un compteur de tentatives remis à zéro) pour un compte pas encore vérifié, et ce nouveau
    /// code doit permettre de vérifier le compte comme le premier l'aurait fait.
    #[tokio::test]
    async fn test_resend_verification_email_issues_a_working_new_code() {
        let state = build_test_state().await;
        let email = "resend@example.com";
        let payload = AuthPayload {
            email: email.to_string(),
            master_password_hash: "mot_de_passe_test_123".to_string(),
            device_id: "device-resend".to_string(),
            remember_me: None,
            max_trusted_devices: None,
        };
        register(State(state.clone()), Json(payload))
            .await
            .expect("l'inscription doit réussir");

        let original_code: String = sqlx::query_scalar("SELECT code FROM tfa_codes WHERE email = ? AND purpose = ?")
            .bind(email).bind(PURPOSE_EMAIL_VERIFICATION).fetch_one(&state.db).await.unwrap();

        // On épuise quelques tentatives sur le code d'origine, pour vérifier que le renvoi
        // repart bien avec un compteur à zéro (INSERT OR REPLACE), pas un compteur hérité.
        sqlx::query("UPDATE tfa_codes SET attempts = 3 WHERE email = ? AND purpose = ?")
            .bind(email).bind(PURPOSE_EMAIL_VERIFICATION).execute(&state.db).await.unwrap();

        // Le code vient d'être émis par l'inscription juste au-dessus : le cooldown
        // anti-email-bombing (voir handlers/auth.rs::is_code_within_cooldown) bloquerait le renvoi.
        // On vieillit artificiellement son expiration pour simuler l'écoulement du cooldown — c'est
        // bien le RENVOI qu'on teste ici, pas le cooldown (couvert par son propre test plus bas).
        sqlx::query("UPDATE tfa_codes SET expires_at = STRFTIME('%Y-%m-%dT%H:%M:%SZ', 'now', '+5 minutes') WHERE email = ? AND purpose = ?")
            .bind(email).bind(PURPOSE_EMAIL_VERIFICATION).execute(&state.db).await.unwrap();

        resend_verification_email(State(state.clone()), Json(ForgotPasswordPayload { email: email.to_string() }))
            .await
            .expect("le renvoi doit réussir pour un compte non vérifié");

        let (new_code, attempts): (String, i64) = sqlx::query_as("SELECT code, attempts FROM tfa_codes WHERE email = ? AND purpose = ?")
            .bind(email).bind(PURPOSE_EMAIL_VERIFICATION).fetch_one(&state.db).await.unwrap();
        assert_ne!(new_code, original_code, "un renvoi doit générer un code différent du précédent (probabilité négligeable de collision sur 1M de valeurs)");
        assert_eq!(attempts, 0, "le compteur de tentatives doit repartir à zéro après un renvoi");

        verify_email(State(state.clone()), Json(VerifyEmailPayload { email: email.to_string(), code: new_code }))
            .await
            .expect("le nouveau code renvoyé doit être valide");
    }

    /// ANTI-EMAIL-BOMBING (trouvé à l'audit) : un renvoi demandé juste après l'émission d'un code
    /// ne doit produire NI nouveau code NI second email — le rate limiting de main.rs étant PAR IP,
    /// il ne protégeait pas une adresse ciblée par un attaquant changeant d'IP. La réponse reste
    /// un 202 identique pour ne pas trahir l'état du compte.
    #[tokio::test]
    async fn test_resend_verification_email_is_rate_limited_per_address() {
        let state = build_test_state().await;
        let email = "resend-bombing@example.com";
        register(State(state.clone()), Json(AuthPayload {
            email: email.to_string(),
            master_password_hash: "mot_de_passe_test_123".to_string(),
            device_id: "device-resend-bombing".to_string(),
            remember_me: None,
            max_trusted_devices: None,
        })).await.expect("l'inscription doit réussir");

        let original_code: String = sqlx::query_scalar("SELECT code FROM tfa_codes WHERE email = ? AND purpose = ?")
            .bind(email).bind(PURPOSE_EMAIL_VERIFICATION).fetch_one(&state.db).await.unwrap();

        let result = resend_verification_email(State(state.clone()), Json(ForgotPasswordPayload { email: email.to_string() })).await;
        assert!(result.is_ok(), "le renvoi trop rapproché doit répondre le même 202 (anti-énumération)");

        let code_after: String = sqlx::query_scalar("SELECT code FROM tfa_codes WHERE email = ? AND purpose = ?")
            .bind(email).bind(PURPOSE_EMAIL_VERIFICATION).fetch_one(&state.db).await.unwrap();
        assert_eq!(
            code_after, original_code,
            "un renvoi immédiat ne doit ni régénérer un code ni déclencher un second email"
        );
    }

    /// resend_verification_email() ne doit RIEN faire (ni erreur, ni nouveau code) pour un
    /// compte déjà vérifié ou inconnu — même stratégie anti-énumération que
    /// request_password_reset() (voir account.rs).
    #[tokio::test]
    async fn test_resend_verification_email_is_a_noop_for_verified_or_unknown_accounts() {
        let state = build_test_state().await;
        let verified_email = "alreadyverified@example.com";
        register_test_user(&state, verified_email, "mot_de_passe_test_123").await; // marque vérifié

        let result = resend_verification_email(State(state.clone()), Json(ForgotPasswordPayload { email: verified_email.to_string() })).await;
        assert!(result.is_ok(), "la requête doit répondre succès même pour un compte déjà vérifié (anti-énumération)");
        let code_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tfa_codes WHERE email = ?")
            .bind(verified_email).fetch_one(&state.db).await.unwrap();
        assert_eq!(code_count, 0, "aucun code ne doit être généré pour un compte déjà vérifié");

        let unknown_result = resend_verification_email(State(state.clone()), Json(ForgotPasswordPayload { email: "personne@example.com".to_string() })).await;
        assert!(unknown_result.is_ok(), "la requête doit répondre succès même pour un email inconnu (anti-énumération)");
    }

    /// register() doit créer directement un compte administrateur si l'email correspond à
    /// ADMIN_EMAIL (Config::admin_email), et ne JAMAIS le faire pour un autre email.
    #[tokio::test]
    async fn test_register_admin_bootstrap_via_admin_email() {
        let state = build_test_state_with_admin_email("boss@example.com").await;

        let admin_payload = AuthPayload {
            email: "Boss@Example.com".to_string(), // casse différente : doit quand même matcher
            master_password_hash: "mot_de_passe_test_123".to_string(),
            device_id: "unused".to_string(),
            remember_me: None,
            max_trusted_devices: None,
        };
        register(State(state.clone()), Json(admin_payload)).await.expect("l'inscription doit réussir");

        let is_moderator: bool = sqlx::query_scalar("SELECT is_moderator FROM users WHERE email = ?")
            .bind("boss@example.com").fetch_one(&state.db).await.unwrap();
        assert!(is_moderator, "le compte correspondant à ADMIN_EMAIL doit être admin dès l'inscription");

        let regular_payload = AuthPayload {
            email: "employee@example.com".to_string(),
            master_password_hash: "mot_de_passe_test_123".to_string(),
            device_id: "unused".to_string(),
            remember_me: None,
            max_trusted_devices: None,
        };
        register(State(state.clone()), Json(regular_payload)).await.expect("l'inscription doit réussir");
        let is_admin_regular: bool = sqlx::query_scalar("SELECT is_moderator FROM users WHERE email = ?")
            .bind("employee@example.com").fetch_one(&state.db).await.unwrap();
        assert!(!is_admin_regular, "un email différent d'ADMIN_EMAIL ne doit jamais devenir admin automatiquement");
    }

    /// RÉGRESSION : deux flux de code concurrents (2FA de connexion et réinitialisation de mot
    /// de passe) pour le MÊME email ne doivent jamais se marcher dessus, maintenant que
    /// `tfa_codes` est clé par (email, purpose) plutôt que par email seul (voir la migration
    /// 20260806000000_tfa_codes_purpose.sql). Avant ce correctif, un `INSERT OR REPLACE` sur un
    /// flux écrasait silencieusement le code d'un autre flux en cours pour le même compte — ex:
    /// une demande de reset de mot de passe pouvait invalider un code 2FA de connexion en attente.
    #[tokio::test]
    async fn test_concurrent_code_flows_do_not_clobber_each_other() {
        let state = build_test_state().await;
        let email = "concurrent@example.com";
        let password = "mot_de_passe_test_123";
        register_test_user(&state, email, password).await; // compte vérifié, aucun code résiduel

        // 1. Simule ce que login() insère pour un appareil non reconnu (purpose = login_2fa) —
        // sans passer par le VRAI handler login(), qui enverrait un email réel via SMTP
        // (impossible en test, voir trust_device() dans session.rs qui applique la même stratégie).
        let login_code = "111111".to_string();
        let login_expires_at = (Utc::now() + chrono::Duration::minutes(5))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        sqlx::query("INSERT OR REPLACE INTO tfa_codes (email, purpose, code, expires_at) VALUES (?, ?, ?, ?)")
            .bind(email)
            .bind(crate::handlers::auth::PURPOSE_LOGIN_2FA)
            .bind(&login_code)
            .bind(login_expires_at)
            .execute(&state.db)
            .await
            .expect("insertion du code 2FA de test");

        // 2. En parallèle, une demande de réinitialisation de mot de passe -> génère un DEUXIÈME
        // code (purpose = password_reset), pour le MÊME email.
        crate::handlers::auth::account::request_password_reset(State(state.clone()), Json(ForgotPasswordPayload { email: email.to_string() }))
            .await
            .expect("la demande de reset doit réussir");

        let reset_code: String = sqlx::query_scalar("SELECT code FROM tfa_codes WHERE email = ? AND purpose = ?")
            .bind(email).bind(PURPOSE_PASSWORD_RESET).fetch_one(&state.db).await
            .expect("un code de reset doit avoir été généré, sans écraser le code 2FA");

        // Les deux codes doivent coexister comme deux lignes distinctes, jamais s'écraser.
        let total_codes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tfa_codes WHERE email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert_eq!(total_codes, 2, "les deux flux doivent coexister comme deux lignes distinctes (email, purpose)");
        assert_ne!(login_code, reset_code, "probabilité négligeable de collision sur 1M de valeurs");

        let login_code_after: String = sqlx::query_scalar("SELECT code FROM tfa_codes WHERE email = ? AND purpose = ?")
            .bind(email).bind(crate::handlers::auth::PURPOSE_LOGIN_2FA).fetch_one(&state.db).await.unwrap();
        assert_eq!(login_code_after, login_code, "le code 2FA de connexion ne doit pas avoir été écrasé par la demande de reset");

        // 3. Un mauvais code de reset doit incrémenter les tentatives UNIQUEMENT sur le code de
        // reset, jamais sur le code 2FA du flux concurrent.
        let bad_reset_payload = ConfirmResetPayload {
            email: email.to_string(),
            code: "000000".to_string(),
            new_master_password_hash: "peu_importe".to_string(),
        };
        let _ = crate::handlers::auth::account::confirm_password_reset(State(state.clone()), Json(bad_reset_payload)).await;

        let reset_attempts: i64 = sqlx::query_scalar("SELECT attempts FROM tfa_codes WHERE email = ? AND purpose = ?")
            .bind(email).bind(PURPOSE_PASSWORD_RESET).fetch_one(&state.db).await.unwrap();
        let login_attempts: i64 = sqlx::query_scalar("SELECT attempts FROM tfa_codes WHERE email = ? AND purpose = ?")
            .bind(email).bind(crate::handlers::auth::PURPOSE_LOGIN_2FA).fetch_one(&state.db).await.unwrap();
        assert_eq!(reset_attempts, 1, "la tentative échouée doit incrémenter le compteur du code de reset");
        assert_eq!(login_attempts, 0, "le code 2FA du flux concurrent ne doit jamais être affecté par les tentatives sur le code de reset");

        // 4. Le BON code de reset doit fonctionner malgré la présence du code 2FA concurrent, et
        // consomme (par design, voir account.rs::confirm_password_reset) TOUS les codes de cet
        // email — y compris le code 2FA — puisqu'une réinitialisation de mot de passe est un
        // événement majeur qui invalide tout flux en cours pour ce compte.
        let good_reset_payload = ConfirmResetPayload {
            email: email.to_string(),
            code: reset_code,
            new_master_password_hash: "nouveau_mot_de_passe_123".to_string(),
        };
        crate::handlers::auth::account::confirm_password_reset(State(state.clone()), Json(good_reset_payload))
            .await
            .expect("le bon code de reset doit réussir malgré le flux 2FA concurrent");

        let remaining_codes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tfa_codes WHERE email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert_eq!(remaining_codes, 0, "confirm_password_reset() purge volontairement tous les codes en attente pour cet email");
    }
}
