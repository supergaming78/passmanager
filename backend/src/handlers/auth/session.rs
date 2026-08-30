// =========================================================================
// SESSION : CONNEXION, 2FA, RAFRAÎCHISSEMENT, DÉCONNEXION
// =========================================================================
// Tout ce qui concerne l'établissement et le maintien d'une session : login (+ 2FA sur appareil
// non reconnu), validation du code 2FA pour enregistrer un nouvel appareil de confiance,
// rafraîchissement de l'access token, et déconnexion d'un appareil. Voir register.rs pour la
// création de compte, account.rs pour la gestion du mot de passe/email/profil.

use axum::{
    extract::{State, ConnectInfo},
    http::{StatusCode, HeaderMap},
    response::IntoResponse,
    Json
};
use std::{sync::Arc, net::SocketAddr};
use crate::{AppState, crypto, mailer, error::AppError, models::*};
use chrono::Utc;
use serde_json::json;
use tracing::{instrument, warn, info, error};
use sqlx::Row;
use rand::RngExt;
use validator::Validate;
use super::super::common::get_user_agent;
use super::{MAX_CODE_ATTEMPTS, PURPOSE_LOGIN_2FA, MAX_FAILED_LOGIN_ATTEMPTS, FAILED_LOGIN_WINDOW_MINUTES};

/// ALERTE DE CONNEXION INHABITUELLE — voir la migration 20260831000000_trusted_device_ips.sql :
/// un appareil DÉJÀ approuvé qui se connecte depuis une IP JAMAIS vue pour LUI (pas juste "une IP
/// différente de la dernière fois", pour tolérer un utilisateur mobile/FAI dynamique — voir la
/// fenêtre glissante de 5 IP ci-dessous) est un signal fort de session/device_id volé. Ne bloque
/// JAMAIS la connexion (une IP seule n'est pas fiable — VPN, itinérance...), seulement une
/// notification best-effort, comme les autres alertes de sécurité déjà existantes.
///
/// Aucune alerte n'est envoyée si AUCUNE IP n'était encore connue pour cet appareil avant cet
/// appel (`previously_known_count == 0`) — ce cas couvre à la fois le tout premier login d'un
/// appareil qui vient d'être approuvé (l'alerte "nouvel appareil" vient déjà d'être envoyée juste
/// avant, voir verify_2fa_and_register_device()) ET un appareil approuvé AVANT l'existence de
/// cette table (évite une vague d'alertes non pertinentes pour tous les appareils déjà existants
/// juste après le déploiement de cette fonctionnalité).
async fn record_device_ip_and_maybe_alert(state: &AppState, email: &str, device_id: &str, device_label: &str, ip: &str, agent: Option<String>) {
    let already_known = sqlx::query("SELECT 1 FROM trusted_device_ips WHERE device_id = ? AND user_email = ? AND ip_address = ?")
        .bind(device_id)
        .bind(email)
        .bind(ip)
        .fetch_optional(&state.db)
        .await;

    match already_known {
        // IP déjà connue pour cet appareil : simple mise à jour de fraîcheur, jamais d'alerte.
        Ok(Some(_)) => {
            let _ = sqlx::query("UPDATE trusted_device_ips SET last_seen_at = CURRENT_TIMESTAMP WHERE device_id = ? AND user_email = ? AND ip_address = ?")
                .bind(device_id)
                .bind(email)
                .bind(ip)
                .execute(&state.db)
                .await;
        }
        Ok(None) => {
            let previously_known_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM trusted_device_ips WHERE device_id = ? AND user_email = ?",
            )
            .bind(device_id)
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);

            if sqlx::query("INSERT INTO trusted_device_ips (device_id, user_email, ip_address) VALUES (?, ?, ?)")
                .bind(device_id)
                .bind(email)
                .bind(ip)
                .execute(&state.db)
                .await
                .is_err()
            {
                return; // best-effort : un échec ici ne doit jamais faire échouer le login
            }

            // Fenêtre glissante : ne garde que les 5 IP les plus récentes par appareil — même motif
            // SQL que archive_password_history() dans repository.rs pour l'historique de mots de
            // passe (`id DESC` en second critère de tri : last_seen_at n'a qu'une précision à la
            // seconde en SQLite, deux insertions rapprochées pourraient sinon être ambiguës).
            let _ = sqlx::query(
                "DELETE FROM trusted_device_ips WHERE device_id = ? AND user_email = ? AND id NOT IN (
                    SELECT id FROM trusted_device_ips WHERE device_id = ? AND user_email = ? ORDER BY last_seen_at DESC, id DESC LIMIT 5
                )",
            )
            .bind(device_id)
            .bind(email)
            .bind(device_id)
            .bind(email)
            .execute(&state.db)
            .await;

            if previously_known_count > 0 {
                state.log_audit(email, "LOGIN_NEW_IP_DETECTED", ip.to_string(), agent).await;
                let _ = mailer::send_security_alert(
                    email,
                    &format!(
                        "Connexion à votre compte depuis une nouvelle adresse IP ({ip}) sur l'appareil déjà approuvé « {device_label} ». Si vous n'êtes pas à l'origine de cette connexion, changez immédiatement votre mot de passe et consultez vos appareils de confiance."
                    ),
                    &state.config,
                )
                .await;
            }
        }
        Err(_) => {} // best-effort : une erreur de lecture ne doit jamais faire échouer le login
    }
}

// --- ROUTE : CONNEXION (LOGIN) ---

/// Gère l'authentification des utilisateurs, la vérification 2FA et la gestion des sessions.
#[instrument(skip(state, payload, addr, headers), fields(email = %payload.email))]
pub async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>, // Récupère l'adresse IP et le port du client
    headers: HeaderMap,                         // Accès aux en-têtes HTTP
    Json(payload): Json<AuthPayload>,
) -> Result<impl IntoResponse, AppError> {
    // CORRECTIF SÉCURITÉ : sans ce .validate(), master_password_hash (jusqu'à la limite globale de
    // 256 Ko) pouvait être envoyé directement à crypto::verify_password() -> Argon2, un vecteur
    // d'amplification CPU/mémoire non authentifié (les 6-128 caractères attendus sont vérifiés ici,
    // avant tout calcul coûteux).
    payload.validate()?;

    // Extrait tôt : utilisé à la fois par le chemin d'échec (log d'audit LOGIN_FAILED) et par
    // le chemin de succès plus bas.
    let agent = get_user_agent(&headers);

    // 1. Recherche de l'utilisateur en base de données par son email
    // On ne court-circuite PAS avec `.ok_or()` ici pour éviter les attaques temporelles.
    let user_opt = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = ?")
        .bind(payload.email.to_lowercase())
        .fetch_optional(&state.db)
        .await?;

    // 2. Si l'utilisateur existe, on prend son vrai hash ; sinon une chaîne vide, qui déclenche le
    // repli sur le dummy_hash interne de crypto::verify_password() (mêmes paramètres Argon2id que
    // hash_password(), voir crypto.rs) — garantit que le serveur passe le même temps CPU/mémoire à
    // "vérifier" dans les deux cas. CORRECTIF : ce fichier dupliquait auparavant son PROPRE
    // dummy_hash littéral, avec des paramètres Argon2id différents (plus faibles) de ceux de
    // crypto.rs — la vérification contre un compte inconnu coûtait alors moins cher que contre un
    // compte connu, réintroduisant la fuite temporelle que ce mécanisme est censé empêcher.
    // Un seul dummy_hash, dans crypto.rs, plutôt que deux copies qui peuvent diverger.
    let hash_to_verify = user_opt.as_ref().map(|user| user.password_hash.as_str()).unwrap_or("");

    // 3. Vérification du mot de passe (Lourd calcul Argon2 exécuté dans TOUS les cas)
    let is_password_valid = crypto::verify_password(&payload.master_password_hash, hash_to_verify, &state.config.password_pepper);

    // 4. Validation de la sécurité
    // Si l'utilisateur n'existe pas en BDD OU si son mot de passe est incorrect, on rejette la demande.
    if user_opt.is_none() || !is_password_valid {
        // Trace d'audit sur l'échec (auparavant seuls les succès étaient journalisés, rendant
        // impossible toute détection a posteriori de brute-force/credential-stuffing depuis
        // GET /audit). On utilise l'email TENTÉ, pas un email de compte réel s'il n'existe pas.
        state.log_audit(&payload.email.to_lowercase(), "LOGIN_FAILED", addr.to_string(), agent.clone()).await;
        // Anti-bruteforce PAR COMPTE (voir auth.rs::MAX_FAILED_LOGIN_ATTEMPTS) : incrémente
        // UNIQUEMENT si le compte existe réellement (rien à protéger sinon, et incrémenter un
        // compte inexistant n'aurait aucun effet observable — pas la peine de la requête).
        if let Some(user) = &user_opt {
            sqlx::query("UPDATE users SET failed_login_attempts = failed_login_attempts + 1, last_failed_login_at = DATETIME('now') WHERE email = ?")
                .bind(&user.email)
                .execute(&state.db)
                .await?;
        }
        return Err(AppError::InvalidCredentials);
    }

    // On peut désormais déballer l'utilisateur en toute sécurité pour la suite du flux
    let user = user_opt.unwrap();

    // 4ter. Blocage anti-bruteforce PAR COMPTE : le mot de passe vient d'être validé, mais un
    // compte avec trop d'échecs récents reste bloqué tant que la fenêtre n'est pas expirée —
    // MÊME avec le bon mot de passe (c'est le principe même d'un verrou temporaire : un
    // attaquant qui aurait fini par deviner le mot de passe après de nombreux essais ne doit pas
    // pouvoir s'y connecter immédiatement). Message DISTINCT du "identifiants invalides"
    // générique : sans risque ici, l'appelant vient justement de prouver qu'il connaît le bon mot
    // de passe — cette information ne profite à personne d'autre qu'au titulaire légitime du compte.
    if user.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS {
        let still_locked: bool = sqlx::query_scalar(
            "SELECT last_failed_login_at > DATETIME('now', ?) FROM users WHERE email = ?"
        )
        .bind(format!("-{} minutes", FAILED_LOGIN_WINDOW_MINUTES))
        .bind(&user.email)
        .fetch_one(&state.db)
        .await?;
        if still_locked {
            state.log_audit(&user.email, "LOGIN_BLOCKED_TOO_MANY_ATTEMPTS", addr.to_string(), agent.clone()).await;
            return Err(AppError::ValidationError(
                "Trop de tentatives de connexion échouées récemment sur ce compte. Réessaie dans quelques minutes.".to_string()
            ));
        }
    }

    // Mot de passe valide et aucun blocage actif : remet le compteur à zéro (une connexion qui
    // aboutit efface l'historique des échecs précédents, comme un login normal le voudrait).
    if user.failed_login_attempts > 0 {
        sqlx::query("UPDATE users SET failed_login_attempts = 0 WHERE email = ?")
            .bind(&user.email)
            .execute(&state.db)
            .await?;
    }

    // 4bis. Compte pas encore vérifié (voir register.rs) : on bloque APRÈS avoir validé le mot
    // de passe (pas avant), pour ne pas transformer ce check en un oracle d'énumération de
    // comptes plus fort que celui déjà accepté par le message d'erreur générique.
    if !user.email_verified {
        warn!("Tentative de connexion sur un compte non vérifié : {}", user.email);
        state.log_audit(&user.email, "LOGIN_BLOCKED_UNVERIFIED", addr.to_string(), agent.clone()).await;
        return Err(AppError::ValidationError(
            "Veuillez confirmer votre adresse email avant de vous connecter (code envoyé à l'inscription).".to_string()
        ));
    }

    // 5. Vérification de l'appareil : est-il déjà enregistré dans les "appareils de confiance" ?
    // On récupère aussi device_name ici (pas juste l'existence) : réutilisé plus bas par l'alerte
    // de connexion depuis une IP inhabituelle, pour un message nommant l'appareil concerné.
    let trusted_device_row: Option<(Option<String>,)> = sqlx::query_as("SELECT device_name FROM trusted_devices WHERE device_id = ? AND user_email = ?")
        .bind(&payload.device_id)
        .bind(&user.email)
        .fetch_optional(&state.db)
        .await?;
    let is_trusted = trusted_device_row.is_some();

    // 6. GESTION DU CAS DE DOUBLE FACTEUR (2FA) : Si l'appareil n'est pas de confiance
    if !is_trusted {
        // a. Génération d'un code de sécurité aléatoire à 6 chiffres
        let generated_code = format!("{:06}", rand::rng().random_range(0..1000000));

        // b. Définition de la date d'expiration (+5 minutes) au format UTC ISO 8601
        let expires_at = (Utc::now() + chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%SZ").to_string();

        // c. Enregistrement (ou remplacement) du code 2FA en base de données
        sqlx::query("INSERT OR REPLACE INTO tfa_codes (email, purpose, code, expires_at) VALUES (?, ?, ?, ?)")
            .bind(&user.email)
            .bind(PURPOSE_LOGIN_2FA)
            .bind(&generated_code)
            .bind(expires_at)
            .execute(&state.db)
            .await?;

        // d. Envoi de l'e-mail contenant le code 2FA
        match mailer::send_tfa_email(&user.email, &generated_code, &state.config).await {
            Ok(_) => info!("E-mail de sécurité envoyé à {}", user.email),
            Err(e) => {
                error!("Erreur lors de l'envoi de l'email : {:?}", e);
                return Err(e);
            }
        }
        // Interruption du flux : on renvoie un statut 202 ACCEPTED indiquant que le 2FA est requis
        let tfa_res = Json(json!({ "status": "2FA_REQUIRED" }));
        return Ok((StatusCode::ACCEPTED, tfa_res).into_response());
    }

    // 7. APPAREIL DE CONFIANCE : Génération des jetons (Tokens) d'accès habituels
    let access_token = crypto::create_jwt(&user.email, &state.encoding_key, state.config.access_token_seconds)?;
    let refresh_token = crypto::create_refresh_token();

    // Trace que CET appareil de confiance vient d'être utilisé — permet à l'utilisateur de
    // repérer sur GET /devices un appareil inactif depuis longtemps, pour le révoquer en confiance.
    sqlx::query("UPDATE trusted_devices SET last_used_at = CURRENT_TIMESTAMP WHERE device_id = ? AND user_email = ?")
        .bind(&payload.device_id)
        .bind(&user.email)
        .execute(&state.db)
        .await?;

    // ALERTE DE CONNEXION INHABITUELLE (voir record_device_ip_and_maybe_alert ci-dessus) — best-
    // effort, ne doit jamais faire échouer ni ralentir un login par ailleurs légitime.
    // CORRECTIF : `addr.ip()` (adresse SEULE), PAS `addr.to_string()` (adresse:PORT) — le port
    // source TCP change quasiment à chaque connexion (choisi aléatoirement par l'OS/le client),
    // donc comparer "adresse:port" aurait fait déclencher l'alerte à quasiment CHAQUE login, même
    // depuis la même IP physique — le contraire du but recherché (voir aussi log_audit ci-dessous,
    // qui garde `addr.to_string()` AVEC port : lui n'est qu'un enregistrement informatif, jamais
    // comparé pour égalité, donc pas concerné par ce problème).
    let device_label = trusted_device_row.and_then(|(name,)| name).unwrap_or_else(|| "un appareil sans nom".to_string());
    record_device_ip_and_maybe_alert(&state, &user.email, &payload.device_id, &device_label, &addr.ip().to_string(), agent.clone()).await;

    // 8. CALCUL DU TEMPS DE SESSION DYNAMIQUE ("Se souvenir de moi")
    let is_remembered = payload.remember_me.unwrap_or(false);
    let action = if is_remembered { "LOGIN_SUCCESS_REMEMBER" } else { "LOGIN_SUCCESS_SESSION" };

    // Log d'audit unique pour ce login (auparavant, un log générique "LOGIN_SUCCESS" était aussi
    // écrit juste avant celui-ci, créant deux lignes d'audit pour une seule connexion réelle).
    state.log_audit(&user.email, action, addr.to_string(), agent).await;

    // Détermination de la durée de validité du Refresh Token selon le choix de l'utilisateur
    let refresh_duration = if is_remembered {
        chrono::Duration::hours(state.config.refresh_token_hours) // Longue durée (ex: 24h ou +)
    } else {
        chrono::Duration::seconds(state.config.refresh_token_short_seconds) // Durée très courte (session)
    };

    let expires_at = (Utc::now() + refresh_duration).format("%Y-%m-%dT%H:%M:%SZ").to_string();

    // 9. Gestion des sessions en base : on supprime l'ancien refresh token de CET APPAREIL uniquement
    // (et pas ceux des autres appareils : un utilisateur doit pouvoir rester connecté sur
    // son app ET son extension en même temps).
    sqlx::query("DELETE FROM refresh_tokens WHERE user_email = ? AND device_id = ?")
        .bind(&user.email)
        .bind(&payload.device_id)
        .execute(&state.db)
        .await?;

    // On ne stocke JAMAIS le refresh token en clair en base : seul son hash SHA-256 est conservé.
    // Le client, lui, reçoit et devra renvoyer le token en clair (voir plus bas) — c'est le seul
    // qui a besoin de le connaître pour prouver sa session. Une fuite de la BDD ne donne donc pas
    // directement accès à des sessions valides.
    let refresh_token_hash = crypto::hash_token(&refresh_token);

    sqlx::query("INSERT INTO refresh_tokens (token, user_email, device_id, expires_at, is_persistent) VALUES (?, ?, ?, ?, ?)")
        .bind(&refresh_token_hash)
        .bind(&user.email)
        .bind(&payload.device_id)
        .bind(expires_at)
        .bind(is_remembered) // Stocke l'état de persistance de la session
        .execute(&state.db)
        .await?;

    // 10. Réponse JSON : Retourne les tokens EN CLAIR au client (c'est la seule fois où le
    // refresh token en clair existe encore quelque part après cet appel, à part chez le client).
    let response_body = Json(json!({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": state.config.access_token_seconds
    }));

    Ok((StatusCode::OK, response_body).into_response())
}

// --- DOUBLE FACTEUR & DISPOSITIFS (2FA & DEVICE REGISTRATION) ---

/// Vérifie la validité du code 2FA envoyé par e-mail et ajoute l'appareil actuel aux appareils de confiance.
pub async fn verify_2fa_and_register_device(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<VerifyTfaPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;

    // Normalisation impérative : le code a été stocké sous l'email en minuscules
    // (par login()), donc toute comparaison/requête doit utiliser la même forme,
    // sinon un email envoyé avec une casse différente ne retrouve ni le code 2FA
    // ni le compte utilisateur référencé par la FK de trusted_devices.
    let email = payload.email.to_lowercase();

    // 1. Récupération du code 2FA stocké pour cet email
    let tfa: TfaCode = sqlx::query_as("SELECT * FROM tfa_codes WHERE email = ? AND purpose = ?")
        .bind(&email)
        .bind(PURPOSE_LOGIN_2FA)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::ValidationError("Aucun code généré".to_string()))?;

    let saved_code = tfa.code;
    let expires_at_str = tfa.expires_at;

    // 2. Vérification de l'expiration du code temporel
    let expires_at = chrono::NaiveDateTime::parse_from_str(&expires_at_str, "%Y-%m-%dT%H:%M:%SZ")
        .map_err(|_| AppError::Internal("Erreur format date".to_string()))?;

    if Utc::now().naive_utc() > expires_at {
        return Err(AppError::ValidationError("Le code a expiré".to_string()));
    }

    // 2bis. Verrouillage : trop de tentatives échouées sur ce code -> on le supprime
    // et on force l'utilisateur à en redemander un nouveau (ex: via un nouveau login).
    if tfa.attempts >= MAX_CODE_ATTEMPTS {
        sqlx::query("DELETE FROM tfa_codes WHERE email = ? AND purpose = ?")
            .bind(&email)
            .bind(PURPOSE_LOGIN_2FA)
            .execute(&state.db)
            .await?;
        warn!("Code 2FA verrouillé après trop de tentatives pour {}", email);
        return Err(AppError::ValidationError("Trop de tentatives, veuillez redemander un code".to_string()));
    }

    // 3. Vérification de la correspondance exacte du code (temps constant : voir crypto::constant_time_eq)
    if !crypto::constant_time_eq(&payload.code, &saved_code) {
        // Tentative échouée : on incrémente le compteur avant de rejeter la requête
        sqlx::query("UPDATE tfa_codes SET attempts = attempts + 1 WHERE email = ? AND purpose = ?")
            .bind(&email)
            .bind(PURPOSE_LOGIN_2FA)
            .execute(&state.db)
            .await?;
        return Err(AppError::ValidationError("Code de vérification incorrect".to_string()));
    }

    // 3bis. Plafond d'appareils de confiance (voir AuthPayload.max_trusted_devices à
    // l'inscription, et update_device_limit() dans handlers/devices.rs pour le modifier ensuite).
    // On ne compte QUE les appareils réellement NOUVEAUX : re-valider un appareil déjà connu
    // (INSERT OR REPLACE plus bas) ne doit jamais être bloqué par sa propre présence.
    let already_trusted = sqlx::query("SELECT 1 FROM trusted_devices WHERE device_id = ? AND user_email = ?")
        .bind(&payload.device_id)
        .bind(&email)
        .fetch_optional(&state.db)
        .await?
        .is_some();

    if !already_trusted {
        let (current_count, max_devices): (i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM trusted_devices WHERE user_email = ?), (SELECT max_trusted_devices FROM users WHERE email = ?)"
        )
        .bind(&email)
        .bind(&email)
        .fetch_one(&state.db)
        .await?;

        if current_count >= max_devices {
            warn!("Plafond d'appareils de confiance atteint ({}/{}) pour {}", current_count, max_devices, email);
            return Err(AppError::ValidationError(format!(
                "Limite de {max_devices} appareils de confiance atteinte. Révoquez un appareil existant (GET /devices) avant d'en ajouter un nouveau."
            )));
        }
    }

    // 4. Si la validation réussit : exécution d'une transaction atomique
    let mut tx = state.db.begin().await?;

    // Enregistrement du terminal dans les appareils de confiance (last_used_at = maintenant :
    // il vient justement de servir à valider ce code, DEFAULT CURRENT_TIMESTAMP suffirait mais
    // on le rend explicite pour la lisibilité — INSERT OR REPLACE recrée la ligne à chaque fois).
    sqlx::query("INSERT OR REPLACE INTO trusted_devices (device_id, user_email, device_name, last_used_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)")
        .bind(&payload.device_id)
        .bind(&email)
        .bind(&payload.device_name)
        .execute(&mut *tx)
        .await?;

    // Consommation du code : on supprime le code 2FA pour qu'il ne serve plus
    sqlx::query("DELETE FROM tfa_codes WHERE email = ? AND purpose = ?")
        .bind(&email)
        .bind(PURPOSE_LOGIN_2FA)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    // ALERTE DE SÉCURITÉ : un nouvel appareil approuvé est le signal le plus révélateur d'une
    // intrusion (quelqu'un vient de valider un code reçu sur CETTE boîte mail) — jusqu'ici seuls
    // le changement de mot de passe et le changement d'email en envoyaient une. Best-effort
    // comme les autres alertes (`let _ =`) : un échec SMTP ne doit pas faire échouer la
    // validation de l'appareil, déjà actée en BDD au-dessus.
    let device_label = payload.device_name.as_deref().unwrap_or("un appareil sans nom");
    let _ = mailer::send_security_alert(
        &email,
        &format!(
            "Un nouvel appareil ({device_label}) vient d'être approuvé sur votre compte. Si vous n'êtes pas à l'origine de cette action, changez immédiatement votre mot de passe et consultez vos appareils de confiance."
        ),
        &state.config
    ).await;

    // Établit la toute première IP connue pour ce nouvel appareil, SANS alerte (voir le commentaire
    // de record_device_ip_and_maybe_alert : previously_known_count vaudra 0 ici, la garde interne à
    // la fonction suffit à ne rien envoyer — l'alerte "nouvel appareil" ci-dessus est déjà suffisante).
    // `addr.ip()`, pas `addr.to_string()` — voir le commentaire équivalent dans login() (le port
    // source TCP change presque à chaque connexion, comparer "adresse:port" viderait la fenêtre
    // glissante de tout intérêt).
    record_device_ip_and_maybe_alert(&state, &email, &payload.device_id, device_label, &addr.ip().to_string(), None).await;

    info!("Appareil {} validé avec succès pour {}", payload.device_id, email);
    Ok(StatusCode::OK)
}

// --- ROUTE : RAFRAÎCHISSEMENT DE SESSION (REFRESH) ---

/// Permet d'obtenir un nouvel Access Token à l'aide d'un Refresh Token valide (non expiré).
#[instrument(skip(state, payload, addr, headers))]
pub async fn refresh(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<RefreshPayload>
) -> Result<impl IntoResponse, AppError> {
    let old_token = &payload.refresh_token;
    // Le client envoie le token EN CLAIR (c'est ce qu'il a reçu au login), mais la BDD ne stocke
    // que son hash — on doit donc hacher la valeur reçue avant de chercher la ligne correspondante.
    let old_token_hash = crypto::hash_token(old_token);

    // Début d'une transaction SQL pour garantir que la suppression et l'insertion forment un bloc atomique
    let mut tx = state.db.begin().await.map_err(AppError::DatabaseError)?;
    let agent = get_user_agent(&headers);

    // Suppression du jeton actuel ET récupération immédiate de ses données s'il est valide (et non expiré)
    // Cela évite la technique de "Replay Attack" (le token ne peut servir qu'une seule fois)
    let row = sqlx::query(
    "DELETE FROM refresh_tokens
     WHERE token = ?
     AND expires_at > STRFTIME('%Y-%m-%dT%H:%M:%SZ', 'now')
     RETURNING user_email, device_id, is_persistent"
    )
        .bind(&old_token_hash)
        .fetch_optional(&mut *tx)
        .await?;

    if let Some(r) = row {
        // Extraction des données de la ligne lue grâce au trait 'sqlx::Row'
        let email: String = r.get("user_email");
        let device_id: String = r.get("device_id");
        let is_persistent: bool = r.get("is_persistent");

        // Génération du nouveau couple de tokens (Rotation des Refresh Tokens)
        let new_access = crypto::create_jwt(&email, &state.encoding_key, state.config.access_token_seconds)?;
        let new_refresh = crypto::create_refresh_token();
        let new_refresh_hash = crypto::hash_token(&new_refresh); // seul le hash va en BDD

        // Conservation du choix de durée initial (session persistante ou éphémère)
        let refresh_duration = if is_persistent {
            chrono::Duration::hours(state.config.refresh_token_hours)
        } else {
            chrono::Duration::seconds(state.config.refresh_token_short_seconds)
        };

        let expires_at = (Utc::now() + refresh_duration).format("%Y-%m-%dT%H:%M:%SZ").to_string();

        // Insertion du nouveau Refresh Token dans la transaction, rattaché au même appareil
        sqlx::query("INSERT INTO refresh_tokens (token, user_email, device_id, expires_at, is_persistent) VALUES (?, ?, ?, ?, ?)")
            .bind(&new_refresh_hash)
            .bind(&email)
            .bind(&device_id)
            .bind(expires_at)
            .bind(is_persistent) // On propage l'état 'is_persistent' d'origine
            .execute(&mut *tx)
            .await?;

        // Validation finale des changements en base de données
        tx.commit().await.map_err(AppError::DatabaseError)?;

        // Envoi des nouveaux tokens EN CLAIR au client (le hash reste le seul en BDD)
        Ok(Json(json!({
            "access_token": new_access,
            "refresh_token": new_refresh
        })))
    } else {
        // Si aucun jeton n'a été trouvé ou s'il était expiré, alerte de sécurité et erreur
        warn!("Session expirée ou jeton invalide pour l'IP {}", addr);
        state.log_audit("unknown", "REFRESH_TOKEN_EXPIRED", addr.to_string(), agent).await;

        Err(AppError::SessionExpired)
    }
}

// --- ROUTE : DÉCONNEXION (LOGOUT) ---

/// Révoque UNIQUEMENT le refresh token fourni (donc UN SEUL appareil), sans toucher
/// aux sessions actives des autres appareils du même utilisateur.
/// Volontairement pas de vérification d'ownership via AuthUser : comme pour refresh(),
/// la seule connaissance du refresh token (256 bits aléatoires, non devinable) suffit
/// à prouver la légitimité de la déconnexion — c'est le même modèle de confiance que
/// pour le renouvellement de session.
/// Idempotent : renvoie 204 même si le token n'existait déjà plus (déconnexion "réussie" dans tous les cas).
pub async fn logout(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RefreshPayload>,
) -> Result<impl IntoResponse, AppError> {
    // Même principe que refresh() : le client envoie le token en clair, la BDD ne connaît que son hash.
    let token_hash = crypto::hash_token(&payload.refresh_token);
    sqlx::query("DELETE FROM refresh_tokens WHERE token = ?")
        .bind(&token_hash)
        .execute(&state.db)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

// =========================================================================
// TESTS D'INTÉGRATION SUR LES FLUX CRITIQUES
// =========================================================================
// On appelle les handlers directement comme des fonctions Rust normales, sans passer par
// une vraie requête HTTP : les extracteurs Axum (State, Json, ConnectInfo...) sont de simples
// structs qu'on peut construire à la main. Chaque test tourne sur sa propre BDD SQLite en
// mémoire (une connexion unique, pour que toutes les requêtes du test partagent le même état),
// avec les migrations réelles du projet — donc contre le VRAI schéma, pas une version simplifiée.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::handlers::auth::register::register;
    use sqlx::sqlite::SqlitePoolOptions;

    /// Construit un AppState de test : BDD SQLite en mémoire + migrations réelles + config factice.
    async fn build_test_state() -> Arc<AppState> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1) // Une seule connexion : garantit que tous les appels du test
            .connect("sqlite::memory:") // voient la même BDD en mémoire (sinon chaque connexion
            .await                      // du pool aurait sa propre BDD vide indépendante).
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

    /// Fait passer un appareil en "appareil de confiance" SANS passer par l'envoi d'email réel
    /// (impossible en test) : on insère directement le code 2FA en BDD, comme le ferait login(),
    /// puis on appelle le VRAI handler verify_2fa_and_register_device() pour le valider.
    async fn trust_device(state: &Arc<AppState>, email: &str, device_id: &str) {
        let code = "111111";
        let expires_at = (Utc::now() + chrono::Duration::minutes(5))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();

        sqlx::query("INSERT OR REPLACE INTO tfa_codes (email, purpose, code, expires_at) VALUES (?, ?, ?, ?)")
            .bind(email)
            .bind(PURPOSE_LOGIN_2FA)
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

    /// Lit le corps JSON d'une réponse Axum en `serde_json::Value` générique. Nécessaire pour
    /// récupérer le refresh_token EN CLAIR renvoyé au client (depuis le hachage des tokens en
    /// BDD, on ne peut plus le relire directement depuis la base).
    async fn read_json_body(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("lecture du corps de la réponse");
        serde_json::from_slice(&bytes).expect("le corps doit être du JSON valide")
    }

    /// Régression du bug corrigé : login() ne devait plus purger TOUTES les sessions de
    /// l'utilisateur, seulement celle de l'appareil courant. Deux appareils de confiance qui se
    /// connectent l'un après l'autre doivent tous les deux garder un refresh token actif en BDD.
    #[tokio::test]
    async fn test_login_multi_device_sessions_coexist() {
        let state = build_test_state().await;
        let email = "multidevice@example.com";
        let password = "mot_de_passe_test_123";

        register_test_user(&state, email, password).await;
        trust_device(&state, email, "device-app").await;
        trust_device(&state, email, "device-extension").await;

        for device_id in ["device-app", "device-extension"] {
            let payload = AuthPayload {
                email: email.to_string(),
                master_password_hash: password.to_string(),
                device_id: device_id.to_string(),
                remember_me: Some(true),
                max_trusted_devices: None,
            };
            let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
            login(State(state.clone()), ConnectInfo(addr), HeaderMap::new(), Json(payload))
                .await
                .expect("le login sur un appareil de confiance doit réussir sans 2FA");
        }

        // Les DEUX appareils doivent avoir chacun leur refresh token actif, pas un seul.
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE user_email = ?")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap();

        assert_eq!(count, 2, "les deux appareils devraient avoir une session active en parallèle");
    }

    /// Régression du verrouillage anti-bruteforce : après MAX_CODE_ATTEMPTS codes faux, le code
    /// doit être invalidé, et une tentative supplémentaire doit échouer MÊME avec le bon code.
    #[tokio::test]
    async fn test_verify_2fa_locks_after_max_attempts() {
        let state = build_test_state().await;
        let email = "lockout@example.com";
        register_test_user(&state, email, "mot_de_passe_test_123").await;

        let real_code = "654321";
        let expires_at = (Utc::now() + chrono::Duration::minutes(5))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        sqlx::query("INSERT OR REPLACE INTO tfa_codes (email, purpose, code, expires_at) VALUES (?, ?, ?, ?)")
            .bind(email)
            .bind(PURPOSE_LOGIN_2FA)
            .bind(real_code)
            .bind(expires_at)
            .execute(&state.db)
            .await
            .unwrap();

        // MAX_CODE_ATTEMPTS tentatives avec un mauvais code : chacune doit échouer "code incorrect"
        for attempt in 1..=MAX_CODE_ATTEMPTS {
            let payload = VerifyTfaPayload {
                email: email.to_string(),
                code: "000000".to_string(), // toujours faux
                device_id: "device-bruteforce".to_string(),
                device_name: None,
            };
            let result = verify_2fa_and_register_device(State(state.clone()), ConnectInfo("127.0.0.1:1".parse().unwrap()), Json(payload)).await;
            match &result {
                Err(AppError::ValidationError(_)) => {}
                Err(other) => panic!("tentative {attempt} : erreur inattendue : {other:?}"),
                Ok(_) => panic!("tentative {attempt} : un mauvais code ne devrait jamais réussir"),
            }
        }

        // La tentative suivante doit être bloquée par le verrouillage, MÊME avec le bon code.
        let payload = VerifyTfaPayload {
            email: email.to_string(),
            code: real_code.to_string(),
            device_id: "device-bruteforce".to_string(),
            device_name: None,
        };
        let result = verify_2fa_and_register_device(State(state.clone()), ConnectInfo("127.0.0.1:1".parse().unwrap()), Json(payload)).await;
        assert!(
            matches!(result, Err(AppError::ValidationError(_))),
            "le bon code ne devrait plus être accepté après le verrouillage"
        );

        // Le code doit avoir été supprimé de la BDD par le verrouillage.
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tfa_codes WHERE email = ?")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(remaining, 0, "le code verrouillé doit être supprimé de la BDD");
    }

    /// login() doit rejeter un mauvais mot de passe ET un email inconnu, sans distinction
    /// de message d'erreur entre les deux cas (anti-énumération de comptes).
    #[tokio::test]
    async fn test_login_rejects_invalid_credentials() {
        let state = build_test_state().await;
        let email = "logintest@example.com";
        register_test_user(&state, email, "bon_mot_de_passe_123").await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        // Mauvais mot de passe sur un compte existant
        let wrong_password = AuthPayload {
            email: email.to_string(),
            master_password_hash: "mauvais_mot_de_passe".to_string(),
            device_id: "device-x".to_string(),
            remember_me: None,
            max_trusted_devices: None,
        };
        let result = login(State(state.clone()), ConnectInfo(addr), HeaderMap::new(), Json(wrong_password)).await;
        assert!(
            matches!(result, Err(AppError::InvalidCredentials)),
            "un mauvais mot de passe doit être rejeté"
        );

        // Email totalement inconnu
        let unknown_email = AuthPayload {
            email: "personne-nexiste-pas@example.com".to_string(),
            master_password_hash: "peu_importe_le_mot_de_passe".to_string(),
            device_id: "device-x".to_string(),
            remember_me: None,
            max_trusted_devices: None,
        };
        let result = login(State(state.clone()), ConnectInfo(addr), HeaderMap::new(), Json(unknown_email)).await;
        assert!(
            matches!(result, Err(AppError::InvalidCredentials)),
            "un email inconnu doit renvoyer la même erreur qu'un mauvais mot de passe"
        );
    }

    /// Anti-bruteforce PAR COMPTE : après MAX_FAILED_LOGIN_ATTEMPTS échecs consécutifs, le compte
    /// doit rester bloqué même avec le BON mot de passe — sinon la protection ne protège rien
    /// (un attaquant qui finit par deviner le mot de passe après plusieurs essais ne doit pas
    /// pouvoir en profiter immédiatement).
    #[tokio::test]
    async fn test_login_locks_account_after_max_failed_attempts() {
        let state = build_test_state().await;
        let email = "lockouttest@example.com";
        let real_password = "bon_mot_de_passe_123";
        register_test_user(&state, email, real_password).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        for _ in 0..MAX_FAILED_LOGIN_ATTEMPTS {
            let wrong = AuthPayload {
                email: email.to_string(),
                master_password_hash: "mauvais_mot_de_passe".to_string(),
                device_id: "device-x".to_string(),
                remember_me: None,
                max_trusted_devices: None,
            };
            let result = login(State(state.clone()), ConnectInfo(addr), HeaderMap::new(), Json(wrong)).await;
            assert!(matches!(result, Err(AppError::InvalidCredentials)));
        }

        // Le compte est maintenant au seuil — même le BON mot de passe doit être rejeté, avec un
        // message DISTINCT (le compte est bloqué, pas "identifiants invalides").
        let correct = AuthPayload {
            email: email.to_string(),
            master_password_hash: real_password.to_string(),
            device_id: "device-x".to_string(),
            remember_me: None,
            max_trusted_devices: None,
        };
        let result = login(State(state.clone()), ConnectInfo(addr), HeaderMap::new(), Json(correct)).await;
        match result {
            Err(AppError::ValidationError(msg)) => {
                assert!(msg.contains("Trop de tentatives"), "le message doit expliquer le blocage anti-bruteforce, reçu: {msg}");
            }
            Err(other) => panic!("le compte devrait être bloqué après {MAX_FAILED_LOGIN_ATTEMPTS} échecs, mauvaise erreur reçue: {other:?}"),
            Ok(_) => panic!("le compte devrait être bloqué après {MAX_FAILED_LOGIN_ATTEMPTS} échecs, la connexion a pourtant réussi"),
        }
    }

    /// Une connexion réussie doit remettre le compteur d'échecs à zéro — sinon quelques mauvaises
    /// frappes suivies d'une connexion normale finiraient quand même par déclencher un blocage
    /// après plusieurs sessions distinctes, jamais réinitialisé.
    #[tokio::test]
    async fn test_login_resets_failed_attempts_counter_on_success() {
        let state = build_test_state().await;
        let email = "resetcountertest@example.com";
        let real_password = "bon_mot_de_passe_123";
        register_test_user(&state, email, real_password).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        // Quelques échecs, mais SOUS le seuil de blocage.
        for _ in 0..(MAX_FAILED_LOGIN_ATTEMPTS - 1) {
            let wrong = AuthPayload {
                email: email.to_string(),
                master_password_hash: "mauvais_mot_de_passe".to_string(),
                device_id: "device-x".to_string(),
                remember_me: None,
                max_trusted_devices: None,
            };
            let _ = login(State(state.clone()), ConnectInfo(addr), HeaderMap::new(), Json(wrong)).await;
        }

        let attempts_before: i64 = sqlx::query_scalar("SELECT failed_login_attempts FROM users WHERE email = ?")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(attempts_before, MAX_FAILED_LOGIN_ATTEMPTS - 1, "les échecs précédents doivent bien être comptabilisés");

        // Connexion réussie (2FA requis car appareil non reconnu, mais login() doit déjà avoir
        // validé le mot de passe et remis le compteur à zéro à ce stade).
        let correct = AuthPayload {
            email: email.to_string(),
            master_password_hash: real_password.to_string(),
            device_id: "device-x".to_string(),
            remember_me: None,
            max_trusted_devices: None,
        };
        let _ = login(State(state.clone()), ConnectInfo(addr), HeaderMap::new(), Json(correct)).await;

        let attempts_after: i64 = sqlx::query_scalar("SELECT failed_login_attempts FROM users WHERE email = ?")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(attempts_after, 0, "une connexion avec le bon mot de passe doit remettre le compteur à zéro");
    }

    /// refresh() doit faire tourner (rotation) le refresh token à chaque utilisation, ET
    /// l'ancien token ne doit plus jamais fonctionner ensuite (protection anti-rejeu).
    /// Depuis le hachage des refresh tokens en BDD, on ne peut plus lire le token en clair
    /// directement en base (seul son hash SHA-256 y est stocké) : on le récupère donc depuis
    /// le corps JSON des réponses login()/refresh(), exactement comme le ferait un vrai client.
    #[tokio::test]
    async fn test_refresh_rotates_token_and_rejects_replay() {
        let state = build_test_state().await;
        let email = "refreshtest@example.com";
        register_test_user(&state, email, "mot_de_passe_test_123").await;
        trust_device(&state, email, "device-refresh").await;

        let login_payload = AuthPayload {
            email: email.to_string(),
            master_password_hash: "mot_de_passe_test_123".to_string(),
            device_id: "device-refresh".to_string(),
            remember_me: Some(true),
            max_trusted_devices: None,
        };
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let login_result = login(State(state.clone()), ConnectInfo(addr), HeaderMap::new(), Json(login_payload))
            .await
            .expect("le login doit réussir");
        let old_token = read_json_body(login_result.into_response()).await["refresh_token"]
            .as_str().expect("le login doit renvoyer un refresh_token").to_string();

        // Premier refresh : doit réussir et faire tourner le token
        let refresh_payload = RefreshPayload { refresh_token: old_token.clone() };
        let refresh_result = refresh(State(state.clone()), ConnectInfo(addr), HeaderMap::new(), Json(refresh_payload))
            .await
            .expect("le premier refresh doit réussir");
        let new_token = read_json_body(refresh_result.into_response()).await["refresh_token"]
            .as_str().expect("refresh doit renvoyer un nouveau refresh_token").to_string();

        assert_ne!(old_token, new_token, "le token doit avoir changé après un refresh");

        // La BDD ne doit contenir QUE le hash du nouveau token, jamais un token en clair
        let stored_token: String = sqlx::query_scalar("SELECT token FROM refresh_tokens WHERE user_email = ?")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_ne!(stored_token, new_token, "la BDD ne doit jamais stocker le refresh token en clair");
        assert_eq!(stored_token, crypto::hash_token(&new_token), "la BDD doit stocker le hash SHA-256 du nouveau token");

        // Rejouer l'ANCIEN token (déjà consommé) doit maintenant échouer
        let replay_payload = RefreshPayload { refresh_token: old_token };
        let result = refresh(State(state.clone()), ConnectInfo(addr), HeaderMap::new(), Json(replay_payload)).await;
        assert!(
            matches!(result, Err(AppError::SessionExpired)),
            "rejouer un refresh token déjà utilisé doit échouer"
        );
    }

    /// logout() ne doit révoquer QUE le token fourni, jamais les autres sessions actives.
    /// Le token en clair est capturé depuis le corps JSON de login() (la BDD ne stocke plus
    /// que son hash, exactement comme un vrai client qui n'a que le token reçu à la connexion).
    #[tokio::test]
    async fn test_logout_revokes_only_the_given_token() {
        let state = build_test_state().await;
        let email = "logouttest@example.com";
        register_test_user(&state, email, "mot_de_passe_test_123").await;
        trust_device(&state, email, "device-a").await;
        trust_device(&state, email, "device-b").await;

        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut token_a = String::new();
        for device_id in ["device-a", "device-b"] {
            let payload = AuthPayload {
                email: email.to_string(),
                master_password_hash: "mot_de_passe_test_123".to_string(),
                device_id: device_id.to_string(),
                remember_me: Some(true),
                max_trusted_devices: None,
            };
            let result = login(State(state.clone()), ConnectInfo(addr), HeaderMap::new(), Json(payload))
                .await
                .expect("le login doit réussir");
            if device_id == "device-a" {
                token_a = read_json_body(result.into_response()).await["refresh_token"]
                    .as_str().expect("le login doit renvoyer un refresh_token").to_string();
            }
        }

        logout(State(state.clone()), Json(RefreshPayload { refresh_token: token_a }))
            .await
            .expect("le logout doit réussir");

        let remaining_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE user_email = ?")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(remaining_count, 1, "seule la session de device-a doit avoir été révoquée");

        let remaining_device: String = sqlx::query_scalar("SELECT device_id FROM refresh_tokens WHERE user_email = ?")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(remaining_device, "device-b", "la session de device-b doit rester active");
    }

    /// verify_2fa_and_register_device() doit lui aussi être insensible à la casse de l'email
    /// (même raison que pour confirm_password_reset : le code est stocké en minuscules).
    #[tokio::test]
    async fn test_verify_2fa_is_case_insensitive_on_email() {
        let state = build_test_state().await;
        let email_lowercase = "verify2facase@example.com";
        register_test_user(&state, email_lowercase, "mot_de_passe_test_123").await;

        let code = "333333";
        let expires_at = (Utc::now() + chrono::Duration::minutes(5))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        sqlx::query("INSERT OR REPLACE INTO tfa_codes (email, purpose, code, expires_at) VALUES (?, ?, ?, ?)")
            .bind(email_lowercase)
            .bind(PURPOSE_LOGIN_2FA)
            .bind(code)
            .bind(expires_at)
            .execute(&state.db)
            .await
            .unwrap();

        let payload = VerifyTfaPayload {
            email: "Verify2FaCase@Example.com".to_string(), // casse différente
            code: code.to_string(),
            device_id: "device-casse".to_string(),
            device_name: None,
        };
        let result = verify_2fa_and_register_device(State(state.clone()), ConnectInfo("127.0.0.1:1".parse().unwrap()), Json(payload)).await;
        assert!(result.is_ok(), "la vérification 2FA doit réussir malgré la casse différente");
    }

    /// login() sur un appareil déjà de confiance doit rafraîchir last_used_at — c'est ce qui
    /// permet à l'utilisateur de repérer un appareil inactif depuis longtemps (voir GET /devices).
    #[tokio::test]
    async fn test_login_updates_last_used_at_on_trusted_device() {
        let state = build_test_state().await;
        let email = "lastused@example.com";
        register_test_user(&state, email, "mot_de_passe_test_123").await;
        trust_device(&state, email, "device-lastused").await;

        // On force artificiellement last_used_at dans le passé (hier), pour vérifier ensuite que
        // le login le ramène bien à "maintenant" — comparer à la valeur d'avant le login aurait
        // été fragile (résolution à la seconde de CURRENT_TIMESTAMP, risque de faux négatif si
        // les deux événements tombent dans la même seconde).
        sqlx::query("UPDATE trusted_devices SET last_used_at = DATETIME('now', '-1 day') WHERE device_id = ?")
            .bind("device-lastused")
            .execute(&state.db)
            .await
            .unwrap();
        let forced_past: String = sqlx::query_scalar("SELECT last_used_at FROM trusted_devices WHERE device_id = ?")
            .bind("device-lastused")
            .fetch_one(&state.db)
            .await
            .unwrap();

        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let payload = AuthPayload {
            email: email.to_string(),
            master_password_hash: "mot_de_passe_test_123".to_string(),
            device_id: "device-lastused".to_string(),
            remember_me: Some(true),
            max_trusted_devices: None,
        };
        login(State(state.clone()), ConnectInfo(addr), HeaderMap::new(), Json(payload))
            .await
            .expect("le login doit réussir");

        let after_login: String = sqlx::query_scalar("SELECT last_used_at FROM trusted_devices WHERE device_id = ?")
            .bind("device-lastused")
            .fetch_one(&state.db)
            .await
            .unwrap();

        assert_ne!(forced_past, after_login, "last_used_at doit avoir été rafraîchi par le login, pas rester bloqué dans le passé");
    }

    /// register() doit créer un compte NON vérifié, et login() doit le refuser tant que le code
    /// de confirmation envoyé à l'inscription n'a pas été validé via verify_email() (register.rs).
    #[tokio::test]
    async fn test_login_blocked_until_email_verified() {
        let state = build_test_state().await;
        let email = "unverified@example.com";
        let password = "mot_de_passe_test_123";

        // Inscription DIRECTE (pas via register_test_user(), qui marque le compte vérifié pour
        // les autres tests) : on veut ici tester le compte fraîchement créé, non vérifié.
        let payload = AuthPayload {
            email: email.to_string(),
            master_password_hash: password.to_string(),
            device_id: "device-unverified".to_string(),
            remember_me: None,
            max_trusted_devices: None,
        };
        register(State(state.clone()), Json(payload))
            .await
            .expect("l'inscription doit réussir");

        let verified: bool = sqlx::query_scalar("SELECT email_verified FROM users WHERE email = ?")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert!(!verified, "un compte fraîchement inscrit ne doit pas être vérifié par défaut");

        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let login_payload = AuthPayload {
            email: email.to_string(),
            master_password_hash: password.to_string(),
            device_id: "device-unverified".to_string(),
            remember_me: None,
            max_trusted_devices: None,
        };
        let result = login(State(state.clone()), ConnectInfo(addr), HeaderMap::new(), Json(login_payload)).await;
        assert!(
            matches!(result, Err(AppError::ValidationError(_))),
            "login() doit refuser un compte dont l'email n'est pas encore vérifié"
        );
    }

    /// register() doit respecter le plafond d'appareils de confiance choisi par le client
    /// (AuthPayload.max_trusted_devices), et verify_2fa_and_register_device() doit le faire
    /// respecter : un plafond de 2 laisse passer 2 appareils, refuse le 3ème.
    #[tokio::test]
    async fn test_registration_custom_device_limit_is_enforced() {
        let state = build_test_state().await;
        let email = "customlimit@example.com";
        let payload = AuthPayload {
            email: email.to_string(),
            master_password_hash: "mot_de_passe_test_123".to_string(),
            device_id: "unused-at-registration".to_string(),
            remember_me: None,
            max_trusted_devices: Some(2),
        };
        register(State(state.clone()), Json(payload)).await.expect("l'inscription doit réussir");
        sqlx::query("UPDATE users SET email_verified = 1 WHERE email = ?")
            .bind(email).execute(&state.db).await.unwrap();

        let stored_limit: i64 = sqlx::query_scalar("SELECT max_trusted_devices FROM users WHERE email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert_eq!(stored_limit, 2, "le plafond choisi à l'inscription doit être appliqué");

        trust_device(&state, email, "device-1").await;
        trust_device(&state, email, "device-2").await;

        // Un 3ème appareil NOUVEAU doit être refusé (plafond atteint)
        let code = "444444";
        let expires_at = (Utc::now() + chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%SZ").to_string();
        sqlx::query("INSERT OR REPLACE INTO tfa_codes (email, purpose, code, expires_at) VALUES (?, ?, ?, ?)")
            .bind(email)
            .bind(PURPOSE_LOGIN_2FA).bind(code).bind(expires_at).execute(&state.db).await.unwrap();
        let result = verify_2fa_and_register_device(State(state.clone()), ConnectInfo("127.0.0.1:1".parse().unwrap()), Json(VerifyTfaPayload {
            email: email.to_string(), code: code.to_string(), device_id: "device-3".to_string(), device_name: None,
        })).await;
        assert!(matches!(result, Err(AppError::ValidationError(_))), "un 3ème appareil doit être refusé au-delà du plafond de 2");

        // Mais RE-valider un appareil déjà connu (device-1) doit toujours fonctionner : ce n'est
        // pas un NOUVEL appareil, il ne doit jamais être bloqué par sa propre présence.
        let code2 = "555555";
        let expires_at2 = (Utc::now() + chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%SZ").to_string();
        sqlx::query("INSERT OR REPLACE INTO tfa_codes (email, purpose, code, expires_at) VALUES (?, ?, ?, ?)")
            .bind(email)
            .bind(PURPOSE_LOGIN_2FA).bind(code2).bind(expires_at2).execute(&state.db).await.unwrap();
        let result2 = verify_2fa_and_register_device(State(state.clone()), ConnectInfo("127.0.0.1:1".parse().unwrap()), Json(VerifyTfaPayload {
            email: email.to_string(), code: code2.to_string(), device_id: "device-1".to_string(), device_name: None,
        })).await;
        assert!(result2.is_ok(), "re-valider un appareil déjà connu ne doit jamais être bloqué par le plafond");
    }

    /// Compte le nombre d'entrées d'audit `LOGIN_NEW_IP_DETECTED` pour un email — utilisé par les
    /// tests ci-dessous, qui ne peuvent pas vérifier directement l'envoi de l'email (impossible en
    /// test) mais peuvent vérifier que l'événement a bien été journalisé.
    async fn count_new_ip_alerts(state: &Arc<AppState>, email: &str) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE user_email = ? AND action = 'LOGIN_NEW_IP_DETECTED'")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap()
    }

    /// Le tout premier login d'un appareil fraîchement approuvé (via verify_2fa_and_register_device)
    /// ne doit JAMAIS déclencher l'alerte "nouvelle IP" — l'alerte "nouvel appareil" déjà envoyée à
    /// cette occasion suffit, une deuxième serait redondante (voir record_device_ip_and_maybe_alert).
    #[tokio::test]
    async fn test_first_ever_device_registration_does_not_trigger_new_ip_alert() {
        let state = build_test_state().await;
        let email = "newipbaseline@example.com";
        register_test_user(&state, email, "mot_de_passe_test_123").await;
        trust_device(&state, email, "device-baseline").await;

        assert_eq!(count_new_ip_alerts(&state, email).await, 0, "aucune alerte 'nouvelle IP' pour le tout premier login d'un appareil");

        let ip_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM trusted_device_ips WHERE device_id = ? AND user_email = ?")
            .bind("device-baseline").bind(email).fetch_one(&state.db).await.unwrap();
        assert_eq!(ip_count, 1, "la toute première IP doit tout de même être enregistrée comme référence");
    }

    /// Un login depuis la MÊME IP qu'une précédente connexion sur un appareil approuvé ne doit
    /// jamais déclencher d'alerte ni créer de nouvelle ligne — seule la fraîcheur est mise à jour.
    #[tokio::test]
    async fn test_login_from_same_ip_never_alerts() {
        let state = build_test_state().await;
        let email = "sameip@example.com";
        register_test_user(&state, email, "mot_de_passe_test_123").await;
        trust_device(&state, email, "device-sameip").await; // baseline IP = 127.0.0.1:1 (voir trust_device)

        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let payload = AuthPayload {
            email: email.to_string(),
            master_password_hash: "mot_de_passe_test_123".to_string(),
            device_id: "device-sameip".to_string(),
            remember_me: Some(true),
            max_trusted_devices: None,
        };
        login(State(state.clone()), ConnectInfo(addr), HeaderMap::new(), Json(payload))
            .await
            .expect("le login doit réussir");

        assert_eq!(count_new_ip_alerts(&state, email).await, 0, "une IP déjà connue ne doit jamais déclencher d'alerte");
        let ip_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM trusted_device_ips WHERE device_id = ? AND user_email = ?")
            .bind("device-sameip").bind(email).fetch_one(&state.db).await.unwrap();
        assert_eq!(ip_count, 1, "aucune nouvelle ligne pour une IP déjà connue");
    }

    /// RÉGRESSION : un login depuis la MÊME adresse IP mais un PORT source TCP différent (le cas
    /// réaliste à chaque connexion — le port est choisi aléatoirement par l'OS/le client, presque
    /// jamais identique deux fois) ne doit JAMAIS déclencher l'alerte. Un bug corrigé comparait
    /// `SocketAddr::to_string()` ("adresse:port") au lieu de `SocketAddr::ip()` ("adresse" seule),
    /// ce qui aurait fait déclencher l'alerte à quasiment CHAQUE login réel — ce test précis n'aurait
    /// pas existé avant ce correctif (tous les autres tests réutilisent le même port d'un appel à
    /// l'autre, donc ne l'auraient jamais détecté).
    #[tokio::test]
    async fn test_login_from_same_ip_different_port_never_alerts() {
        let state = build_test_state().await;
        let email = "sameipdiffport@example.com";
        register_test_user(&state, email, "mot_de_passe_test_123").await;
        trust_device(&state, email, "device-sameipdiffport").await; // baseline IP = 127.0.0.1:1

        // Même IP hôte (127.0.0.1), port TCP DIFFÉRENT (54321 au lieu de 1).
        let addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let payload = AuthPayload {
            email: email.to_string(),
            master_password_hash: "mot_de_passe_test_123".to_string(),
            device_id: "device-sameipdiffport".to_string(),
            remember_me: Some(true),
            max_trusted_devices: None,
        };
        login(State(state.clone()), ConnectInfo(addr), HeaderMap::new(), Json(payload))
            .await
            .expect("le login doit réussir");

        assert_eq!(
            count_new_ip_alerts(&state, email).await, 0,
            "un port TCP source différent ne doit jamais être confondu avec une IP différente"
        );
        let ip_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM trusted_device_ips WHERE device_id = ? AND user_email = ?")
            .bind("device-sameipdiffport").bind(email).fetch_one(&state.db).await.unwrap();
        assert_eq!(ip_count, 1, "l'adresse IP (sans le port) doit être reconnue comme déjà connue");
    }

    /// Un login depuis une IP JAMAIS vue sur un appareil DÉJÀ approuvé (donc après son tout premier
    /// login, voir le test précédent) doit déclencher l'alerte — c'est le vrai signal recherché par
    /// cette fonctionnalité (device_id/session potentiellement volé et utilisé ailleurs).
    #[tokio::test]
    async fn test_login_from_new_ip_on_trusted_device_triggers_alert() {
        let state = build_test_state().await;
        let email = "newip@example.com";
        register_test_user(&state, email, "mot_de_passe_test_123").await;
        trust_device(&state, email, "device-newip").await; // baseline IP = 127.0.0.1:1

        let different_addr: SocketAddr = "203.0.113.7:1".parse().unwrap();
        let payload = AuthPayload {
            email: email.to_string(),
            master_password_hash: "mot_de_passe_test_123".to_string(),
            device_id: "device-newip".to_string(),
            remember_me: Some(true),
            max_trusted_devices: None,
        };
        login(State(state.clone()), ConnectInfo(different_addr), HeaderMap::new(), Json(payload))
            .await
            .expect("le login doit réussir malgré l'IP inhabituelle (jamais bloquant)");

        assert_eq!(count_new_ip_alerts(&state, email).await, 1, "une IP jamais vue sur un appareil déjà approuvé doit déclencher l'alerte");
        let ip_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM trusted_device_ips WHERE device_id = ? AND user_email = ?")
            .bind("device-newip").bind(email).fetch_one(&state.db).await.unwrap();
        assert_eq!(ip_count, 2, "la nouvelle IP doit s'ajouter aux IP déjà connues pour cet appareil");
    }

    /// La fenêtre glissante ne garde que les 5 IP les plus récentes par appareil — au-delà, les
    /// plus anciennes sont purgées automatiquement (même principe que l'historique de mots de passe).
    #[tokio::test]
    async fn test_trusted_device_ip_window_keeps_only_5_most_recent() {
        let state = build_test_state().await;
        let email = "ipwindow@example.com";
        register_test_user(&state, email, "mot_de_passe_test_123").await;
        trust_device(&state, email, "device-window").await; // 1 IP déjà connue (127.0.0.1:1)

        // 6 IP supplémentaires, toutes distinctes de la baseline et entre elles -> 7 au total avant purge.
        for i in 1..=6 {
            let addr: SocketAddr = format!("10.0.0.{i}:1").parse().unwrap();
            let payload = AuthPayload {
                email: email.to_string(),
                master_password_hash: "mot_de_passe_test_123".to_string(),
                device_id: "device-window".to_string(),
                remember_me: Some(true),
                max_trusted_devices: None,
            };
            login(State(state.clone()), ConnectInfo(addr), HeaderMap::new(), Json(payload))
                .await
                .expect("le login doit réussir");
        }

        let ip_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM trusted_device_ips WHERE device_id = ? AND user_email = ?")
            .bind("device-window").bind(email).fetch_one(&state.db).await.unwrap();
        assert_eq!(ip_count, 5, "seules les 5 IP les plus récentes doivent être conservées par appareil");
    }
}
