// =========================================================================
// COMPTE : MOT DE PASSE, EMAIL, PROFIL
// =========================================================================
// Tout ce qui concerne la gestion d'un compte DÉJÀ créé et vérifié : changement volontaire du
// mot de passe maître (avec re-chiffrement du coffre), réinitialisation en cas d'oubli (purge du
// coffre, Zero-Knowledge oblige), changement d'email, et consultation du profil. Voir register.rs
// pour la création de compte, session.rs pour login/2FA/refresh/logout.

use axum::{
    extract::{ConnectInfo, State},
    http::{StatusCode, HeaderMap},
    response::IntoResponse,
    Json
};
use std::sync::Arc;
use std::net::SocketAddr;
use crate::{AppState, crypto, mailer, error::AppError, middleware::AuthUser, repository::VaultRepository, models::*};
use validator::Validate;
use chrono::Utc;
use serde_json::json;
use tracing::{instrument, warn, info};
use rand::RngExt;
use super::{MAX_CODE_ATTEMPTS, PURPOSE_PASSWORD_RESET, RESET_CODE_LIFETIME_MINUTES, is_code_within_cooldown};
use super::super::common::{get_user_agent, is_extension_origin};

/// Plafond de lecture pour la récupération — aligné sur MAX_VAULT_ENTRIES_PER_USER
/// (handlers/vault.rs) : un compte ne peut pas dépasser ce nombre d'entrées, donc une seule page
/// suffit toujours à tout couvrir, sans avoir à paginer un flux qui doit rester d'un seul tenant.
const MAX_VAULT_ENTRIES_FOR_RECOVERY: i64 = 5000;

/// Vérifie un code de réinitialisation reçu par email : verrouillage après trop d'essais,
/// comparaison en temps constant, contrôle d'expiration. `consume` supprime le code en cas de
/// succès.
///
/// Extrait de confirm_password_reset() pour être partagé avec la RÉCUPÉRATION, qui se déroule en
/// DEUX requêtes (obtenir le kit, puis renvoyer le coffre re-chiffré) et doit donc valider le même
/// code deux fois : la première SANS le consommer — sinon la seconde n'aurait plus rien pour
/// s'autoriser — la seconde en le consommant. Une seule implémentation pour les trois appels : le
/// verrouillage anti-bruteforce ne peut pas diverger d'un chemin à l'autre.
async fn verify_reset_code(state: &AppState, email: &str, code: &str, consume: bool) -> Result<(), AppError> {
    let tfa: TfaCode = sqlx::query_as("SELECT * FROM tfa_codes WHERE email = ? AND purpose = ?")
        .bind(email)
        .bind(PURPOSE_PASSWORD_RESET)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::ValidationError("Code invalide ou expiré".to_string()))?;

    if tfa.attempts >= MAX_CODE_ATTEMPTS {
        sqlx::query("DELETE FROM tfa_codes WHERE email = ? AND purpose = ?")
            .bind(email)
            .bind(PURPOSE_PASSWORD_RESET)
            .execute(&state.db)
            .await?;
        warn!("Code de reset verrouillé après trop de tentatives pour {}", email);
        return Err(AppError::ValidationError("Trop de tentatives, veuillez redemander un code".to_string()));
    }

    if !crypto::constant_time_eq(code, &tfa.code) {
        sqlx::query("UPDATE tfa_codes SET attempts = attempts + 1 WHERE email = ? AND purpose = ?")
            .bind(email)
            .bind(PURPOSE_PASSWORD_RESET)
            .execute(&state.db)
            .await?;
        return Err(AppError::ValidationError("Code incorrect".to_string()));
    }

    let expires_at = chrono::NaiveDateTime::parse_from_str(&tfa.expires_at, "%Y-%m-%dT%H:%M:%SZ")
        .map_err(|_| AppError::Internal("Erreur technique de date".to_string()))?;
    if Utc::now().naive_utc() > expires_at {
        return Err(AppError::ValidationError("Le code a expiré".to_string()));
    }

    if consume {
        sqlx::query("DELETE FROM tfa_codes WHERE email = ? AND purpose = ?")
            .bind(email)
            .bind(PURPOSE_PASSWORD_RESET)
            .execute(&state.db)
            .await?;
    }
    Ok(())
}

// --- ROUTE : MISE À JOUR DU MOT DE PASSE (PASSWORD UPDATE) ---

/// Vérifie que les identifiants re-chiffrés reçus recouvrent EXACTEMENT ceux présents en base :
/// ni doublon, ni manquant, ni inconnu. Voir son appel dans update_password() pour le pourquoi
/// détaillé — en résumé, un simple contrôle du NOMBRE d'éléments laissait passer un même id
/// envoyé deux fois, ce qui laissait une autre donnée chiffrée avec l'ancienne clé, définitivement
/// illisible et sans le moindre message d'erreur.
///
/// `label` s'insère dans le message d'erreur ("Re-chiffrement {label} incomplet : ...") pour
/// dire à l'utilisateur LAQUELLE des trois catégories pose problème.
fn check_reencrypted_ids<'a>(
    label: &str,
    expected: &[String],
    received: impl Iterator<Item = &'a str>,
) -> Result<(), AppError> {
    use std::collections::HashSet;

    let expected_set: HashSet<&str> = expected.iter().map(|s| s.as_str()).collect();
    let mut received_set: HashSet<&str> = HashSet::new();
    let mut received_len = 0usize;
    for id in received {
        received_len += 1;
        received_set.insert(id);
    }

    // Doublon : c'est LE cas que l'ancien contrôle par comptage ne voyait pas.
    if received_len != received_set.len() {
        return Err(AppError::ValidationError(format!(
            "Re-chiffrement {label} invalide : un même identifiant a été envoyé plusieurs fois ({} envoyé(s) pour {} distinct(s)). Le changement de mot de passe a été annulé pour éviter de perdre des données.",
            received_len,
            received_set.len()
        )));
    }

    let missing = expected_set.difference(&received_set).count();
    let unknown = received_set.difference(&expected_set).count();
    if missing > 0 || unknown > 0 {
        return Err(AppError::ValidationError(format!(
            "Re-chiffrement {label} incomplet : {} manquant(s) et {} inconnu(s), sur {} en base. Le changement de mot de passe a été annulé pour éviter de perdre des données.",
            missing,
            unknown,
            expected_set.len()
        )));
    }

    Ok(())
}

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

    // 3. Calcul du hachage du NOUVEAU hash d'authentification (double hachage, comme au login).
    // Le GARDE-FOU qui vérifie que le client a bien tout re-chiffré n'est plus ici mais DANS la
    // transaction, plus bas — voir son commentaire pour pourquoi ce déplacement était nécessaire.
    // Argon2id est calculé avant d'ouvrir la transaction : il coûte volontairement ~46 Mo et
    // plusieurs dizaines de ms (voir crypto.rs), autant ne pas tenir le verrou d'écriture SQLite
    // pendant ce temps-là.
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

    // GARDE-FOU CRITIQUE (renforcé — voir check_reencrypted_ids en bas de fichier) : le client
    // doit avoir re-chiffré EXACTEMENT toutes les entrées actives, tout l'historique et toutes les
    // pièces jointes — un oubli rendrait cette donnée définitivement indéchiffrable (elle
    // resterait chiffrée avec l'ANCIENNE clé, perdue à jamais).
    //
    // Vérifie désormais l'ENSEMBLE DES IDENTIFIANTS, plus seulement leur NOMBRE. L'ancienne
    // version ne comparait que des `len()` : envoyer deux fois le même id (bug de déduplication
    // côté client, retry partiel...) satisfaisait le compte tout en laissant une autre entrée
    // JAMAIS re-chiffrée — perte définitive et SILENCIEUSE, puisque la transaction committait
    // normalement. `reencrypt()` ne pouvait pas le rattraper : un id dupliqué met bien à jour une
    // ligne existante, donc `rows_affected == 1` à chaque passage.
    //
    // Fait ICI, DANS la transaction et APRÈS l'écriture ci-dessus (qui prend le verrou d'écriture
    // SQLite, les transactions étant DEFERRED par défaut) : les identifiants lus ne peuvent donc
    // plus changer avant le COMMIT. L'ancienne version lisait ses COUNT hors transaction, si bien
    // qu'une entrée ajoutée par un AUTRE appareil entretemps n'était jamais re-chiffrée — même
    // perte définitive, par une course cette fois.
    let active_ids: Vec<String> = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ? AND deleted_at IS NULL")
        .bind(&user.email)
        .fetch_all(&mut *tx)
        .await?;
    let history_ids: Vec<String> = sqlx::query_scalar("SELECT id FROM vault_password_history WHERE user_email = ?")
        .bind(&user.email)
        .fetch_all(&mut *tx)
        .await?;
    let attachment_ids: Vec<String> = sqlx::query_scalar("SELECT id FROM vault_attachments WHERE user_email = ?")
        .bind(&user.email)
        .fetch_all(&mut *tx)
        .await?;

    check_reencrypted_ids("des entrées", &active_ids, payload.reencrypted_entries.iter().map(|e| e.id.as_str()))?;
    check_reencrypted_ids("de l'historique", &history_ids, payload.reencrypted_history.iter().map(|e| e.id.as_str()))?;
    check_reencrypted_ids("des pièces jointes", &attachment_ids, payload.reencrypted_attachments.iter().map(|a| a.id.as_str()))?;

    for entry in &payload.reencrypted_entries {
        VaultRepository::reencrypt(&mut tx, &user.email, entry).await?;
    }
    for entry in &payload.reencrypted_history {
        VaultRepository::reencrypt_history_row(&mut tx, &user.email, entry).await?;
    }
    for attachment in &payload.reencrypted_attachments {
        VaultRepository::reencrypt_attachment(&mut tx, &user.email, attachment).await?;
    }

    // Le kit de récupération scelle l'ANCIENNE clé du coffre, dérivée du mot de passe qu'on vient
    // de remplacer : il ne déchiffrerait plus rien. Le laisser en place donnerait un kit
    // SILENCIEUSEMENT INOPÉRANT — pire qu'aucun kit, puisque l'utilisateur se croirait couvert et
    // ne le découvrirait qu'au pire moment. Le serveur ne peut pas le re-sceller lui-même (il n'a
    // jamais vu le code), et le client non plus (le code n'est affiché qu'une fois, jamais stocké)
    // : l'invalider et laisser l'utilisateur en régénérer un est la seule issue correcte.
    // GET /me repassera à has_recovery_kit=false, ce que l'écran Réglages reflète aussitôt.
    sqlx::query("UPDATE users SET recovery_sealed_vault_key = NULL WHERE email = ?")
        .bind(&user.email)
        .execute(&mut *tx)
        .await?;

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
    let (max_trusted_devices, can_change_email_via_extension, can_choose_server_in_settings, preferred_theme, recovery_kit): (i64, bool, bool, String, Option<String>) = sqlx::query_as(
        "SELECT max_trusted_devices, can_change_email_via_extension, can_choose_server_in_settings, preferred_theme, recovery_sealed_vault_key FROM users WHERE email = ?"
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
        // PRÉSENCE d'un kit de récupération, jamais son contenu : le client n'a besoin que de
        // savoir s'il doit proposer "générer un kit" ou "kit déjà configuré". Le blob scellé, lui,
        // ne sort qu'au bout du flux de récupération (voir get_recovery_data).
        "has_recovery_kit": recovery_kit.is_some(),
        // Retour utilisateur : "que le thème soit appliqué partout" — voir
        // handlers/theme_customization.rs::update_preferred_theme et la migration
        // 20260903070000_users_preferred_theme.sql. Appliqué par le CLIENT à l'établissement de
        // session (voir state/AuthContext.tsx::establishSession côté app, App.tsx côté extension),
        // jamais interprété ici — le serveur ne fait que stocker/relire une chaîne opaque.
        "preferred_theme": preferred_theme,
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

    // ANTI-EMAIL-BOMBING : un code déjà envoyé il y a moins de EMAIL_RESEND_COOLDOWN_SECONDS
    // interdit d'en renvoyer un. Sans ce contrôle, seule la limite PAR IP protégeait cette route,
    // alors qu'elle expédie un email vers une adresse choisie par l'appelant : quelques IP
    // suffisaient à noyer la boîte d'un utilisateur connu et à griller le quota/la réputation du
    // serveur SMTP. Le code déjà émis reste valide, l'utilisateur légitime n'est donc pas bloqué.
    //
    // Aucune colonne « émis à » n'est nécessaire : la durée de vie d'un code de reset est fixe
    // (RESET_CODE_LIFETIME_MINUTES), donc « expire encore dans plus de (durée de vie - cooldown) »
    // équivaut exactement à « a été émis il y a moins de cooldown ».
    //
    // Appliqué SILENCIEUSEMENT (on saute juste l'envoi, la réponse reste un 202 identique) :
    // renvoyer une erreur ici trahirait l'existence du compte, exactement ce que le reste de cette
    // fonction s'applique à masquer.
    let recently_sent = is_code_within_cooldown(&state, &email, PURPOSE_PASSWORD_RESET, RESET_CODE_LIFETIME_MINUTES).await?;

    if user_exists && !recently_sent {
        // 1. Génère un code de sécurité temporaire à 6 chiffres
        let reset_code = format!("{:06}", rand::rng().random_range(0..1000000));
        let expires_at = (Utc::now() + chrono::Duration::minutes(RESET_CODE_LIFETIME_MINUTES)).format("%Y-%m-%dT%H:%M:%SZ").to_string();

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
    } else if user_exists {
        warn!("Demande de reset ignorée (cooldown anti-email-bombing encore actif) pour {}", email);
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

    // Vérification du code reçu par email — factorisée (voir verify_reset_code en tête de
    // fichier), partagée avec le flux de RÉCUPÉRATION. Consommé ici : ce chemin va détruire le
    // coffre, le code ne doit pas pouvoir resservir.
    verify_reset_code(&state, &email, &payload.code, true).await?;

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
    // Même raison que dans update_password (voir son commentaire) — et ici le coffre lui-même
    // vient d'être vidé : le kit scellerait la clé d'un contenu qui n'existe plus.
    sqlx::query("UPDATE users SET recovery_sealed_vault_key = NULL WHERE email = ?")
        .bind(&email)
        .execute(&mut *tx)
        .await?;

    sqlx::query("DELETE FROM refresh_tokens WHERE user_email = ?").bind(&email).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM tfa_codes WHERE email = ?").bind(&email).execute(&mut *tx).await?;

    tx.commit().await?;

    info!("Réinitialisation totale du compte (MDP + Vault) pour : {}", email);
    Ok(StatusCode::OK)
}

// =========================================================================
// TESTS
// =========================================================================
// =========================================================================
// KIT DE RÉCUPÉRATION (voir crypto-core/src/recovery.rs et la migration 20260904000000)
// =========================================================================
// Sans kit, oublier son mot de passe maître condamne le coffre : confirm_password_reset() ci-dessus
// ne peut que le VIDER, faute de la moindre clé pour re-chiffrer quoi que ce soit. Le kit stocke la
// clé du coffre SCELLÉE par un code que seul l'utilisateur détient — le serveur n'en voit jamais
// que des octets qu'il ne peut pas ouvrir.
//
// La récupération se fait en DEUX requêtes, parce que le travail cryptographique a lieu ENTRE les
// deux, côté client : obtenir le blob + de quoi lire le coffre (get_recovery_data), desceller et
// tout re-chiffrer localement, puis renvoyer le résultat (complete_recovery).

/// Enregistre (ou remplace) le kit. Route authentifiée : seul le titulaire, coffre déverrouillé,
/// peut sceller sa propre clé — le serveur ne reçoit que le blob déjà scellé.
pub async fn save_recovery_kit(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<SaveRecoveryKitPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;

    sqlx::query("UPDATE users SET recovery_sealed_vault_key = ? WHERE email = ?")
        .bind(&payload.sealed_vault_key)
        .bind(&user.email)
        .execute(&state.db)
        .await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "RECOVERY_KIT_CREATED", addr.to_string(), agent).await;

    let _ = mailer::send_security_alert(
        &user.email,
        "Un kit de récupération vient d'être généré pour votre coffre. Si vous n'êtes pas à l'origine de cette action, changez immédiatement votre mot de passe maître.",
        &state.config,
    ).await;

    Ok(StatusCode::NO_CONTENT)
}

/// Supprime le kit. L'ancien code imprimé devient alors inopérant — c'est précisément l'intérêt
/// (feuille égarée, code peut-être vu par quelqu'un).
pub async fn delete_recovery_kit(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    sqlx::query("UPDATE users SET recovery_sealed_vault_key = NULL WHERE email = ?")
        .bind(&user.email)
        .execute(&state.db)
        .await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "RECOVERY_KIT_DELETED", addr.to_string(), agent).await;

    Ok(StatusCode::NO_CONTENT)
}

/// Étape 1 de la récupération : le code reçu par email prouve la possession de l'adresse, et donne
/// le blob scellé PLUS une session permettant de lire le coffre chiffré à re-chiffrer.
///
/// Le code n'est PAS consommé ici : complete_recovery() en a encore besoin pour s'autoriser. Il
/// reste soumis au même verrouillage anti-bruteforce (voir verify_reset_code).
///
/// Délivrer une session n'accorde rien de nouveau : avec ce même code, confirm_password_reset()
/// permet déjà de fixer un nouveau mot de passe — donc d'obtenir une session — au prix de la
/// destruction du coffre. Et ce que cette session rend lisible reste chiffré de bout en bout :
/// sans le code de récupération, ces octets ne servent à rien.
pub async fn get_recovery_data(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<RecoveryDataPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    let email = payload.email.to_lowercase();

    verify_reset_code(&state, &email, &payload.code, false).await?;

    let sealed: Option<String> = sqlx::query_scalar("SELECT recovery_sealed_vault_key FROM users WHERE email = ?")
        .bind(&email)
        .fetch_optional(&state.db)
        .await?
        .flatten();
    let sealed = sealed.ok_or_else(|| {
        AppError::ValidationError(
            "Aucun kit de récupération n'est configuré pour ce compte. La réinitialisation du mot de passe reste possible, mais elle videra le coffre.".to_string(),
        )
    })?;

    // CONTENU CHIFFRÉ du coffre, joint à cette réponse plutôt que laissé au client à récupérer
    // ensuite : les routes d'export habituelles exigent le hash du mot de passe maître (voir
    // ExportVaultPayload), précisément ce que l'utilisateur a oublié. Les renvoyer ici évite aussi
    // d'avoir à délivrer une session — ce qui aurait élargi inutilement ce que ce code autorise.
    //
    // Ces octets restent chiffrés de bout en bout : sans le code de récupération, ils ne servent à
    // rien. Volume comparable à celui de PUT /auth/password, d'où les mêmes plafonds sur la route.
    let entries = VaultRepository::get_all(&state.db, &email, MAX_VAULT_ENTRIES_FOR_RECOVERY, 0).await?;
    let history = VaultRepository::get_all_history_for_user(&state.db, &email).await?;
    let attachments = VaultRepository::get_all_attachments_for_user(&state.db, &email).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&email, "RECOVERY_STARTED", addr.to_string(), agent).await;

    Ok(Json(json!({
        "sealed_vault_key": sealed,
        "entries": entries,
        "history": history,
        "attachments": attachments,
    })))
}

/// Étape 2 : le client a descellé la clé avec son code et tout re-chiffré avec la clé dérivée du
/// NOUVEAU mot de passe maître. On applique le tout — et le coffre est CONSERVÉ, contrairement à
/// confirm_password_reset().
///
/// Réutilise exactement le même garde-fou que le changement volontaire de mot de passe
/// (check_reencrypted_ids, dans la transaction, après une écriture qui prend le verrou) : une
/// récupération qui oublierait une entrée la laisserait chiffrée avec une clé désormais
/// inaccessible — la perte serait définitive et silencieuse.
pub async fn complete_recovery(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<CompleteRecoveryPayload>,
) -> Result<impl IntoResponse, AppError> {
    payload.validate()?;
    for entry in &payload.reencrypted_entries {
        entry.validate()?;
    }
    for entry in &payload.reencrypted_history {
        entry.validate()?;
    }
    for attachment in &payload.reencrypted_attachments {
        attachment.validate()?;
    }

    let email = payload.email.to_lowercase();
    // Consommé cette fois : la récupération va aboutir, le code ne doit pas pouvoir resservir.
    verify_reset_code(&state, &email, &payload.code, true).await?;

    let new_password_hash = crypto::hash_password(&payload.new_master_password_hash, &state.config.password_pepper)
        .await
        .map_err(|_| AppError::HashError)?;

    let mut tx = state.db.begin().await?;

    // Première écriture de la transaction : prend le verrou d'écriture SQLite avant les lectures
    // ci-dessous (voir update_password pour le raisonnement détaillé).
    sqlx::query("UPDATE users SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP WHERE email = ?")
        .bind(&new_password_hash)
        .bind(&email)
        .execute(&mut *tx)
        .await?;

    let active_ids: Vec<String> = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ? AND deleted_at IS NULL")
        .bind(&email)
        .fetch_all(&mut *tx)
        .await?;
    let history_ids: Vec<String> = sqlx::query_scalar("SELECT id FROM vault_password_history WHERE user_email = ?")
        .bind(&email)
        .fetch_all(&mut *tx)
        .await?;
    let attachment_ids: Vec<String> = sqlx::query_scalar("SELECT id FROM vault_attachments WHERE user_email = ?")
        .bind(&email)
        .fetch_all(&mut *tx)
        .await?;

    check_reencrypted_ids("des entrées", &active_ids, payload.reencrypted_entries.iter().map(|e| e.id.as_str()))?;
    check_reencrypted_ids("de l'historique", &history_ids, payload.reencrypted_history.iter().map(|e| e.id.as_str()))?;
    check_reencrypted_ids("des pièces jointes", &attachment_ids, payload.reencrypted_attachments.iter().map(|a| a.id.as_str()))?;

    for entry in &payload.reencrypted_entries {
        VaultRepository::reencrypt(&mut tx, &email, entry).await?;
    }
    for entry in &payload.reencrypted_history {
        VaultRepository::reencrypt_history_row(&mut tx, &email, entry).await?;
    }
    for attachment in &payload.reencrypted_attachments {
        VaultRepository::reencrypt_attachment(&mut tx, &email, attachment).await?;
    }

    // Le kit qui vient de servir est INVALIDÉ : il scelle la clé de l'ANCIEN mot de passe, qui ne
    // déchiffre plus rien. Le laisser en place donnerait un kit silencieusement inopérant — pire
    // qu'aucun kit, puisqu'on croirait être couvert. L'utilisateur en régénère un après coup.
    sqlx::query("UPDATE users SET recovery_sealed_vault_key = NULL WHERE email = ?")
        .bind(&email)
        .execute(&mut *tx)
        .await?;

    // Toutes les sessions tombent, y compris celle délivrée à l'étape 1.
    sqlx::query("DELETE FROM refresh_tokens WHERE user_email = ?").bind(&email).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM tfa_codes WHERE email = ?").bind(&email).execute(&mut *tx).await?;

    tx.commit().await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&email, "RECOVERY_COMPLETED", addr.to_string(), agent).await;

    let _ = mailer::send_security_alert(
        &email,
        "Votre coffre vient d'être récupéré à l'aide de votre kit de récupération, et votre mot de passe maître a été changé. Si vous n'êtes pas à l'origine de cette action, sécurisez immédiatement votre compte.",
        &state.config,
    ).await;

    info!("Récupération du coffre menée à bien pour : {}", email);
    Ok(StatusCode::OK)
}

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
    /// puis marque directement le compte comme vérifié en BDD (voir register.rs::tests pour
    /// l'explication détaillée — dupliqué ici volontairement, chaque module de tests reste autonome).
    /// Lit le corps JSON d'une réponse — même petit utilitaire que dans les autres modules de
    /// tests de ce projet (voir handlers/auth/session.rs), recopié par module pour éviter un
    /// module de test partagé juste pour trois lignes.
    async fn read_json_body(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("lecture du corps de la réponse");
        serde_json::from_slice(&bytes).expect("le corps doit être du JSON valide")
    }

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

    /// RÉGRESSION (faille de PERTE DE DONNÉES trouvée à l'audit) : envoyer le MÊME identifiant
    /// deux fois satisfaisait l'ancien garde-fou, qui ne comparait que le NOMBRE d'entrées reçues
    /// au nombre en base. Conséquence : l'autre entrée n'était jamais re-chiffrée et restait
    /// chiffrée avec l'ANCIENNE clé — définitivement illisible — alors que la transaction
    /// committait normalement et que l'utilisateur voyait un succès. `reencrypt()` ne pouvait pas
    /// le rattraper : un id dupliqué met bien à jour une ligne existante à chaque passage.
    #[tokio::test]
    async fn test_update_password_rejects_duplicate_entry_ids() {
        let state = build_test_state().await;
        let email = "duplicateids@example.com";
        register_test_user(&state, email, "mot_de_passe_actuel_123").await;

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

        let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_all(&state.db).await.unwrap();

        // Le BON NOMBRE d'entrées (2 pour 2 en base), mais c'est deux fois la MÊME.
        let make = |id: &str| crate::models::ReencryptedVaultEntry {
            id: id.to_string(),
            encrypted_site_name: "ReChiffre".to_string(),
            encrypted_username: None,
            encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None,
            encrypted_password: "nouveau_chiffre".to_string(),
            encrypted_preferred_login_type: "email".to_string(),
            encrypted_extra_fields: None,
        };
        let duplicate_payload = ChangeMasterPasswordPayload {
            old_master_password_hash: "mot_de_passe_actuel_123".to_string(),
            new_master_password_hash: "nouveau_mot_de_passe_789".to_string(),
            reencrypted_entries: vec![make(&ids[0]), make(&ids[0])],
            reencrypted_history: vec![],
            reencrypted_attachments: vec![],
        };
        let result = update_password(State(state.clone()), AuthUser { email: email.to_string(), is_moderator: false }, Json(duplicate_payload)).await;
        assert!(
            matches!(result, Err(AppError::ValidationError(_))),
            "un identifiant envoyé deux fois doit être refusé, même si le NOMBRE d'entrées correspond"
        );

        // Rien ne doit avoir changé : ni le mot de passe, ni la seconde entrée restée intacte.
        let current_user: User = sqlx::query_as("SELECT * FROM users WHERE email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert!(
            crypto::verify_password("mot_de_passe_actuel_123", &current_user.password_hash, &state.config.password_pepper).await,
            "l'ancien mot de passe doit rester valide, la transaction devant être annulée en entier"
        );
        let untouched: String = sqlx::query_scalar("SELECT encrypted_password FROM vault WHERE id = ?")
            .bind(&ids[1]).fetch_one(&state.db).await.unwrap();
        assert_eq!(untouched, "chiffre", "l'entrée jamais renvoyée ne doit pas avoir été touchée");
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

    /// ANTI-EMAIL-BOMBING (trouvé à l'audit) : deux demandes de reset coup sur coup pour la MÊME
    /// adresse ne doivent produire qu'UN SEUL email. Le rate limiting de main.rs étant PAR IP, il
    /// ne protégeait pas une adresse ciblée par un attaquant changeant d'IP, alors que chaque
    /// requête expédie un vrai email. La 2e demande doit rester un 202 identique (ne jamais
    /// trahir l'existence du compte) et laisser le PREMIER code intact (l'utilisateur légitime
    /// qui vient de recevoir son code doit pouvoir continuer à s'en servir).
    #[tokio::test]
    async fn test_request_password_reset_is_rate_limited_per_address() {
        let state = build_test_state().await;
        let email = "bombing-target@example.com";
        register_test_user(&state, email, "mot_de_passe_test_123").await;

        request_password_reset(State(state.clone()), Json(ForgotPasswordPayload { email: email.to_string() }))
            .await
            .expect("la première demande doit réussir");
        let first_code: String = sqlx::query_scalar("SELECT code FROM tfa_codes WHERE email = ? AND purpose = ?")
            .bind(email).bind(PURPOSE_PASSWORD_RESET)
            .fetch_one(&state.db).await.unwrap();

        let second = request_password_reset(State(state.clone()), Json(ForgotPasswordPayload { email: email.to_string() })).await;
        assert!(second.is_ok(), "la seconde demande doit répondre le même 202 (anti-énumération)");

        let code_after: String = sqlx::query_scalar("SELECT code FROM tfa_codes WHERE email = ? AND purpose = ?")
            .bind(email).bind(PURPOSE_PASSWORD_RESET)
            .fetch_one(&state.db).await.unwrap();
        assert_eq!(
            code_after, first_code,
            "une seconde demande immédiate ne doit ni régénérer un code ni déclencher un second email"
        );
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
            geoip: base_state.geoip.clone(),
            started_at: base_state.started_at,
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

    // =========================================================================
    // KIT DE RÉCUPÉRATION
    // =========================================================================

    /// Prépare un compte avec un kit enregistré et un code de reset valide en base, et renvoie ce
    /// code. Reproduit ce que ferait request_password_reset(), sans passer par l'envoi d'email.
    async fn setup_recovery(state: &Arc<AppState>, email: &str, sealed: &str) -> String {
        sqlx::query("UPDATE users SET recovery_sealed_vault_key = ? WHERE email = ?")
            .bind(sealed)
            .bind(email)
            .execute(&state.db)
            .await
            .unwrap();

        let code = "424242".to_string();
        let expires_at = (Utc::now() + chrono::Duration::minutes(15)).format("%Y-%m-%dT%H:%M:%SZ").to_string();
        sqlx::query("INSERT OR REPLACE INTO tfa_codes (email, purpose, code, expires_at) VALUES (?, ?, ?, ?)")
            .bind(email)
            .bind(PURPOSE_PASSWORD_RESET)
            .bind(&code)
            .bind(expires_at)
            .execute(&state.db)
            .await
            .unwrap();
        code
    }

    fn addr() -> SocketAddr {
        "127.0.0.1:1".parse().unwrap()
    }

    /// get_recovery_data() doit rendre le blob scellé ET une session utilisable, SANS consommer le
    /// code — complete_recovery() en a encore besoin juste après.
    #[tokio::test]
    async fn test_recovery_data_returns_kit_with_vault_and_does_not_consume_the_code() {
        let state = build_test_state().await;
        let email = "recovery-data@example.com";
        register_test_user(&state, email, "mot_de_passe_initial_123").await;
        let code = setup_recovery(&state, email, "blob-scelle-de-test").await;

        let result = get_recovery_data(
            State(state.clone()),
            ConnectInfo(addr()),
            HeaderMap::new(),
            Json(RecoveryDataPayload { email: email.to_string(), code: code.clone(), device_id: "dev-1".to_string() }),
        )
        .await
        .expect("la première étape doit réussir");

        let value = read_json_body(result.into_response()).await;
        assert_eq!(value["sealed_vault_key"], "blob-scelle-de-test");
        // Le contenu chiffré du coffre accompagne la réponse : les routes d'export habituelles
        // exigent le hash du mot de passe maître, précisément ce que l'utilisateur a oublié.
        assert!(value["entries"].is_array(), "les entrées chiffrées doivent accompagner le kit");
        assert!(value["history"].is_array(), "l'historique chiffré doit accompagner le kit");
        assert!(value["attachments"].is_array(), "les pièces jointes chiffrées doivent accompagner le kit");
        assert!(value.get("access_token").is_none(), "aucune session ne doit être délivrée : inutile, donc à ne pas accorder");

        let still_there: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tfa_codes WHERE email = ? AND purpose = ?")
            .bind(email)
            .bind(PURPOSE_PASSWORD_RESET)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(still_there, 1, "le code ne doit PAS être consommé par la première étape");
    }

    /// Sans kit configuré, la récupération doit être refusée explicitement — et surtout ne rien
    /// détruire : l'utilisateur garde le choix de la réinitialisation classique.
    #[tokio::test]
    async fn test_recovery_data_rejects_account_without_kit() {
        let state = build_test_state().await;
        let email = "no-kit@example.com";
        register_test_user(&state, email, "mot_de_passe_initial_123").await;

        let code = "424242".to_string();
        let expires_at = (Utc::now() + chrono::Duration::minutes(15)).format("%Y-%m-%dT%H:%M:%SZ").to_string();
        sqlx::query("INSERT OR REPLACE INTO tfa_codes (email, purpose, code, expires_at) VALUES (?, ?, ?, ?)")
            .bind(email).bind(PURPOSE_PASSWORD_RESET).bind(&code).bind(expires_at)
            .execute(&state.db).await.unwrap();

        let result = get_recovery_data(
            State(state.clone()),
            ConnectInfo(addr()),
            HeaderMap::new(),
            Json(RecoveryDataPayload { email: email.to_string(), code, device_id: "dev-1".to_string() }),
        )
        .await;
        assert!(matches!(result, Err(AppError::ValidationError(_))), "sans kit, la récupération doit être refusée");
    }

    #[tokio::test]
    async fn test_recovery_data_rejects_wrong_code() {
        let state = build_test_state().await;
        let email = "wrong-code@example.com";
        register_test_user(&state, email, "mot_de_passe_initial_123").await;
        setup_recovery(&state, email, "blob").await;

        let result = get_recovery_data(
            State(state.clone()),
            ConnectInfo(addr()),
            HeaderMap::new(),
            Json(RecoveryDataPayload { email: email.to_string(), code: "999999".to_string(), device_id: "dev-1".to_string() }),
        )
        .await;
        assert!(matches!(result, Err(AppError::ValidationError(_))), "un code faux doit être rejeté");
    }

    /// LE test qui compte : contrairement à confirm_password_reset(), le coffre doit SURVIVRE —
    /// c'est toute la raison d'être du kit. Le mot de passe change, le contenu est remplacé par sa
    /// version re-chiffrée, et le kit consommé est invalidé.
    #[tokio::test]
    async fn test_complete_recovery_preserves_vault_and_invalidates_kit() {
        let state = build_test_state().await;
        let email = "recovered@example.com";
        register_test_user(&state, email, "ancien_mot_de_passe_123").await;
        let code = setup_recovery(&state, email, "blob").await;

        // Deux entrées, chiffrées avec l'ANCIENNE clé.
        for site in ["Site1", "Site2"] {
            let entry = VaultEntryInput {
                encrypted_site_name: site.to_string(), encrypted_username: None, encrypted_login_email: None,
                encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false,
                expected_version: None, entry_type: "login".to_string(), encrypted_extra_fields: None,
                encrypted_password: "ancien_chiffre".to_string(),
                encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
            };
            crate::handlers::vault::add_to_vault(
                State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
                AuthUser { email: email.to_string(), is_moderator: false }, Json(entry),
            ).await.expect("l'ajout doit réussir");
        }

        let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_all(&state.db).await.unwrap();

        let reencrypted: Vec<crate::models::ReencryptedVaultEntry> = ids.iter().map(|id| crate::models::ReencryptedVaultEntry {
            id: id.clone(),
            encrypted_site_name: "re_chiffre".to_string(),
            encrypted_username: None, encrypted_login_email: None, encrypted_folder: None,
            encrypted_notes: None, encrypted_url: None,
            encrypted_password: "nouveau_chiffre".to_string(),
            encrypted_preferred_login_type: "email".to_string(),
            encrypted_extra_fields: None,
        }).collect();

        complete_recovery(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            Json(CompleteRecoveryPayload {
                email: email.to_string(), code,
                new_master_password_hash: "nouveau_mot_de_passe_789".to_string(),
                reencrypted_entries: reencrypted,
                reencrypted_history: vec![], reencrypted_attachments: vec![],
            }),
        ).await.expect("la récupération doit aboutir");

        // 1. Le coffre a SURVÉCU, avec le contenu re-chiffré.
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert_eq!(remaining, 2, "le coffre ne doit PAS être vidé — c'est toute la raison d'être du kit");
        let stored: String = sqlx::query_scalar("SELECT encrypted_password FROM vault WHERE id = ?")
            .bind(&ids[0]).fetch_one(&state.db).await.unwrap();
        assert_eq!(stored, "nouveau_chiffre", "le contenu re-chiffré doit avoir été appliqué");

        // 2. Le nouveau mot de passe est en vigueur.
        let user: User = sqlx::query_as("SELECT * FROM users WHERE email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert!(
            crypto::verify_password("nouveau_mot_de_passe_789", &user.password_hash, &state.config.password_pepper).await,
            "le nouveau mot de passe maître doit être en vigueur"
        );

        // 3. Le kit consommé est invalidé : il scelle une clé qui ne déchiffre plus rien.
        let kit: Option<String> = sqlx::query_scalar("SELECT recovery_sealed_vault_key FROM users WHERE email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert!(kit.is_none(), "le kit utilisé doit être invalidé, jamais laissé silencieusement inopérant");
    }

    /// Le garde-fou du re-chiffrement s'applique AUSSI à la récupération : un identifiant envoyé
    /// deux fois laisserait une entrée chiffrée avec une clé désormais perdue à jamais.
    #[tokio::test]
    async fn test_complete_recovery_rejects_duplicate_entry_ids() {
        let state = build_test_state().await;
        let email = "recovery-dup@example.com";
        register_test_user(&state, email, "ancien_mot_de_passe_123").await;
        let code = setup_recovery(&state, email, "blob").await;

        for site in ["Site1", "Site2"] {
            let entry = VaultEntryInput {
                encrypted_site_name: site.to_string(), encrypted_username: None, encrypted_login_email: None,
                encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false,
                expected_version: None, entry_type: "login".to_string(), encrypted_extra_fields: None,
                encrypted_password: "ancien_chiffre".to_string(),
                encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
            };
            crate::handlers::vault::add_to_vault(
                State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
                AuthUser { email: email.to_string(), is_moderator: false }, Json(entry),
            ).await.unwrap();
        }
        let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_all(&state.db).await.unwrap();

        let make = |id: &str| crate::models::ReencryptedVaultEntry {
            id: id.to_string(),
            encrypted_site_name: "re_chiffre".to_string(),
            encrypted_username: None, encrypted_login_email: None, encrypted_folder: None,
            encrypted_notes: None, encrypted_url: None,
            encrypted_password: "nouveau_chiffre".to_string(),
            encrypted_preferred_login_type: "email".to_string(),
            encrypted_extra_fields: None,
        };

        let result = complete_recovery(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            Json(CompleteRecoveryPayload {
                email: email.to_string(), code,
                new_master_password_hash: "nouveau_mot_de_passe_789".to_string(),
                reencrypted_entries: vec![make(&ids[0]), make(&ids[0])],
                reencrypted_history: vec![], reencrypted_attachments: vec![],
            }),
        ).await;

        assert!(matches!(result, Err(AppError::ValidationError(_))), "un identifiant dupliqué doit être refusé");

        let untouched: String = sqlx::query_scalar("SELECT encrypted_password FROM vault WHERE id = ?")
            .bind(&ids[1]).fetch_one(&state.db).await.unwrap();
        assert_eq!(untouched, "ancien_chiffre", "rien ne doit avoir été modifié");
        let user: User = sqlx::query_as("SELECT * FROM users WHERE email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert!(
            crypto::verify_password("ancien_mot_de_passe_123", &user.password_hash, &state.config.password_pepper).await,
            "l'ancien mot de passe doit rester en vigueur, la transaction devant être annulée en entier"
        );
    }

    /// save_recovery_kit()/delete_recovery_kit() : le titulaire enregistre puis retire son kit, et
    /// GET /me reflète la présence sans jamais exposer le blob.
    #[tokio::test]
    async fn test_save_then_delete_recovery_kit_is_reflected_in_get_me() {
        let state = build_test_state().await;
        let email = "kit-lifecycle@example.com";
        register_test_user(&state, email, "mot_de_passe_initial_123").await;
        let user = || AuthUser { email: email.to_string(), is_moderator: false };

        let me = read_json_body(get_me(State(state.clone()), user()).await.unwrap().into_response()).await;
        assert_eq!(me["has_recovery_kit"], false, "aucun kit au départ");

        save_recovery_kit(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(), user(),
            Json(SaveRecoveryKitPayload { sealed_vault_key: "blob-scelle".to_string() }),
        ).await.expect("l'enregistrement doit réussir");

        let me = read_json_body(get_me(State(state.clone()), user()).await.unwrap().into_response()).await;
        assert_eq!(me["has_recovery_kit"], true, "le kit doit être signalé comme présent");
        assert!(me.get("recovery_sealed_vault_key").is_none(), "GET /me ne doit JAMAIS exposer le blob lui-même");

        delete_recovery_kit(State(state.clone()), ConnectInfo(addr()), HeaderMap::new(), user())
            .await.expect("la suppression doit réussir");
        let me = read_json_body(get_me(State(state.clone()), user()).await.unwrap().into_response()).await;
        assert_eq!(me["has_recovery_kit"], false, "après suppression, plus de kit");
    }


    /// RÉGRESSION : un changement VOLONTAIRE de mot de passe doit invalider le kit de récupération.
    /// Il scelle l'ANCIENNE clé du coffre — le laisser en place donnerait un kit silencieusement
    /// inopérant, que l'utilisateur ne découvrirait qu'au moment où il en aurait besoin.
    #[tokio::test]
    async fn test_update_password_invalidates_recovery_kit() {
        let state = build_test_state().await;
        let email = "kit-after-change@example.com";
        register_test_user(&state, email, "ancien_mot_de_passe_123").await;
        sqlx::query("UPDATE users SET recovery_sealed_vault_key = ? WHERE email = ?")
            .bind("blob-scelle-ancienne-cle")
            .bind(email)
            .execute(&state.db)
            .await
            .unwrap();

        update_password(
            State(state.clone()),
            AuthUser { email: email.to_string(), is_moderator: false },
            Json(ChangeMasterPasswordPayload {
                old_master_password_hash: "ancien_mot_de_passe_123".to_string(),
                new_master_password_hash: "nouveau_mot_de_passe_789".to_string(),
                reencrypted_entries: vec![],
                reencrypted_history: vec![],
                reencrypted_attachments: vec![],
            }),
        )
        .await
        .expect("le changement de mot de passe doit réussir");

        let kit: Option<String> = sqlx::query_scalar("SELECT recovery_sealed_vault_key FROM users WHERE email = ?")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert!(
            kit.is_none(),
            "le kit doit être invalidé : il scelle une clé qui ne déchiffre plus rien"
        );
    }

    /// Même exigence pour la réinitialisation — et ici le coffre lui-même vient d'être vidé, donc
    /// le kit scellerait la clé d'un contenu qui n'existe plus.
    #[tokio::test]
    async fn test_password_reset_invalidates_recovery_kit() {
        let state = build_test_state().await;
        let email = "kit-after-reset@example.com";
        register_test_user(&state, email, "ancien_mot_de_passe_123").await;
        let code = setup_recovery(&state, email, "blob-scelle-ancienne-cle").await;

        confirm_password_reset(
            State(state.clone()),
            Json(ConfirmResetPayload {
                email: email.to_string(),
                code,
                new_master_password_hash: "nouveau_mot_de_passe_789".to_string(),
            }),
        )
        .await
        .expect("la réinitialisation doit réussir");

        let kit: Option<String> = sqlx::query_scalar("SELECT recovery_sealed_vault_key FROM users WHERE email = ?")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert!(kit.is_none(), "le kit doit être invalidé après une réinitialisation");
    }

}
