use axum::{
    extract::{State, Path, ConnectInfo},
    http::{StatusCode, HeaderMap, header},
    response::IntoResponse,
    Json
};
use std::{sync::Arc, net::SocketAddr};
use crate::{AppState, mailer, error::AppError, middleware::AuthUser, models::*};
use tracing::{warn, info};
use validator::Validate;
use super::common::{get_user_agent, set_server_choice_at_login_cache};

// --- ADMINISTRATION & LOGS ---

/// Récupère l'historique complet des logs d'audit du système (Réservé aux modérateurs et à l'Admin).
pub async fn get_audit_logs(
    State(state): State<Arc<AppState>>,
    user: AuthUser
) -> Result<impl IntoResponse, AppError> {
    // Vérification du rôle de modérateur (l'Admin, promu au démarrage, passe aussi cette porte)
    if !user.is_moderator {
        warn!("Tentative d'accès non autorisé aux logs par {}", user.email);
        return Err(AppError::Forbidden); // Retourne un statut 403 Forbidden
    }

    // Sélection des 100 derniers logs d'audit triés par date décroissante
    let logs = sqlx::query_as::<_, AuditLog>(
        "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 100"
    )
    .fetch_all(&state.db)
    .await?;

    Ok(Json(logs))
}

// --- ADMINISTRATION : GESTION DES COMPTES UTILISATEURS ---
// Tout ce qui suit est réservé AU MINIMUM aux modérateurs (`user.is_moderator`, vérifié
// systématiquement en première étape de chaque handler) — certaines actions sont en plus
// réservées exclusivement à l'Admin (voir `AuthUser::is_admin()` et check_can_act_on_target()
// plus bas). AUCUN de ces endpoints ne renvoie jamais `password_hash` (voir
// models.rs::AdminUserView) — même haché, ce champ n'a rien à faire dans une réponse HTTP.

/// Liste tous les comptes de l'application (email, rôle, statut de vérification, plafond
/// d'appareils) — vue d'ensemble pour un modérateur, ex. repérer un compte jamais vérifié ou
/// vérifier qui a les droits de modérateur avant de les révoquer.
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_moderator {
        warn!("Tentative d'accès non autorisé au listage des comptes par {}", user.email);
        return Err(AppError::Forbidden);
    }

    let mut users = sqlx::query_as::<_, AdminUserView>(
        "SELECT email, is_moderator, email_verified, created_at, max_trusted_devices, can_change_email_via_extension, can_choose_server_in_settings, is_suspended, max_vault_entries, max_attachments FROM users ORDER BY created_at DESC"
    )
    .fetch_all(&state.db)
    .await?;

    // ESPACE OCCUPÉ par compte — deux agrégats séparés plutôt qu'une jointure sur la requête
    // ci-dessus : joindre `vault` et `vault_attachments` à `users` en une fois multiplierait les
    // lignes (une par entrée ET par pièce jointe) et fausserait les totaux sans un GROUP BY
    // acrobatique. Deux petites requêtes agrégées, lues dans des tables de correspondance, restent
    // plus simples à relire — et le panneau Administration n'est pas un chemin chaud.
    let entry_counts: Vec<(String, i64)> = sqlx::query_as(
        "SELECT user_email, COUNT(*) FROM vault WHERE deleted_at IS NULL GROUP BY user_email",
    )
    .fetch_all(&state.db)
    .await?;
    let attachment_sizes: Vec<(String, i64)> = sqlx::query_as(
        "SELECT user_email, COALESCE(SUM(content_size), 0) FROM vault_attachments GROUP BY user_email",
    )
    .fetch_all(&state.db)
    .await?;

    // DERNIÈRE ACTIVITÉ — lue dans account_ip_history et non dans audit_logs, précisément parce
    // que cette table survit à la purge à 10 jours. Sur audit_logs, un compte dormant depuis huit
    // mois et un compte inactif depuis onze jours seraient indiscernables : tous deux « aucune
    // trace ». C'est justement la distinction qu'on cherche.
    let last_seen: Vec<(String, String)> = sqlx::query_as(
        "SELECT user_email, MAX(last_seen) FROM account_ip_history GROUP BY user_email",
    )
    .fetch_all(&state.db)
    .await?;

    let entry_counts: std::collections::HashMap<String, i64> = entry_counts.into_iter().collect();
    let attachment_sizes: std::collections::HashMap<String, i64> = attachment_sizes.into_iter().collect();
    let last_seen: std::collections::HashMap<String, String> = last_seen.into_iter().collect();

    // is_admin n'est pas une colonne SQL (voir models.rs::AdminUserView) — un seul compte peut
    // jamais correspondre à ADMIN_EMAIL, rempli après coup plutôt que par une comparaison SQL
    // supplémentaire.
    for u in &mut users {
        u.is_admin = state.config.admin_email.as_deref() == Some(u.email.as_str());
        // Absent des agrégats = aucune entrée / aucune pièce jointe, donc zéro (un GROUP BY ne
        // renvoie pas de ligne pour un compte qui n'a rien).
        u.entry_count = entry_counts.get(&u.email).copied().unwrap_or(0);
        u.attachment_bytes = attachment_sizes.get(&u.email).copied().unwrap_or(0);
        // Volontairement None et non une date bidon pour un compte jamais vu : « jamais connecté »
        // est une information à part entière, à ne pas confondre avec « connecté il y a longtemps ».
        u.last_seen = last_seen.get(&u.email).cloned();
    }

    Ok(Json(users))
}

/// Promeut ou rétrograde un compte MODÉRATEUR — il n'existe qu'un seul "Admin" (voir
/// `AuthUser::is_admin()`), on ne "promeut" jamais personne à ce rang.
/// GARDE-FOUS (demandés explicitement par le propriétaire de l'instance) :
/// - SEUL l'Admin (le compte configuré via `ADMIN_EMAIL` — voir
///   maintenance.rs::promote_configured_admin(), qui le repromeut modérateur de toute façon à
///   chaque redémarrage) peut appeler cet endpoint. Un modérateur, même avec `is_moderator = true`
///   en base, ne peut promouvoir ni rétrograder personne — seul l'Admin gère les rôles.
///   CONSÉQUENCE si `ADMIN_EMAIL` n'est pas configuré (`None`) : personne ne peut plus changer de
///   rôle via cet endpoint (aucun compte ne correspond) — acceptable pour ce déploiement (qui
///   configure toujours `ADMIN_EMAIL`), mais à savoir si ce n'était pas le cas ailleurs.
/// - L'Admin ne peut pas modifier SON PROPRE rôle via cet endpoint (évite un verrouillage
///   accidentel — voir aussi la vérification ci-dessous, qui reste une seconde ligne de défense
///   même si la garde ci-dessus la rend normalement inatteignable en pratique).
pub async fn update_user_role(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(target_email): Path<String>,
    Json(payload): Json<UpdateUserRolePayload>,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_admin(&state) {
        warn!("Tentative d'accès non autorisé au changement de rôle par {} (pas l'Admin)", user.email);
        return Err(AppError::Forbidden);
    }

    let target_email = target_email.to_lowercase();
    if target_email == user.email {
        return Err(AppError::ValidationError(
            "Impossible de modifier son propre rôle via cet endpoint".to_string()
        ));
    }

    // Seconde ligne de défense (voir la doc ci-dessus) : normalement inatteignable puisque seul
    // l'Admin peut arriver jusqu'ici, et la vérification d'auto-modification juste au-dessus
    // bloque déjà cette cible précise — gardée pour rester sûr même si l'une des deux évolue seule.
    if !payload.is_moderator && state.config.admin_email.as_deref() == Some(target_email.as_str()) {
        warn!("Tentative de rétrogradation de l'Admin (ADMIN_EMAIL) par {}", user.email);
        return Err(AppError::ValidationError(
            "L'Admin (défini par ADMIN_EMAIL) ne peut jamais être rétrogradé".to_string()
        ));
    }

    let res = sqlx::query("UPDATE users SET is_moderator = ? WHERE email = ?")
        .bind(payload.is_moderator)
        .bind(&target_email)
        .execute(&state.db)
        .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    let action = if payload.is_moderator { "MODERATOR_ROLE_GRANTED" } else { "MODERATOR_ROLE_REVOKED" };
    let agent = get_user_agent(&headers);
    // Journalisé sous l'email de la CIBLE (voir get_audit_logs) : un modérateur qui consulte
    // l'audit voit directement quel compte a été affecté, cohérent avec le reste des logs d'audit
    // du projet (ex: DEVICE_REVOKED, LOGOUT_ALL_DEVICES...).
    state.log_audit(&target_email, action, addr.to_string(), agent).await;
    info!("Rôle modérateur de {} modifié par {} (is_moderator={})", target_email, user.email, payload.is_moderator);

    Ok(StatusCode::OK)
}

/// Vérifie qu'un modérateur (ou l'Admin) a le droit d'agir sur `target_email` via un endpoint qui
/// cible UN compte précis (suppression, révocation de sessions, réglage extension/email) — règle
/// demandée explicitement par le propriétaire de l'instance :
///
/// - L'Admin (`ADMIN_EMAIL`) ne peut JAMAIS être la cible d'un de ces endpoints, par personne (lui
///   y compris — il doit utiliser les équivalents en libre-service pour son propre compte, ex:
///   `POST /devices/logout-all`).
/// - Un modérateur ne peut agir QUE sur des comptes non-modérateur — agir sur un AUTRE modérateur
///   (promotion mise à part, déjà réservée à l'Admin via `update_user_role()`) reste réservé à
///   l'Admin.
/// - L'Admin peut agir sur n'importe quel compte non-modérateur ou modérateur.
///
/// Renvoie `NotFound` si la cible n'existe pas — centralise ce cas ici plutôt que de le répéter
/// dans chaque handler appelant.
async fn check_can_act_on_target(state: &AppState, caller: &AuthUser, target_email: &str) -> Result<(), AppError> {
    if state.config.admin_email.as_deref() == Some(target_email) {
        return Err(AppError::Forbidden);
    }

    let target_is_moderator: Option<bool> = sqlx::query_scalar("SELECT is_moderator FROM users WHERE email = ?")
        .bind(target_email)
        .fetch_optional(&state.db)
        .await?;
    let target_is_moderator = target_is_moderator.ok_or(AppError::NotFound)?;

    if target_is_moderator && !caller.is_admin(state) {
        return Err(AppError::Forbidden);
    }

    Ok(())
}

/// Change l'email d'un AUTRE compte, DÉCLENCHÉ PAR UN MODÉRATEUR (ou l'Admin) — pour un
/// utilisateur qui a perdu l'accès à sa boîte mail, ou une simple faute de frappe à l'inscription.
/// Ne touche JAMAIS au mot de passe maître ni à la clé du coffre (email seul, pas de donnée
/// cryptographique) : le Zero-Knowledge reste intact, l'appelant ne peut toujours pas accéder au
/// contenu du coffre de la cible.
///
/// GARDE-FOUS (discutés avec l'utilisateur avant implémentation) :
///
/// - L'appelant ne peut PAS l'utiliser sur SON PROPRE compte — l'auto-service `PUT /auth/email`
///   existe déjà pour ça, avec sa propre reconfirmation par mot de passe.
/// - L'alerte de sécurité part vers L'ANCIENNE adresse (comme pour un changement volontaire) —
///   seul moyen pour le vrai propriétaire du compte de s'apercevoir du changement s'il n'en est
///   pas à l'origine (ex: modérateur compromis essayant de détourner l'identité d'un compte via
///   email + "mot de passe oublié" — la purge du coffre inhérente à cette dernière étape empêche
///   toujours l'accès au contenu EXISTANT, mais pas la prise de contrôle de l'identité elle-même :
///   cette alerte reste la seule protection contre CE scénario précis).
/// - Tracé dans l'audit sous le NOUVEL email (comme ça, l'historique de sécurité du compte reste
///   consultable par son propriétaire une fois reconnecté sous sa nouvelle adresse).
///
/// Voir aussi check_can_act_on_target() ci-dessus : même hiérarchie que
/// delete_user()/revoke_user_sessions()/update_extension_email_change_setting() — l'Admin ne peut
/// JAMAIS être ciblé (personne ne peut changer son email, lui y compris via cet endpoint), et un
/// modérateur ne peut cibler que des comptes non-modérateur.
pub async fn admin_update_user_email(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(target_email): Path<String>,
    Json(payload): Json<AdminUpdateEmailPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_moderator {
        warn!("Tentative d'accès non autorisé au changement d'email admin par {}", user.email);
        return Err(AppError::Forbidden);
    }

    payload.validate()?;

    let old_email = target_email.to_lowercase();
    if old_email == user.email {
        return Err(AppError::ValidationError(
            "Impossible de modifier son propre email via cet endpoint — utilise PUT /auth/email".to_string()
        ));
    }
    check_can_act_on_target(&state, &user, &old_email).await?;

    let new_email = payload.new_email.to_lowercase();

    let mut tx = state.db.begin().await?;

    let res = sqlx::query("UPDATE users SET email = ? WHERE email = ?")
        .bind(&new_email)
        .bind(&old_email)
        .execute(&mut *tx)
        .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    // Invalidation forcée des sessions, même raison que le changement d'email en libre-service
    // (voir handlers/auth/account.rs::update_email) : le compte doit se reconnecter sous sa
    // nouvelle adresse.
    sqlx::query("DELETE FROM refresh_tokens WHERE user_email = ?")
        .bind(&new_email)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    let _ = mailer::send_security_alert(
        &old_email,
        "Votre adresse e-mail a été modifiée par un administrateur. Si vous n'êtes pas à l'origine de cette demande, contacte immédiatement un administrateur de confiance.",
        &state.config,
    ).await;

    let agent = get_user_agent(&headers);
    state.log_audit(&new_email, "ADMIN_EMAIL_CHANGED", addr.to_string(), agent).await;
    info!("Email de {} changé en {} par {}", old_email, new_email, user.email);

    Ok(StatusCode::OK)
}

/// Autorise ou interdit à UN compte précis de changer son email DEPUIS L'EXTENSION NAVIGATEUR
/// (voir handlers/auth/account.rs::update_email() + common::is_extension_origin) — désactivé par
/// défaut pour tout le monde (voir la migration), l'Admin reste toujours autorisé indépendamment
/// de cette colonne. Voir aussi update_extension_email_change_setting_all() ci-dessous pour
/// l'activer/désactiver en masse.
pub async fn update_extension_email_change_setting(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(target_email): Path<String>,
    Json(payload): Json<UpdateExtensionEmailChangePayload>,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_moderator {
        warn!("Tentative d'accès non autorisé au réglage extension/email par {}", user.email);
        return Err(AppError::Forbidden);
    }

    let target_email = target_email.to_lowercase();
    check_can_act_on_target(&state, &user, &target_email).await?;

    let res = sqlx::query("UPDATE users SET can_change_email_via_extension = ? WHERE email = ?")
        .bind(payload.enabled)
        .bind(&target_email)
        .execute(&state.db)
        .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    let action = if payload.enabled { "EXTENSION_EMAIL_CHANGE_ENABLED" } else { "EXTENSION_EMAIL_CHANGE_DISABLED" };
    let agent = get_user_agent(&headers);
    state.log_audit(&target_email, action, addr.to_string(), agent).await;
    info!("Changement d'email via extension pour {} réglé par {} (enabled={})", target_email, user.email, payload.enabled);

    Ok(StatusCode::OK)
}

/// Même réglage que ci-dessus, mais appliqué à TOUS les comptes d'un coup (pas de `Path`, pas de
/// `WHERE` dans la requête) — le levier "pour tout le monde" demandé en plus du réglage par compte.
/// GARDE-FOU : réservé à l'Admin uniquement — cette variante touche TOUS les comptes, modérateurs
/// compris (impossible de les exclure proprement d'un `UPDATE` sans clause), donc la même règle
/// "un modérateur ne peut pas agir sur un autre modérateur" s'applique de fait à l'ensemble.
pub async fn update_extension_email_change_setting_all(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<UpdateExtensionEmailChangePayload>,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_admin(&state) {
        warn!("Tentative d'accès non autorisé au réglage extension/email (global) par {} (pas l'Admin)", user.email);
        return Err(AppError::Forbidden);
    }

    sqlx::query("UPDATE users SET can_change_email_via_extension = ?")
        .bind(payload.enabled)
        .execute(&state.db)
        .await?;

    let action = if payload.enabled { "EXTENSION_EMAIL_CHANGE_ENABLED_ALL" } else { "EXTENSION_EMAIL_CHANGE_DISABLED_ALL" };
    let agent = get_user_agent(&headers);
    // Journalisé sous l'email de L'ADMIN qui a déclenché l'action (pas de "cible" unique ici,
    // contrairement à la variante par compte ci-dessus).
    state.log_audit(&user.email, action, addr.to_string(), agent).await;
    info!("Changement d'email via extension réglé pour TOUS les comptes par {} (enabled={})", user.email, payload.enabled);

    Ok(StatusCode::OK)
}

/// Autorise ou interdit à UN compte précis de changer l'adresse du backend DEPUIS LES RÉGLAGES,
/// une fois connecté (voir frontend(app)/src/components/ServerUrlForm.tsx) — désactivé par défaut
/// pour tout le monde (voir la migration), l'Admin reste toujours autorisé indépendamment de cette
/// colonne. Voir aussi update_server_choice_in_settings_all() pour l'activer/désactiver en masse,
/// et update_server_choice_at_login() pour le réglage GLOBAL équivalent côté écran de connexion.
///
/// GARDE-FOU délibérément plus strict que update_extension_email_change_setting() ci-dessus
/// (réservé aux modérateurs) : réservé à l'ADMIN SEUL. Rediriger l'app de quelqu'un vers un autre
/// backend est un vecteur d'hameçonnage bien plus sensible qu'autoriser un changement d'email —
/// un faux backend pourrait capter le hash du mot de passe maître envoyé à la connexion.
pub async fn update_server_choice_in_settings(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(target_email): Path<String>,
    Json(payload): Json<UpdateServerChoiceInSettingsPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_admin(&state) {
        warn!("Tentative d'accès non autorisé au réglage choix de serveur par {} (pas l'Admin)", user.email);
        return Err(AppError::Forbidden);
    }

    let target_email = target_email.to_lowercase();
    check_can_act_on_target(&state, &user, &target_email).await?;

    let res = sqlx::query("UPDATE users SET can_choose_server_in_settings = ? WHERE email = ?")
        .bind(payload.enabled)
        .bind(&target_email)
        .execute(&state.db)
        .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    let action = if payload.enabled { "SERVER_CHOICE_IN_SETTINGS_ENABLED" } else { "SERVER_CHOICE_IN_SETTINGS_DISABLED" };
    let agent = get_user_agent(&headers);
    state.log_audit(&target_email, action, addr.to_string(), agent).await;
    info!("Choix du serveur dans les réglages pour {} réglé par {} (enabled={})", target_email, user.email, payload.enabled);

    Ok(StatusCode::OK)
}

/// Même réglage que ci-dessus, mais appliqué à TOUS les comptes d'un coup — voir
/// update_extension_email_change_setting_all() pour le raisonnement identique (Admin uniquement,
/// touche potentiellement des modérateurs sans clause d'exclusion possible dans un `UPDATE` seul).
pub async fn update_server_choice_in_settings_all(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<UpdateServerChoiceInSettingsPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_admin(&state) {
        warn!("Tentative d'accès non autorisé au réglage choix de serveur (global) par {} (pas l'Admin)", user.email);
        return Err(AppError::Forbidden);
    }

    sqlx::query("UPDATE users SET can_choose_server_in_settings = ?")
        .bind(payload.enabled)
        .execute(&state.db)
        .await?;

    let action = if payload.enabled { "SERVER_CHOICE_IN_SETTINGS_ENABLED_ALL" } else { "SERVER_CHOICE_IN_SETTINGS_DISABLED_ALL" };
    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, action, addr.to_string(), agent).await;
    info!("Choix du serveur dans les réglages réglé pour TOUS les comptes par {} (enabled={})", user.email, payload.enabled);

    Ok(StatusCode::OK)
}

/// Réglage GLOBAL (PAS par compte, voir la table app_settings/migration) : contrôle si le lien
/// "Configurer le serveur" est visible sur l'écran de connexion, AVANT toute authentification (voir
/// pages/Login.tsx, qui lit ce réglage via l'endpoint public GET /public-config, et
/// handlers/common.rs::get_public_config()). Réservé à l'Admin seul, même raisonnement que
/// update_server_choice_in_settings() ci-dessus — encore plus sensible ici : quiconque ouvre l'app,
/// même sans compte, verrait ce lien si activé.
pub async fn update_server_choice_at_login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<UpdateServerChoiceAtLoginPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_admin(&state) {
        warn!("Tentative d'accès non autorisé au réglage choix de serveur à la connexion par {} (pas l'Admin)", user.email);
        return Err(AppError::Forbidden);
    }

    sqlx::query("UPDATE app_settings SET server_choice_at_login_enabled = ? WHERE id = 1")
        .bind(payload.enabled)
        .execute(&state.db)
        .await?;
    // CORRECTIF PERF (voir handlers/common.rs::get_public_config) : garde le cache en mémoire à
    // jour immédiatement, sans quoi /public-config continuerait de refléter l'ANCIENNE valeur
    // jusqu'au redémarrage du serveur (le cache, une fois rempli, ne se revalide jamais tout seul
    // contre la base — c'est justement tout l'intérêt en termes de performance).
    set_server_choice_at_login_cache(payload.enabled);

    let action = if payload.enabled { "SERVER_CHOICE_AT_LOGIN_ENABLED" } else { "SERVER_CHOICE_AT_LOGIN_DISABLED" };
    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, action, addr.to_string(), agent).await;
    info!("Choix du serveur à la connexion (global) réglé par {} (enabled={})", user.email, payload.enabled);

    Ok(StatusCode::OK)
}

/// Révoque IMMÉDIATEMENT toutes les sessions actives d'un AUTRE utilisateur (tous appareils,
/// access tokens déjà émis inclus) — même mécanisme que handlers/devices.rs::logout_all_devices(),
/// déclenché ici par un modérateur (ou l'Admin) plutôt que par l'utilisateur lui-même. Utile en
/// cas de compte compromis signalé, sans avoir à attendre que l'utilisateur agisse de son côté.
/// Voir check_can_act_on_target() : l'Admin (ADMIN_EMAIL) ne peut jamais être ciblé (même par
/// lui-même — utiliser POST /devices/logout-all pour ses propres sessions), et un modérateur ne
/// peut cibler que des comptes non-modérateur.
pub async fn revoke_user_sessions(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(target_email): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_moderator {
        warn!("Tentative d'accès non autorisé à la révocation de sessions par {}", user.email);
        return Err(AppError::Forbidden);
    }

    let target_email = target_email.to_lowercase();
    check_can_act_on_target(&state, &user, &target_email).await?;

    let mut tx = state.db.begin().await?;

    sqlx::query("DELETE FROM refresh_tokens WHERE user_email = ?")
        .bind(&target_email)
        .execute(&mut *tx)
        .await?;

    // "sessions_revoked_at" n'existe QUE sur une ligne `users` déjà présente : si la cible
    // n'existe pas, cette requête affecte 0 ligne et on renvoie NotFound plus bas — même si le
    // DELETE ci-dessus a "réussi" (0 ligne supprimée aussi dans ce cas, silencieusement).
    let res = sqlx::query("UPDATE users SET sessions_revoked_at = CURRENT_TIMESTAMP WHERE email = ?")
        .bind(&target_email)
        .execute(&mut *tx)
        .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    tx.commit().await?;

    // Ferme aussi toute connexion WebSocket active de la cible — même mécanisme que
    // logout_all_devices() (voir handlers/sync.rs::handle_socket()).
    let _ = state.sync_tx.send(SyncEvent { user_email: target_email.clone(), event_type: "SESSION_REVOKED".to_string() });

    let agent = get_user_agent(&headers);
    state.log_audit(&target_email, "ADMIN_SESSIONS_REVOKED", addr.to_string(), agent).await;
    info!("Sessions de {} révoquées par {}", target_email, user.email);

    Ok(StatusCode::NO_CONTENT)
}

/// Supprime DÉFINITIVEMENT un compte (et tout ce qui lui est rattaché : coffre, appareils de
/// confiance, sessions, codes 2FA en attente — voir `ON DELETE CASCADE` dans les migrations).
/// Aucun retour en arrière possible.
/// GARDE-FOUS :
/// - L'appelant ne peut pas supprimer SON PROPRE compte via cet endpoint (même raison que
///   update_user_role() — évite de se retrouver sans accès par erreur de manipulation).
/// - Voir check_can_act_on_target() : l'Admin (ADMIN_EMAIL) ne peut jamais être supprimé, et un
///   modérateur ne peut supprimer que des comptes non-modérateur (supprimer un AUTRE modérateur
///   reste réservé à l'Admin).
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(target_email): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_moderator {
        warn!("Tentative d'accès non autorisé à la suppression de compte par {}", user.email);
        return Err(AppError::Forbidden);
    }

    let target_email = target_email.to_lowercase();
    if target_email == user.email {
        return Err(AppError::ValidationError("Impossible de supprimer son propre compte via cet endpoint".to_string()));
    }
    check_can_act_on_target(&state, &user, &target_email).await?;

    let res = sqlx::query("DELETE FROM users WHERE email = ?")
        .bind(&target_email)
        .execute(&state.db)
        .await?;

    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    // CORRECTIF : `audit_logs.user_email` n'a plus de contrainte de clé étrangère vers
    // `users(email)` (voir migration 20260829000001_audit_logs_survive_account_deletion.sql,
    // précisément pour ce genre de cas) — on peut donc désormais journaliser cet événement sous
    // l'email de la CIBLE, pour que son historique d'audit reste consultable jusqu'à sa toute
    // dernière action même après suppression du compte (c'est là tout l'intérêt d'un journal
    // d'audit). L'identité de l'appelant qui a agi reste, elle, dans le log applicatif structuré
    // (`info!` ci-dessous) plutôt que dans cette colonne, qui ne porte qu'un seul email.
    let agent = get_user_agent(&headers);
    state.log_audit(&target_email, "ADMIN_DELETED_USER_ACCOUNT", addr.to_string(), agent).await;
    info!("Compte {} supprimé définitivement par {}", target_email, user.email);

    Ok(StatusCode::NO_CONTENT)
}

// =========================================================================
// TESTS SUR L'ADMINISTRATION
// =========================================================================
// =========================================================================
// CONTRÔLES D'ADMINISTRATION (voir la migration 20260904100000_admin_controls.sql)
// =========================================================================

/// Ouvre ou ferme les INSCRIPTIONS (réglage global, Admin uniquement).
///
/// L'inscription était ouverte à quiconque atteignait le serveur : sur un déploiement familial
/// exposé sur Internet, n'importe qui trouvant l'URL pouvait créer un compte, donc consommer
/// l'espace disque, déclencher des envois depuis le SMTP du propriétaire et remplir le journal
/// d'audit. Le réglage reste OUVERT par défaut pour ne rien casser à la migration — c'est à
/// l'Admin de refermer une fois ses comptes créés.
pub async fn update_registration_open(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<UpdateRegistrationOpenPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_admin(&state) {
        warn!("Tentative de modification de l'ouverture des inscriptions par {} (pas l'Admin)", user.email);
        return Err(AppError::Forbidden);
    }

    sqlx::query("UPDATE app_settings SET registration_open = ? WHERE id = 1")
        .bind(payload.enabled)
        .execute(&state.db)
        .await?;

    let action = if payload.enabled { "REGISTRATION_OPENED" } else { "REGISTRATION_CLOSED" };
    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, action, addr.to_string(), agent).await;
    info!("Inscriptions réglées par {} (open={})", user.email, payload.enabled);

    Ok(StatusCode::OK)
}

/// Toutes les adresses IP vues pour UN compte, avec ce qu'elles ont produit.
///
/// Lit `account_ip_history` (voir la migration 20260904120000), pas `audit_logs` : l'historique
/// n'est donc plus tronqué à la purge de 10 jours du journal. Une adresse revenant tous les
/// quinze jours n'apparaît plus comme neuve à chaque fois — c'est justement le cas à repérer.
///
/// Trois chiffres par adresse, parce qu'une IP nue ne dit rien :
/// - `success_count` / `failure_count` : beaucoup d'échecs PUIS une réussite depuis la même
///   adresse est la signature d'une intrusion réussie par tâtonnement. C'est le signal qui répond
///   réellement à "quelqu'un a-t-il réussi à entrer sur le compte d'un autre".
/// - `other_accounts` : combien d'AUTRES comptes ont utilisé cette même adresse. À lire avec
///   prudence sur un serveur familial, où tout le monde partage l'IP publique de la maison : c'est
///   le croisement (adresse partagée QUI PORTE AUSSI des échecs) qui est parlant, pas le partage.
///
/// Même porte que `GET /audit` (modérateur) : réserver celle-ci à l'Admin donnerait l'illusion
/// d'une protection alors que les mêmes IP restent lisibles en vrac juste à côté.
///
/// ATTENTION à l'interprétation : derrière un reverse proxy sans `TRUST_PROXY_HEADERS=true`, TOUS
/// les comptes apparaissent avec l'IP du proxy. La route ne peut pas le deviner ; le client
/// prévient (voir Admin.tsx).
pub async fn get_user_ip_history(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(target_email): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_moderator {
        warn!("Tentative de consultation d'historique IP par {} (pas modérateur)", user.email);
        return Err(AppError::Forbidden);
    }
    let target_email = target_email.to_lowercase();

    // Plafond dur : un compte visé par une rotation d'adresses pourrait sinon renvoyer une réponse
    // sans borne. 500 adresses distinctes dépassent de très loin tout usage réel, et la purge de
    // maintenance ramène de toute façon la table sous ce seuil (voir maintenance.rs).
    let history = sqlx::query_as::<_, crate::models::UserIpHistoryEntry>(
        "SELECT h.ip_address,                 h.first_seen,                 h.last_seen,                 h.event_count,                 h.success_count,                 h.failure_count,                 (SELECT COUNT(*) FROM account_ip_history AS o                   WHERE o.ip_address = h.ip_address AND o.user_email <> h.user_email) AS other_accounts            FROM account_ip_history AS h           WHERE h.user_email = ?           ORDER BY h.last_seen DESC           LIMIT 500",
    )
    .bind(&target_email)
    .fetch_all(&state.db)
    .await?;

    // Résolution de l'origine APRÈS la requête, en mémoire : la base MMDB est déjà chargée (voir
    // geoip.rs), donc chaque adresse coûte une lecture d'arbre, sans I/O ni réseau. Inerte tant
    // qu'aucune base n'est configurée.
    let entries: Vec<_> = history
        .into_iter()
        .map(|mut row| {
            row.location = state.geoip.lookup(&row.ip_address);
            row
        })
        .collect();

    // Surveiller les surveillants : consulter les adresses de quelqu'un est un acte privilégié, il
    // laisse donc lui-même une trace. Sans cela, un modérateur pourrait éplucher les déplacements
    // des autres comptes sans qu'il en reste rien — la seule catégorie d'accès de l'application
    // qui échapperait au journal. Tracé sous l'email du CONSULTANT, avec la cible en clair.
    let agent = get_user_agent(&headers);
    state
        .log_audit(&user.email, &format!("IP_HISTORY_VIEWED:{target_email}"), addr.to_string(), agent)
        .await;

    Ok(Json(crate::models::UserIpHistoryResponse {
        // Lu APRÈS les résolutions ci-dessus : le résolveur peut charger sa base à ce moment-là
        // (reprise différée, voir geoip.rs), et annoncer `false` juste avant serait faux.
        geoip_enabled: state.geoip.is_enabled(),
        entries,
    }))
}

/// Exporte le journal d'audit complet en CSV.
///
/// Le journal est purgé à 10 jours (voir maintenance.rs) : sans moyen de l'emporter, tout ce qui
/// dépasse cette fenêtre est perdu pour de bon. Cette route permet d'en garder une trace hors du
/// serveur, et de l'analyser dans un tableur plutôt qu'à travers un écran paginé.
///
/// Réservé aux modérateurs, comme `GET /audit` : ce sont exactement les mêmes données, dans un
/// autre emballage — les réserver ici tout en les laissant lisibles là ne protégerait rien.
///
/// Exporte TOUT le journal, sans la limite de 100 lignes de `GET /audit` : une exportation
/// tronquée serait pire qu'inutile, on croirait tenir l'historique complet. La table est bornée
/// par la purge, donc l'export l'est aussi.
pub async fn export_audit_logs_csv(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_moderator {
        warn!("Tentative d'export du journal par {} (pas modérateur)", user.email);
        return Err(AppError::Forbidden);
    }

    let lignes: Vec<(String, String, String, Option<String>, String)> = sqlx::query_as(
        "SELECT created_at, user_email, action, user_agent, ip_address \
           FROM audit_logs ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await?;

    let mut csv = String::from("date,compte,action,adresse_ip,navigateur\n");
    for (date, email, action, agent, ip) in &lignes {
        csv.push_str(&format!(
            "{},{},{},{},{}\n",
            csv_field(date),
            csv_field(email),
            csv_field(action),
            csv_field(ip),
            csv_field(agent.as_deref().unwrap_or("")),
        ));
    }

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "AUDIT_LOG_EXPORTED", addr.to_string(), agent).await;

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"journal-audit.csv\"".to_string(),
            ),
        ],
        csv,
    ))
}

/// Échappe un champ CSV selon la RFC 4180.
///
/// Indispensable ici : un User-Agent contient des virgules et des guillemets, et une adresse IP
/// n'est pas garantie exempte de surprise. Sans échappement, une seule virgule décale toutes les
/// colonnes de la ligne — et un tableur ouvre le fichier sans rien signaler, ce qui donne une
/// analyse fausse plutôt qu'une erreur visible.
fn csv_field(valeur: &str) -> String {
    if valeur.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", valeur.replace('"', "\"\""))
    } else {
        valeur.to_string()
    }
}

/// Règle les quotas d'UN compte (Admin uniquement).
///
/// `null` sur un champ remet ce compte sur le plafond global codé dans handlers/vault.rs — c'est
/// distinct de `0`, qui interdit réellement toute nouvelle entrée. Les deux sont légitimes : le
/// premier dit « comme tout le monde », le second gèle un compte sans le suspendre.
///
/// Les quotas ne s'appliquent qu'aux AJOUTS. Abaisser un quota sous ce qu'un compte possède déjà
/// ne supprime rien : il conserve ses entrées et ne peut plus en créer. Supprimer les données de
/// quelqu'un parce qu'un chiffre a bougé dans un écran d'administration serait indéfendable.
pub async fn update_quotas(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(target_email): Path<String>,
    Json(payload): Json<crate::models::UpdateQuotasPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_admin(&state) {
        warn!("Tentative de modification de quotas par {} (pas l'Admin)", user.email);
        return Err(AppError::Forbidden);
    }
    if payload.entries_value().is_some_and(|v| v < 0) || payload.attachments_value().is_some_and(|v| v < 0) {
        return Err(AppError::ValidationError("Un quota ne peut pas être négatif.".to_string()));
    }
    let target_email = target_email.to_lowercase();

    // Chaque champ n'est écrit que s'il était PRÉSENT dans la requête. Sans ces conditions, un
    // client envoyant `{"max_vault_entries": 5}` verrait l'autre quota remis à NULL sans l'avoir
    // demandé : en serde, un champ Option absent vaut None, indistinguable d'un `null` explicite.
    // Le CASE garde le SQL statique — pas de requête construite à la volée, le projet l'interdit.
    let res = sqlx::query(
        "UPDATE users SET \
             max_vault_entries = CASE WHEN ? THEN ? ELSE max_vault_entries END, \
             max_attachments   = CASE WHEN ? THEN ? ELSE max_attachments END \
           WHERE email = ?",
    )
    .bind(payload.entries_present())
    .bind(payload.entries_value())
    .bind(payload.attachments_present())
    .bind(payload.attachments_value())
    .bind(&target_email)
    .execute(&state.db)
    .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "QUOTAS_UPDATED", addr.to_string(), agent).await;
    info!(
        "Quotas de {} réglés par {} (entrées={:?}, pièces jointes={:?})",
        target_email, user.email, payload.entries_value(), payload.attachments_value()
    );

    Ok(StatusCode::OK)
}

/// Compacte la base (VACUUM) et renvoie ce que l'opération a rendu au disque.
///
/// Réservé à l'Admin : c'est une opération sur le fichier, pas sur des comptes.
///
/// VACUUM réécrit INTÉGRALEMENT la base dans un fichier temporaire avant de la remplacer. Deux
/// conséquences à ne pas ignorer :
/// - il faut temporairement de la place pour une seconde copie. Sur un disque déjà tendu — la
///   situation même qui pousse à lancer un VACUUM — l'opération peut échouer faute d'espace, et
///   c'est pour cela que l'écran affiche l'espace libre juste à côté du bouton ;
/// - il prend un verrou exclusif : les écritures attendent. Sur une base familiale de quelques
///   centaines de Mo, c'est l'affaire de quelques secondes.
///
/// Aucune donnée n'est perdue : VACUUM ne supprime rien, il réorganise. Ce qu'il rend est l'espace
/// déjà libéré par des suppressions passées, que SQLite conservait pour ses prochaines écritures.
pub async fn vacuum_database(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_admin(&state) {
        warn!("Tentative de VACUUM par {} (pas l'Admin)", user.email);
        return Err(AppError::Forbidden);
    }

    // `swap` plutôt que `load` puis `store` : la vérification et la prise du drapeau sont une
    // seule opération atomique, donc deux requêtes simultanées ne peuvent pas passer toutes les
    // deux (ce qu'un test-puis-pose laisserait arriver).
    use std::sync::atomic::Ordering;
    if state.vacuum_in_progress.swap(true, Ordering::SeqCst) {
        return Err(AppError::ValidationError(
            "Un compactage est déjà en cours. Il continue même si la requête précédente a expiré : \
             attends qu'il se termine avant d'en lancer un autre."
                .to_string(),
        ));
    }

    let chemin = crate::health::database_path(&state.config.database_url);
    let before = crate::health::file_size(&chemin);

    let resultat = sqlx::query("VACUUM").execute(&state.db).await;

    // Relâché dans TOUS les cas, y compris en échec : sans cela, un VACUUM raté condamnerait la
    // fonctionnalité jusqu'au prochain redémarrage.
    state.vacuum_in_progress.store(false, Ordering::SeqCst);
    resultat?;

    let after = crate::health::file_size(&chemin);
    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "DATABASE_VACUUMED", addr.to_string(), agent).await;
    info!("VACUUM par {} : {} -> {} octets", user.email, before, after);

    Ok(Json(crate::models::VacuumResult {
        before_bytes: before,
        after_bytes: after,
        // Signé : un VACUUM peut très légèrement AGRANDIR une base déjà compacte (réorganisation
        // des pages). Renvoyer un négatif est honnête ; le forcer à 0 masquerait le fait qu'il
        // n'y avait rien à gagner.
        freed_bytes: before as i64 - after as i64,
    }))
}

/// Envoie un email de test à l'adresse de l'Admin, pour vérifier la configuration SMTP.
///
/// Existe parce qu'un SMTP cassé ne se découvre autrement qu'au pire moment : quand quelqu'un a
/// besoin d'une réinitialisation de mot de passe ou d'un code de connexion, et que rien n'arrive.
/// C'est le même piège que la sauvegarde silencieuse — ça casse sans bruit.
///
/// Toujours envoyé à l'Admin lui-même, jamais à une adresse fournie dans la requête : une route
/// authentifiée capable d'expédier du courrier vers une adresse arbitraire serait un relais ouvert
/// pour qui volerait ce compte.
pub async fn send_test_email(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_admin(&state) {
        warn!("Tentative d'envoi d'email de test par {} (pas l'Admin)", user.email);
        return Err(AppError::Forbidden);
    }

    // DÉLAI MINIMAL ENTRE DEUX TESTS.
    //
    // Signalé en usage réel : un clic sur le bouton, quatre emails reçus. L'envoi SMTP prend
    // plusieurs secondes, le bouton ne montrait rien, l'utilisateur a cliqué à nouveau. Le client
    // affiche désormais son état — mais compter là-dessus ne suffit pas : chaque envoi consomme le
    // quota SMTP du propriétaire et pèse sur la réputation de son domaine, et un client buggé,
    // rechargé ou remplacé n'a aucune obligation d'être prudent.
    //
    // 60 secondes : assez pour absorber une rafale de clics, assez court pour retester après avoir
    // corrigé un réglage SMTP — le cas d'usage même de cette route.
    const DELAI_ENTRE_TESTS_SECONDES: i64 = 60;
    let recent: Option<String> = sqlx::query_scalar(
        "SELECT created_at FROM audit_logs \
          WHERE action = 'TEST_EMAIL_SENT' AND created_at > DATETIME('now', '-60 seconds') \
          LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await?;
    if recent.is_some() {
        return Err(AppError::ValidationError(format!(
            "Un email de test vient d'être envoyé. Attends {DELAI_ENTRE_TESTS_SECONDES} secondes avant de recommencer — vérifie d'abord ta boîte, y compris les indésirables."
        )));
    }

    crate::mailer::send_security_alert(
        &user.email,
        "Ceci est un email de test envoyé depuis le panneau Administration de ton gestionnaire de \
         mots de passe. Si tu le reçois, la configuration SMTP du serveur fonctionne : les codes de \
         connexion, vérifications d'adresse et réinitialisations de mot de passe partiront bien.",
        &state.config,
    )
    .await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "TEST_EMAIL_SENT", addr.to_string(), agent).await;
    Ok(StatusCode::OK)
}

/// État de santé du serveur : disque, base, sauvegardes, activité (voir health.rs).
///
/// Réservé à l'Admin, et non aux modérateurs comme le reste de cet écran : ces mesures portent sur
/// la MACHINE, pas sur les comptes. Un modérateur gère des personnes ; connaître l'espace disque
/// restant et l'empreinte mémoire du processus relève de celui qui exploite le serveur.
pub async fn get_server_health(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_admin(&state) {
        warn!("Tentative de consultation de l'état du serveur par {} (pas l'Admin)", user.email);
        return Err(AppError::Forbidden);
    }

    let started_at = state.started_at;
    Ok(Json(crate::health::collect(&state, started_at).await))
}

/// Suspend ou réactive un compte — marche intermédiaire entre "ne rien faire" et la suppression
/// définitive, qui cascade sur tout le coffre et ne se rattrape pas.
///
/// Une suspension coupe AUSSI les sessions en cours : sans cela, un compte suspendu resterait
/// utilisable jusqu'à l'expiration de son jeton d'accès. Le middleware refuse par ailleurs tout
/// jeton d'un compte suspendu (voir middleware.rs).
///
/// Passe par check_can_act_on_target() comme les autres actions sur un compte tiers : l'Admin ne
/// peut pas être suspendu, et un modérateur ne peut pas suspendre un autre modérateur.
pub async fn update_suspended(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(target_email): Path<String>,
    Json(payload): Json<UpdateSuspendedPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_moderator {
        warn!("Tentative de suspension de compte par {} (pas modérateur)", user.email);
        return Err(AppError::Forbidden);
    }
    let target_email = target_email.to_lowercase();
    check_can_act_on_target(&state, &user, &target_email).await?;

    let mut tx = state.db.begin().await?;
    let res = sqlx::query("UPDATE users SET is_suspended = ? WHERE email = ?")
        .bind(payload.is_suspended)
        .bind(&target_email)
        .execute(&mut *tx)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }

    if payload.is_suspended {
        sqlx::query("DELETE FROM refresh_tokens WHERE user_email = ?")
            .bind(&target_email)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;

    let action = if payload.is_suspended { "ACCOUNT_SUSPENDED" } else { "ACCOUNT_UNSUSPENDED" };
    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, action, addr.to_string(), agent).await;
    info!("Compte {} suspendu={} par {}", target_email, payload.is_suspended, user.email);

    Ok(StatusCode::OK)
}

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
            started_at: std::time::Instant::now(),
            vacuum_in_progress: Default::default(),
        })
    }

    /// Un utilisateur non-admin doit se voir refuser l'accès aux logs d'audit (403 Forbidden).
    #[tokio::test]
    async fn test_get_audit_logs_requires_admin() {
        let state = build_test_state().await;
        let user = AuthUser { email: "simple_user@example.com".to_string(), is_moderator: false };

        let result = get_audit_logs(State(state.clone()), user).await;
        assert!(
            matches!(result, Err(AppError::Forbidden)),
            "un utilisateur non-admin ne doit pas accéder aux logs d'audit"
        );
    }

    /// Un administrateur doit pouvoir consulter les logs d'audit existants.
    #[tokio::test]
    async fn test_get_audit_logs_succeeds_for_admin() {
        let state = build_test_state().await;

        // L'utilisateur référencé par la FK de audit_logs doit exister
        sqlx::query("INSERT INTO users (email, password_hash) VALUES (?, ?)")
            .bind("someone@example.com")
            .bind("hash_non_pertinent")
            .execute(&state.db)
            .await
            .unwrap();

        // Insère un log d'audit factice directement en BDD
        sqlx::query("INSERT INTO audit_logs (user_email, action, ip_address, user_agent) VALUES (?, ?, ?, ?)")
            .bind("someone@example.com")
            .bind("LOGIN_SUCCESS")
            .bind("127.0.0.1")
            .bind("test-agent")
            .execute(&state.db)
            .await
            .unwrap();

        let admin = AuthUser { email: "admin@example.com".to_string(), is_moderator: true };
        let result = get_audit_logs(State(state.clone()), admin).await;
        assert!(result.is_ok(), "un administrateur doit pouvoir consulter les logs");
    }

    // =========================================================================
    // TESTS SUR LA GESTION ADMIN DES COMPTES UTILISATEURS
    // =========================================================================

    async fn register_test_user(state: &Arc<AppState>, email: &str, is_moderator: bool) {
        sqlx::query("INSERT INTO users (email, password_hash, is_moderator) VALUES (?, ?, ?)")
            .bind(email)
            .bind("hash_non_pertinent_pour_ce_test")
            .bind(is_moderator)
            .execute(&state.db)
            .await
            .expect("l'insertion de l'utilisateur de test doit réussir");
    }

    fn addr() -> SocketAddr { "127.0.0.1:1".parse().unwrap() }

    /// Variante de build_test_state() avec `ADMIN_EMAIL` configuré — nécessaire pour tester la
    /// protection anti-rétrogradation du premier admin, qui dépend de cette config précise.
    async fn build_test_state_with_admin_email(admin_email: &str) -> Arc<AppState> {
        let state = build_test_state().await;
        // AppState n'est pas Clone-avec-mutation-de-config facilement (Config n'a pas de setter
        // public) — on reconstruit un état complet plutôt que de dupliquer toute la logique de
        // build_test_state() ici, pour rester sûr que les DEUX restent alignées si l'une change.
        Arc::new(AppState {
            encoding_key: state.encoding_key.clone(),
            decoding_key: state.decoding_key.clone(),
            app_env: state.app_env.clone(),
            db: state.db.clone(),
            config: Config { admin_email: Some(admin_email.to_lowercase()), ..state.config.clone() },
            sync_tx: state.sync_tx.clone(),
            shutdown_tx: state.shutdown_tx.clone(),
            ws_connections: state.ws_connections.clone(),
            geoip: state.geoip.clone(),
            started_at: state.started_at,
            vacuum_in_progress: state.vacuum_in_progress.clone(),
        })
    }

    /// list_users() doit refuser un non-admin, et renvoyer TOUS les comptes (sans jamais exposer
    /// password_hash, même haché) à un admin.
    #[tokio::test]
    async fn test_list_users_requires_admin_and_never_exposes_password_hash() {
        let state = build_test_state().await;
        register_test_user(&state, "userone@example.com", false).await;
        register_test_user(&state, "usertwo@example.com", true).await;

        let non_admin = AuthUser { email: "userone@example.com".to_string(), is_moderator: false };
        let denied = list_users(State(state.clone()), non_admin).await;
        assert!(matches!(denied, Err(AppError::Forbidden)), "un non-admin ne doit pas pouvoir lister les comptes");

        let admin = AuthUser { email: "usertwo@example.com".to_string(), is_moderator: true };
        let result = list_users(State(state.clone()), admin).await.expect("un admin doit pouvoir lister les comptes");
        let bytes = axum::body::to_bytes(result.into_response().into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let users = json.as_array().expect("la réponse doit être un tableau JSON");
        assert_eq!(users.len(), 2, "les deux comptes doivent apparaître dans le listage");
        for entry in users {
            assert!(entry.get("password_hash").is_none(), "password_hash ne doit JAMAIS apparaître dans la réponse admin");
        }
    }

    /// list_users() doit exposer is_admin=true UNIQUEMENT sur la ligne du compte
    /// ADMIN_EMAIL — un seul "Admin", tout autre compte avec is_moderator=true est un "Modérateur".
    #[tokio::test]
    async fn test_list_users_exposes_is_admin_only_on_the_configured_account() {
        let state = build_test_state_with_admin_email("owner@example.com").await;
        register_test_user(&state, "owner@example.com", true).await;
        register_test_user(&state, "moderator@example.com", true).await;
        register_test_user(&state, "regular@example.com", false).await;

        let admin = AuthUser { email: "owner@example.com".to_string(), is_moderator: true };
        let result = list_users(State(state.clone()), admin).await.expect("le premier admin doit pouvoir lister les comptes");
        let bytes = axum::body::to_bytes(result.into_response().into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let users = json.as_array().expect("la réponse doit être un tableau JSON");

        let find = |email: &str| users.iter().find(|u| u["email"] == email).expect("compte attendu dans le listage");
        assert_eq!(find("owner@example.com")["is_admin"], true, "le compte ADMIN_EMAIL doit être marqué comme le premier admin");
        assert_eq!(find("moderator@example.com")["is_admin"], false, "un modérateur (is_moderator=true, pas ADMIN_EMAIL) ne doit pas être marqué premier admin");
        assert_eq!(find("regular@example.com")["is_admin"], false, "un compte non-admin ne doit évidemment pas être marqué premier admin");
    }

    /// update_user_role() doit refuser un non-admin, promouvoir/rétrograder correctement quand
    /// c'est le PREMIER admin (ADMIN_EMAIL) qui appelle, et refuser qu'il modifie SON PROPRE rôle.
    #[tokio::test]
    async fn test_update_user_role_promotes_demotes_and_rejects_self_modification() {
        let state = build_test_state_with_admin_email("admin@example.com").await;
        register_test_user(&state, "admin@example.com", true).await;
        register_test_user(&state, "target@example.com", false).await;

        let non_admin = AuthUser { email: "target@example.com".to_string(), is_moderator: false };
        let denied = update_user_role(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(), non_admin,
            Path("admin@example.com".to_string()), Json(UpdateUserRolePayload { is_moderator: false }),
        ).await;
        assert!(matches!(denied, Err(AppError::Forbidden)), "un non-admin ne doit pas pouvoir changer un rôle");

        // Auto-modification refusée, même pour le premier admin
        let self_mod = update_user_role(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "admin@example.com".to_string(), is_moderator: true },
            Path("admin@example.com".to_string()), Json(UpdateUserRolePayload { is_moderator: false }),
        ).await;
        assert!(matches!(self_mod, Err(AppError::ValidationError(_))), "le premier admin ne doit pas pouvoir modifier son propre rôle");

        // Promotion réelle d'un autre compte, par le premier admin
        update_user_role(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "admin@example.com".to_string(), is_moderator: true },
            Path("target@example.com".to_string()), Json(UpdateUserRolePayload { is_moderator: true }),
        ).await.expect("la promotion doit réussir");

        let is_moderator: bool = sqlx::query_scalar("SELECT is_moderator FROM users WHERE email = ?")
            .bind("target@example.com").fetch_one(&state.db).await.unwrap();
        assert!(is_moderator, "le compte cible doit être promu admin");

        let audit_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE user_email = ? AND action = 'MODERATOR_ROLE_GRANTED'")
            .bind("target@example.com").fetch_one(&state.db).await.unwrap();
        assert_eq!(audit_count, 1, "la promotion doit être tracée dans l'audit, sous l'email de la CIBLE");
    }

    /// SEUL le premier admin (ADMIN_EMAIL) peut changer un rôle — un AUTRE admin, même avec
    /// `is_moderator = true` en base, ne peut NI promouvoir NI rétrograder personne via cet endpoint,
    /// pas même le premier admin lui-même.
    #[tokio::test]
    async fn test_update_user_role_only_the_original_admin_can_change_roles() {
        let state = build_test_state_with_admin_email("owner@example.com").await;
        register_test_user(&state, "owner@example.com", true).await;
        register_test_user(&state, "other-admin@example.com", true).await;
        register_test_user(&state, "regular@example.com", false).await;

        // Un AUTRE admin ne doit pouvoir NI promouvoir...
        let denied_promote = update_user_role(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "other-admin@example.com".to_string(), is_moderator: true },
            Path("regular@example.com".to_string()), Json(UpdateUserRolePayload { is_moderator: true }),
        ).await;
        assert!(matches!(denied_promote, Err(AppError::Forbidden)), "seul le premier admin peut promouvoir quelqu'un");

        // ... NI rétrograder, même le premier admin lui-même.
        let denied_demote = update_user_role(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "other-admin@example.com".to_string(), is_moderator: true },
            Path("owner@example.com".to_string()), Json(UpdateUserRolePayload { is_moderator: false }),
        ).await;
        assert!(matches!(denied_demote, Err(AppError::Forbidden)), "seul le premier admin peut rétrograder quelqu'un");

        let is_moderator: bool = sqlx::query_scalar("SELECT is_moderator FROM users WHERE email = ?")
            .bind("owner@example.com").fetch_one(&state.db).await.unwrap();
        assert!(is_moderator, "le premier admin doit rester admin après la tentative refusée");
        let regular_is_admin: bool = sqlx::query_scalar("SELECT is_moderator FROM users WHERE email = ?")
            .bind("regular@example.com").fetch_one(&state.db).await.unwrap();
        assert!(!regular_is_admin, "regular@example.com ne doit pas avoir été promu par un admin non-originel");

        // Le PREMIER admin, lui, peut promouvoir normalement.
        update_user_role(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "owner@example.com".to_string(), is_moderator: true },
            Path("regular@example.com".to_string()), Json(UpdateUserRolePayload { is_moderator: true }),
        ).await.expect("le premier admin doit pouvoir promouvoir quelqu'un");
    }

    /// update_user_role() sur un email inconnu doit renvoyer NotFound (appelé par le premier admin).
    #[tokio::test]
    async fn test_update_user_role_unknown_target_not_found() {
        let state = build_test_state_with_admin_email("admin@example.com").await;
        register_test_user(&state, "admin@example.com", true).await;
        let admin = AuthUser { email: "admin@example.com".to_string(), is_moderator: true };

        let result = update_user_role(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(), admin,
            Path("personne@example.com".to_string()), Json(UpdateUserRolePayload { is_moderator: true }),
        ).await;
        assert!(matches!(result, Err(AppError::NotFound)), "un email inconnu doit renvoyer NotFound");
    }

    /// admin_update_user_email() doit refuser un non-admin, refuser qu'un admin se modifie
    /// lui-même via cet endpoint, renvoyer NotFound sur une cible inconnue, et sinon changer
    /// l'email réellement, invalider ses sessions, et tracer l'événement dans l'audit sous le
    /// NOUVEL email.
    #[tokio::test]
    async fn test_admin_update_user_email_changes_email_and_rejects_self_modification() {
        let state = build_test_state().await;
        register_test_user(&state, "admin@example.com", true).await;
        register_test_user(&state, "target@example.com", false).await;

        sqlx::query("INSERT INTO refresh_tokens (token, user_email, device_id, expires_at, is_persistent) VALUES (?, ?, ?, ?, ?)")
            .bind("token-target")
            .bind("target@example.com")
            .bind("device-target")
            .bind((chrono::Utc::now() + chrono::Duration::hours(1)).format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .bind(false)
            .execute(&state.db)
            .await
            .unwrap();

        let non_admin = AuthUser { email: "target@example.com".to_string(), is_moderator: false };
        let denied = admin_update_user_email(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(), non_admin,
            Path("admin@example.com".to_string()), Json(AdminUpdateEmailPayload { new_email: "hacked@example.com".to_string() }),
        ).await;
        assert!(matches!(denied, Err(AppError::Forbidden)), "un non-admin ne doit pas pouvoir changer l'email d'un compte");

        let admin = AuthUser { email: "admin@example.com".to_string(), is_moderator: true };
        let self_mod = admin_update_user_email(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "admin@example.com".to_string(), is_moderator: true },
            Path("admin@example.com".to_string()), Json(AdminUpdateEmailPayload { new_email: "nouveau-admin@example.com".to_string() }),
        ).await;
        assert!(matches!(self_mod, Err(AppError::ValidationError(_))), "un admin ne doit pas pouvoir changer son propre email via cet endpoint");

        let unknown = admin_update_user_email(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(), admin,
            Path("personne@example.com".to_string()), Json(AdminUpdateEmailPayload { new_email: "peu-importe@example.com".to_string() }),
        ).await;
        assert!(matches!(unknown, Err(AppError::NotFound)), "un email cible inconnu doit renvoyer NotFound");

        let admin = AuthUser { email: "admin@example.com".to_string(), is_moderator: true };
        admin_update_user_email(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(), admin,
            Path("target@example.com".to_string()), Json(AdminUpdateEmailPayload { new_email: "renomme@example.com".to_string() }),
        ).await.expect("le changement d'email par un admin doit réussir");

        let old_exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = ?")
            .bind("target@example.com").fetch_one(&state.db).await.unwrap();
        assert_eq!(old_exists, 0, "l'ancien email ne doit plus exister");
        let new_exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = ?")
            .bind("renomme@example.com").fetch_one(&state.db).await.unwrap();
        assert_eq!(new_exists, 1, "le nouvel email doit exister");

        let remaining_sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE user_email = ?")
            .bind("renomme@example.com").fetch_one(&state.db).await.unwrap();
        assert_eq!(remaining_sessions, 0, "les sessions doivent être invalidées après un changement d'email par un admin");

        let audit_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE user_email = ? AND action = 'ADMIN_EMAIL_CHANGED'")
            .bind("renomme@example.com").fetch_one(&state.db).await.unwrap();
        assert_eq!(audit_count, 1, "le changement doit être tracé dans l'audit sous le NOUVEL email");
    }

    /// admin_update_user_email() : même tiering que delete_user()/revoke_user_sessions() — un
    /// admin normal peut changer l'email d'un compte non-admin, mais PAS celui d'un autre admin ;
    /// PERSONNE ne peut changer l'email du premier admin.
    #[tokio::test]
    async fn test_admin_update_user_email_tiering_between_admins() {
        let state = build_test_state_with_admin_email("owner@example.com").await;
        register_test_user(&state, "owner@example.com", true).await;
        register_test_user(&state, "other-admin@example.com", true).await;
        register_test_user(&state, "another-admin@example.com", true).await;
        register_test_user(&state, "regular@example.com", false).await;

        admin_update_user_email(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "other-admin@example.com".to_string(), is_moderator: true },
            Path("regular@example.com".to_string()), Json(AdminUpdateEmailPayload { new_email: "regular-renomme@example.com".to_string() }),
        ).await.expect("un admin normal doit pouvoir changer l'email d'un compte non-admin");

        let denied = admin_update_user_email(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "other-admin@example.com".to_string(), is_moderator: true },
            Path("another-admin@example.com".to_string()), Json(AdminUpdateEmailPayload { new_email: "vole@example.com".to_string() }),
        ).await;
        assert!(matches!(denied, Err(AppError::Forbidden)), "un admin normal ne doit pas pouvoir changer l'email d'un autre admin");

        let denied_owner = admin_update_user_email(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "other-admin@example.com".to_string(), is_moderator: true },
            Path("owner@example.com".to_string()), Json(AdminUpdateEmailPayload { new_email: "vole@example.com".to_string() }),
        ).await;
        assert!(matches!(denied_owner, Err(AppError::Forbidden)), "le premier admin ne doit jamais pouvoir se faire changer son email par quelqu'un d'autre");

        admin_update_user_email(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "owner@example.com".to_string(), is_moderator: true },
            Path("another-admin@example.com".to_string()), Json(AdminUpdateEmailPayload { new_email: "another-admin-renomme@example.com".to_string() }),
        ).await.expect("le premier admin doit pouvoir changer l'email d'un autre admin");
    }

    /// revoke_user_sessions() doit refuser un non-admin, et ne révoquer QUE les sessions de la
    /// cible — jamais celles d'un autre compte, admin inclus.
    #[tokio::test]
    async fn test_revoke_user_sessions_revokes_only_the_target() {
        let state = build_test_state().await;
        register_test_user(&state, "admin@example.com", true).await;
        register_test_user(&state, "target@example.com", false).await;
        register_test_user(&state, "bystander@example.com", false).await;

        for (owner, device) in [("target@example.com", "device-a"), ("bystander@example.com", "device-b")] {
            sqlx::query("INSERT INTO refresh_tokens (token, user_email, device_id, expires_at, is_persistent) VALUES (?, ?, ?, ?, ?)")
                .bind(format!("token-{device}"))
                .bind(owner)
                .bind(device)
                .bind((chrono::Utc::now() + chrono::Duration::hours(1)).format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .bind(false)
                .execute(&state.db)
                .await
                .unwrap();
        }

        let non_admin = AuthUser { email: "bystander@example.com".to_string(), is_moderator: false };
        let denied = revoke_user_sessions(State(state.clone()), ConnectInfo(addr()), HeaderMap::new(), non_admin, Path("target@example.com".to_string())).await;
        assert!(matches!(denied, Err(AppError::Forbidden)), "un non-admin ne doit pas pouvoir révoquer les sessions d'un compte");

        let admin = AuthUser { email: "admin@example.com".to_string(), is_moderator: true };
        revoke_user_sessions(State(state.clone()), ConnectInfo(addr()), HeaderMap::new(), admin, Path("target@example.com".to_string()))
            .await.expect("la révocation par un admin doit réussir");

        let target_sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE user_email = ?")
            .bind("target@example.com").fetch_one(&state.db).await.unwrap();
        assert_eq!(target_sessions, 0, "les sessions de la cible doivent être révoquées");

        let bystander_sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE user_email = ?")
            .bind("bystander@example.com").fetch_one(&state.db).await.unwrap();
        assert_eq!(bystander_sessions, 1, "les sessions d'un AUTRE compte ne doivent jamais être touchées");
    }

    /// delete_user() doit refuser un non-admin, refuser l'auto-suppression, et supprimer
    /// définitivement le compte cible ET tout ce qui lui est rattaché (cascade FK).
    #[tokio::test]
    async fn test_delete_user_rejects_self_deletion_and_cascades_on_success() {
        let state = build_test_state().await;
        register_test_user(&state, "admin@example.com", true).await;
        register_test_user(&state, "target@example.com", false).await;

        sqlx::query("INSERT INTO vault (id, encrypted_site_name, encrypted_password, encrypted_preferred_login_type, user_email) VALUES (?, ?, ?, ?, ?)")
            .bind("vault-id-1").bind("Site").bind("chiffre").bind("email").bind("target@example.com")
            .execute(&state.db).await.unwrap();
        sqlx::query("INSERT OR REPLACE INTO trusted_devices (device_id, user_email) VALUES (?, ?)")
            .bind("device-x").bind("target@example.com")
            .execute(&state.db).await.unwrap();

        let non_admin = AuthUser { email: "target@example.com".to_string(), is_moderator: false };
        let denied = delete_user(State(state.clone()), ConnectInfo(addr()), HeaderMap::new(), non_admin, Path("target@example.com".to_string())).await;
        assert!(matches!(denied, Err(AppError::Forbidden)), "un non-admin ne doit pas pouvoir supprimer un compte");

        let self_delete = delete_user(
            State(state.clone()), ConnectInfo(addr()),
            HeaderMap::new(), AuthUser { email: "admin@example.com".to_string(), is_moderator: true },
            Path("admin@example.com".to_string()),
        ).await;
        assert!(matches!(self_delete, Err(AppError::ValidationError(_))), "un admin ne doit pas pouvoir se supprimer lui-même via cet endpoint");

        let admin = AuthUser { email: "admin@example.com".to_string(), is_moderator: true };
        delete_user(State(state.clone()), ConnectInfo(addr()), HeaderMap::new(), admin, Path("target@example.com".to_string()))
            .await.expect("la suppression par un admin doit réussir");

        let remaining_user: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = ?")
            .bind("target@example.com").fetch_one(&state.db).await.unwrap();
        assert_eq!(remaining_user, 0, "le compte doit avoir été supprimé");

        let remaining_vault: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault WHERE user_email = ?")
            .bind("target@example.com").fetch_one(&state.db).await.unwrap();
        assert_eq!(remaining_vault, 0, "le coffre du compte supprimé doit disparaître (ON DELETE CASCADE)");

        let remaining_devices: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM trusted_devices WHERE user_email = ?")
            .bind("target@example.com").fetch_one(&state.db).await.unwrap();
        assert_eq!(remaining_devices, 0, "les appareils de confiance du compte supprimé doivent disparaître");

        // L'événement doit être tracé sous l'email de la CIBLE (voir le commentaire dans
        // delete_user() — audit_logs n'a plus de contrainte de clé étrangère vers users(email),
        // donc cette ligne survit à la suppression du compte qu'elle documente).
        let audit_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE user_email = ? AND action = 'ADMIN_DELETED_USER_ACCOUNT'")
            .bind("target@example.com").fetch_one(&state.db).await.unwrap();
        assert_eq!(audit_count, 1, "la suppression doit rester tracée dans l'historique d'audit du compte supprimé");
    }

    /// delete_user() sur un email inconnu doit renvoyer NotFound.
    #[tokio::test]
    async fn test_delete_user_unknown_target_not_found() {
        let state = build_test_state().await;
        register_test_user(&state, "admin@example.com", true).await;
        let admin = AuthUser { email: "admin@example.com".to_string(), is_moderator: true };

        let result = delete_user(State(state.clone()), ConnectInfo(addr()), HeaderMap::new(), admin, Path("personne@example.com".to_string())).await;
        assert!(matches!(result, Err(AppError::NotFound)), "un email inconnu doit renvoyer NotFound");
    }

    /// delete_user() : un admin normal peut supprimer un compte non-admin, mais PAS un autre
    /// admin (réservé au premier admin) ; PERSONNE ne peut supprimer le premier admin lui-même.
    #[tokio::test]
    async fn test_delete_user_tiering_between_admins() {
        let state = build_test_state_with_admin_email("owner@example.com").await;
        register_test_user(&state, "owner@example.com", true).await;
        register_test_user(&state, "other-admin@example.com", true).await;
        register_test_user(&state, "another-admin@example.com", true).await;
        register_test_user(&state, "regular@example.com", false).await;

        // Un admin normal PEUT supprimer un compte non-admin.
        delete_user(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "other-admin@example.com".to_string(), is_moderator: true },
            Path("regular@example.com".to_string()),
        ).await.expect("un admin normal doit pouvoir supprimer un compte non-admin");

        // Un admin normal NE PEUT PAS supprimer un AUTRE admin.
        let denied = delete_user(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "other-admin@example.com".to_string(), is_moderator: true },
            Path("another-admin@example.com".to_string()),
        ).await;
        assert!(matches!(denied, Err(AppError::Forbidden)), "un admin normal ne doit pas pouvoir supprimer un autre admin");

        // PERSONNE ne peut supprimer le premier admin — même un autre admin qui essaierait.
        let denied_owner = delete_user(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "other-admin@example.com".to_string(), is_moderator: true },
            Path("owner@example.com".to_string()),
        ).await;
        assert!(matches!(denied_owner, Err(AppError::Forbidden)), "le premier admin ne doit jamais pouvoir être supprimé");

        // Le PREMIER admin, lui, peut supprimer un autre admin.
        delete_user(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "owner@example.com".to_string(), is_moderator: true },
            Path("another-admin@example.com".to_string()),
        ).await.expect("le premier admin doit pouvoir supprimer un autre admin");
    }

    /// revoke_user_sessions() : même tiering que delete_user() — un admin normal peut agir sur un
    /// compte non-admin, pas sur un autre admin ; personne ne peut cibler le premier admin.
    #[tokio::test]
    async fn test_revoke_user_sessions_tiering_between_admins() {
        let state = build_test_state_with_admin_email("owner@example.com").await;
        register_test_user(&state, "owner@example.com", true).await;
        register_test_user(&state, "other-admin@example.com", true).await;
        register_test_user(&state, "another-admin@example.com", true).await;
        register_test_user(&state, "regular@example.com", false).await;

        revoke_user_sessions(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "other-admin@example.com".to_string(), is_moderator: true },
            Path("regular@example.com".to_string()),
        ).await.expect("un admin normal doit pouvoir révoquer les sessions d'un compte non-admin");

        let denied = revoke_user_sessions(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "other-admin@example.com".to_string(), is_moderator: true },
            Path("another-admin@example.com".to_string()),
        ).await;
        assert!(matches!(denied, Err(AppError::Forbidden)), "un admin normal ne doit pas pouvoir révoquer les sessions d'un autre admin");

        let denied_owner = revoke_user_sessions(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "other-admin@example.com".to_string(), is_moderator: true },
            Path("owner@example.com".to_string()),
        ).await;
        assert!(matches!(denied_owner, Err(AppError::Forbidden)), "le premier admin ne doit jamais pouvoir être ciblé, même pour révoquer ses sessions");

        revoke_user_sessions(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "owner@example.com".to_string(), is_moderator: true },
            Path("another-admin@example.com".to_string()),
        ).await.expect("le premier admin doit pouvoir révoquer les sessions d'un autre admin");
    }

    /// update_extension_email_change_setting() (par compte) : même tiering.
    #[tokio::test]
    async fn test_update_extension_email_change_setting_tiering_between_admins() {
        let state = build_test_state_with_admin_email("owner@example.com").await;
        register_test_user(&state, "owner@example.com", true).await;
        register_test_user(&state, "other-admin@example.com", true).await;
        register_test_user(&state, "another-admin@example.com", true).await;
        register_test_user(&state, "regular@example.com", false).await;

        update_extension_email_change_setting(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "other-admin@example.com".to_string(), is_moderator: true },
            Path("regular@example.com".to_string()), Json(UpdateExtensionEmailChangePayload { enabled: true }),
        ).await.expect("un admin normal doit pouvoir régler ce paramètre pour un compte non-admin");

        let denied = update_extension_email_change_setting(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "other-admin@example.com".to_string(), is_moderator: true },
            Path("another-admin@example.com".to_string()), Json(UpdateExtensionEmailChangePayload { enabled: true }),
        ).await;
        assert!(matches!(denied, Err(AppError::Forbidden)), "un admin normal ne doit pas pouvoir régler ce paramètre pour un autre admin");

        let denied_owner = update_extension_email_change_setting(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "other-admin@example.com".to_string(), is_moderator: true },
            Path("owner@example.com".to_string()), Json(UpdateExtensionEmailChangePayload { enabled: true }),
        ).await;
        assert!(matches!(denied_owner, Err(AppError::Forbidden)), "le premier admin ne doit jamais pouvoir être ciblé par ce réglage");
    }

    /// update_extension_email_change_setting_all() (le levier "pour tout le monde") : réservé
    /// EXCLUSIVEMENT au premier admin, contrairement à la variante par compte.
    #[tokio::test]
    async fn test_update_extension_email_change_setting_all_requires_original_admin() {
        let state = build_test_state_with_admin_email("owner@example.com").await;
        register_test_user(&state, "owner@example.com", true).await;
        register_test_user(&state, "other-admin@example.com", true).await;

        let denied = update_extension_email_change_setting_all(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "other-admin@example.com".to_string(), is_moderator: true },
            Json(UpdateExtensionEmailChangePayload { enabled: true }),
        ).await;
        assert!(matches!(denied, Err(AppError::Forbidden)), "un admin normal ne doit pas pouvoir activer ce réglage pour tout le monde");

        update_extension_email_change_setting_all(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "owner@example.com".to_string(), is_moderator: true },
            Json(UpdateExtensionEmailChangePayload { enabled: true }),
        ).await.expect("le premier admin doit pouvoir activer ce réglage pour tout le monde");
    }

    /// update_server_choice_in_settings() : réservé à l'ADMIN SEUL, PAS un simple modérateur —
    /// contrairement à update_extension_email_change_setting() (moins sensible), voir le
    /// commentaire du handler. Un modérateur non-admin doit être rejeté AVANT même
    /// check_can_act_on_target (donc y compris sur une cible non-modérateur, sans rapport avec le
    /// tiering habituel).
    #[tokio::test]
    async fn test_update_server_choice_in_settings_requires_admin_not_just_moderator() {
        let state = build_test_state_with_admin_email("owner@example.com").await;
        register_test_user(&state, "owner@example.com", true).await;
        register_test_user(&state, "moderator@example.com", true).await;
        register_test_user(&state, "regular@example.com", false).await;

        let denied = update_server_choice_in_settings(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "moderator@example.com".to_string(), is_moderator: true },
            Path("regular@example.com".to_string()), Json(UpdateServerChoiceInSettingsPayload { enabled: true }),
        ).await;
        assert!(matches!(denied, Err(AppError::Forbidden)), "un modérateur non-admin ne doit jamais pouvoir régler ce paramètre, même pour un compte non-modérateur");

        let denied_on_self = update_server_choice_in_settings(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "owner@example.com".to_string(), is_moderator: true },
            Path("owner@example.com".to_string()), Json(UpdateServerChoiceInSettingsPayload { enabled: true }),
        ).await;
        assert!(matches!(denied_on_self, Err(AppError::Forbidden)), "l'Admin ne peut pas être la cible de ce réglage, même par lui-même (il y est toujours autorisé indépendamment de la colonne)");

        update_server_choice_in_settings(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "owner@example.com".to_string(), is_moderator: true },
            Path("moderator@example.com".to_string()), Json(UpdateServerChoiceInSettingsPayload { enabled: true }),
        ).await.expect("l'Admin doit pouvoir régler ce paramètre pour n'importe quel compte, modérateur compris");
    }

    /// update_server_choice_in_settings_all() : réservé à l'Admin, même raisonnement que
    /// update_extension_email_change_setting_all().
    #[tokio::test]
    async fn test_update_server_choice_in_settings_all_requires_admin() {
        let state = build_test_state_with_admin_email("owner@example.com").await;
        register_test_user(&state, "owner@example.com", true).await;
        register_test_user(&state, "moderator@example.com", true).await;

        let denied = update_server_choice_in_settings_all(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "moderator@example.com".to_string(), is_moderator: true },
            Json(UpdateServerChoiceInSettingsPayload { enabled: true }),
        ).await;
        assert!(matches!(denied, Err(AppError::Forbidden)), "un modérateur non-admin ne doit pas pouvoir activer ce réglage pour tout le monde");

        update_server_choice_in_settings_all(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "owner@example.com".to_string(), is_moderator: true },
            Json(UpdateServerChoiceInSettingsPayload { enabled: true }),
        ).await.expect("l'Admin doit pouvoir activer ce réglage pour tout le monde");
    }

    /// update_server_choice_at_login() : réglage GLOBAL, réservé à l'Admin — vérifie en plus que
    /// la valeur est bien persistée (relue directement via la table app_settings), pas juste que
    /// l'appel réussit.
    #[tokio::test]
    async fn test_update_server_choice_at_login_requires_admin_and_persists() {
        let state = build_test_state_with_admin_email("owner@example.com").await;
        register_test_user(&state, "owner@example.com", true).await;
        register_test_user(&state, "moderator@example.com", true).await;

        let denied = update_server_choice_at_login(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "moderator@example.com".to_string(), is_moderator: true },
            Json(UpdateServerChoiceAtLoginPayload { enabled: true }),
        ).await;
        assert!(matches!(denied, Err(AppError::Forbidden)), "un modérateur non-admin ne doit pas pouvoir changer ce réglage global");

        update_server_choice_at_login(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "owner@example.com".to_string(), is_moderator: true },
            Json(UpdateServerChoiceAtLoginPayload { enabled: true }),
        ).await.expect("l'Admin doit pouvoir changer ce réglage global");

        let persisted: bool = sqlx::query_scalar("SELECT server_choice_at_login_enabled FROM app_settings WHERE id = 1")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert!(persisted, "la valeur doit être réellement persistée en base, pas juste acceptée par le handler");
    }

    // =========================================================================
    // CONTRÔLES D'ADMINISTRATION (inscriptions, suspension)
    // =========================================================================

    fn ctrl_addr() -> SocketAddr {
        "127.0.0.1:1".parse().unwrap()
    }

    /// Ce qui compte n'est pas d'enregistrer le réglage, mais qu'il soit APPLIQUÉ : inscriptions
    /// fermées doit réellement refuser une inscription.
    #[tokio::test]
    async fn test_closed_registration_actually_blocks_signup() {
        let state = build_test_state().await;
        sqlx::query("UPDATE app_settings SET registration_open = 0 WHERE id = 1")
            .execute(&state.db)
            .await
            .unwrap();

        let result = crate::handlers::auth::register(
            State(state.clone()),
            Json(AuthPayload {
                email: "intrus@example.com".to_string(),
                master_password_hash: "mot_de_passe_test_123".to_string(),
                device_id: "dev".to_string(),
                remember_me: None,
                max_trusted_devices: None,
            }),
        )
        .await;
        assert!(matches!(result, Err(AppError::ValidationError(_))), "inscriptions fermées : l'inscription doit être refusée");

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE email = ?")
            .bind("intrus@example.com")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(count, 0, "aucun compte ne doit avoir été créé");
    }

    /// L'Admin configuré reste toujours autorisé : sur un serveur neuf aux inscriptions fermées,
    /// s'en exclure soi-même laisserait le déploiement sans aucun administrateur possible.
    #[tokio::test]
    async fn test_closed_registration_still_allows_configured_admin() {
        let state = build_test_state().await;
        let admin_email = "patron@example.com";
        let state = Arc::new(AppState {
            config: Config { admin_email: Some(admin_email.to_string()), ..state.config.clone() },
            ..Arc::try_unwrap(state).ok().expect("état de test non partagé")
        });
        sqlx::query("UPDATE app_settings SET registration_open = 0 WHERE id = 1")
            .execute(&state.db)
            .await
            .unwrap();

        let result = crate::handlers::auth::register(
            State(state.clone()),
            Json(AuthPayload {
                email: admin_email.to_string(),
                master_password_hash: "mot_de_passe_test_123".to_string(),
                device_id: "dev".to_string(),
                remember_me: None,
                max_trusted_devices: None,
            }),
        )
        .await;
        assert!(result.is_ok(), "l'Admin configuré doit pouvoir s'inscrire même inscriptions fermées");
    }

    /// La suspension doit COUPER les sessions en cours, pas seulement empêcher les suivantes.
    #[tokio::test]
    async fn test_suspending_account_revokes_its_sessions() {
        let state = build_test_state().await;
        let admin = AuthUser { email: "boss@example.com".to_string(), is_moderator: true };
        register_test_user(&state, &admin.email, true).await;
        register_test_user(&state, "cible@example.com", false).await;

        sqlx::query("INSERT INTO refresh_tokens (token, user_email, device_id, expires_at, is_persistent) VALUES (?, ?, ?, ?, 0)")
            .bind("un-hash-de-token")
            .bind("cible@example.com")
            .bind("dev")
            .bind((chrono::Utc::now() + chrono::Duration::hours(1)).format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .execute(&state.db)
            .await
            .unwrap();

        update_suspended(
            State(state.clone()),
            ConnectInfo(ctrl_addr()),
            HeaderMap::new(),
            admin,
            Path("cible@example.com".to_string()),
            Json(UpdateSuspendedPayload { is_suspended: true }),
        )
        .await
        .expect("la suspension doit réussir");

        let suspended: bool = sqlx::query_scalar("SELECT is_suspended FROM users WHERE email = ?")
            .bind("cible@example.com")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert!(suspended, "le compte doit être marqué suspendu");

        let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE user_email = ?")
            .bind("cible@example.com")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(sessions, 0, "les sessions en cours doivent être coupées, pas seulement les suivantes");
    }

    /// La suspension passe par le même garde que les autres actions : l'Admin est intouchable.
    #[tokio::test]
    async fn test_moderator_cannot_suspend_the_admin() {
        let state = build_test_state().await;
        let admin_email = "patron@example.com";
        let state = Arc::new(AppState {
            config: Config { admin_email: Some(admin_email.to_string()), ..state.config.clone() },
            ..Arc::try_unwrap(state).ok().expect("état de test non partagé")
        });
        register_test_user(&state, admin_email, true).await;
        register_test_user(&state, "moderateur@example.com", true).await;

        let result = update_suspended(
            State(state.clone()),
            ConnectInfo(ctrl_addr()),
            HeaderMap::new(),
            AuthUser { email: "moderateur@example.com".to_string(), is_moderator: true },
            Path(admin_email.to_string()),
            Json(UpdateSuspendedPayload { is_suspended: true }),
        )
        .await;
        assert!(matches!(result, Err(AppError::Forbidden)), "un modérateur ne doit pas pouvoir suspendre l'Admin");
    }

    /// Ouvrir/fermer les inscriptions est réservé au SEUL Admin, pas aux modérateurs.
    #[tokio::test]
    async fn test_registration_setting_refused_to_moderators() {
        let state = build_test_state().await;
        let moderator = || AuthUser { email: "moderateur@example.com".to_string(), is_moderator: true };

        let r1 = update_registration_open(
            State(state.clone()), ConnectInfo(ctrl_addr()), HeaderMap::new(), moderator(),
            Json(UpdateRegistrationOpenPayload { enabled: true }),
        ).await;
        assert!(matches!(r1, Err(AppError::Forbidden)), "ouvrir les inscriptions est réservé à l'Admin");

    }



    // ---- Historique des IP par compte -------------------------------------------------

    /// Passe par le vrai chemin d'écriture (`log_audit` -> `record_ip_seen`) plutôt que par un
    /// INSERT direct : c'est justement ce branchement qu'on veut voir marcher.
    async fn seen(state: &Arc<AppState>, email: &str, action: &str, ip: &str) {
        state.log_audit(email, action, ip.to_string(), None).await;
    }

    async fn ip_history_of(state: &Arc<AppState>, caller_is_moderator: bool, target: &str) -> serde_json::Value {
        let result = get_user_ip_history(
            State(state.clone()),
            ConnectInfo(addr()),
            HeaderMap::new(),
            AuthUser { email: "boss@example.com".to_string(), is_moderator: caller_is_moderator },
            Path(target.to_string()),
        ).await.expect("la consultation doit réussir");
        let bytes = axum::body::to_bytes(result.into_response().into_body(), usize::MAX).await.unwrap();
        let corps: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        corps["entries"].clone()
    }

    /// Même porte que le journal d'audit : un simple utilisateur ne voit pas les IP.
    #[tokio::test]
    async fn test_ip_history_requires_moderator() {
        let state = build_test_state().await;
        let result = get_user_ip_history(
            State(state.clone()),
            ConnectInfo(addr()),
            HeaderMap::new(),
            AuthUser { email: "curieux@example.com".to_string(), is_moderator: false },
            Path("cible@example.com".to_string()),
        ).await;
        assert!(matches!(result, Err(AppError::Forbidden)), "un non-modérateur ne doit pas voir les IP");
    }

    /// Le regroupement fait toute la valeur : plusieurs événements depuis la MÊME adresse donnent
    /// UNE ligne comptée, pas une ligne par événement.
    #[tokio::test]
    async fn test_ip_history_groups_by_ip_and_counts() {
        let state = build_test_state().await;
        register_test_user(&state, "cible@example.com", false).await;
        seen(&state, "cible@example.com", "LOGIN", "10.0.0.1").await;
        seen(&state, "cible@example.com", "LOGIN", "10.0.0.1").await;
        seen(&state, "cible@example.com", "VAULT_EXPORT", "10.0.0.1").await;
        seen(&state, "cible@example.com", "LOGIN", "203.0.113.7").await;

        let history = ip_history_of(&state, true, "cible@example.com").await;
        let rows = history.as_array().unwrap();
        assert_eq!(rows.len(), 2, "deux adresses distinctes, pas une ligne par événement");

        let row = rows.iter().find(|r| r["ip_address"] == "10.0.0.1").unwrap();
        assert_eq!(row["event_count"], 3, "les 3 événements de 10.0.0.1 comptent ensemble");
        assert_eq!(row["success_count"], 2, "seules les connexions réussies comptent comme succès");
        assert_eq!(row["failure_count"], 0);
    }

    /// LE cas visé : une adresse qui accumule des échecs PUIS finit par réussir. C'est la signature
    /// d'une intrusion par tâtonnement, et c'est ce que les deux compteurs rendent lisible.
    #[tokio::test]
    async fn test_ip_history_exposes_failures_then_success() {
        let state = build_test_state().await;
        register_test_user(&state, "victime@example.com", false).await;
        for _ in 0..7 {
            seen(&state, "victime@example.com", "LOGIN_FAILED", "198.51.100.66").await;
        }
        seen(&state, "victime@example.com", "LOGIN_BLOCKED_TOO_MANY_ATTEMPTS", "198.51.100.66").await;
        seen(&state, "victime@example.com", "LOGIN_SUCCESS", "198.51.100.66").await;

        let history = ip_history_of(&state, true, "victime@example.com").await;
        let row = &history.as_array().unwrap()[0];
        assert_eq!(row["failure_count"], 8, "les échecs ET les blocages comptent comme échecs");
        assert_eq!(row["success_count"], 1, "la réussite finale doit ressortir séparément");
        assert_eq!(row["event_count"], 9);
    }

    /// `other_accounts` répond à "quelqu'un s'est-il connecté au compte d'un autre" : la même
    /// adresse vue sur plusieurs comptes doit être signalée comme telle.
    #[tokio::test]
    async fn test_ip_history_counts_other_accounts_sharing_the_ip() {
        let state = build_test_state().await;
        register_test_user(&state, "papa@example.com", false).await;
        register_test_user(&state, "ado@example.com", false).await;
        register_test_user(&state, "solo@example.com", false).await;

        seen(&state, "papa@example.com", "LOGIN", "203.0.113.5").await;
        seen(&state, "ado@example.com", "LOGIN", "203.0.113.5").await;
        seen(&state, "solo@example.com", "LOGIN", "192.0.2.99").await;

        let papa = ip_history_of(&state, true, "papa@example.com").await;
        assert_eq!(papa.as_array().unwrap()[0]["other_accounts"], 1, "l'adresse partagée doit signaler l'autre compte");

        let solo = ip_history_of(&state, true, "solo@example.com").await;
        assert_eq!(solo.as_array().unwrap()[0]["other_accounts"], 0, "une adresse utilisée par un seul compte n'est partagée avec personne");
    }

    /// Une vue "par compte" qui laisserait fuiter les adresses d'un autre compte serait pire
    /// qu'inutile.
    #[tokio::test]
    async fn test_ip_history_does_not_leak_other_accounts() {
        let state = build_test_state().await;
        register_test_user(&state, "cible@example.com", false).await;
        register_test_user(&state, "voisin@example.com", false).await;
        seen(&state, "cible@example.com", "LOGIN", "10.0.0.1").await;
        seen(&state, "voisin@example.com", "LOGIN", "198.51.100.9").await;

        let history = ip_history_of(&state, true, "cible@example.com").await;
        let rows = history.as_array().unwrap();
        assert_eq!(rows.len(), 1, "seules les adresses du compte demandé doivent apparaître");
        assert_eq!(rows[0]["ip_address"], "10.0.0.1");
    }

    /// La raison d'être de la table séparée : elle doit SURVIVRE à la purge du journal d'audit,
    /// sinon une adresse revenant après quelques semaines paraîtrait neuve à chaque fois.
    #[tokio::test]
    async fn test_ip_history_survives_audit_log_purge() {
        let state = build_test_state().await;
        register_test_user(&state, "cible@example.com", false).await;
        seen(&state, "cible@example.com", "LOGIN", "203.0.113.7").await;

        // Vieillit l'événement au-delà de la fenêtre, puis applique la VRAIE purge.
        sqlx::query("UPDATE audit_logs SET created_at = DATETIME('now', '-60 days')")
            .execute(&state.db).await.unwrap();
        crate::maintenance::purge_old_audit_logs(&state.db).await;

        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs")
            .fetch_one(&state.db).await.unwrap();
        assert_eq!(remaining, 0, "le journal doit bien avoir été purgé (sinon le test ne prouve rien)");

        let history = ip_history_of(&state, true, "cible@example.com").await;
        assert_eq!(history.as_array().unwrap().len(), 1, "l'historique IP doit survivre à la purge du journal");
    }

    // ---- Quotas, VACUUM, export CSV, comptes dormants ---------------------------------

    /// Construit un état dont ADMIN_EMAIL est renseigné — nécessaire à toutes les routes
    /// réservées à l'Admin.
    async fn state_with_admin(admin_email: &str) -> Arc<AppState> {
        let state = build_test_state().await;
        Arc::new(AppState {
            config: Config { admin_email: Some(admin_email.to_string()), ..state.config.clone() },
            ..Arc::try_unwrap(state).ok().expect("état de test non partagé")
        })
    }

    fn admin_user(email: &str) -> AuthUser {
        AuthUser { email: email.to_string(), is_moderator: true }
    }

    /// Régler un quota doit être réservé à l'Admin, et un quota négatif refusé.
    #[tokio::test]
    async fn test_quotas_are_admin_only_and_validated() {
        let state = state_with_admin("patron@example.com").await;
        register_test_user(&state, "cible@example.com", false).await;

        let refus = update_quotas(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "moderateur@example.com".to_string(), is_moderator: true },
            Path("cible@example.com".to_string()),
            Json(UpdateQuotasPayload { max_vault_entries: Some(Some(10)), max_attachments: Some(None) }),
        ).await;
        assert!(matches!(refus, Err(AppError::Forbidden)), "un modérateur ne règle pas les quotas");

        let negatif = update_quotas(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            admin_user("patron@example.com"),
            Path("cible@example.com".to_string()),
            Json(UpdateQuotasPayload { max_vault_entries: Some(Some(-1)), max_attachments: Some(None) }),
        ).await;
        assert!(matches!(negatif, Err(AppError::ValidationError(_))), "un quota négatif n'a pas de sens");
    }

    /// `null` doit remettre le compte sur le plafond global, et `0` rester distinct — l'un dit
    /// « comme tout le monde », l'autre gèle réellement le compte.
    #[tokio::test]
    async fn test_null_quota_differs_from_zero() {
        let state = state_with_admin("patron@example.com").await;
        register_test_user(&state, "cible@example.com", false).await;

        let regler = |v: Option<i64>| {
            let state = state.clone();
            async move {
                update_quotas(
                    State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
                    admin_user("patron@example.com"),
                    Path("cible@example.com".to_string()),
                    Json(UpdateQuotasPayload { max_vault_entries: Some(v), max_attachments: Some(None) }),
                ).await.expect("le réglage doit réussir");
                sqlx::query_scalar::<_, Option<i64>>("SELECT max_vault_entries FROM users WHERE email = ?")
                    .bind("cible@example.com").fetch_one(&state.db).await.unwrap()
            }
        };

        assert_eq!(regler(Some(0)).await, Some(0), "0 doit être stocké tel quel");
        assert_eq!(regler(None).await, None, "null doit effacer la surcharge, pas écrire 0");
    }

/// Une requête ne mentionnant QU'UN des deux quotas ne doit pas effacer l'autre.
    ///
    /// C'est le piège de `Option` en serde : un champ absent y vaut `None`, exactement comme un
    /// `null` explicite. Sans distinguer les deux, un client réglant un seul quota remettrait
    /// l'autre au plafond global sans l'avoir demandé — et rien ne le lui dirait.
    #[tokio::test]
    async fn test_partial_payload_leaves_the_other_quota_untouched() {
        let state = state_with_admin("patron@example.com").await;
        register_test_user(&state, "cible@example.com", false).await;
        sqlx::query("UPDATE users SET max_vault_entries = 42, max_attachments = 7 WHERE email = ?")
            .bind("cible@example.com").execute(&state.db).await.unwrap();

        // Charge utile mentionnant UNIQUEMENT les entrées, telle qu'elle arriverait en JSON.
        let payload: UpdateQuotasPayload = serde_json::from_str(r#"{"max_vault_entries": 99}"#).unwrap();
        update_quotas(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            admin_user("patron@example.com"), Path("cible@example.com".to_string()), Json(payload),
        ).await.expect("le réglage partiel doit réussir");

        let (entrees, pieces): (Option<i64>, Option<i64>) =
            sqlx::query_as("SELECT max_vault_entries, max_attachments FROM users WHERE email = ?")
                .bind("cible@example.com").fetch_one(&state.db).await.unwrap();
        assert_eq!(entrees, Some(99), "le champ envoyé doit être écrit");
        assert_eq!(pieces, Some(7), "le champ ABSENT doit rester intact, pas être remis à NULL");

        // Un `null` EXPLICITE, lui, doit bien effacer — c'est la différence qu'on tient à garder.
        let payload: UpdateQuotasPayload = serde_json::from_str(r#"{"max_attachments": null}"#).unwrap();
        update_quotas(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            admin_user("patron@example.com"), Path("cible@example.com".to_string()), Json(payload),
        ).await.expect("le réglage doit réussir");

        let (entrees, pieces): (Option<i64>, Option<i64>) =
            sqlx::query_as("SELECT max_vault_entries, max_attachments FROM users WHERE email = ?")
                .bind("cible@example.com").fetch_one(&state.db).await.unwrap();
        assert_eq!(entrees, Some(99), "l'autre champ reste intact");
        assert_eq!(pieces, None, "un null explicite doit bien remettre sur le plafond global");
    }

    /// Deux compactages simultanés ne doivent pas s'empiler : le premier prend le drapeau, le
    /// second est refusé. Sans cela, un 408 dû au délai de 30 s (alors que SQLite poursuit)
    /// pousserait à relancer par-dessus l'opération en cours.
    #[tokio::test]
    async fn test_concurrent_vacuum_is_refused() {
        let state = state_with_admin("patron@example.com").await;
        // Simule un compactage déjà en cours.
        state.vacuum_in_progress.store(true, std::sync::atomic::Ordering::SeqCst);

        let refus = vacuum_database(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            admin_user("patron@example.com"),
        ).await;
        assert!(matches!(refus, Err(AppError::ValidationError(_))), "un second compactage doit être refusé");

        // Le drapeau ne doit PAS avoir été relâché par le refus : le vrai compactage tourne encore.
        assert!(state.vacuum_in_progress.load(std::sync::atomic::Ordering::SeqCst));
    }

        /// Un compte inexistant ne doit pas être silencieusement ignoré : sinon une faute de frappe
    /// dans l'adresse donnerait l'impression d'avoir réglé un quota.
    #[tokio::test]
    async fn test_quota_on_unknown_account_is_not_found() {
        let state = state_with_admin("patron@example.com").await;
        let r = update_quotas(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            admin_user("patron@example.com"),
            Path("fantome@example.com".to_string()),
            Json(UpdateQuotasPayload { max_vault_entries: Some(Some(10)), max_attachments: Some(Some(2)) }),
        ).await;
        assert!(matches!(r, Err(AppError::NotFound)));
    }

/// Un clic répété ne doit pas produire un email par clic : chaque envoi consomme le quota SMTP du
    /// propriétaire et pèse sur la réputation de son domaine. Cas réel — un clic voulu, quatre
    /// emails reçus, parce que le bouton ne montrait pas qu'il travaillait.
    ///
    /// Le test ne peut pas envoyer réellement (pas de SMTP en test) : il vérifie la garde EN AMONT,
    /// c'est-à-dire qu'un envoi récent déjà tracé bloque le suivant avant toute tentative.
    #[tokio::test]
    async fn test_test_email_refuses_a_second_send_within_the_cooldown() {
        let state = state_with_admin("patron@example.com").await;
        register_test_user(&state, "patron@example.com", true).await;

        // Simule un envoi qui vient d'avoir lieu, tel que le handler le trace.
        state.log_audit("patron@example.com", "TEST_EMAIL_SENT", "127.0.0.1".to_string(), None).await;

        let refus = send_test_email(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            admin_user("patron@example.com"),
        ).await;
        assert!(
            matches!(refus, Err(AppError::ValidationError(_))),
            "un second envoi dans la minute doit être refusé AVANT d'atteindre le SMTP"
        );
    }

    /// La garde ne doit pas être permanente : le cas d'usage même de cette route est de retester
    /// après avoir corrigé un réglage SMTP.
    #[tokio::test]
    async fn test_test_email_cooldown_expires() {
        let state = state_with_admin("patron@example.com").await;
        register_test_user(&state, "patron@example.com", true).await;
        state.log_audit("patron@example.com", "TEST_EMAIL_SENT", "127.0.0.1".to_string(), None).await;
        // Vieillit la trace au-delà du délai.
        sqlx::query("UPDATE audit_logs SET created_at = DATETIME('now', '-5 minutes') WHERE action = 'TEST_EMAIL_SENT'")
            .execute(&state.db).await.unwrap();

        let r = send_test_email(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            admin_user("patron@example.com"),
        ).await;
        // Sans SMTP joignable en test, l'envoi échoue — mais PAS avec une erreur de validation :
        // c'est ce qui distingue « bloqué par la garde » de « la garde a laissé passer ».
        assert!(
            !matches!(r, Err(AppError::ValidationError(_))),
            "passé le délai, la garde ne doit plus bloquer"
        );
    }

        /// VACUUM : réservé à l'Admin, et doit réussir en renvoyant des tailles cohérentes.
    #[tokio::test]
    async fn test_vacuum_is_admin_only_and_reports_sizes() {
        let state = state_with_admin("patron@example.com").await;

        let refus = vacuum_database(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "moderateur@example.com".to_string(), is_moderator: true },
        ).await;
        assert!(matches!(refus, Err(AppError::Forbidden)), "un modérateur ne compacte pas la base");

        let ok = vacuum_database(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            admin_user("patron@example.com"),
        ).await.expect("le VACUUM doit réussir");
        let bytes = axum::body::to_bytes(ok.into_response().into_body(), usize::MAX).await.unwrap();
        let corps: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(corps["before_bytes"].is_number() && corps["after_bytes"].is_number());
        assert_eq!(
            corps["freed_bytes"].as_i64().unwrap(),
            corps["before_bytes"].as_i64().unwrap() - corps["after_bytes"].as_i64().unwrap(),
            "l'espace libéré doit être la différence exacte, signe compris"
        );
    }

    /// L'export CSV doit ÉCHAPPER les champs : un User-Agent contient virgules et guillemets, et
    /// sans échappement une seule virgule décale toutes les colonnes — un tableur ouvrirait le
    /// fichier sans rien signaler, donnant une analyse fausse plutôt qu'une erreur visible.
    #[tokio::test]
    async fn test_csv_export_escapes_dangerous_fields() {
        let state = build_test_state().await;
        register_test_user(&state, "cible@example.com", false).await;
        sqlx::query("INSERT INTO audit_logs (user_email, action, ip_address, user_agent) VALUES (?, ?, ?, ?)")
            .bind("cible@example.com")
            .bind("LOGIN")
            .bind("203.0.113.7")
            .bind("Mozilla/5.0 (X11; Linux), \"faux\" navigateur")
            .execute(&state.db).await.unwrap();

        let reponse = export_audit_logs_csv(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "moderateur@example.com".to_string(), is_moderator: true },
        ).await.expect("l'export doit réussir");
        let bytes = axum::body::to_bytes(reponse.into_response().into_body(), usize::MAX).await.unwrap();
        let csv = String::from_utf8(bytes.to_vec()).unwrap();

        assert!(csv.starts_with("date,compte,action,adresse_ip,navigateur\n"), "en-tête attendu : {csv}");
        assert!(csv.contains("\"Mozilla/5.0 (X11; Linux), \"\"faux\"\" navigateur\""), "champ mal échappé : {csv}");

        // Une seule ligne de données : les colonnes ne doivent pas avoir été décalées.
        let ligne = csv.lines().nth(1).expect("une ligne de données");
        assert!(ligne.contains("203.0.113.7"), "l'adresse doit rester dans sa colonne : {ligne}");
    }

    /// L'export est réservé aux modérateurs, comme la consultation du journal.
    #[tokio::test]
    async fn test_csv_export_requires_moderator() {
        let state = build_test_state().await;
        let r = export_audit_logs_csv(
            State(state.clone()), ConnectInfo(addr()), HeaderMap::new(),
            AuthUser { email: "curieux@example.com".to_string(), is_moderator: false },
        ).await;
        assert!(matches!(r, Err(AppError::Forbidden)));
    }

    /// « Jamais connecté » et « connecté il y a longtemps » sont deux états différents, et le
    /// listage doit les distinguer — c'est tout l'intérêt de repérer un compte dormant.
    #[tokio::test]
    async fn test_listing_distinguishes_never_seen_from_seen() {
        let state = state_with_admin("patron@example.com").await;
        register_test_user(&state, "actif@example.com", false).await;
        register_test_user(&state, "jamais@example.com", false).await;
        state.log_audit("actif@example.com", "LOGIN", "203.0.113.7".to_string(), None).await;

        let reponse = list_users(State(state.clone()), admin_user("patron@example.com"))
            .await
            .expect("le listage doit réussir");
        let bytes = axum::body::to_bytes(reponse.into_response().into_body(), usize::MAX).await.unwrap();
        let comptes: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        let trouver = |email: &str| {
            comptes.as_array().unwrap().iter()
                .find(|u| u["email"] == email).cloned().expect("compte présent")
        };
        assert!(trouver("actif@example.com")["last_seen"].is_string(), "un compte vu doit porter une date");
        assert!(trouver("jamais@example.com")["last_seen"].is_null(), "un compte jamais vu doit rester null");
    }

    /// L'état du serveur est réservé à l'Admin, PAS aux modérateurs : ces mesures portent sur la
    /// machine, pas sur les comptes.
    #[tokio::test]
    async fn test_server_health_is_admin_only() {
        let state = build_test_state().await;
        let refus = get_server_health(
            State(state.clone()),
            AuthUser { email: "moderateur@example.com".to_string(), is_moderator: true },
        )
        .await;
        assert!(matches!(refus, Err(AppError::Forbidden)), "un modérateur ne doit pas voir l'état du serveur");
    }

    /// Les mesures doivent refléter la BASE, pas des zéros : un écran d'état qui affiche tout à
    /// zéro passerait pour un serveur au repos alors qu'il serait simplement cassé.
    #[tokio::test]
    async fn test_server_health_reports_real_counts() {
        let admin_email = "patron@example.com";
        let state = build_test_state().await;
        let state = Arc::new(AppState {
            config: Config { admin_email: Some(admin_email.to_string()), ..state.config.clone() },
            ..Arc::try_unwrap(state).ok().expect("état de test non partagé")
        });
        register_test_user(&state, admin_email, true).await;
        register_test_user(&state, "autre@example.com", false).await;
        state.log_audit("autre@example.com", "LOGIN_FAILED", "203.0.113.9".to_string(), None).await;

        let reponse = get_server_health(
            State(state.clone()),
            AuthUser { email: admin_email.to_string(), is_moderator: true },
        )
        .await
        .expect("l'Admin doit pouvoir consulter l'état");

        let bytes = axum::body::to_bytes(reponse.into_response().into_body(), usize::MAX).await.unwrap();
        let corps: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(corps["database"]["users"], 2, "les deux comptes créés doivent être comptés");
        assert_eq!(corps["activity"]["failed_logins_24h"], 1, "l'échec de connexion récent doit remonter");
        assert_eq!(corps["database"]["ip_history_rows"], 1, "l'historique IP alimenté par l'audit doit remonter");
        assert!(corps["app_env"].is_string(), "l'environnement doit être renvoyé");
        // Aucune sauvegarde dans un environnement de test : l'absence doit être dite par `null`,
        // pas par un 0 qui se lirait comme « sauvegarde de 0 octet, à l'instant ».
        assert!(corps["backup"]["newest_age_hours"].is_null(), "sans sauvegarde, l'âge doit être null");
        assert_eq!(corps["backup"]["count"], 0);
    }

    /// Surveiller les surveillants : consulter les adresses de quelqu'un est un acte privilégié et
    /// doit donc laisser lui-même une trace. Sans ce test, rien n'empêcherait la trace de
    /// disparaître à la prochaine refonte, et ce serait le seul accès privilégié de l'application
    /// à échapper au journal.
    #[tokio::test]
    async fn test_viewing_ip_history_is_itself_audited() {
        let state = build_test_state().await;
        register_test_user(&state, "moderateur@example.com", true).await;
        register_test_user(&state, "surveille@example.com", false).await;

        get_user_ip_history(
            State(state.clone()),
            ConnectInfo(addr()),
            HeaderMap::new(),
            AuthUser { email: "moderateur@example.com".to_string(), is_moderator: true },
            Path("surveille@example.com".to_string()),
        )
        .await
        .expect("la consultation doit réussir");

        let (actor, action): (String, String) = sqlx::query_as(
            "SELECT user_email, action FROM audit_logs WHERE action LIKE 'IP_HISTORY_VIEWED%'",
        )
        .fetch_one(&state.db)
        .await
        .expect("la consultation doit avoir laissé une entrée d'audit");

        assert_eq!(actor, "moderateur@example.com", "la trace doit désigner CELUI QUI CONSULTE");
        assert_eq!(
            action, "IP_HISTORY_VIEWED:surveille@example.com",
            "la trace doit nommer le compte consulté, sinon elle ne dit pas grand-chose"
        );
    }

    /// Un refus ne doit PAS laisser de trace de consultation : sinon le journal se remplirait
    /// d'accès qui n'ont jamais eu lieu, et une vraie consultation s'y noierait.
    #[tokio::test]
    async fn test_refused_ip_history_is_not_audited_as_a_view() {
        let state = build_test_state().await;

        let _ = get_user_ip_history(
            State(state.clone()),
            ConnectInfo(addr()),
            HeaderMap::new(),
            AuthUser { email: "curieux@example.com".to_string(), is_moderator: false },
            Path("cible@example.com".to_string()),
        )
        .await;

        let traces: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action LIKE 'IP_HISTORY_VIEWED%'",
        )
        .fetch_one(&state.db)
        .await
        .unwrap();
        assert_eq!(traces, 0, "un accès refusé n'est pas une consultation");
    }

    /// Suppression d'un compte : son historique IP part avec lui (ON DELETE CASCADE), contrairement
    /// au journal d'audit volontairement conservé. Le garder serait de la rétention sans usage.
    #[tokio::test]
    async fn test_ip_history_is_removed_with_the_account() {
        let state = build_test_state().await;
        register_test_user(&state, "partant@example.com", false).await;
        seen(&state, "partant@example.com", "LOGIN", "10.0.0.42").await;

        sqlx::query("DELETE FROM users WHERE email = ?")
            .bind("partant@example.com")
            .execute(&state.db).await.unwrap();

        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_ip_history WHERE user_email = ?")
            .bind("partant@example.com")
            .fetch_one(&state.db).await.unwrap();
        assert_eq!(left, 0, "l'historique IP doit disparaître avec le compte");
    }

}