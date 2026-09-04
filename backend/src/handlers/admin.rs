use axum::{
    extract::{State, Path, ConnectInfo},
    http::{StatusCode, HeaderMap},
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
        "SELECT email, is_moderator, email_verified, created_at, max_trusted_devices, can_change_email_via_extension, can_choose_server_in_settings, is_suspended FROM users ORDER BY created_at DESC"
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

    let entry_counts: std::collections::HashMap<String, i64> = entry_counts.into_iter().collect();
    let attachment_sizes: std::collections::HashMap<String, i64> = attachment_sizes.into_iter().collect();

    // is_admin n'est pas une colonne SQL (voir models.rs::AdminUserView) — un seul compte peut
    // jamais correspondre à ADMIN_EMAIL, rempli après coup plutôt que par une comparaison SQL
    // supplémentaire.
    for u in &mut users {
        u.is_admin = state.config.admin_email.as_deref() == Some(u.email.as_str());
        // Absent des agrégats = aucune entrée / aucune pièce jointe, donc zéro (un GROUP BY ne
        // renvoie pas de ligne pour un compte qui n'a rien).
        u.entry_count = entry_counts.get(&u.email).copied().unwrap_or(0);
        u.attachment_bytes = attachment_sizes.get(&u.email).copied().unwrap_or(0);
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

/// Les adresses IP vues pour UN compte, sur la fenêtre du journal d'audit.
///
/// N'ajoute AUCUNE donnée personnelle : `audit_logs` enregistre déjà une IP par événement, et
/// `GET /audit` les expose déjà aux modérateurs — en vrac, tous comptes mêlés, limité aux 100
/// derniers événements. Cette route ne fait que regrouper ce qui existe par compte et par IP, ce
/// qui répond à la question réellement utile ("cette connexion vient-elle d'un endroit
/// inhabituel ?") là où une liste brute ne répond à rien.
///
/// Conséquence directe : la vue est bornée par `AUDIT_LOG_RETENTION_DAYS` (purge à 10 jours). Un
/// historique perpétuel demanderait une nouvelle table, donc une nouvelle rétention de données
/// personnelles et un passif en cas de fuite de la base — pour une valeur de sécurité qui se joue
/// sur les jours récents. Le choix de ne PAS le faire est délibéré.
///
/// Même porte que `GET /audit` (modérateur) : réserver celle-ci à l'Admin donnerait l'illusion
/// d'une protection alors que la même information reste lisible en vrac juste à côté.
///
/// ATTENTION à l'interprétation : derrière un reverse proxy sans `TRUST_PROXY_HEADERS=true`, TOUS
/// les comptes apparaissent avec l'IP du proxy. La route ne peut pas le deviner ; le client
/// prévient (voir Admin.tsx).
pub async fn get_user_ip_history(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(target_email): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    if !user.is_moderator {
        warn!("Tentative de consultation d'historique IP par {} (pas modérateur)", user.email);
        return Err(AppError::Forbidden);
    }
    let target_email = target_email.to_lowercase();

    // Plafond dur : un compte très actif pourrait sinon renvoyer autant de lignes que d'IP vues.
    // 200 IP distinctes sur 10 jours dépasse déjà de loin tout usage familial.
    let history = sqlx::query_as::<_, crate::models::UserIpHistoryEntry>(
        "SELECT ip_address,                 MIN(created_at) AS first_seen,                 MAX(created_at) AS last_seen,                 COUNT(*) AS event_count,                 (SELECT action FROM audit_logs AS inner_log                   WHERE inner_log.user_email = audit_logs.user_email                     AND inner_log.ip_address = audit_logs.ip_address                   ORDER BY inner_log.created_at DESC LIMIT 1) AS last_action            FROM audit_logs           WHERE user_email = ?           GROUP BY ip_address           ORDER BY last_seen DESC           LIMIT 200",
    )
    .bind(&target_email)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(history))
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

    async fn log_event(state: &Arc<AppState>, email: &str, action: &str, ip: &str, at: &str) {
        sqlx::query("INSERT INTO audit_logs (user_email, action, ip_address, user_agent, created_at) VALUES (?, ?, ?, NULL, ?)")
            .bind(email).bind(action).bind(ip).bind(at)
            .execute(&state.db).await.unwrap();
    }

    async fn ip_history_of(state: &Arc<AppState>, caller_is_moderator: bool, target: &str) -> serde_json::Value {
        let result = get_user_ip_history(
            State(state.clone()),
            AuthUser { email: "boss@example.com".to_string(), is_moderator: caller_is_moderator },
            Path(target.to_string()),
        ).await.expect("la consultation doit réussir");
        let bytes = axum::body::to_bytes(result.into_response().into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Même porte que le journal d'audit : un simple utilisateur ne voit pas les IP.
    #[tokio::test]
    async fn test_ip_history_requires_moderator() {
        let state = build_test_state().await;
        let result = get_user_ip_history(
            State(state.clone()),
            AuthUser { email: "curieux@example.com".to_string(), is_moderator: false },
            Path("cible@example.com".to_string()),
        ).await;
        assert!(matches!(result, Err(AppError::Forbidden)), "un non-modérateur ne doit pas voir les IP");
    }

    /// Le regroupement est ce qui fait toute la valeur de la route : plusieurs événements depuis la
    /// MÊME IP doivent donner UNE ligne comptée, pas plusieurs lignes identiques.
    #[tokio::test]
    async fn test_ip_history_groups_by_ip_and_counts() {
        let state = build_test_state().await;
        register_test_user(&state, "cible@example.com", false).await;
        log_event(&state, "cible@example.com", "LOGIN", "10.0.0.1", "2026-09-01 08:00:00").await;
        log_event(&state, "cible@example.com", "LOGIN", "10.0.0.1", "2026-09-01 09:00:00").await;
        log_event(&state, "cible@example.com", "LOGIN_FAILED", "10.0.0.1", "2026-09-02 10:00:00").await;
        log_event(&state, "cible@example.com", "LOGIN", "203.0.113.7", "2026-09-03 11:00:00").await;

        let history = ip_history_of(&state, true, "cible@example.com").await;
        let rows = history.as_array().unwrap();
        assert_eq!(rows.len(), 2, "deux IP distinctes attendues, pas une ligne par événement");

        // Tri par dernière activité décroissante : l'IP vue le 03 passe devant.
        assert_eq!(rows[0]["ip_address"], "203.0.113.7");
        assert_eq!(rows[1]["ip_address"], "10.0.0.1");

        assert_eq!(rows[1]["event_count"], 3, "les 3 événements de 10.0.0.1 doivent être comptés ensemble");
        assert_eq!(rows[1]["first_seen"], "2026-09-01 08:00:00");
        assert_eq!(rows[1]["last_seen"], "2026-09-02 10:00:00");
        assert_eq!(rows[1]["last_action"], "LOGIN_FAILED", "l'action affichée doit être la plus RÉCENTE de cette IP");
    }

    /// Une vue "par compte" qui laisserait fuiter les IP d'un autre compte serait pire qu'inutile.
    #[tokio::test]
    async fn test_ip_history_does_not_leak_other_accounts() {
        let state = build_test_state().await;
        register_test_user(&state, "cible@example.com", false).await;
        register_test_user(&state, "voisin@example.com", false).await;
        log_event(&state, "cible@example.com", "LOGIN", "10.0.0.1", "2026-09-01 08:00:00").await;
        log_event(&state, "voisin@example.com", "LOGIN", "198.51.100.9", "2026-09-01 08:30:00").await;

        let history = ip_history_of(&state, true, "cible@example.com").await;
        let rows = history.as_array().unwrap();
        assert_eq!(rows.len(), 1, "seules les IP du compte demandé doivent apparaître");
        assert_eq!(rows[0]["ip_address"], "10.0.0.1");
        assert_eq!(rows[0]["event_count"], 1, "le sous-select last_action ne doit pas compter d'autres comptes");
    }

}