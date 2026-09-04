use axum::{
    extract::{State, Query, Path, ConnectInfo},
    http::{StatusCode, HeaderMap},
    response::IntoResponse,
    Json
};
use std::{sync::Arc, net::SocketAddr};
use crate::{AppState, error::AppError, crypto, middleware::AuthUser, repository::VaultRepository, models::*};
use validator::Validate;
use tracing::instrument;
use sqlx::Row;
use super::common::get_user_agent;

/// Nombre maximum d'entrées ACTIVES autorisées dans le coffre d'un même utilisateur.
/// Protection contre l'épuisement de stockage : la BDD SQLite est un fichier UNIQUE partagé par
/// tous les utilisateurs — un compte compromis (ou un client buggé) qui spammerait add_to_vault
/// sans limite affecterait tout le monde, pas que son propre coffre. 5000 est très généreux pour
/// un usage personnel réel (largement au-delà de ce qu'un gestionnaire de mots de passe contient
/// habituellement), donc sans impact sur l'usage légitime.
const MAX_VAULT_ENTRIES_PER_USER: i64 = 5000;

// --- GESTION DU COFFRE-FORT (VAULT) ---

/// Liste les entrées chiffrées du coffre-fort de l'utilisateur (avec pagination).
/// PAS de recherche ici (voir models.rs::PaginationParams) : le client doit récupérer les
/// entrées et filtrer/rechercher localement après déchiffrement.
pub async fn get_vault(
    State(state): State<Arc<AppState>>, 
    user: AuthUser, 
    Query(p): Query<PaginationParams> // Extrait les paramètres de pagination (?limit=...&offset=...)
) -> Result<impl IntoResponse, AppError> {
    // Appel de la couche Repository pour récupérer les données en base
    let entries = VaultRepository::get_all(
        &state.db, 
        &user.email, 
        p.effective_limit(), // Plafonné côté serveur, quoi que le client demande dans l'URL
        p.offset.unwrap_or(0) as i64
    ).await?;

    Ok(Json(entries))
}

/// Exporte l'INTÉGRALITÉ du coffre actif (pas de pagination) — permet à l'utilisateur de garder
/// une sauvegarde hors plateforme. Le coffre reste chiffré (Zero-Knowledge) : le serveur ne
/// déchiffre jamais rien, c'est exactement le même contenu que get_vault() renverrait paginé.
/// Redemande le hash du mot de passe maître (comme update_password()/update_email()) : sans ça,
/// un access token volé (courte durée de vie, mais suffisant) permettrait d'exfiltrer TOUT le
/// coffre en un seul appel plutôt que d'être limité à ce que les routes normales exposent.
pub async fn export_vault(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<ExportVaultPayload>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = ?")
        .bind(&user.email)
        .fetch_one(&state.db)
        .await?;
    if !crypto::verify_password(&payload.master_password_hash, &current_user.password_hash, &state.config.password_pepper).await {
        return Err(AppError::InvalidCredentials);
    }

    // MAX_VAULT_ENTRIES_PER_USER couvre déjà le pire cas réel (un utilisateur ne peut jamais
    // avoir plus d'entrées actives que ce plafond, voir add_to_vault()) : pas besoin d'une vraie
    // pagination ici, une seule requête suffit à tout récupérer.
    let entries = VaultRepository::get_all(&state.db, &user.email, MAX_VAULT_ENTRIES_PER_USER, 0).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "VAULT_EXPORT", addr.to_string(), agent).await;

    Ok(Json(entries))
}

/// Exporte l'INTÉGRALITÉ de l'historique de mots de passe de l'utilisateur (tous dossiers/entrées
/// confondus) — c'est ce que le CLIENT doit récupérer, re-chiffrer, puis renvoyer dans
/// `ChangeMasterPasswordPayload::reencrypted_history` lors d'un changement de mot de passe maître
/// (voir update_password() dans handlers/auth/account.rs). Même exigence de reconfirmation du mot
/// de passe maître qu'export_vault(), pour la même raison (éviter qu'un access token volé suffise
/// à exfiltrer tout l'historique en un seul appel).
pub async fn export_vault_history(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<ExportVaultPayload>,
) -> Result<impl IntoResponse, AppError> {
    let current_user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = ?")
        .bind(&user.email)
        .fetch_one(&state.db)
        .await?;
    if !crypto::verify_password(&payload.master_password_hash, &current_user.password_hash, &state.config.password_pepper).await {
        return Err(AppError::InvalidCredentials);
    }

    let history = VaultRepository::get_all_history_for_user(&state.db, &user.email).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "VAULT_HISTORY_EXPORT", addr.to_string(), agent).await;

    Ok(Json(history))
}

/// Importe en bloc un ensemble d'entrées (typiquement la restauration d'un backup produit par
/// export_vault()). Chaque entrée devient une NOUVELLE ligne du coffre — jamais de fusion ni
/// d'écrasement de l'existant : c'est la sémantique la plus simple et la plus sûre possible, un
/// import ne peut jamais faire perdre ou altérer une donnée déjà présente, seulement en ajouter.
/// Tout ou rien (transaction) : si une seule entrée est invalide, ou si l'import dépasse le
/// plafond du coffre, RIEN n'est importé plutôt que de laisser un import à moitié appliqué.
/// Pas de reconfirmation du mot de passe maître (contrairement à export_vault()) : un import ne
/// peut qu'AJOUTER des données au coffre de son propriétaire, jamais en exfiltrer ou en altérer —
/// même modèle de confiance que add_to_vault() (un access token valide suffit).
pub async fn import_vault(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Json(payload): Json<ImportVaultPayload>,
) -> Result<impl IntoResponse, AppError> {
    if payload.entries.is_empty() {
        return Err(AppError::ValidationError("Aucune entrée à importer".to_string()));
    }
    for entry in &payload.entries {
        entry.validate()?;
    }

    // Garde-fou anti-épuisement de stockage, même raison que add_to_vault() : voir
    // MAX_VAULT_ENTRIES_PER_USER. Vérifié AVANT toute écriture pour que l'import reste tout-ou-rien.
    let active_count = VaultRepository::count_active(&state.db, &user.email).await?;
    let import_count = payload.entries.len() as i64;
    if active_count + import_count > MAX_VAULT_ENTRIES_PER_USER {
        return Err(AppError::ValidationError(format!(
            "Cet import dépasserait la limite de {MAX_VAULT_ENTRIES_PER_USER} entrées du coffre ({active_count} déjà présente(s), {import_count} à importer)."
        )));
    }

    let mut tx = state.db.begin().await?;
    // CORRECTIF PERF (retour utilisateur, 2026-09-02) : add_many_in_tx() groupe les entrées en
    // INSERT multi-lignes par lots, plutôt qu'une requête séparée par entrée — voir son
    // commentaire dans repository.rs pour le détail (limite de paramètres SQLite, découpage en lots).
    VaultRepository::add_many_in_tx(&mut tx, &user.email, &payload.entries).await?;
    tx.commit().await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "VAULT_IMPORT", addr.to_string(), agent).await;

    // Réveille les AUTRES appareils connectés (voir handlers/sync.rs), un seul événement pour
    // tout l'import plutôt qu'un par entrée : le client doit de toute façon rappeler GET /vault.
    let _ = state.sync_tx.send(SyncEvent { user_email: user.email.clone(), event_type: "VAULT_IMPORT".to_string() });

    Ok((StatusCode::CREATED, Json(serde_json::json!({ "imported": import_count }))))
}

/// Ajoute un nouvel élément (identifiant/mot de passe chiffré) au coffre-fort.
pub async fn add_to_vault(
    State(state): State<Arc<AppState>>, 
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser, 
    Json(entry): Json<VaultEntryInput> // Données de l'élément à ajouter
) -> Result<impl IntoResponse, AppError> {
    entry.validate()?;

    // Garde-fou anti-épuisement de stockage : voir MAX_VAULT_ENTRIES_PER_USER ci-dessus.
    let active_count = VaultRepository::count_active(&state.db, &user.email).await?;
    if active_count >= MAX_VAULT_ENTRIES_PER_USER {
        return Err(AppError::ValidationError(format!(
            "Limite de {} entrées atteinte pour ce coffre.",
            MAX_VAULT_ENTRIES_PER_USER
        )));
    }

    // Persistance de l'élément via le VaultRepository
    VaultRepository::add(&state.db, &user.email, entry).await?;
    
    // Log d'audit de l'action
    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "VAULT_ADD", addr.to_string(), agent).await;

    // Réveille les AUTRES appareils connectés de cet utilisateur (voir handlers/sync.rs) :
    // ignore volontairement le résultat, `send` échoue seulement si personne n'écoute
    // actuellement (aucune connexion WebSocket ouverte) — ce n'est pas une erreur.
    let _ = state.sync_tx.send(SyncEvent { user_email: user.email.clone(), event_type: "VAULT_ADD".to_string() });
        
    Ok(StatusCode::CREATED)
}

/// Supprime un élément spécifique du coffre-fort via son identifiant (ID passé dans l'URL).
pub async fn delete_vault_entry(
    State(state): State<Arc<AppState>>, 
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser, 
    Path(id): Path<String> // Extrait le paramètre d'URL dynamique :id
) -> Result<impl IntoResponse, AppError> {
    VaultRepository::delete(&state.db, &user.email, &id).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "VAULT_DELETE", addr.to_string(), agent).await;

    // Réveille les AUTRES appareils connectés de cet utilisateur (voir handlers/sync.rs) :
    // ignore volontairement le résultat, `send` échoue seulement si personne n'écoute
    // actuellement (aucune connexion WebSocket ouverte) — ce n'est pas une erreur.
    let _ = state.sync_tx.send(SyncEvent { user_email: user.email.clone(), event_type: "VAULT_DELETE".to_string() });

    Ok(StatusCode::NO_CONTENT) // 204 No Content : Suppression réussie sans données de retour
}

/// Modifie un élément existant du coffre-fort.
#[instrument(skip(state, entry, user, addr, headers), fields(user = %user.email))]
pub async fn update_vault_entry(
    State(state): State<Arc<AppState>>, 
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser, 
    Path(id): Path<String>, 
    Json(entry): Json<VaultEntryInput>
) -> Result<impl IntoResponse, AppError> {
    entry.validate()?;
    VaultRepository::update(&state.db, &user.email, &id, entry).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "VAULT_UPDATE", addr.to_string(), agent).await;

    // Réveille les AUTRES appareils connectés de cet utilisateur (voir handlers/sync.rs) :
    // ignore volontairement le résultat, `send` échoue seulement si personne n'écoute
    // actuellement (aucune connexion WebSocket ouverte) — ce n'est pas une erreur.
    let _ = state.sync_tx.send(SyncEvent { user_email: user.email.clone(), event_type: "VAULT_UPDATE".to_string() });

    Ok(StatusCode::OK)
}

/// Alterne le statut "favori" d'un élément du coffre (Ajoute ou retire des favoris).
pub async fn toggle_favorite(
    State(state): State<Arc<AppState>>, 
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser, 
    Path(id): Path<String>
) -> Result<impl IntoResponse, AppError> {
    VaultRepository::toggle_favorite(&state.db, &user.email, &id).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "VAULT_TOGGLE_FAVORITE", addr.to_string(), agent).await;

    // Réveille les AUTRES appareils connectés de cet utilisateur (voir handlers/sync.rs) :
    // ignore volontairement le résultat, `send` échoue seulement si personne n'écoute
    // actuellement (aucune connexion WebSocket ouverte) — ce n'est pas une erreur.
    let _ = state.sync_tx.send(SyncEvent { user_email: user.email.clone(), event_type: "VAULT_TOGGLE_FAVORITE".to_string() });

    Ok(StatusCode::OK)
}

/// Enregistre une UTILISATION d'une entrée (copie du mot de passe OU remplissage automatique,
/// décidés comme équivalents côté client — voir lib/vaultUsage.ts) — retour utilisateur
/// (2026-09-02), pour un tri "le plus utilisé" côté client (voir VaultEntry::use_count). Appelée
/// en best-effort par le client (jamais bloquant sur l'action réelle : copier/remplir doit rester
/// instantané pour l'utilisateur, cet appel part sans attendre sa réponse).
///
/// Volontairement PAS de log d'audit (une copie de mot de passe est une action ROUTINE et
/// FRÉQUENTE, pas un événement de sécurité comme une connexion ou un changement de mot de passe —
/// en journaliser chaque occurrence gonflerait `audit_logs` sans intérêt de sécurité réel) NI de
/// réveil des autres appareils via sync_tx (contrairement à toggle_favorite ci-dessus) : diffuser
/// un événement de synchronisation à CHAQUE copie de mot de passe déclencherait un rechargement
/// complet du coffre sur tous les autres appareils connectés, potentiellement plusieurs fois par
/// minute pour un usage actif — bien plus coûteux que l'intérêt d'un compteur d'usage à jour à la
/// seconde près. Les autres appareils verront la valeur à jour au prochain rechargement naturel du
/// coffre (connexion, actualisation manuelle...), cohérence "à terme" largement suffisante ici.
pub async fn record_vault_entry_use(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    VaultRepository::record_use(&state.db, &user.email, &id).await?;
    Ok(StatusCode::OK)
}

/// Nombre maximum de versions d'historique renvoyées par appel — reflète MAX_HISTORY_PER_ENTRY
/// (voir repository.rs), qui plafonne déjà ce qui est CONSERVÉ en base.
const MAX_HISTORY_RESULTS: i64 = 20;

/// Historique des mots de passe d'UNE entrée du coffre, du plus récent au plus ancien — archivé
/// automatiquement à chaque changement RÉEL de mot de passe (voir
/// VaultEntryInput::password_changed et VaultRepository::update()). Ne nécessite pas de
/// reconfirmation du mot de passe maître (contrairement à /vault/export) : ce n'est qu'un
/// sous-ensemble du même contenu déjà accessible via GET /vault, chiffré de la même façon — un
/// access token valide suffit, comme pour le reste des routes /vault/*.
pub async fn get_vault_entry_history(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let history = VaultRepository::get_history(&state.db, &user.email, &id, MAX_HISTORY_RESULTS).await?;
    Ok(Json(history))
}

// --- PIÈCES JOINTES CHIFFRÉES ---
// Nom de fichier ET contenu chiffrés côté client (voir crypto.rs), le serveur ne les lit jamais —
// juste des quotas EN CLAIR (nombre de fichiers, taille annoncée) pour se protéger contre
// l'épuisement de stockage, même logique que MAX_VAULT_ENTRIES_PER_USER ci-dessus.

/// Nombre maximum de pièces jointes par ENTRÉE — garde le listing d'une entrée raisonnable, et
/// évite qu'une seule entrée n'accapare tout le quota utilisateur ci-dessous.
const MAX_ATTACHMENTS_PER_ENTRY: i64 = 5;

/// Nombre maximum de pièces jointes, TOUTES entrées confondues, par utilisateur. À 5 Mo par
/// fichier max (voir models.rs::VaultAttachmentInput), ce plafond borne le pire cas à 50 x 5 Mo =
/// 250 Mo par utilisateur — généreux pour un usage personnel (codes de secours, scans de pièces
/// d'identité...), sans laisser un compte unique saturer le fichier SQLite partagé.
const MAX_ATTACHMENTS_PER_USER: i64 = 50;

/// Ajoute une pièce jointe chiffrée à une entrée du coffre.
pub async fn add_vault_attachment(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(vault_id): Path<String>,
    Json(input): Json<VaultAttachmentInput>,
) -> Result<impl IntoResponse, AppError> {
    input.validate()?;

    // CORRECTIF PERF (retour utilisateur, 2026-09-02) : les deux COUNT() sont indépendants (l'un
    // filtré par entrée+email, l'autre par email seul) — lancés en parallèle plutôt qu'enchaînés,
    // même raisonnement que update_password() dans handlers/auth/account.rs.
    let (per_entry_count, total_count) = tokio::try_join!(
        VaultRepository::count_attachments_for_entry(&state.db, &user.email, &vault_id),
        VaultRepository::count_attachments_for_user(&state.db, &user.email),
    )?;
    if per_entry_count >= MAX_ATTACHMENTS_PER_ENTRY {
        return Err(AppError::ValidationError(format!(
            "Limite de {MAX_ATTACHMENTS_PER_ENTRY} pièce(s) jointe(s) par entrée atteinte."
        )));
    }
    if total_count >= MAX_ATTACHMENTS_PER_USER {
        return Err(AppError::ValidationError(format!(
            "Limite de {MAX_ATTACHMENTS_PER_USER} pièces jointes atteinte pour ce coffre."
        )));
    }

    let id = VaultRepository::add_attachment(&state.db, &user.email, &vault_id, &input).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "VAULT_ATTACHMENT_ADD", addr.to_string(), agent).await;
    let _ = state.sync_tx.send(SyncEvent { user_email: user.email.clone(), event_type: "VAULT_ATTACHMENT_ADD".to_string() });

    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id }))))
}

/// Liste les pièces jointes d'une entrée, SANS leur contenu (voir VaultAttachmentMeta) — le
/// contenu de chaque fichier se récupère séparément via GET .../attachments/{attachment_id}.
pub async fn get_vault_attachments(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path(vault_id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    let attachments = VaultRepository::list_attachments(&state.db, &user.email, &vault_id).await?;
    Ok(Json(attachments))
}

/// Récupère UNE pièce jointe complète (avec son contenu chiffré) — pour le téléchargement.
pub async fn get_vault_attachment(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
    Path((vault_id, attachment_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    let attachment = VaultRepository::get_attachment(&state.db, &user.email, &vault_id, &attachment_id).await?;
    Ok(Json(attachment))
}

/// Supprime définitivement une pièce jointe (pas de corbeille pour les pièces jointes).
pub async fn delete_vault_attachment(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path((vault_id, attachment_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, AppError> {
    VaultRepository::delete_attachment(&state.db, &user.email, &vault_id, &attachment_id).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "VAULT_ATTACHMENT_DELETE", addr.to_string(), agent).await;
    let _ = state.sync_tx.send(SyncEvent { user_email: user.email.clone(), event_type: "VAULT_ATTACHMENT_DELETE".to_string() });

    Ok(StatusCode::NO_CONTENT)
}

// --- CORBEILLE (SUPPRESSION DOUCE) ---
// delete_vault_entry() ci-dessus ne fait plus qu'une suppression DOUCE (voir repository.rs) :
// l'entrée disparaît des listages normaux mais reste récupérable pendant 30 jours via les
// deux routes ci-dessous, avant d'être purgée automatiquement (voir main.rs).

/// Liste les entrées récemment supprimées (corbeille) de l'utilisateur connecté.
pub async fn get_trash(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    let entries = VaultRepository::get_trash(&state.db, &user.email).await?;
    Ok(Json(entries))
}

/// Restaure une entrée de la corbeille : elle réapparaît immédiatement dans le coffre normal.
pub async fn restore_vault_entry(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    VaultRepository::restore(&state.db, &user.email, &id).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "VAULT_RESTORE", addr.to_string(), agent).await;

    // Réveille les AUTRES appareils connectés de cet utilisateur (voir handlers/sync.rs) :
    // ignore volontairement le résultat, `send` échoue seulement si personne n'écoute
    // actuellement (aucune connexion WebSocket ouverte) — ce n'est pas une erreur.
    let _ = state.sync_tx.send(SyncEvent { user_email: user.email.clone(), event_type: "VAULT_RESTORE".to_string() });

    Ok(StatusCode::OK)
}

/// Supprime DÉFINITIVEMENT une entrée déjà présente dans la corbeille (vidage manuel,
/// sans attendre la purge automatique à 30 jours). Aucun retour en arrière possible après ça.
pub async fn permanently_delete_vault_entry(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, AppError> {
    VaultRepository::purge(&state.db, &user.email, &id).await?;

    let agent = get_user_agent(&headers);
    state.log_audit(&user.email, "VAULT_PURGE", addr.to_string(), agent).await;

    // Réveille les AUTRES appareils connectés de cet utilisateur (voir handlers/sync.rs) :
    // ignore volontairement le résultat, `send` échoue seulement si personne n'écoute
    // actuellement (aucune connexion WebSocket ouverte) — ce n'est pas une erreur.
    let _ = state.sync_tx.send(SyncEvent { user_email: user.email.clone(), event_type: "VAULT_PURGE".to_string() });

    Ok(StatusCode::NO_CONTENT)
}

// --- ROUTE : GET /api/vault/sync et son alias /api/vault/sync-check ---

/// Endpoint de synchronisation ultra-léger pour l'App et l'Extension.
/// Permet au client de savoir s'il doit télécharger une mise à jour du coffre.
/// Les deux routes (/api/vault/sync et /api/vault/sync-check, alias historique de l'extension)
/// pointent vers ce même handler dans main.rs — inutile de dupliquer la requête SQL.
#[instrument(skip(state, user))]
pub async fn check_sync(
    State(state): State<Arc<AppState>>,
    user: AuthUser, // Ton middleware extrait l'utilisateur authentifié
) -> Result<impl IntoResponse, AppError> {

    // On récupère le nombre d'éléments et la date de la modification la plus récente.
    // "deleted_at IS NULL" : une entrée passée à la corbeille ne doit pas compter dans le total
    // ni faire bouger le sync_token — pour le client, elle a bel et bien disparu du coffre.
    // IMPORTANT : la valeur de secours ('1970-01-01 00:00:00') utilise le MÊME format que celui
    // produit par CURRENT_TIMESTAMP de SQLite (espace, pas de 'T'/'Z') — sinon le champ
    // `last_modified` renvoyé au client aurait un format différent selon que le coffre est vide
    // ou non, ce qui pourrait faire échouer un parseur de date strict côté client.
    let row = sqlx::query(
        "SELECT 
            COUNT(*) as total, 
            COALESCE(MAX(updated_at), '1970-01-01 00:00:00') as last_update 
         FROM vault 
         WHERE user_email = ? AND deleted_at IS NULL"
    )
    .bind(&user.email)
    .fetch_one(&state.db)
    .await?;

    let total_entries: i64 = row.get("total");
    let last_update: String = row.get("last_update");

    // Génération d'un token déterministe unique basé sur l'état du coffre
    let sync_token = format!("{}_{}", total_entries, last_update);

    Ok(Json(SyncResponse {
        sync_token,
        total_entries,
        last_modified: last_update,
    }))
}

// =========================================================================
// TESTS SUR LE COFFRE-FORT
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use sqlx::sqlite::SqlitePoolOptions;

    /// Construit un AppState de test : BDD SQLite en mémoire + migrations réelles + config factice.
    /// Dupliqué depuis handlers/auth.rs volontairement : chaque module de tests reste autonome,
    /// sans dépendance croisée entre modules de handlers juste pour les tests.
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

    /// Crée un utilisateur de test directement en BDD (pas besoin du handler register() ici,
    /// on ne teste pas l'inscription dans ce module — juste le coffre d'un utilisateur qui existe).
    async fn register_test_user(state: &Arc<AppState>, email: &str) {
        sqlx::query("INSERT INTO users (email, password_hash) VALUES (?, ?)")
            .bind(email)
            .bind("hash_non_pertinent_pour_ce_test")
            .execute(&state.db)
            .await
            .expect("l'insertion de l'utilisateur de test doit réussir");
    }

    /// Variante avec un VRAI hash Argon2, nécessaire pour tester export_vault() qui vérifie
    /// réellement le mot de passe fourni (contrairement à register_test_user() ci-dessus).
    async fn register_user_with_real_password(state: &Arc<AppState>, email: &str, password: &str) {
        let hash = crate::crypto::hash_password(password, &state.config.password_pepper).await.unwrap();
        sqlx::query("INSERT INTO users (email, password_hash) VALUES (?, ?)")
            .bind(email)
            .bind(hash)
            .execute(&state.db)
            .await
            .expect("l'insertion de l'utilisateur de test doit réussir");
    }

    /// Vérifie le cycle de vie complet d'une entrée du coffre : ajout, bascule favori,
    /// modification, puis suppression — chaque étape est vérifiée directement en BDD.
    #[tokio::test]
    async fn test_vault_crud_lifecycle() {
        let state = build_test_state().await;
        let email = "vaultowner@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        // 1. Ajout
        let entry = VaultEntryInput {
            encrypted_site_name: "GitHub".to_string(),
            encrypted_username: Some("moi".to_string()),
            encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre_xyz".to_string(),
            encrypted_preferred_login_type: "username".to_string(),
            is_favorite: false,
        };
        add_to_vault(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Json(entry),
        ).await.expect("l'ajout doit réussir");

        let id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .expect("l'entrée doit exister en BDD après l'ajout");

        // 2. Bascule favori : false -> true
        toggle_favorite(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Path(id.clone()),
        ).await.expect("la bascule favori doit réussir");

        let is_favorite: bool = sqlx::query_scalar("SELECT is_favorite FROM vault WHERE id = ?")
            .bind(&id)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert!(is_favorite, "is_favorite doit être passé à true");

        // 3. Modification
        let updated_entry = VaultEntryInput {
            encrypted_site_name: "GitLab".to_string(), // renommé
            encrypted_username: Some("moi".to_string()),
            encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre_xyz".to_string(),
            encrypted_preferred_login_type: "username".to_string(),
            is_favorite: true,
        };
        update_vault_entry(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Path(id.clone()),
            Json(updated_entry),
        ).await.expect("la modification doit réussir");

        let encrypted_site_name: String = sqlx::query_scalar("SELECT encrypted_site_name FROM vault WHERE id = ?")
            .bind(&id)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(encrypted_site_name, "GitLab", "le nom du site doit avoir été mis à jour");

        // 4. Suppression (DOUCE — voir la corbeille : la ligne reste en BDD, testée en détail
        // par test_delete_vault_entry_soft_deletes_and_hides_from_listing et les tests dédiés
        // restore()/purge(). Ici on vérifie juste que le cycle de vie normal déclenche bien ça.)
        delete_vault_entry(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Path(id.clone()),
        ).await.expect("la suppression doit réussir");

        // La ligne existe TOUJOURS (suppression douce), mais deleted_at doit être renseigné
        let deleted_at: Option<String> = sqlx::query_scalar("SELECT deleted_at FROM vault WHERE id = ?")
            .bind(&id)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert!(deleted_at.is_some(), "l'entrée doit être passée à la corbeille (deleted_at renseigné)");

        // Et elle ne doit plus apparaître dans le listage actif
        let active_entries = VaultRepository::get_all(&state.db, email, 50, 0).await.unwrap();
        assert!(active_entries.is_empty(), "une entrée supprimée ne doit plus apparaître dans le listage actif");
    }

    /// PATCH /vault/{id}/use (voir record_vault_entry_use) doit incrémenter use_count à chaque
    /// appel, sans jamais toucher updated_at/version (contrairement à toggle_favorite) — retour
    /// utilisateur (2026-09-02), pour le tri "le plus utilisé". Vérifie aussi l'isolation entre
    /// utilisateurs (même raisonnement que test_vault_isolation_between_users pour les autres
    /// routes) : un appel sur l'entrée d'un AUTRE utilisateur doit échouer en 404, pas incrémenter
    /// silencieusement le compteur de quelqu'un d'autre.
    #[tokio::test]
    async fn test_record_vault_entry_use_increments_counter_without_touching_version_or_ownership() {
        let state = build_test_state().await;
        let owner = "usecountowner@example.com";
        let other = "usecountother@example.com";
        register_test_user(&state, owner).await;
        register_test_user(&state, other).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = VaultEntryInput {
            encrypted_site_name: "GitHub".to_string(),
            encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre_xyz".to_string(),
            encrypted_preferred_login_type: "username".to_string(),
            is_favorite: false,
        };
        add_to_vault(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: owner.to_string(), is_moderator: false },
            Json(entry),
        ).await.expect("l'ajout doit réussir");

        let id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(owner).fetch_one(&state.db).await.unwrap();
        let (version_before, updated_at_before): (i64, String) = sqlx::query_as("SELECT version, updated_at FROM vault WHERE id = ?")
            .bind(&id).fetch_one(&state.db).await.unwrap();

        // Un autre utilisateur ne doit jamais pouvoir incrémenter le compteur de quelqu'un d'autre.
        let denied = record_vault_entry_use(
            State(state.clone()),
            AuthUser { email: other.to_string(), is_moderator: false },
            Path(id.clone()),
        ).await;
        assert!(denied.is_err(), "un utilisateur ne doit pas pouvoir marquer une entrée qui ne lui appartient pas comme utilisée");

        // Deux appels du propriétaire -> use_count = 2, version/updated_at INCHANGÉS.
        for _ in 0..2 {
            record_vault_entry_use(
                State(state.clone()),
                AuthUser { email: owner.to_string(), is_moderator: false },
                Path(id.clone()),
            ).await.expect("l'enregistrement d'usage doit réussir pour le propriétaire");
        }

        let (use_count, version_after, updated_at_after): (i64, i64, String) = sqlx::query_as("SELECT use_count, version, updated_at FROM vault WHERE id = ?")
            .bind(&id).fetch_one(&state.db).await.unwrap();
        assert_eq!(use_count, 2, "use_count doit refléter les deux appels réussis (celui de l'autre utilisateur ne doit pas avoir compté)");
        assert_eq!(version_after, version_before, "un simple compteur d'usage ne doit jamais faire avancer version (pas une modification de contenu)");
        assert_eq!(updated_at_after, updated_at_before, "un simple compteur d'usage ne doit jamais toucher updated_at");
    }

    /// encrypted_folder doit vraiment être persisté et renvoyé (round-trip complet) : à l'ajout,
    /// à la lecture, et lors d'une modification — pas juste accepté sans erreur puis perdu en
    /// route (un bug d'ordre de colonne/bind serait invisible dans les autres tests, qui utilisent
    /// tous `encrypted_folder: None`).
    #[tokio::test]
    async fn test_encrypted_folder_round_trips_through_add_get_and_update() {
        let state = build_test_state().await;
        let email = "folderowner@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = VaultEntryInput {
            encrypted_site_name: "Banque".to_string(),
            encrypted_username: None,
            encrypted_login_email: None,
            encrypted_folder: Some("chiffre_dossier_travail".to_string()),
            encrypted_notes: None,
            encrypted_url: None,
            password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(),
            encrypted_preferred_login_type: "email".to_string(),
            is_favorite: false,
        };
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");

        let result = get_vault(
            State(state.clone()),
            AuthUser { email: email.to_string(), is_moderator: false },
            Query(PaginationParams { limit: None, offset: None }),
        ).await.expect("la lecture doit réussir");
        let value = read_json_body(result.into_response()).await;
        let entries = value.as_array().expect("la réponse doit être un tableau JSON");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0]["encrypted_folder"].as_str(),
            Some("chiffre_dossier_travail"),
            "le dossier doit être renvoyé tel quel après l'ajout"
        );

        let id = entries[0]["id"].as_str().unwrap().to_string();
        let updated = VaultEntryInput {
            encrypted_site_name: "Banque".to_string(),
            encrypted_username: None,
            encrypted_login_email: None,
            encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None, // retire le dossier
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(),
            encrypted_preferred_login_type: "email".to_string(),
            is_favorite: false,
        };
        update_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(id), Json(updated))
            .await.expect("la modification doit réussir");

        let after_update = VaultRepository::get_all(&state.db, email, 50, 0).await.unwrap();
        assert_eq!(after_update.len(), 1);
        assert_eq!(after_update[0].encrypted_folder, None, "le dossier doit avoir été retiré après la modification");
    }

    /// CORRECTIF (détection de conflit) : un PUT dont `expected_version` correspond bien à
    /// `version` tel qu'il est actuellement en base doit réussir normalement — le garde-fou ne
    /// doit jamais bloquer le cas normal (personne d'autre n'a touché l'entrée entre-temps).
    #[tokio::test]
    async fn test_update_succeeds_when_expected_version_matches() {
        let state = build_test_state().await;
        let email = "conflictok@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = VaultEntryInput {
            encrypted_site_name: "Site".to_string(), encrypted_username: None, encrypted_login_email: None,
            encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");

        let (id, version): (String, i64) = sqlx::query_as("SELECT id, version FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert_eq!(version, 1, "une entrée fraîchement créée doit démarrer à la version 1");

        let update = VaultEntryInput {
            encrypted_site_name: "Site modifié".to_string(), encrypted_username: None, encrypted_login_email: None,
            encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false,
            expected_version: Some(version),
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        let result = update_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(id.clone()), Json(update)).await;
        assert!(result.is_ok(), "un expected_version qui correspond bien à l'état actuel ne doit jamais être bloqué");

        let new_version: i64 = sqlx::query_scalar("SELECT version FROM vault WHERE id = ?")
            .bind(&id).fetch_one(&state.db).await.unwrap();
        assert_eq!(new_version, 2, "version doit être incrémentée à chaque modification réussie");
    }

    /// CORRECTIF CRITIQUE (perte de données silencieuse) : si l'entrée a été modifiée depuis que
    /// le client l'a chargée (version différente de expected_version), la modification doit être
    /// REFUSÉE (409 Conflict) plutôt que d'écraser silencieusement le changement intermédiaire —
    /// le scénario exact d'un même compte édité depuis deux appareils presque simultanément.
    /// N'utilise PAS updated_at pour cette détection : CURRENT_TIMESTAMP en SQLite n'a qu'une
    /// précision à la seconde, donc deux modifications survenant dans la même seconde de test
    /// auraient le même horodatage — c'est justement pour ça que `version` (un compteur entier
    /// dédié) est utilisé à la place, voir models.rs.
    #[tokio::test]
    async fn test_update_rejects_stale_expected_version() {
        let state = build_test_state().await;
        let email = "conflictstale@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = VaultEntryInput {
            encrypted_site_name: "Site".to_string(), encrypted_username: None, encrypted_login_email: None,
            encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");

        let (id, original_version): (String, i64) = sqlx::query_as("SELECT id, version FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        // "Appareil A" modifie l'entrée en premier (sans condition, comme un client à jour qui
        // vient de charger l'entrée) — la version passe à 2 en base.
        let first_update = VaultEntryInput {
            encrypted_site_name: "Modifié par A".to_string(), encrypted_username: None, encrypted_login_email: None,
            encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false,
            expected_version: Some(original_version),
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        update_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(id.clone()), Json(first_update))
            .await.expect("la première modification doit réussir");

        // "Appareil B" avait chargé l'entrée AVANT la modification de A — son expected_version
        // (toujours l'original) est donc désormais périmé (la vraie version en base est 2).
        let second_update = VaultEntryInput {
            encrypted_site_name: "Modifié par B".to_string(), encrypted_username: None, encrypted_login_email: None,
            encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false,
            expected_version: Some(original_version),
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        let result = update_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(id.clone()), Json(second_update)).await;
        assert!(matches!(result, Err(AppError::Conflict(_))), "une modification basée sur un expected_version périmé doit être refusée en conflit");

        // La modification de A doit être celle qui a survécu, pas écrasée silencieusement par B.
        let current: String = sqlx::query_scalar("SELECT encrypted_site_name FROM vault WHERE id = ?")
            .bind(&id).fetch_one(&state.db).await.unwrap();
        assert_eq!(current, "Modifié par A", "le refus du conflit ne doit pas avoir laissé passer B malgré tout");
    }

    /// Un client qui n'envoie pas `expected_version` (`None`, ex: ancien client) doit conserver
    /// EXACTEMENT le comportement d'avant ce correctif : aucune vérification, toujours accepté.
    #[tokio::test]
    async fn test_update_without_expected_version_skips_conflict_check() {
        let state = build_test_state().await;
        let email = "conflictskip@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = VaultEntryInput {
            encrypted_site_name: "Site".to_string(), encrypted_username: None, encrypted_login_email: None,
            encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");
        let id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        // Deux modifications successives, toutes deux sans expected_version : aucune ne doit
        // jamais être bloquée, peu importe combien de fois l'entrée a changé entre-temps.
        for i in 0..2 {
            let update = VaultEntryInput {
                encrypted_site_name: format!("Modif {i}"), encrypted_username: None, encrypted_login_email: None,
                encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
                entry_type: "login".to_string(), encrypted_extra_fields: None,
                encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
            };
            update_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
                AuthUser { email: email.to_string(), is_moderator: false }, Path(id.clone()), Json(update))
                .await.expect("sans expected_version, la modification ne doit jamais être bloquée");
        }
    }

    /// Un changement RÉEL de mot de passe (password_changed: true) doit archiver l'ANCIEN mot de
    /// passe chiffré dans l'historique avant de l'écraser.
    #[tokio::test]
    async fn test_password_history_archives_on_real_password_change() {
        let state = build_test_state().await;
        let email = "historyowner@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = VaultEntryInput {
            encrypted_site_name: "Site".to_string(), encrypted_username: None, encrypted_login_email: None,
            encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "ancien_chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");
        let id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        let updated = VaultEntryInput {
            encrypted_site_name: "Site".to_string(), encrypted_username: None, encrypted_login_email: None,
            encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: true, expected_version: None, // <- changement réel
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "nouveau_chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        update_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(id.clone()), Json(updated))
            .await.expect("la modification doit réussir");

        let history_result = get_vault_entry_history(
            State(state.clone()),
            AuthUser { email: email.to_string(), is_moderator: false },
            Path(id),
        ).await.expect("la lecture de l'historique doit réussir");
        let value = read_json_body(history_result.into_response()).await;
        let rows = value.as_array().expect("la réponse doit être un tableau JSON");
        assert_eq!(rows.len(), 1, "l'ancien mot de passe doit avoir été archivé une fois");
        assert_eq!(
            rows[0]["encrypted_password"].as_str(),
            Some("ancien_chiffre"),
            "la ligne archivée doit contenir l'ANCIEN mot de passe, pas le nouveau"
        );
    }

    /// Une modification qui ne touche PAS réellement le mot de passe (password_changed: false, expected_version: None, ex:
    /// juste renommer le site) ne doit rien archiver — sinon l'historique se remplirait de bruit à
    /// chaque édition anodine.
    #[tokio::test]
    async fn test_password_history_not_archived_without_real_password_change() {
        let state = build_test_state().await;
        let email = "nohistoryowner@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = VaultEntryInput {
            encrypted_site_name: "Site".to_string(), encrypted_username: None, encrypted_login_email: None,
            encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");
        let id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        // Renomme le site, mais password_changed reste false — même si un blob "encrypted_password"
        // est bien resoumis à chaque appel (comme le fait un vrai client), il ne doit PAS être
        // archivé puisqu'il ne s'agit pas d'un changement voulu du mot de passe.
        let updated = VaultEntryInput {
            encrypted_site_name: "SiteRenomme".to_string(), encrypted_username: None, encrypted_login_email: None,
            encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre_reencode_differemment".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        update_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(id.clone()), Json(updated))
            .await.expect("la modification doit réussir");

        let history_result = get_vault_entry_history(
            State(state.clone()),
            AuthUser { email: email.to_string(), is_moderator: false },
            Path(id),
        ).await.expect("la lecture de l'historique doit réussir");
        let value = read_json_body(history_result.into_response()).await;
        let rows = value.as_array().expect("la réponse doit être un tableau JSON");
        assert!(rows.is_empty(), "aucune ligne d'historique ne doit être créée sans changement réel du mot de passe");
    }

    /// L'historique est plafonné par entrée (MAX_HISTORY_PER_ENTRY = 20, voir repository.rs) : au
    /// delà, les versions les plus anciennes sont purgées automatiquement plutôt que de croître
    /// indéfiniment.
    #[tokio::test]
    async fn test_password_history_retention_caps_oldest_versions() {
        const MAX_HISTORY_PER_ENTRY: usize = 20; // doit rester synchronisé avec repository.rs

        let state = build_test_state().await;
        let email = "retentionowner@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = VaultEntryInput {
            encrypted_site_name: "Site".to_string(), encrypted_username: None, encrypted_login_email: None,
            encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "version_0".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");
        let id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        // MAX_HISTORY_PER_ENTRY + 5 changements réels -> seules les MAX_HISTORY_PER_ENTRY plus
        // récentes versions archivées doivent survivre.
        for i in 1..=(MAX_HISTORY_PER_ENTRY + 5) {
            let updated = VaultEntryInput {
                encrypted_site_name: "Site".to_string(), encrypted_username: None, encrypted_login_email: None,
                encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: true, expected_version: None,
                entry_type: "login".to_string(), encrypted_extra_fields: None,
                encrypted_password: format!("version_{i}"), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
            };
            update_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
                AuthUser { email: email.to_string(), is_moderator: false }, Path(id.clone()), Json(updated))
                .await.expect("la modification doit réussir");
        }

        let history = VaultRepository::get_history(&state.db, email, &id, 100).await.unwrap();
        assert_eq!(history.len(), MAX_HISTORY_PER_ENTRY, "l'historique ne doit pas dépasser le plafond de rétention");
        // La version la plus récemment archivée est "version_24" (l'ancien mot de passe juste
        // avant le tout dernier "version_25", jamais lui-même archivé puisqu'il est toujours actif).
        assert_eq!(history[0].encrypted_password, format!("version_{}", MAX_HISTORY_PER_ENTRY + 4));
        // La plus ancienne conservée doit être "version_5" (0..4 purgées, 20 versions gardées : 5..24).
        assert_eq!(history[history.len() - 1].encrypted_password, "version_5");
    }

    /// LE test de sécurité le plus important sur le coffre : un utilisateur ne doit JAMAIS
    /// pouvoir lire, modifier, supprimer ou basculer en favori l'entrée d'un AUTRE utilisateur,
    /// même en connaissant son ID exact (ex: deviné, ou intercepté).
    #[tokio::test]
    async fn test_vault_isolation_between_users() {
        let state = build_test_state().await;
        let owner_email = "owner@example.com";
        let attacker_email = "attacker@example.com";
        register_test_user(&state, owner_email).await;
        register_test_user(&state, attacker_email).await;

        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        // Le propriétaire ajoute une entrée
        let entry = VaultEntryInput {
            encrypted_site_name: "Compte bancaire".to_string(),
            encrypted_username: None,
            encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "secret_du_owner".to_string(),
            encrypted_preferred_login_type: "email".to_string(),
            is_favorite: false,
        };
        add_to_vault(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            AuthUser { email: owner_email.to_string(), is_moderator: false },
            Json(entry),
        ).await.expect("l'ajout par le propriétaire doit réussir");

        let id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(owner_email)
            .fetch_one(&state.db)
            .await
            .unwrap();

        // L'attaquant tente de MODIFIER l'entrée du propriétaire -> doit échouer en NotFound
        let malicious_update = VaultEntryInput {
            encrypted_site_name: "Piraté".to_string(),
            encrypted_username: None,
            encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "injecte_par_attaquant".to_string(),
            encrypted_preferred_login_type: "email".to_string(),
            is_favorite: false,
        };
        let update_result = update_vault_entry(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            AuthUser { email: attacker_email.to_string(), is_moderator: false },
            Path(id.clone()),
            Json(malicious_update),
        ).await;
        assert!(
            matches!(update_result, Err(AppError::NotFound)),
            "un utilisateur ne doit pas pouvoir modifier l'entrée d'un autre"
        );

        // L'attaquant tente de basculer le favori -> doit échouer en NotFound
        let favorite_result = toggle_favorite(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            AuthUser { email: attacker_email.to_string(), is_moderator: false },
            Path(id.clone()),
        ).await;
        assert!(
            matches!(favorite_result, Err(AppError::NotFound)),
            "un utilisateur ne doit pas pouvoir basculer le favori d'un autre"
        );

        // L'attaquant tente de SUPPRIMER l'entrée -> doit échouer en NotFound
        let delete_result = delete_vault_entry(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            AuthUser { email: attacker_email.to_string(), is_moderator: false },
            Path(id.clone()),
        ).await;
        assert!(
            matches!(delete_result, Err(AppError::NotFound)),
            "un utilisateur ne doit pas pouvoir supprimer l'entrée d'un autre"
        );

        // L'entrée doit être INTACTE : toujours présente, jamais modifiée, appartenant au propriétaire
        let (site_name, user_email): (String, String) = sqlx::query_as(
            "SELECT encrypted_site_name, user_email FROM vault WHERE id = ?"
        )
        .bind(&id)
        .fetch_one(&state.db)
        .await
        .expect("l'entrée doit toujours exister, intacte");
        assert_eq!(site_name, "Compte bancaire", "le contenu ne doit pas avoir été altéré");
        assert_eq!(user_email, owner_email, "l'entrée doit toujours appartenir au propriétaire");

        // L'attaquant ne doit rien voir dans SON PROPRE listage du coffre
        let attacker_entries = VaultRepository::get_all(&state.db, attacker_email, 50, 0)
            .await
            .unwrap();
        assert!(attacker_entries.is_empty(), "l'attaquant ne doit voir aucune entrée du propriétaire");

        // Le propriétaire, lui, voit toujours sa seule entrée
        let owner_entries = VaultRepository::get_all(&state.db, owner_email, 50, 0)
            .await
            .unwrap();
        assert_eq!(owner_entries.len(), 1, "le propriétaire doit toujours voir son entrée");
    }

    // NOTE : test_vault_search_filter a été retiré ici. La recherche côté serveur (VaultRepository::get_all
    // prenait un paramètre `search` et faisait un LIKE SQL) n'existe plus depuis le passage au
    // Zero-Knowledge total : les champs de contenu sont chiffrés côté client, un LIKE dessus n'a
    // plus aucun sens. La recherche doit désormais se faire côté client après déchiffrement.


    /// Petit utilitaire de test : lit le corps JSON d'une réponse Axum et le renvoie comme
    /// `serde_json::Value` générique. Nécessaire car `VaultEntry`/`SyncResponse` n'implémentent
    /// que `Serialize` (pas `Deserialize`, volontairement — voir models.rs), donc on ne peut pas
    /// désérialiser directement dans ces types depuis un test ; `Value` contourne le problème.
    async fn read_json_body(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("lecture du corps de la réponse");
        serde_json::from_slice(&bytes).expect("le corps doit être du JSON valide")
    }

    /// get_vault() (le handler HTTP, pas seulement le repository) ne doit renvoyer que les
    /// entrées de l'utilisateur connecté.
    #[tokio::test]
    async fn test_get_vault_handler_returns_only_own_entries() {
        let state = build_test_state().await;
        register_test_user(&state, "reader@example.com").await;
        register_test_user(&state, "other@example.com").await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        for site in ["Site1", "Site2"] {
            let entry = VaultEntryInput {
                encrypted_site_name: site.to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
                entry_type: "login".to_string(), encrypted_extra_fields: None,
                encrypted_password: "x".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
            };
            add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
                AuthUser { email: "reader@example.com".to_string(), is_moderator: false }, Json(entry))
                .await.expect("l'ajout doit réussir");
        }
        let other_entry = VaultEntryInput {
            encrypted_site_name: "AutreSite".to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "y".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: "other@example.com".to_string(), is_moderator: false }, Json(other_entry))
            .await.expect("l'ajout doit réussir");

        let result = get_vault(
            State(state.clone()),
            AuthUser { email: "reader@example.com".to_string(), is_moderator: false },
            Query(PaginationParams { limit: None, offset: None }),
        ).await.expect("la lecture doit réussir");

        let value = read_json_body(result.into_response()).await;
        let entries = value.as_array().expect("la réponse doit être un tableau JSON");
        assert_eq!(entries.len(), 2, "le lecteur ne doit voir que ses 2 propres entrées, pas celle de l'autre utilisateur");
    }

    /// Régression du bug corrigé dans repository.rs : update() et toggle_favorite() ne
    /// touchaient jamais `updated_at`, donc check_sync() (utilisé par les clients pour savoir
    /// s'ils doivent re-synchroniser) ne détectait jamais une simple modification de contenu.
    #[tokio::test]
    async fn test_check_sync_reflects_updates_to_existing_entries() {
        let state = build_test_state().await;
        let email = "synctest@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = VaultEntryInput {
            encrypted_site_name: "Original".to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");

        let id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        let sync_before = check_sync(State(state.clone()), AuthUser { email: email.to_string(), is_moderator: false })
            .await.expect("check_sync doit réussir");
        let token_before = read_json_body(sync_before.into_response()).await["sync_token"].clone();

        // On force un écart d'au moins 1 seconde : CURRENT_TIMESTAMP en SQLite a une résolution
        // à la seconde, donc sans cette petite attente le nouveau updated_at pourrait être
        // identique au premier et donner un faux négatif à ce test (pas un bug du code applicatif).
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // Modification d'une entrée EXISTANTE (pas un ajout) : total_entries ne bouge pas,
        // mais le contenu change bel et bien.
        let updated_entry = VaultEntryInput {
            encrypted_site_name: "Modifie".to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        update_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(id), Json(updated_entry))
            .await.expect("la modification doit réussir");

        let sync_after = check_sync(State(state.clone()), AuthUser { email: email.to_string(), is_moderator: false })
            .await.expect("check_sync doit réussir");
        let token_after = read_json_body(sync_after.into_response()).await["sync_token"].clone();

        assert_ne!(
            token_before, token_after,
            "le sync_token doit changer après une modification, même si le nombre d'entrées est resté identique"
        );
    }

    /// Régression du bug de format de date : la valeur de secours pour un coffre vide doit être
    /// dans le MÊME format que celui produit par CURRENT_TIMESTAMP de SQLite pour un coffre non
    /// vide (espace, pas de 'T'/'Z'), sinon le format de `last_modified` change selon l'état du
    /// coffre, ce qui peut faire échouer un parseur de date strict côté client.
    #[tokio::test]
    async fn test_check_sync_uses_consistent_date_format_for_empty_and_populated_vault() {
        let state = build_test_state().await;

        // Coffre vide
        let empty_email = "emptyvault@example.com";
        register_test_user(&state, empty_email).await;
        let empty_result = check_sync(State(state.clone()), AuthUser { email: empty_email.to_string(), is_moderator: false })
            .await.expect("check_sync doit réussir sur un coffre vide");
        let empty_value = read_json_body(empty_result.into_response()).await;
        let empty_last_modified = empty_value["last_modified"].as_str().unwrap().to_string();

        // Coffre avec une entrée
        let filled_email = "filledvault@example.com";
        register_test_user(&state, filled_email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let entry = VaultEntryInput {
            encrypted_site_name: "Site".to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: filled_email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");
        let filled_result = check_sync(State(state.clone()), AuthUser { email: filled_email.to_string(), is_moderator: false })
            .await.expect("check_sync doit réussir sur un coffre rempli");
        let filled_value = read_json_body(filled_result.into_response()).await;
        let filled_last_modified = filled_value["last_modified"].as_str().unwrap().to_string();

        // Les deux formats doivent être identiques : ni l'un ni l'autre ne doit contenir 'T' ou 'Z'
        assert!(!empty_last_modified.contains('T') && !empty_last_modified.contains('Z'),
            "le format du coffre vide doit correspondre à celui de SQLite (pas de 'T'/'Z')");
        assert!(!filled_last_modified.contains('T') && !filled_last_modified.contains('Z'),
            "le format du coffre rempli (CURRENT_TIMESTAMP de SQLite) ne doit pas contenir 'T'/'Z'");
    }

    /// add_to_vault() doit rejeter une entrée avec un site_name vide (validation du payload).
    #[tokio::test]
    async fn test_add_to_vault_rejects_empty_site_name() {
        let state = build_test_state().await;
        let email = "validationtest@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let invalid_entry = VaultEntryInput {
            encrypted_site_name: "".to_string(), // vide -> doit être rejeté
            encrypted_username: None,
            encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(),
            encrypted_preferred_login_type: "email".to_string(),
            is_favorite: false,
        };
        let result = add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(invalid_entry)).await;

        assert!(
            matches!(result, Err(AppError::ValidationError(_))),
            "un site_name vide doit être rejeté par la validation"
        );

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert_eq!(count, 0, "aucune entrée invalide ne doit avoir été insérée");
    }

    /// delete_vault_entry() ne doit PAS effacer la ligne : elle doit juste disparaître du
    /// listage normal (get_all) tout en restant présente en BDD avec deleted_at renseigné.
    #[tokio::test]
    async fn test_delete_vault_entry_soft_deletes_and_hides_from_listing() {
        let state = build_test_state().await;
        let email = "softdeletetest@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = VaultEntryInput {
            encrypted_site_name: "ASupprimer".to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");

        let id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        delete_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(id.clone()))
            .await.expect("la suppression doit réussir");

        // La ligne existe TOUJOURS en BDD (pas de DELETE définitif)
        let still_in_db: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault WHERE id = ?")
            .bind(&id).fetch_one(&state.db).await.unwrap();
        assert_eq!(still_in_db, 1, "la ligne doit toujours exister en BDD après une suppression douce");

        // deleted_at doit être renseigné
        let deleted_at: Option<String> = sqlx::query_scalar("SELECT deleted_at FROM vault WHERE id = ?")
            .bind(&id).fetch_one(&state.db).await.unwrap();
        assert!(deleted_at.is_some(), "deleted_at doit être renseigné après une suppression douce");

        // Mais elle ne doit plus apparaître dans le listage normal
        let active_entries = VaultRepository::get_all(&state.db, email, 50, 0).await.unwrap();
        assert!(active_entries.is_empty(), "une entrée supprimée en douceur ne doit plus apparaître dans le listage normal");
    }

    /// restore_vault_entry() doit faire réapparaître une entrée de la corbeille dans le listage normal.
    #[tokio::test]
    async fn test_restore_vault_entry_brings_it_back() {
        let state = build_test_state().await;
        let email = "restoretest@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = VaultEntryInput {
            encrypted_site_name: "ARestaurer".to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");
        let id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        delete_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(id.clone()))
            .await.expect("la suppression doit réussir");

        restore_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(id.clone()))
            .await.expect("la restauration doit réussir");

        let active_entries = VaultRepository::get_all(&state.db, email, 50, 0).await.unwrap();
        assert_eq!(active_entries.len(), 1, "l'entrée restaurée doit réapparaître dans le listage normal");

        let trash = VaultRepository::get_trash(&state.db, email).await.unwrap();
        assert!(trash.is_empty(), "l'entrée restaurée ne doit plus être dans la corbeille");
    }

    /// permanently_delete_vault_entry() doit effacer réellement la ligne — plus aucun retour
    /// en arrière possible, contrairement à delete_vault_entry() (suppression douce).
    #[tokio::test]
    async fn test_permanently_delete_vault_entry_removes_from_database() {
        let state = build_test_state().await;
        let email = "purgetest@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = VaultEntryInput {
            encrypted_site_name: "APurger".to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");
        let id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        delete_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(id.clone()))
            .await.expect("la suppression doit réussir");

        permanently_delete_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(id.clone()))
            .await.expect("la purge définitive doit réussir");

        let still_in_db: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault WHERE id = ?")
            .bind(&id).fetch_one(&state.db).await.unwrap();
        assert_eq!(still_in_db, 0, "la ligne doit avoir été réellement effacée de la BDD");
    }

    /// Impossible de purger DIRECTEMENT une entrée active (sans être passée par la corbeille
    /// d'abord) — sécurité supplémentaire contre un appel accidentel ou malveillant.
    #[tokio::test]
    async fn test_cannot_permanently_delete_an_active_entry_directly() {
        let state = build_test_state().await;
        let email = "activepurge@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = VaultEntryInput {
            encrypted_site_name: "Actif".to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");
        let id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        // Pas de delete_vault_entry() avant : l'entrée est toujours ACTIVE
        let result = permanently_delete_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(id.clone())).await;

        assert!(
            matches!(result, Err(AppError::NotFound)),
            "purger directement une entrée active (pas encore en corbeille) doit échouer"
        );
        let still_in_db: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault WHERE id = ?")
            .bind(&id).fetch_one(&state.db).await.unwrap();
        assert_eq!(still_in_db, 1, "l'entrée active doit rester intacte");
    }

    /// Une entrée dans la corbeille ne doit pas pouvoir être modifiée (update/toggle_favorite)
    /// sans être d'abord restaurée — sinon on pourrait silencieusement changer le contenu d'une
    /// entrée que l'utilisateur croit avoir supprimée.
    #[tokio::test]
    async fn test_cannot_modify_a_trashed_entry_without_restoring_first() {
        let state = build_test_state().await;
        let email = "trashmodify@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = VaultEntryInput {
            encrypted_site_name: "DansLaCorbeille".to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");
        let id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        delete_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(id.clone()))
            .await.expect("la suppression doit réussir");

        let update_attempt = VaultEntryInput {
            encrypted_site_name: "Modifie".to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        let update_result = update_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(id.clone()), Json(update_attempt)).await;
        assert!(matches!(update_result, Err(AppError::NotFound)), "modifier une entrée en corbeille doit échouer");

        let favorite_result = toggle_favorite(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(id.clone())).await;
        assert!(matches!(favorite_result, Err(AppError::NotFound)), "mettre en favori une entrée en corbeille doit échouer");
    }

    /// get_trash() ne doit renvoyer que les entrées de l'utilisateur connecté, jamais celles
    /// d'un autre utilisateur — même isolation que pour le coffre actif.
    #[tokio::test]
    async fn test_get_trash_isolation_between_users() {
        let state = build_test_state().await;
        register_test_user(&state, "trashowner@example.com").await;
        register_test_user(&state, "trashother@example.com").await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        for (email, site) in [("trashowner@example.com", "SiteA"), ("trashother@example.com", "SiteB")] {
            let entry = VaultEntryInput {
                encrypted_site_name: site.to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
                entry_type: "login".to_string(), encrypted_extra_fields: None,
                encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
            };
            add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
                AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
                .await.expect("l'ajout doit réussir");
            let id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
                .bind(email).fetch_one(&state.db).await.unwrap();
            delete_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
                AuthUser { email: email.to_string(), is_moderator: false }, Path(id))
                .await.expect("la suppression doit réussir");
        }

        let owner_trash = VaultRepository::get_trash(&state.db, "trashowner@example.com").await.unwrap();
        assert_eq!(owner_trash.len(), 1, "chaque utilisateur ne doit voir que sa propre corbeille");
        assert_eq!(owner_trash[0].encrypted_site_name, "SiteA");
    }

    /// check_sync() ne doit pas compter les entrées passées à la corbeille dans total_entries.
    #[tokio::test]
    async fn test_check_sync_excludes_trashed_entries() {
        let state = build_test_state().await;
        let email = "synctrash@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let entry = VaultEntryInput {
            encrypted_site_name: "SeraSupprime".to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");
        let id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        delete_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(id))
            .await.expect("la suppression doit réussir");

        let sync_result = check_sync(State(state.clone()), AuthUser { email: email.to_string(), is_moderator: false })
            .await.expect("check_sync doit réussir");
        let value = read_json_body(sync_result.into_response()).await;
        assert_eq!(value["total_entries"], 0, "une entrée dans la corbeille ne doit pas compter dans total_entries");
    }

    /// add_to_vault() doit refuser une nouvelle entrée une fois MAX_VAULT_ENTRIES_PER_USER
    /// atteint, pour empêcher un compte de saturer la BDD partagée sans limite.
    /// On pré-remplit directement en BDD (bulk insert en une seule requête) plutôt que d'appeler
    /// le handler 5000 fois, pour que le test reste rapide.
    #[tokio::test]
    async fn test_add_to_vault_rejects_when_entry_limit_reached() {
        let state = build_test_state().await;
        let email = "quotatest@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        // Pré-remplissage direct en BDD jusqu'à la limite (MAX_VAULT_ENTRIES_PER_USER = 5000)
        let mut query = String::from(
            "INSERT INTO vault (id, encrypted_site_name, encrypted_password, encrypted_preferred_login_type, user_email) VALUES "
        );
        let placeholders: Vec<String> = (0..MAX_VAULT_ENTRIES_PER_USER)
            .map(|i| format!("('id-{i}', 'site', 'chiffre', 'email', '{email}')"))
            .collect();
        query.push_str(&placeholders.join(","));
        // sqlx 0.9 exige une confirmation explicite pour une requête SQL construite dynamiquement
        // (protection anti-injection par défaut). Ici c'est sûr : `query` ne contient qu'un
        // compteur de boucle et des valeurs fixes du test, aucune entrée utilisateur.
        sqlx::query(sqlx::AssertSqlSafe(query)).execute(&state.db).await.expect("le pré-remplissage doit réussir");

        let entry = VaultEntryInput {
            encrypted_site_name: "SiteEnTrop".to_string(),
            encrypted_username: None,
            encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(),
            encrypted_preferred_login_type: "email".to_string(),
            is_favorite: false,
        };
        let result = add_to_vault(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Json(entry),
        ).await;

        assert!(
            matches!(result, Err(AppError::ValidationError(_))),
            "l'ajout doit être refusé une fois la limite d'entrées atteinte"
        );

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert_eq!(count, MAX_VAULT_ENTRIES_PER_USER, "aucune entrée supplémentaire ne doit avoir été insérée au-delà de la limite");
    }

    /// add_to_vault() doit diffuser un SyncEvent (canal broadcast) pour que les AUTRES appareils
    /// du même utilisateur sachent se re-synchroniser — c'est le cœur de la synchro temps réel.
    /// On vérifie ici le mécanisme de diffusion en lui-même (pas la connexion WebSocket complète,
    /// testée séparément via handlers/sync.rs).
    #[tokio::test]
    async fn test_add_to_vault_broadcasts_sync_event() {
        let state = build_test_state().await;
        let email = "syncevent@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        // S'abonne AVANT l'action, comme le ferait une connexion WebSocket ouverte
        let mut rx = state.sync_tx.subscribe();

        let entry = VaultEntryInput {
            encrypted_site_name: "Site".to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");

        let event = rx.try_recv().expect("un SyncEvent doit avoir été diffusé");
        assert_eq!(event.user_email, email);
        assert_eq!(event.event_type, "VAULT_ADD");
    }

    /// Un utilisateur ne doit JAMAIS recevoir les SyncEvent d'un AUTRE utilisateur — le canal
    /// broadcast est partagé par tout le monde, le filtrage par user_email est donc essentiel
    /// (c'est exactement ce que fait handlers/sync.rs::handle_socket avant de relayer au client).
    #[tokio::test]
    async fn test_sync_event_is_scoped_to_the_correct_user() {
        let state = build_test_state().await;
        register_test_user(&state, "userA@example.com").await;
        register_test_user(&state, "userB@example.com").await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let mut rx = state.sync_tx.subscribe();

        let entry = VaultEntryInput {
            encrypted_site_name: "Site".to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: "userA@example.com".to_string(), is_moderator: false }, Json(entry))
            .await.expect("l'ajout doit réussir");

        let event = rx.try_recv().expect("un événement doit avoir été diffusé");
        assert_eq!(event.user_email, "userA@example.com");
        assert_ne!(
            event.user_email, "userB@example.com",
            "un événement destiné à userA ne doit jamais être attribué à userB"
        );
    }

    /// export_vault() doit refuser un mauvais mot de passe, sans jamais renvoyer le contenu du
    /// coffre dans ce cas.
    #[tokio::test]
    async fn test_export_vault_rejects_wrong_password() {
        let state = build_test_state().await;
        let email = "exportwrongpw@example.com";
        register_user_with_real_password(&state, email, "mot_de_passe_test_123").await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let result = export_vault(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Json(ExportVaultPayload { master_password_hash: "mauvais_mot_de_passe".to_string() }),
        ).await;
        assert!(matches!(result, Err(AppError::InvalidCredentials)), "un mauvais mot de passe doit être rejeté");
    }

    /// export_vault() doit renvoyer TOUTES les entrées actives de l'utilisateur (pas seulement
    /// une page), et jamais celles d'un autre utilisateur, avec le bon mot de passe.
    #[tokio::test]
    async fn test_export_vault_returns_all_own_entries() {
        let state = build_test_state().await;
        let email = "exportowner@example.com";
        register_user_with_real_password(&state, email, "mot_de_passe_test_123").await;
        register_test_user(&state, "exportother@example.com").await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        for site in ["Site1", "Site2", "Site3"] {
            let entry = VaultEntryInput {
                encrypted_site_name: site.to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
                entry_type: "login".to_string(), encrypted_extra_fields: None,
                encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
            };
            add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
                AuthUser { email: email.to_string(), is_moderator: false }, Json(entry))
                .await.expect("l'ajout doit réussir");
        }
        let other_entry = VaultEntryInput {
            encrypted_site_name: "AutreSite".to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        };
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: "exportother@example.com".to_string(), is_moderator: false }, Json(other_entry))
            .await.expect("l'ajout doit réussir");

        let result = export_vault(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Json(ExportVaultPayload { master_password_hash: "mot_de_passe_test_123".to_string() }),
        ).await.expect("l'export avec le bon mot de passe doit réussir");

        let value = read_json_body(result.into_response()).await;
        let entries = value.as_array().expect("la réponse doit être un tableau JSON");
        assert_eq!(entries.len(), 3, "l'export doit contenir les 3 entrées du propriétaire, pas celle d'un autre utilisateur");

        let audit_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE user_email = ? AND action = 'VAULT_EXPORT'")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert_eq!(audit_count, 1, "un export doit être tracé dans l'audit (contenu sensible)");
    }

    fn sample_entry(site: &str) -> VaultEntryInput {
        VaultEntryInput {
            encrypted_site_name: site.to_string(), encrypted_username: None, encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(), encrypted_preferred_login_type: "email".to_string(), is_favorite: false,
        }
    }

    /// import_vault() doit AJOUTER les nouvelles entrées sans jamais toucher à celles déjà
    /// présentes (pas de fusion, pas d'écrasement — voir la doc du handler).
    #[tokio::test]
    async fn test_import_vault_adds_entries_without_touching_existing_ones() {
        let state = build_test_state().await;
        let email = "importowner@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(sample_entry("DejaLa")))
            .await.expect("l'ajout doit réussir");

        let result = import_vault(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Json(ImportVaultPayload { entries: vec![sample_entry("Importee1"), sample_entry("Importee2")] }),
        ).await.expect("l'import doit réussir");

        let value = read_json_body(result.into_response()).await;
        assert_eq!(value["imported"], 2, "la réponse doit indiquer le nombre d'entrées importées");

        let active_entries = VaultRepository::get_all(&state.db, email, 50, 0).await.unwrap();
        assert_eq!(active_entries.len(), 3, "l'entrée déjà présente doit rester, plus les 2 importées");

        let audit_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE user_email = ? AND action = 'VAULT_IMPORT'")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert_eq!(audit_count, 1, "un import doit être tracé dans l'audit");
    }

    /// RÉGRESSION (correctif perf du 2026-09-02, VaultRepository::add_many_in_tx) : un import
    /// dépassant CHUNK_SIZE (300, voir repository.rs) doit insérer TOUTES les entrées correctement
    /// réparties sur plusieurs lots, avec des identifiants tous distincts — pas couvert par le test
    /// ci-dessus (seulement 2 entrées, jamais assez pour déclencher un second lot).
    #[tokio::test]
    async fn test_import_vault_handles_more_entries_than_one_chunk() {
        let state = build_test_state().await;
        let email = "importchunked@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        // 650 = deux lots pleins (300 + 300) + un lot partiel (50), avec CHUNK_SIZE = 300.
        let entries: Vec<VaultEntryInput> = (0..650).map(|i| sample_entry(&format!("Site{i}"))).collect();

        let result = import_vault(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Json(ImportVaultPayload { entries }),
        ).await.expect("l'import de plusieurs lots doit réussir");

        let value = read_json_body(result.into_response()).await;
        assert_eq!(value["imported"], 650, "les 650 entrées doivent être comptées comme importées");

        let active_entries = VaultRepository::get_all(&state.db, email, 1000, 0).await.unwrap();
        assert_eq!(active_entries.len(), 650, "les 650 entrées doivent bien être présentes en base, réparties sur plusieurs lots");

        let distinct_ids: std::collections::HashSet<_> = active_entries.iter().map(|e| e.id.clone()).collect();
        assert_eq!(distinct_ids.len(), 650, "chaque entrée doit avoir un identifiant distinct, même générés à travers plusieurs lots");
    }

    /// GARDE-FOU : si UNE SEULE entrée du lot est invalide, RIEN ne doit être importé (tout ou
    /// rien) — la validation a lieu AVANT toute écriture en BDD.
    #[tokio::test]
    async fn test_import_vault_rejects_whole_batch_if_one_entry_is_invalid() {
        let state = build_test_state().await;
        let email = "importinvalid@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let mut invalid_entry = sample_entry("Invalide");
        invalid_entry.encrypted_site_name = "".to_string(); // vide -> invalide

        let result = import_vault(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Json(ImportVaultPayload { entries: vec![sample_entry("Valide"), invalid_entry] }),
        ).await;
        assert!(matches!(result, Err(AppError::ValidationError(_))), "un lot contenant une entrée invalide doit être refusé");

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert_eq!(count, 0, "aucune entrée ne doit être importée si le lot contient un élément invalide (tout ou rien)");
    }

    /// import_vault() doit refuser un lot qui ferait dépasser MAX_VAULT_ENTRIES_PER_USER, et ne
    /// rien importer dans ce cas (atomique, même garde-fou que add_to_vault()).
    #[tokio::test]
    async fn test_import_vault_rejects_when_exceeding_entry_limit() {
        let state = build_test_state().await;
        let email = "importquota@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        // Pré-remplissage direct en BDD jusqu'à MAX_VAULT_ENTRIES_PER_USER - 1 (même technique
        // que test_add_to_vault_rejects_when_entry_limit_reached).
        let mut query = String::from(
            "INSERT INTO vault (id, encrypted_site_name, encrypted_password, encrypted_preferred_login_type, user_email) VALUES "
        );
        let placeholders: Vec<String> = (0..MAX_VAULT_ENTRIES_PER_USER - 1)
            .map(|i| format!("('id-{i}', 'site', 'chiffre', 'email', '{email}')"))
            .collect();
        query.push_str(&placeholders.join(","));
        sqlx::query(sqlx::AssertSqlSafe(query)).execute(&state.db).await.expect("le pré-remplissage doit réussir");

        // Importer 2 entrées alors qu'il ne reste qu'1 place de libre -> doit être refusé
        let result = import_vault(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Json(ImportVaultPayload { entries: vec![sample_entry("Trop1"), sample_entry("Trop2")] }),
        ).await;
        assert!(matches!(result, Err(AppError::ValidationError(_))), "un import qui dépasserait la limite doit être refusé");

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();
        assert_eq!(count, MAX_VAULT_ENTRIES_PER_USER - 1, "aucune entrée supplémentaire ne doit avoir été importée au-delà de la limite");
    }

    fn sample_attachment(filename: &str) -> VaultAttachmentInput {
        VaultAttachmentInput {
            encrypted_filename: filename.to_string(),
            encrypted_content: "chiffre_contenu_fichier".to_string(),
            content_size: 1234,
        }
    }

    /// Cycle de vie complet d'une pièce jointe : ajoutée, listée (SANS son contenu), récupérée en
    /// entier (AVEC son contenu), puis supprimée — plus aucune trace après coup.
    #[tokio::test]
    async fn test_attachment_round_trips_through_add_list_get_delete() {
        let state = build_test_state().await;
        let email = "attachowner@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(sample_entry("AvecFichier")))
            .await.expect("l'ajout de l'entrée doit réussir");
        let vault_id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        let add_result = add_vault_attachment(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Path(vault_id.clone()), Json(sample_attachment("codes_secours.txt")),
        ).await.expect("l'ajout de la pièce jointe doit réussir");
        let add_value = read_json_body(add_result.into_response()).await;
        let attachment_id = add_value["id"].as_str().expect("la réponse doit contenir l'id créé").to_string();

        let list_result = get_vault_attachments(
            State(state.clone()),
            AuthUser { email: email.to_string(), is_moderator: false },
            Path(vault_id.clone()),
        ).await.expect("le listing doit réussir");
        let list_value = read_json_body(list_result.into_response()).await;
        let rows = list_value.as_array().expect("la réponse doit être un tableau JSON");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["encrypted_filename"].as_str(), Some("codes_secours.txt"));
        assert_eq!(rows[0]["content_size"].as_i64(), Some(1234));
        assert!(rows[0].get("encrypted_content").is_none(), "le listing ne doit JAMAIS inclure le contenu, seulement les métadonnées");

        let get_result = get_vault_attachment(
            State(state.clone()),
            AuthUser { email: email.to_string(), is_moderator: false },
            Path((vault_id.clone(), attachment_id.clone())),
        ).await.expect("la récupération d'une pièce jointe précise doit réussir");
        let get_value = read_json_body(get_result.into_response()).await;
        assert_eq!(get_value["encrypted_content"].as_str(), Some("chiffre_contenu_fichier"), "le contenu chiffré doit être renvoyé tel quel au téléchargement");

        delete_vault_attachment(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Path((vault_id.clone(), attachment_id.clone())),
        ).await.expect("la suppression doit réussir");

        let after_delete = get_vault_attachment(
            State(state.clone()),
            AuthUser { email: email.to_string(), is_moderator: false },
            Path((vault_id, attachment_id)),
        ).await;
        assert!(matches!(after_delete, Err(AppError::NotFound)), "une pièce jointe supprimée ne doit plus être accessible");
    }

    /// CORRECTIF (filtre "avec pièce jointe") : `VaultEntry.has_attachments` doit refléter en
    /// temps réel l'existence d'AU MOINS une pièce jointe pour cette entrée précise — jamais
    /// contaminé par les pièces jointes d'une AUTRE entrée du même utilisateur.
    #[tokio::test]
    async fn test_get_vault_reports_has_attachments_accurately() {
        let state = build_test_state().await;
        let email = "hasattach@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(sample_entry("AvecFichier")))
            .await.expect("l'ajout doit réussir");
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(sample_entry("SansFichier")))
            .await.expect("l'ajout doit réussir");

        let with_attachment_id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ? AND encrypted_site_name = ?")
            .bind(email).bind("AvecFichier").fetch_one(&state.db).await.unwrap();

        add_vault_attachment(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Path(with_attachment_id.clone()), Json(sample_attachment("fichier.txt")),
        ).await.expect("l'ajout de la pièce jointe doit réussir");

        let result = get_vault(
            State(state.clone()),
            AuthUser { email: email.to_string(), is_moderator: false },
            Query(PaginationParams { limit: None, offset: None }),
        ).await.expect("la lecture doit réussir");
        let value = read_json_body(result.into_response()).await;
        let entries = value.as_array().unwrap();
        assert_eq!(entries.len(), 2);

        for entry in entries {
            let has_attachments = entry["has_attachments"].as_bool().expect("has_attachments doit être un booléen");
            if entry["id"].as_str() == Some(with_attachment_id.as_str()) {
                assert!(has_attachments, "l'entrée avec une pièce jointe doit avoir has_attachments = true");
            } else {
                assert!(!has_attachments, "l'entrée SANS pièce jointe ne doit jamais hériter du statut d'une autre entrée");
            }
        }
    }

    /// `entry_type`/`encrypted_extra_fields` (types d'entrée dédiés — carte/identité/note, voir
    /// models.rs) doivent survivre intacts à un ajout PUIS une modification, exactement comme
    /// n'importe quel autre champ chiffré — le serveur ne les interprète jamais, mais ne doit pas
    /// non plus les perdre ou les mélanger entre deux entrées.
    #[tokio::test]
    async fn test_entry_type_and_extra_fields_round_trip_through_add_and_update() {
        let state = build_test_state().await;
        let email = "entrytype@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        // Ajout avec un type dédié et des champs additionnels chiffrés.
        let mut card_entry = sample_entry("MaCarte");
        card_entry.entry_type = "card".to_string();
        card_entry.encrypted_extra_fields = Some("chiffre_cvv_expiration".to_string());
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(card_entry))
            .await.expect("l'ajout doit réussir");

        // Une entrée "login" ordinaire, sans champs additionnels — ne doit jamais hériter de ceux
        // de l'entrée précédente.
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(sample_entry("MonLogin")))
            .await.expect("l'ajout doit réussir");

        let result = get_vault(
            State(state.clone()),
            AuthUser { email: email.to_string(), is_moderator: false },
            Query(PaginationParams { limit: None, offset: None }),
        ).await.expect("la lecture doit réussir");
        let value = read_json_body(result.into_response()).await;
        let entries = value.as_array().unwrap();

        let card = entries.iter().find(|e| e["encrypted_site_name"] == "MaCarte").expect("l'entrée carte doit être présente");
        assert_eq!(card["entry_type"], "card");
        assert_eq!(card["encrypted_extra_fields"], "chiffre_cvv_expiration");

        let login = entries.iter().find(|e| e["encrypted_site_name"] == "MonLogin").expect("l'entrée login doit être présente");
        assert_eq!(login["entry_type"], "login");
        assert!(login["encrypted_extra_fields"].is_null(), "une entrée login sans champs additionnels ne doit jamais en hériter d'une autre");

        // Modification : change de type et de champs additionnels — le serveur doit répercuter
        // fidèlement, comme pour n'importe quel autre champ chiffré via PUT /vault/{id}.
        let card_id = card["id"].as_str().unwrap().to_string();
        let mut updated = sample_entry("MaCarte");
        updated.entry_type = "identity".to_string();
        updated.encrypted_extra_fields = Some("chiffre_date_naissance".to_string());
        update_vault_entry(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Path(card_id.clone()), Json(updated))
            .await.expect("la modification doit réussir");

        let result = get_vault(
            State(state.clone()),
            AuthUser { email: email.to_string(), is_moderator: false },
            Query(PaginationParams { limit: None, offset: None }),
        ).await.expect("la relecture doit réussir");
        let value = read_json_body(result.into_response()).await;
        let entries = value.as_array().unwrap();
        let updated_entry = entries.iter().find(|e| e["id"] == card_id).unwrap();
        assert_eq!(updated_entry["entry_type"], "identity");
        assert_eq!(updated_entry["encrypted_extra_fields"], "chiffre_date_naissance");
    }

    /// Impossible d'attacher un fichier à une entrée qui n'appartient pas à l'utilisateur (ou qui
    /// n'existe pas) — même garde-fou de propriété que le reste des routes /vault/*.
    #[tokio::test]
    async fn test_attachment_rejects_entry_not_owned_by_user() {
        let state = build_test_state().await;
        register_test_user(&state, "owner@example.com").await;
        register_test_user(&state, "attacker@example.com").await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: "owner@example.com".to_string(), is_moderator: false }, Json(sample_entry("PasATa")))
            .await.expect("l'ajout doit réussir");
        let vault_id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind("owner@example.com").fetch_one(&state.db).await.unwrap();

        let result = add_vault_attachment(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: "attacker@example.com".to_string(), is_moderator: false },
            Path(vault_id), Json(sample_attachment("intrus.txt")),
        ).await;
        assert!(matches!(result, Err(AppError::NotFound)), "attacher un fichier à l'entrée d'un AUTRE utilisateur doit échouer en 404, jamais réussir");
    }

    /// Refuse une nouvelle pièce jointe une fois MAX_ATTACHMENTS_PER_ENTRY atteint POUR CETTE
    /// ENTRÉE — sans affecter les autres entrées du même utilisateur.
    #[tokio::test]
    async fn test_attachment_rejects_when_per_entry_limit_reached() {
        let state = build_test_state().await;
        let email = "attachquota@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(sample_entry("Quota")))
            .await.expect("l'ajout doit réussir");
        let vault_id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        for i in 0..MAX_ATTACHMENTS_PER_ENTRY {
            add_vault_attachment(
                State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
                AuthUser { email: email.to_string(), is_moderator: false },
                Path(vault_id.clone()), Json(sample_attachment(&format!("fichier_{i}.txt"))),
            ).await.expect("chaque ajout jusqu'à la limite doit réussir");
        }

        let result = add_vault_attachment(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Path(vault_id), Json(sample_attachment("en_trop.txt")),
        ).await;
        assert!(matches!(result, Err(AppError::ValidationError(_))), "une pièce jointe au-delà de MAX_ATTACHMENTS_PER_ENTRY doit être refusée");
    }

    /// Refuse une nouvelle pièce jointe une fois MAX_ATTACHMENTS_PER_USER atteint, MÊME sur une
    /// entrée qui n'a encore aucune pièce jointe elle-même (quota GLOBAL, pas juste par entrée).
    #[tokio::test]
    async fn test_attachment_rejects_when_per_user_limit_reached() {
        let state = build_test_state().await;
        let email = "attachglobalquota@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        // Répartit MAX_ATTACHMENTS_PER_USER pièces jointes sur PLUSIEURS entrées différentes
        // (jamais plus de MAX_ATTACHMENTS_PER_ENTRY sur une seule), pour isoler le quota global de
        // celui par entrée testé ci-dessus.
        let mut vault_ids = Vec::new();
        let entries_needed = (MAX_ATTACHMENTS_PER_USER + MAX_ATTACHMENTS_PER_ENTRY - 1) / MAX_ATTACHMENTS_PER_ENTRY;
        for i in 0..entries_needed {
            add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
                AuthUser { email: email.to_string(), is_moderator: false }, Json(sample_entry(&format!("Entree{i}"))))
                .await.expect("l'ajout doit réussir");
        }
        let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_all(&state.db).await.unwrap();
        vault_ids.extend(ids);

        let mut remaining = MAX_ATTACHMENTS_PER_USER;
        for vault_id in &vault_ids {
            let for_this_entry = remaining.min(MAX_ATTACHMENTS_PER_ENTRY);
            for i in 0..for_this_entry {
                add_vault_attachment(
                    State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
                    AuthUser { email: email.to_string(), is_moderator: false },
                    Path(vault_id.clone()), Json(sample_attachment(&format!("fichier_{i}.txt"))),
                ).await.expect("chaque ajout jusqu'au quota global doit réussir");
            }
            remaining -= for_this_entry;
        }
        assert_eq!(remaining, 0, "le test doit avoir effectivement atteint le quota global avant de le dépasser");

        // Une entrée TOUTE NEUVE, sans aucune pièce jointe -> refusée quand même, le quota est
        // bien GLOBAL et pas seulement par entrée.
        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(sample_entry("EntreeNeuve")))
            .await.expect("l'ajout doit réussir");
        let fresh_vault_id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ? AND encrypted_site_name = 'EntreeNeuve'")
            .bind(email).fetch_one(&state.db).await.unwrap();

        let result = add_vault_attachment(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Path(fresh_vault_id), Json(sample_attachment("en_trop.txt")),
        ).await;
        assert!(matches!(result, Err(AppError::ValidationError(_))), "au-delà de MAX_ATTACHMENTS_PER_USER, même une entrée neuve doit être refusée");
    }

    /// La validation du payload (voir models.rs::VaultAttachmentInput) doit refuser un
    /// content_size hors bornes AVANT toute écriture — jamais de pièce jointe enregistrée avec
    /// une métadonnée de taille absurde.
    #[tokio::test]
    async fn test_attachment_validation_rejects_oversized_content_size() {
        let state = build_test_state().await;
        let email = "attachvalidation@example.com";
        register_test_user(&state, email).await;
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        add_to_vault(State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false }, Json(sample_entry("Validation")))
            .await.expect("l'ajout doit réussir");
        let vault_id: String = sqlx::query_scalar("SELECT id FROM vault WHERE user_email = ?")
            .bind(email).fetch_one(&state.db).await.unwrap();

        let mut too_big = sample_attachment("trop_gros.bin");
        too_big.content_size = 5_242_881; // 1 octet au-delà de la limite (5 Mo)

        let result = add_vault_attachment(
            State(state.clone()), ConnectInfo(addr), HeaderMap::new(),
            AuthUser { email: email.to_string(), is_moderator: false },
            Path(vault_id), Json(too_big),
        ).await;
        assert!(result.is_err(), "un content_size déclaré au-delà de 5 Mo doit être rejeté par la validation");

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault_attachments").fetch_one(&state.db).await.unwrap();
        assert_eq!(count, 0, "aucune pièce jointe ne doit être enregistrée si la validation échoue");
    }
}