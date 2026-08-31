use sqlx::SqlitePool;
use crate::{models::{VaultEntry, VaultEntryInput, TrashedVaultEntry, PasswordHistoryEntry, ReencryptedHistoryEntry, VaultAttachment, VaultAttachmentInput, VaultAttachmentMeta, UserKeysInput, UserPublicKey, EmergencyContact, VaultShare, SharedWithMeEntry, SharedEntryView, SharedVaultView, SharedVaultMemberView, SharedVaultEntry, SharedVaultEntryInput, VaultBlindShare, BlindShareReceivedView, BlindShareCredentialsView, CreateBugReportPayload, BugReportView}, error::AppError};

/// Historique des mots de passe : garde au plus ce nombre de versions PAR ENTRÉE — au-delà, les
/// plus anciennes sont purgées automatiquement (voir VaultRepository::archive_password_history).
/// Pas pensé pour une conservation illimitée, juste pour retrouver un mot de passe changé
/// récemment par erreur.
const MAX_HISTORY_PER_ENTRY: i64 = 20;

// =========================================================================
// 1. STRUCTURE DU REPOSITORY
// =========================================================================

/// Structure vide servant d'espace de nom (Namespace) pour regrouper toutes
/// les requêtes SQL liées au coffre-fort (Vault).
pub struct VaultRepository;

impl VaultRepository {
    
    // =========================================================================
    // 2. LECTURE (READ) — ZERO-KNOWLEDGE : PAS DE RECHERCHE CÔTÉ SERVEUR
    // =========================================================================
    
    /// Récupère la liste des entrées ACTIVES (non supprimées) du coffre-fort pour un utilisateur
    /// spécifique, avec pagination (limit/offset) mais SANS recherche ni tri par contenu :
    /// tous les champs de contenu sont chiffrés côté client, un `LIKE` ou un `ORDER BY` dessus
    /// n'aurait aucun sens (le texte chiffré ne préserve ni motif ni ordre alphabétique). Le tri
    /// et le filtrage doivent se faire CÔTÉ CLIENT après déchiffrement.
    pub async fn get_all(db: &SqlitePool, email: &str, limit: i64, offset: i64) -> Result<Vec<VaultEntry>, AppError> {
        // `query_as` mappe automatiquement les colonnes SQL vers les champs de la structure `VaultEntry`
        // "deleted_at IS NULL" : exclut les entrées passées à la corbeille (suppression douce).
        // Tri par is_favorite uniquement (seule métadonnée en clair pertinente) : les favoris
        // remontent en premier, le reste garde l'ordre d'insertion.
        // has_attachments : sous-requête EXISTS corrélée (une par ligne) plutôt qu'un JOIN — évite
        // toute duplication de ligne si une entrée a plusieurs pièces jointes (un JOIN classique
        // produirait alors une ligne PAR pièce jointe). Coût négligeable : indexée sur vault_id
        // (voir idx_vault_attachments_vault_id), et le nombre de pièces jointes par utilisateur
        // est plafonné (MAX_ATTACHMENTS_PER_USER, voir handlers/vault.rs).
        sqlx::query_as::<_, VaultEntry>(
        "SELECT id, encrypted_site_name, encrypted_username, encrypted_login_email, encrypted_password, encrypted_preferred_login_type, user_email, is_favorite, encrypted_folder, encrypted_notes, encrypted_url, entry_type, encrypted_extra_fields, updated_at, version,
                EXISTS(SELECT 1 FROM vault_attachments va WHERE va.vault_id = vault.id) AS has_attachments
         FROM vault
         WHERE user_email = ? AND deleted_at IS NULL
         ORDER BY is_favorite DESC LIMIT ? OFFSET ?"
        )
        .bind(email) // Filtre par l'utilisateur connecté
        .bind(limit)                   // Nombre maximum de résultats (Pagination)
        .bind(offset)                  // Nombre d'éléments à sauter (Pagination)
        // Exécute la requête, récupère toutes les lignes, et convertit l'erreur SQLx en erreur d'application via From/Into
        .fetch_all(db).await.map_err(AppError::from)
    }

    /// Récupère les entrées de la CORBEILLE (supprimées en douceur, pas encore purgées)
    /// pour un utilisateur spécifique, triées de la plus récemment supprimée à la plus ancienne.
    pub async fn get_trash(db: &SqlitePool, email: &str) -> Result<Vec<TrashedVaultEntry>, AppError> {
        sqlx::query_as::<_, TrashedVaultEntry>(
        "SELECT id, encrypted_site_name, encrypted_username, encrypted_login_email, encrypted_preferred_login_type, is_favorite, deleted_at, encrypted_folder
         FROM vault
         WHERE user_email = ? AND deleted_at IS NOT NULL
         ORDER BY deleted_at DESC"
        )
        .bind(email)
        .fetch_all(db).await.map_err(AppError::from)
    }

    // =========================================================================
    // 3. AJOUT D'UNE ENTRÉE (CREATE)
    // =========================================================================

    /// Insère un nouvel identifiant / mot de passe chiffré dans le coffre-fort.
    pub async fn add(db: &SqlitePool, email: &str, entry: VaultEntryInput) -> Result<(), AppError> {
        // Génère un identifiant unique universel (UUID v4) sous forme de chaîne de caractères
        let id = uuid::Uuid::new_v4().to_string();
        
        // Requête d'insertion standard
        sqlx::query("INSERT INTO vault (id, encrypted_site_name, encrypted_username, encrypted_login_email, encrypted_password, encrypted_preferred_login_type, user_email, is_favorite, encrypted_folder, encrypted_notes, encrypted_url, entry_type, encrypted_extra_fields) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(id)
            .bind(&entry.encrypted_site_name)
            .bind(&entry.encrypted_username)
            .bind(&entry.encrypted_login_email)
            .bind(&entry.encrypted_password) // Le mot de passe arrive déjà chiffré par le client (Zero-Knowledge)
            .bind(&entry.encrypted_preferred_login_type)
            .bind(email) // Sécurité : On force l'email de l'utilisateur connecté extrait du JWT
            .bind(entry.is_favorite)
            .bind(&entry.encrypted_folder)
            .bind(&entry.encrypted_notes)
            .bind(&entry.encrypted_url)
            .bind(&entry.entry_type)
            .bind(&entry.encrypted_extra_fields)
            .execute(db).await.map_err(AppError::from)?; // Exécute et propage l'erreur si échec

        Ok(())
    }

    /// Variante de add() DANS une transaction déjà ouverte (voir handlers/vault.rs::import_vault()) :
    /// permet d'importer plusieurs entrées de façon atomique — soit toutes sont insérées, soit
    /// aucune ne l'est (même principe que reencrypt() plus bas pour update_password()).
    pub async fn add_in_tx(tx: &mut sqlx::SqliteConnection, email: &str, entry: &VaultEntryInput) -> Result<(), AppError> {
        let id = uuid::Uuid::new_v4().to_string();

        sqlx::query("INSERT INTO vault (id, encrypted_site_name, encrypted_username, encrypted_login_email, encrypted_password, encrypted_preferred_login_type, user_email, is_favorite, encrypted_folder, encrypted_notes, encrypted_url, entry_type, encrypted_extra_fields) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(id)
            .bind(&entry.encrypted_site_name)
            .bind(&entry.encrypted_username)
            .bind(&entry.encrypted_login_email)
            .bind(&entry.encrypted_password)
            .bind(&entry.encrypted_preferred_login_type)
            .bind(email)
            .bind(entry.is_favorite)
            .bind(&entry.encrypted_folder)
            .bind(&entry.encrypted_notes)
            .bind(&entry.encrypted_url)
            .bind(&entry.entry_type)
            .bind(&entry.encrypted_extra_fields)
            .execute(tx).await.map_err(AppError::from)?;

        Ok(())
    }

    // =========================================================================
    // 4. MISE À JOUR (UPDATE)
    // =========================================================================

    /// Modifie les données d'une entrée existante du coffre-fort.
    /// "deleted_at IS NULL" : on ne peut pas modifier une entrée passée à la corbeille sans
    /// d'abord la restaurer (restore()) — sinon une modification silencieuse d'une entrée
    /// "supprimée" serait trompeuse pour l'utilisateur.
    /// Si `entry.password_changed` (voir models.rs), archive d'abord l'ANCIEN mot de passe chiffré
    /// dans l'historique avant de l'écraser — d'où la transaction : lecture de l'ancienne valeur,
    /// archivage, puis mise à jour, tout ou rien.
    ///
    /// DÉTECTION DE CONFLIT : si `entry.expected_version` est fourni (voir models.rs), il DOIT
    /// correspondre à `version` tel qu'il est ACTUELLEMENT en base, sinon `AppError::Conflict` —
    /// sans ce garde-fou, deux appareils modifiant la MÊME entrée à quelques secondes d'intervalle
    /// s'écrasaient silencieusement l'un l'autre (le dernier PUT "gagnait" sans que personne n'en
    /// soit informé). `None` (client ancien, ou création via import qui ne passe pas par cette
    /// fonction) désactive le contrôle — rétrocompatible, comportement inchangé. Compteur entier
    /// dédié plutôt que comparer `updated_at` : CURRENT_TIMESTAMP n'a qu'une précision à la
    /// SECONDE en SQLite, deux modifications dans la même seconde auraient le même horodatage.
    pub async fn update(db: &SqlitePool, email: &str, id: &str, entry: VaultEntryInput) -> Result<(), AppError> {
        let mut tx = db.begin().await?;

        // Lu UNE SEULE FOIS, avant toute décision : sert à la fois à vérifier l'existence/
        // propriété (comme avant), à détecter un conflit de version, ET (si password_changed) à
        // récupérer la valeur à archiver dans l'historique — plutôt que trois requêtes séparées.
        let current: Option<(String, i64)> = sqlx::query_as(
            "SELECT encrypted_password, version FROM vault WHERE id = ? AND user_email = ? AND deleted_at IS NULL",
        )
        .bind(id)
        .bind(email)
        .fetch_optional(&mut *tx)
        .await?;

        let Some((old_encrypted_password, current_version)) = current else {
            return Err(AppError::NotFound);
        };

        if let Some(expected) = entry.expected_version {
            if expected != current_version {
                return Err(AppError::Conflict(
                    "Cette entrée a été modifiée ailleurs entre-temps — rechargez-la avant de réessayer.".to_string(),
                ));
            }
        }

        if entry.password_changed {
            Self::archive_password_history(&mut tx, email, id, &old_encrypted_password).await?;
        }

        let res = sqlx::query(
        "UPDATE vault
         SET encrypted_site_name = ?, encrypted_username = ?, encrypted_login_email = ?, encrypted_password = ?, encrypted_preferred_login_type = ?, is_favorite = ?, encrypted_folder = ?, encrypted_notes = ?, encrypted_url = ?, entry_type = ?, encrypted_extra_fields = ?, updated_at = CURRENT_TIMESTAMP, version = version + 1
         WHERE id = ? AND user_email = ? AND deleted_at IS NULL"
        )
        .bind(&entry.encrypted_site_name)
        .bind(&entry.encrypted_username)
        .bind(&entry.encrypted_login_email)
        .bind(&entry.encrypted_password)
        .bind(&entry.encrypted_preferred_login_type)
        .bind(entry.is_favorite)
        .bind(&entry.encrypted_folder)
        .bind(&entry.encrypted_notes)
        .bind(&entry.encrypted_url)
        .bind(&entry.entry_type)
        .bind(&entry.encrypted_extra_fields)
        .bind(id)     // L'ID de l'élément à modifier
        .bind(email)  // Sécurité cruciale : empêche de modifier l'élément d'un AUTRE utilisateur
        .execute(&mut *tx)
        .await?;

        // Ne peut plus arriver en pratique (existence déjà confirmée juste au-dessus, dans la MÊME
        // transaction), mais gardé par prudence plutôt que de supposer que rows_affected() vaut
        // forcément 1 ici.
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }

        tx.commit().await?;
        Ok(())
    }

    /// Archive `old_encrypted_password` dans l'historique de `vault_id`, puis fait respecter
    /// MAX_HISTORY_PER_ENTRY en purgeant les versions les plus anciennes au-delà de ce plafond.
    async fn archive_password_history(
        tx: &mut sqlx::SqliteConnection,
        email: &str,
        vault_id: &str,
        old_encrypted_password: &str,
    ) -> Result<(), AppError> {
        let history_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO vault_password_history (id, vault_id, user_email, encrypted_password) VALUES (?, ?, ?, ?)")
            .bind(&history_id)
            .bind(vault_id)
            .bind(email)
            .bind(old_encrypted_password)
            .execute(&mut *tx)
            .await?;

        // `ORDER BY changed_at DESC, rowid DESC` : `changed_at` (CURRENT_TIMESTAMP) n'a qu'une
        // résolution à la SECONDE en SQLite — plusieurs archivages rapprochés (ex: dans une boucle
        // de test, ou un import scripté) peuvent partager exactement le même changed_at, ce qui
        // rendrait le tri ambigu sans second critère. `rowid` (toujours présent implicitement ici,
        // la clé primaire `id` étant TEXT et non INTEGER) croît de façon strictement monotone à
        // l'insertion, donc départage les égalités de façon fiable, dans le bon ordre.
        sqlx::query(
            "DELETE FROM vault_password_history
             WHERE vault_id = ? AND id NOT IN (
                 SELECT id FROM vault_password_history WHERE vault_id = ? ORDER BY changed_at DESC, rowid DESC LIMIT ?
             )",
        )
        .bind(vault_id)
        .bind(vault_id)
        .bind(MAX_HISTORY_PER_ENTRY)
        .execute(&mut *tx)
        .await?;

        Ok(())
    }

    /// Historique des mots de passe d'UNE entrée, du plus récent au plus ancien. Le filtre sur
    /// `user_email` (présent sur chaque ligne d'historique dès l'archivage, voir
    /// archive_password_history) suffit à empêcher un utilisateur d'accéder à l'historique d'un
    /// autre — pas besoin d'une jointure supplémentaire vers `vault` pour vérifier la propriété.
    pub async fn get_history(db: &SqlitePool, email: &str, vault_id: &str, limit: i64) -> Result<Vec<PasswordHistoryEntry>, AppError> {
        sqlx::query_as::<_, PasswordHistoryEntry>(
            "SELECT id, vault_id, encrypted_password, changed_at
             FROM vault_password_history
             WHERE vault_id = ? AND user_email = ?
             ORDER BY changed_at DESC, rowid DESC LIMIT ?",
        )
        .bind(vault_id)
        .bind(email)
        .bind(limit)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// TOUT l'historique d'un utilisateur, tous dossiers/entrées confondus — utilisé UNIQUEMENT
    /// lors d'un changement de mot de passe MAÎTRE (voir ChangeMasterPasswordPayload), où chaque
    /// ligne doit être re-chiffrée avec la nouvelle clé, sans exception.
    pub async fn get_all_history_for_user(db: &SqlitePool, email: &str) -> Result<Vec<PasswordHistoryEntry>, AppError> {
        sqlx::query_as::<_, PasswordHistoryEntry>(
            "SELECT id, vault_id, encrypted_password, changed_at FROM vault_password_history WHERE user_email = ?",
        )
        .bind(email)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Compte les lignes d'historique d'un utilisateur — sert à vérifier qu'un changement de mot
    /// de passe maître a bien re-chiffré TOUT l'historique, comme count_active() le fait déjà pour
    /// les entrées actives elles-mêmes.
    pub async fn count_history_for_user(db: &SqlitePool, email: &str) -> Result<i64, AppError> {
        sqlx::query_scalar("SELECT COUNT(*) FROM vault_password_history WHERE user_email = ?")
            .bind(email)
            .fetch_one(db)
            .await
            .map_err(AppError::from)
    }

    /// Remplace le mot de passe chiffré d'UNE ligne d'historique par sa version re-chiffrée —
    /// pendant de reencrypt() ci-dessus, mais pour vault_password_history plutôt que vault.
    pub async fn reencrypt_history_row(
        tx: &mut sqlx::SqliteConnection,
        email: &str,
        entry: &ReencryptedHistoryEntry,
    ) -> Result<(), AppError> {
        let res = sqlx::query("UPDATE vault_password_history SET encrypted_password = ? WHERE id = ? AND user_email = ?")
            .bind(&entry.encrypted_password)
            .bind(&entry.id)
            .bind(email)
            .execute(&mut *tx)
            .await?;

        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Remplace les champs chiffrés d'une entrée EXISTANTE par leur version RE-CHIFFRÉE avec la
    /// nouvelle clé (après un changement de mot de passe maître). Ne touche PAS `is_favorite`
    /// (métadonnée en clair, non affectée par un changement de clé de chiffrement).
    /// Volontairement séparée de update() : sémantique différente (re-chiffrement forcé, appelée
    /// uniquement dans la transaction de changement de mot de passe, jamais par l'utilisateur
    /// pour une modification normale de contenu).
    pub async fn reencrypt(db: &mut sqlx::SqliteConnection, email: &str, entry: &crate::models::ReencryptedVaultEntry) -> Result<(), AppError> {
        let res = sqlx::query(
        "UPDATE vault
         SET encrypted_site_name = ?, encrypted_username = ?, encrypted_login_email = ?, encrypted_password = ?, encrypted_preferred_login_type = ?, encrypted_folder = ?, encrypted_notes = ?, encrypted_url = ?, encrypted_extra_fields = ?
         WHERE id = ? AND user_email = ? AND deleted_at IS NULL"
        )
        .bind(&entry.encrypted_site_name)
        .bind(&entry.encrypted_username)
        .bind(&entry.encrypted_login_email)
        .bind(&entry.encrypted_password)
        .bind(&entry.encrypted_preferred_login_type)
        .bind(&entry.encrypted_folder)
        .bind(&entry.encrypted_notes)
        .bind(&entry.encrypted_url)
        .bind(&entry.encrypted_extra_fields)
        .bind(&entry.id)
        .bind(email)
        .execute(db)
        .await?;

        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Compte le nombre d'entrées ACTIVES d'un utilisateur — sert à vérifier qu'un changement de
    /// mot de passe maître a bien re-chiffré TOUTES les entrées (ni oubli, ni entrée fantôme).
    pub async fn count_active(db: &SqlitePool, email: &str) -> Result<i64, AppError> {
        sqlx::query_scalar("SELECT COUNT(*) FROM vault WHERE user_email = ? AND deleted_at IS NULL")
            .bind(email)
            .fetch_one(db)
            .await
            .map_err(AppError::from)
    }

    // =========================================================================
    // 5. SUPPRESSION DOUCE, RESTAURATION, PURGE DÉFINITIVE (CORBEILLE)
    // =========================================================================

    /// "Supprime" une entrée SANS effacer ses données (suppression douce / corbeille) :
    /// marque `deleted_at`. L'entrée disparaît immédiatement des listages normaux (get_all)
    /// mais reste récupérable via restore() pendant 30 jours, avant d'être purgée
    /// automatiquement (voir purge_old_trashed_vault_entries() dans main.rs).
    pub async fn delete(db: &sqlx::SqlitePool, email: &str, id: &str) -> Result<(), AppError> {
        // "deleted_at IS NULL" dans le WHERE : on ne "supprime" pas une entrée déjà supprimée
        // (renvoie NotFound plutôt que de rafraîchir silencieusement sa date de suppression).
        let res = sqlx::query("UPDATE vault SET deleted_at = CURRENT_TIMESTAMP WHERE id = ? AND user_email = ? AND deleted_at IS NULL")
            .bind(id)
            .bind(email)
            .execute(db)
            .await?;
            
        // Si aucune ligne n'a été modifiée, l'élément n'existait pas, n'appartenait pas à
        // l'appelant, ou était déjà dans la corbeille.
        if res.rows_affected() == 0 { 
            return Err(AppError::NotFound); 
        }
        Ok(())
    }

    /// Restaure une entrée de la corbeille : annule la suppression douce (deleted_at = NULL).
    /// L'entrée réapparaît immédiatement dans les listages normaux.
    pub async fn restore(db: &sqlx::SqlitePool, email: &str, id: &str) -> Result<(), AppError> {
        // "deleted_at IS NOT NULL" : on ne peut restaurer qu'une entrée effectivement en corbeille.
        let res = sqlx::query("UPDATE vault SET deleted_at = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_email = ? AND deleted_at IS NOT NULL")
            .bind(id)
            .bind(email)
            .execute(db)
            .await?;

        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Supprime DÉFINITIVEMENT une entrée déjà présente dans la corbeille (vidage manuel).
    /// Contrairement à delete(), il n'y a ici aucun retour en arrière possible.
    pub async fn purge(db: &sqlx::SqlitePool, email: &str, id: &str) -> Result<(), AppError> {
        // "deleted_at IS NOT NULL" : sécurité supplémentaire — on ne purge que ce qui est déjà
        // dans la corbeille, jamais une entrée active par erreur d'appel.
        let res = sqlx::query("DELETE FROM vault WHERE id = ? AND user_email = ? AND deleted_at IS NOT NULL")
            .bind(id)
            .bind(email)
            .execute(db)
            .await?;

        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    // =========================================================================
    // 6. ACTION SPÉCIFIQUE (TOGGLE FAVORITE)
    // =========================================================================

    /// Alterne l'état de favori (Vrai <-> Faux) d'un élément sans toucher au reste des données.
    /// "deleted_at IS NULL" : même logique que pour update() — pas de modification silencieuse
    /// d'une entrée dans la corbeille.
    pub async fn toggle_favorite(db: &SqlitePool, email: &str, id: &str) -> Result<(), AppError> {
        // Utilisation de l'opérateur SQL 'NOT' pour inverser directement le booléen en base de données
        let res = sqlx::query("UPDATE vault SET is_favorite = NOT is_favorite, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_email = ? AND deleted_at IS NULL")
            .bind(id).bind(email).execute(db).await?;
            
        // Même sécurité : si 0 ligne modifiée, on lève une erreur 404.
        if res.rows_affected() == 0 {
             return Err(AppError::NotFound);
        }
        Ok(())
    }

    // =========================================================================
    // 7. PIÈCES JOINTES CHIFFRÉES
    // =========================================================================

    /// Compte les pièces jointes déjà attachées à UNE entrée — sert à faire respecter
    /// MAX_ATTACHMENTS_PER_ENTRY côté handler (voir handlers/vault.rs). CORRECTIF SÉCURITÉ :
    /// filtré par `user_email` en plus de `vault_id`, comme absolument toutes les autres requêtes
    /// de ce fichier — sans ce filtre, ce comptage s'exécutait sur N'IMPORTE QUEL vault_id, y
    /// compris celui d'un AUTRE utilisateur (ex: obtenu via un partage, voir SharedWithMeEntry
    /// dans models.rs, qui expose légitimement le vault_id du propriétaire) : le message d'erreur
    /// "quota atteint" renvoyé AVANT toute vérification de propriété (voir add_attachment()
    /// ci-dessous, appelée après) formait un oracle révélant si l'entrée d'autrui avait déjà
    /// atteint son quota de pièces jointes — une information que l'appelant n'a aucun droit de
    /// connaître.
    pub async fn count_attachments_for_entry(db: &SqlitePool, email: &str, vault_id: &str) -> Result<i64, AppError> {
        sqlx::query_scalar("SELECT COUNT(*) FROM vault_attachments WHERE vault_id = ? AND user_email = ?")
            .bind(vault_id)
            .bind(email)
            .fetch_one(db)
            .await
            .map_err(AppError::from)
    }

    /// Compte TOUTES les pièces jointes d'un utilisateur, tous dossiers/entrées confondus — sert
    /// à faire respecter MAX_ATTACHMENTS_PER_USER (quota global, indépendant de l'entrée visée).
    pub async fn count_attachments_for_user(db: &SqlitePool, email: &str) -> Result<i64, AppError> {
        sqlx::query_scalar("SELECT COUNT(*) FROM vault_attachments WHERE user_email = ?")
            .bind(email)
            .fetch_one(db)
            .await
            .map_err(AppError::from)
    }

    /// Ajoute une pièce jointe à UNE entrée active du coffre. Vérifie D'ABORD que l'entrée existe,
    /// appartient à l'utilisateur ET n'est pas dans la corbeille — sinon `AppError::NotFound`
    /// plutôt qu'un rattachement silencieux à une entrée qui ne devrait plus être modifiable.
    pub async fn add_attachment(db: &SqlitePool, email: &str, vault_id: &str, input: &VaultAttachmentInput) -> Result<String, AppError> {
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM vault WHERE id = ? AND user_email = ? AND deleted_at IS NULL",
        )
        .bind(vault_id)
        .bind(email)
        .fetch_optional(db)
        .await?;
        if exists.is_none() {
            return Err(AppError::NotFound);
        }

        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO vault_attachments (id, vault_id, user_email, encrypted_filename, encrypted_content, content_size) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(vault_id)
        .bind(email)
        .bind(&input.encrypted_filename)
        .bind(&input.encrypted_content)
        .bind(input.content_size)
        .execute(db)
        .await?;

        Ok(id)
    }

    /// Liste les pièces jointes d'UNE entrée, SANS leur contenu (voir VaultAttachmentMeta) — la
    /// plus récente en premier.
    pub async fn list_attachments(db: &SqlitePool, email: &str, vault_id: &str) -> Result<Vec<VaultAttachmentMeta>, AppError> {
        sqlx::query_as::<_, VaultAttachmentMeta>(
            "SELECT id, encrypted_filename, content_size, created_at
             FROM vault_attachments
             WHERE vault_id = ? AND user_email = ?
             ORDER BY created_at DESC",
        )
        .bind(vault_id)
        .bind(email)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Récupère UNE pièce jointe complète (avec son contenu chiffré) — pour le téléchargement.
    /// `vault_id` ET `user_email` filtrés tous les deux : empêche de récupérer une pièce jointe
    /// via l'id d'une AUTRE entrée que celle indiquée dans l'URL, en plus de la protection
    /// habituelle par propriétaire.
    pub async fn get_attachment(db: &SqlitePool, email: &str, vault_id: &str, attachment_id: &str) -> Result<VaultAttachment, AppError> {
        sqlx::query_as::<_, VaultAttachment>(
            "SELECT id, vault_id, encrypted_filename, encrypted_content, content_size, created_at
             FROM vault_attachments
             WHERE id = ? AND vault_id = ? AND user_email = ?",
        )
        .bind(attachment_id)
        .bind(vault_id)
        .bind(email)
        .fetch_optional(db)
        .await?
        .ok_or(AppError::NotFound)
    }

    /// Supprime définitivement UNE pièce jointe — pas de corbeille pour les pièces jointes
    /// (contrairement aux entrées elles-mêmes) : un fichier joint supprimé l'est pour de bon.
    pub async fn delete_attachment(db: &SqlitePool, email: &str, vault_id: &str, attachment_id: &str) -> Result<(), AppError> {
        let res = sqlx::query("DELETE FROM vault_attachments WHERE id = ? AND vault_id = ? AND user_email = ?")
            .bind(attachment_id)
            .bind(vault_id)
            .bind(email)
            .execute(db)
            .await?;

        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Remplace les deux champs chiffrés (nom ET contenu) d'UNE pièce jointe EXISTANTE par leur
    /// version RE-CHIFFRÉE avec la nouvelle clé — pendant de reencrypt()/reencrypt_history_row()
    /// ci-dessus, mais pour vault_attachments, appelée uniquement dans la transaction de
    /// changement de mot de passe maître (voir handlers/auth/account.rs::update_password).
    pub async fn reencrypt_attachment(
        db: &mut sqlx::SqliteConnection,
        email: &str,
        attachment: &crate::models::ReencryptedVaultAttachment,
    ) -> Result<(), AppError> {
        let res = sqlx::query(
            "UPDATE vault_attachments SET encrypted_filename = ?, encrypted_content = ? WHERE id = ? AND user_email = ?",
        )
        .bind(&attachment.encrypted_filename)
        .bind(&attachment.encrypted_content)
        .bind(&attachment.id)
        .bind(email)
        .execute(db)
        .await?;

        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }
}

// =========================================================================
// ACCÈS D'URGENCE — voir handlers/emergency.rs pour la machine à états complète, ce namespace ne
// contient que les requêtes SQL brutes. Le serveur ne déchiffre ni ne lit jamais le CONTENU des
// clés/blobs qu'il stocke ici, exactement comme pour `vault`.
// =========================================================================

/// Plafond du nombre de contacts de confiance qu'un même propriétaire peut désigner. Même
/// raisonnement que MAX_SHARES_PER_OWNER ci-dessus — CORRECTIF : absent jusqu'ici.
const MAX_EMERGENCY_CONTACTS_PER_OWNER: i64 = 50;

pub struct EmergencyRepository;

impl EmergencyRepository {
    /// Crée OU remplace la paire de clés X25519 de l'utilisateur (une seule par compte — un
    /// second appel remplace la précédente, ex: si l'utilisateur régénère ses clés).
    pub async fn upsert_user_keys(db: &SqlitePool, email: &str, input: &UserKeysInput) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO user_keys (user_email, public_key, encrypted_private_key) VALUES (?, ?, ?)
             ON CONFLICT(user_email) DO UPDATE SET public_key = excluded.public_key, encrypted_private_key = excluded.encrypted_private_key",
        )
        .bind(email)
        .bind(&input.public_key)
        .bind(&input.encrypted_private_key)
        .execute(db)
        .await?;
        Ok(())
    }

    /// Sa PROPRE paire de clés (publique + privée CHIFFRÉE) — pour un utilisateur qui a besoin de
    /// déchiffrer sa propre clé privée (voir POST /emergency/contacts/{id}/request-access, où le
    /// CONTACT doit desceller la clé de coffre du propriétaire avec la sienne).
    pub async fn get_own_keys(db: &SqlitePool, email: &str) -> Result<UserKeysInput, AppError> {
        sqlx::query_as::<_, UserKeysInput>(
            "SELECT public_key, encrypted_private_key FROM user_keys WHERE user_email = ?",
        )
        .bind(email)
        .fetch_optional(db)
        .await?
        .ok_or(AppError::NotFound)
    }

    /// UNIQUEMENT la clé publique d'un autre utilisateur (voir GET /emergency/keys/{email}) — ce
    /// qu'il faut pour lui sceller quelque chose, jamais sa clé privée.
    pub async fn get_public_key(db: &SqlitePool, email: &str) -> Result<UserPublicKey, AppError> {
        sqlx::query_as::<_, UserPublicKey>("SELECT public_key FROM user_keys WHERE user_email = ?")
            .bind(email)
            .fetch_optional(db)
            .await?
            .ok_or(AppError::NotFound)
    }

    /// Désigne un nouveau contact de confiance — vérifie D'ABORD qu'aucune relation n'existe déjà
    /// pour ce couple (owner_email, contact_email), plutôt que de laisser la contrainte UNIQUE de
    /// la table échouer (même convention que le reste de ce backend, voir register()).
    pub async fn add_contact(db: &SqlitePool, owner_email: &str, contact_email: &str, waiting_period_days: i64) -> Result<String, AppError> {
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM emergency_contacts WHERE owner_email = ? AND contact_email = ?",
        )
        .bind(owner_email)
        .bind(contact_email)
        .fetch_optional(db)
        .await?;
        if exists.is_some() {
            return Err(AppError::Conflict("Ce contact de confiance existe déjà.".to_string()));
        }

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM emergency_contacts WHERE owner_email = ?")
            .bind(owner_email)
            .fetch_one(db)
            .await?;
        if count >= MAX_EMERGENCY_CONTACTS_PER_OWNER {
            return Err(AppError::ValidationError(format!(
                "Limite de {MAX_EMERGENCY_CONTACTS_PER_OWNER} contacts de confiance atteinte pour ce compte."
            )));
        }

        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO emergency_contacts (id, owner_email, contact_email, waiting_period_days, status) VALUES (?, ?, ?, ?, 'pending')",
        )
        .bind(&id)
        .bind(owner_email)
        .bind(contact_email)
        .bind(waiting_period_days)
        .execute(db)
        .await?;

        Ok(id)
    }

    /// Contacts que CET utilisateur a désignés (il est owner_email) — "les gens en qui j'ai
    /// confiance".
    pub async fn list_as_owner(db: &SqlitePool, owner_email: &str) -> Result<Vec<EmergencyContact>, AppError> {
        sqlx::query_as::<_, EmergencyContact>(
            "SELECT id, owner_email, contact_email, waiting_period_days, status, requested_at, available_at, created_at
             FROM emergency_contacts WHERE owner_email = ? ORDER BY created_at DESC",
        )
        .bind(owner_email)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Relations où CET utilisateur est le contact désigné (il est contact_email) — "les comptes
    /// où on m'a fait confiance".
    pub async fn list_as_contact(db: &SqlitePool, contact_email: &str) -> Result<Vec<EmergencyContact>, AppError> {
        sqlx::query_as::<_, EmergencyContact>(
            "SELECT id, owner_email, contact_email, waiting_period_days, status, requested_at, available_at, created_at
             FROM emergency_contacts WHERE contact_email = ? ORDER BY created_at DESC",
        )
        .bind(contact_email)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Une relation précise par id — SANS vérification d'appartenance (l'appelant, voir
    /// handlers/emergency.rs, doit vérifier lui-même que owner_email OU contact_email correspond
    /// à l'utilisateur authentifié selon l'action demandée).
    pub async fn get_by_id(db: &SqlitePool, id: &str) -> Result<EmergencyContact, AppError> {
        sqlx::query_as::<_, EmergencyContact>(
            "SELECT id, owner_email, contact_email, waiting_period_days, status, requested_at, available_at, created_at
             FROM emergency_contacts WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(db)
        .await?
        .ok_or(AppError::NotFound)
    }

    /// Renvoie (owner_email, sealed_vault_key) UNIQUEMENT si l'accès est bien accordé À CET
    /// UTILISATEUR PRÉCIS — "contact_email = ? AND status = 'access_granted'" fait PARTIE de la
    /// requête SQL elle-même plutôt que d'être revérifié après coup côté Rust, pour qu'il soit
    /// STRUCTURELLEMENT impossible d'oublier ce contrôle. `sealed_vault_key` n'apparaît JAMAIS
    /// dans `EmergencyContact` (voir get_by_id/list_as_owner/list_as_contact ci-dessus/dessous) :
    /// s'il y figurait, un contact pourrait le récupérer via un simple listing AVANT même d'avoir
    /// demandé l'accès, et le desceller avec sa propre clé privée — contournant entièrement le
    /// délai d'attente et l'approbation du propriétaire, qui ne sont alors QUE des vérifications
    /// applicatives, pas cryptographiques.
    pub async fn get_granted_vault_key(db: &SqlitePool, id: &str, contact_email: &str) -> Result<(String, String), AppError> {
        let row: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT owner_email, sealed_vault_key FROM emergency_contacts
             WHERE id = ? AND contact_email = ? AND status = 'access_granted'",
        )
        .bind(id)
        .bind(contact_email)
        .fetch_optional(db)
        .await?;

        let (owner_email, sealed_vault_key) = row.ok_or(AppError::NotFound)?;
        let sealed_vault_key = sealed_vault_key.ok_or(AppError::NotFound)?;
        Ok((owner_email, sealed_vault_key))
    }

    /// Le CONTACT accepte l'invitation — seulement depuis 'pending'. "id + contact_email +
    /// status" tous filtrés dans le WHERE : 0 ligne affectée couvre indifféremment "id inconnu",
    /// "ce n'est pas vous le contact désigné" et "déjà accepté/pas encore invité" — 404 générique
    /// dans tous les cas, pas d'information à glaner en sondant les réponses.
    pub async fn accept(db: &SqlitePool, id: &str, contact_email: &str) -> Result<(), AppError> {
        let res = sqlx::query(
            "UPDATE emergency_contacts SET status = 'active' WHERE id = ? AND contact_email = ? AND status = 'pending'",
        )
        .bind(id)
        .bind(contact_email)
        .execute(db)
        .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Le CONTACT décline l'invitation — supprime carrément la relation (pas d'intérêt à garder
    /// une trace d'une invitation refusée).
    pub async fn decline(db: &SqlitePool, id: &str, contact_email: &str) -> Result<(), AppError> {
        let res = sqlx::query("DELETE FROM emergency_contacts WHERE id = ? AND contact_email = ? AND status = 'pending'")
            .bind(id)
            .bind(contact_email)
            .execute(db)
            .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Le PROPRIÉTAIRE chiffre (scelle) sa clé de coffre pour ce contact (voir emergency.rs::seal
    /// côté client) — peut être rappelé à tout moment pour rafraîchir le blob (ex: après un
    /// changement de mot de passe maître, voir AuthContext.tsx côté frontend).
    pub async fn seed(db: &SqlitePool, id: &str, owner_email: &str, sealed_vault_key: &str) -> Result<(), AppError> {
        let res = sqlx::query("UPDATE emergency_contacts SET sealed_vault_key = ? WHERE id = ? AND owner_email = ?")
            .bind(sealed_vault_key)
            .bind(id)
            .bind(owner_email)
            .execute(db)
            .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Le CONTACT demande l'accès — seulement depuis 'active' (invitation déjà acceptée) ET une
    /// clé déjà scellée par le propriétaire (sans quoi la demande n'aboutirait jamais à rien de
    /// déchiffrable). `requested_at`/`available_at` calculés côté appelant (voir
    /// handlers/emergency.rs) pour ne pas dépendre de l'arithmétique de dates SQLite.
    pub async fn request_access(
        db: &SqlitePool,
        id: &str,
        contact_email: &str,
        requested_at: chrono::NaiveDateTime,
        available_at: chrono::NaiveDateTime,
    ) -> Result<(), AppError> {
        let res = sqlx::query(
            "UPDATE emergency_contacts
             SET status = 'access_requested', requested_at = ?, available_at = ?
             WHERE id = ? AND contact_email = ? AND status = 'active' AND sealed_vault_key IS NOT NULL",
        )
        .bind(requested_at)
        .bind(available_at)
        .bind(id)
        .bind(contact_email)
        .execute(db)
        .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Le PROPRIÉTAIRE approuve immédiatement une demande en cours, sans attendre la fin du délai.
    pub async fn approve(db: &SqlitePool, id: &str, owner_email: &str) -> Result<(), AppError> {
        let res = sqlx::query(
            "UPDATE emergency_contacts SET status = 'access_granted' WHERE id = ? AND owner_email = ? AND status = 'access_requested'",
        )
        .bind(id)
        .bind(owner_email)
        .execute(db)
        .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Le PROPRIÉTAIRE refuse une demande en cours — revient à 'active' (le contact reste
    /// désigné, juste sans accès accordé), pas de suppression de la relation elle-même.
    pub async fn reject(db: &SqlitePool, id: &str, owner_email: &str) -> Result<(), AppError> {
        let res = sqlx::query(
            "UPDATE emergency_contacts SET status = 'active', requested_at = NULL, available_at = NULL
             WHERE id = ? AND owner_email = ? AND status = 'access_requested'",
        )
        .bind(id)
        .bind(owner_email)
        .execute(db)
        .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Promotion PARESSEUSE 'access_requested' -> 'access_granted' une fois le délai d'attente
    /// écoulé — appelée juste avant de servir GET /emergency/contacts/{id}/vault, plutôt que via
    /// une tâche de fond planifiée (voir main.rs::maintenance pour les tâches, volontairement pas
    /// alourdies de celle-ci : l'écart de quelques secondes entre l'échéance réelle et le prochain
    /// appel du contact n'a aucune conséquence pratique). Ne fait rien si la ligne n'est pas dans
    /// l'état attendu ou si le délai n'est pas encore écoulé — pas une erreur, juste un no-op.
    pub async fn maybe_auto_grant(db: &SqlitePool, id: &str) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE emergency_contacts SET status = 'access_granted'
             WHERE id = ? AND status = 'access_requested' AND available_at <= CURRENT_TIMESTAMP",
        )
        .bind(id)
        .execute(db)
        .await?;
        Ok(())
    }

    /// Révoque une relation — l'un OU l'autre côté peut y mettre fin à tout moment (le propriétaire
    /// retire sa confiance, ou le contact se retire lui-même).
    pub async fn revoke(db: &SqlitePool, id: &str, caller_email: &str) -> Result<(), AppError> {
        let res = sqlx::query("DELETE FROM emergency_contacts WHERE id = ? AND (owner_email = ? OR contact_email = ?)")
            .bind(id)
            .bind(caller_email)
            .bind(caller_email)
            .execute(db)
            .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }
}

// =========================================================================
// PARTAGE SÉCURISÉ D'UNE ENTRÉE — voir handlers/sharing.rs pour le flux complet, ce namespace ne
// contient que les requêtes SQL brutes. Réutilise EmergencyRepository::get_public_key (déjà
// générique, pas de logique propre à l'accès d'urgence) pour résoudre la clé publique du
// destinataire — voir handlers/sharing.rs::share_entry.
// =========================================================================

/// Plafond du nombre TOTAL de partages actifs qu'un même propriétaire peut créer, tous
/// destinataires et toutes entrées confondus. Même raisonnement que MAX_VAULT_ENTRIES_PER_USER/
/// MAX_ATTACHMENTS_PER_USER (voir handlers/vault.rs) : la BDD SQLite est un fichier UNIQUE partagé
/// par tous les utilisateurs — sans plafond, un compte compromis ou scripté pourrait faire croître
/// `vault_shares` sans limite (jusqu'à MAX_VAULT_ENTRIES_PER_USER entrées x autant de destinataires
/// distincts que souhaité), affectant tout le monde. CORRECTIF : absent jusqu'ici, contrairement
/// aux entrées/pièces jointes qui ont, elles, toujours été plafonnées.
const MAX_SHARES_PER_OWNER: i64 = 200;

pub struct SharingRepository;

impl SharingRepository {
    /// Crée OU remplace un partage — vérifie D'ABORD que `vault_id` appartient bien à
    /// `owner_email` ET n'est pas dans la corbeille (comme add_attachment côté VaultRepository),
    /// puis insère/remplace via `ON CONFLICT` sur la contrainte UNIQUE(vault_id, shared_with_email)
    /// plutôt que d'échouer si un partage existe déjà pour ce couple : repartager la même entrée
    /// avec la même personne doit simplement mettre à jour le blob scellé (ex: l'entrée a changé
    /// depuis), pas créer un doublon ni exiger un appel de mise à jour séparé.
    pub async fn share_entry(db: &SqlitePool, vault_id: &str, owner_email: &str, shared_with_email: &str, sealed_entry: &str) -> Result<String, AppError> {
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM vault WHERE id = ? AND user_email = ? AND deleted_at IS NULL",
        )
        .bind(vault_id)
        .bind(owner_email)
        .fetch_optional(db)
        .await?;
        if exists.is_none() {
            return Err(AppError::NotFound);
        }

        // Réutilise l'id existant si un partage pour ce couple (entrée, destinataire) existe déjà,
        // plutôt que d'en générer un nouveau à chaque fois — évite de faire "disparaître" l'id
        // d'un partage déjà en cours côté client sur un simple re-partage après modification.
        let existing_id: Option<String> = sqlx::query_scalar(
            "SELECT id FROM vault_shares WHERE vault_id = ? AND shared_with_email = ?",
        )
        .bind(vault_id)
        .bind(shared_with_email)
        .fetch_optional(db)
        .await?;

        // Le plafond ne s'applique QUE lors de la création d'une ligne réellement NOUVELLE — un
        // re-partage (mise à jour du blob d'un partage déjà existant) ne doit jamais être bloqué
        // par un plafond qui n'a de sens que pour limiter la CROISSANCE du nombre de partages.
        if existing_id.is_none() {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault_shares WHERE owner_email = ?")
                .bind(owner_email)
                .fetch_one(db)
                .await?;
            if count >= MAX_SHARES_PER_OWNER {
                return Err(AppError::ValidationError(format!(
                    "Limite de {MAX_SHARES_PER_OWNER} partages atteinte pour ce compte."
                )));
            }
        }

        let id = existing_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        sqlx::query(
            "INSERT INTO vault_shares (id, vault_id, owner_email, shared_with_email, sealed_entry) VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(vault_id, shared_with_email) DO UPDATE SET sealed_entry = excluded.sealed_entry, updated_at = CURRENT_TIMESTAMP",
        )
        .bind(&id)
        .bind(vault_id)
        .bind(owner_email)
        .bind(shared_with_email)
        .bind(sealed_entry)
        .execute(db)
        .await?;

        Ok(id)
    }

    /// Liste les partages actifs d'UNE entrée, vus par son PROPRIÉTAIRE — jamais `sealed_entry`
    /// (voir VaultShare). Sert aussi à reseedEntryShares() côté client (lib/entrySharing.ts) pour
    /// savoir à qui re-sceller après une modification de l'entrée.
    pub async fn list_shares_for_entry(db: &SqlitePool, vault_id: &str, owner_email: &str) -> Result<Vec<VaultShare>, AppError> {
        sqlx::query_as::<_, VaultShare>(
            "SELECT id, shared_with_email, created_at FROM vault_shares WHERE vault_id = ? AND owner_email = ? ORDER BY created_at DESC",
        )
        .bind(vault_id)
        .bind(owner_email)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Liste tout ce qui a été partagé AVEC l'utilisateur courant, tous propriétaires confondus —
    /// jamais `sealed_entry` (voir SharedWithMeEntry).
    pub async fn list_shared_with_me(db: &SqlitePool, recipient_email: &str) -> Result<Vec<SharedWithMeEntry>, AppError> {
        sqlx::query_as::<_, SharedWithMeEntry>(
            "SELECT id, vault_id, owner_email, created_at FROM vault_shares WHERE shared_with_email = ? ORDER BY created_at DESC",
        )
        .bind(recipient_email)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Récupère le blob scellé d'UN partage précis — UNIQUEMENT pour son DESTINATAIRE.
    /// `shared_with_email = ?` est encodé DIRECTEMENT dans le WHERE (jamais une vérification a
    /// posteriori en Rust) — même pattern de sécurité que
    /// EmergencyRepository::get_granted_vault_key : rend l'autorisation structurellement
    /// impossible à oublier. Vérifie en plus, via une sous-requête, que l'entrée sous-jacente n'est
    /// pas dans la corbeille — un partage d'une entrée entre-temps supprimée ne doit plus être
    /// consultable, même si la ligne `vault_shares` existe encore (elle disparaîtra de toute façon
    /// à la purge définitive, voir ON DELETE CASCADE dans la migration, mais la corbeille laisse un
    /// délai avant purge pendant lequel l'entrée ne doit déjà plus être consultable via un partage).
    pub async fn get_shared_entry(db: &SqlitePool, share_id: &str, recipient_email: &str) -> Result<SharedEntryView, AppError> {
        sqlx::query_as::<_, SharedEntryView>(
            "SELECT owner_email, sealed_entry FROM vault_shares
             WHERE id = ? AND shared_with_email = ?
             AND vault_id IN (SELECT id FROM vault WHERE deleted_at IS NULL)",
        )
        .bind(share_id)
        .bind(recipient_email)
        .fetch_optional(db)
        .await?
        .ok_or(AppError::NotFound)
    }

    /// Révoque un partage — l'un OU l'autre côté peut y mettre fin (le propriétaire retire l'accès,
    /// ou le destinataire quitte le partage), même principe que EmergencyRepository::revoke.
    pub async fn revoke_share(db: &SqlitePool, share_id: &str, caller_email: &str) -> Result<(), AppError> {
        let res = sqlx::query("DELETE FROM vault_shares WHERE id = ? AND (owner_email = ? OR shared_with_email = ?)")
            .bind(share_id)
            .bind(caller_email)
            .bind(caller_email)
            .execute(db)
            .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }
}

// =========================================================================
// COFFRES PARTAGÉS FAMILIAUX (voir migration 20260831000004_shared_vaults.sql et
// crypto-core/src/shared_vault.rs) — même philosophie d'autorisation que SharingRepository
// ci-dessus : chaque condition d'accès (appartenance, propriété) est encodée DIRECTEMENT dans le
// WHERE de la requête SQL, jamais vérifiée séparément en Rust après coup.
// =========================================================================

/// Plafond du nombre de coffres partagés qu'un même compte peut CRÉER — même raisonnement que
/// MAX_SHARES_PER_OWNER ci-dessus (protection contre l'épuisement de stockage), pas une limite
/// fonctionnelle réaliste pour un usage familial.
const MAX_SHARED_VAULTS_PER_CREATOR: i64 = 50;
/// Par coffre partagé (pas par créateur) — voir invite_member() pour le raisonnement.
const MAX_MEMBERS_PER_SHARED_VAULT: i64 = 25;

pub struct SharedVaultRepository;

impl SharedVaultRepository {
    /// Crée un nouveau coffre partagé ET la ligne de membre du créateur (is_owner=true) dans la
    /// MÊME transaction — un coffre partagé sans aucun membre (donc sans personne capable de le
    /// déchiffrer, y compris son propre créateur) ne doit jamais pouvoir exister, même
    /// momentanément.
    pub async fn create(db: &SqlitePool, creator_email: &str, encrypted_name: &str, sealed_vault_key: &str) -> Result<String, AppError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM shared_vaults WHERE created_by = ?")
            .bind(creator_email)
            .fetch_one(db)
            .await?;
        if count >= MAX_SHARED_VAULTS_PER_CREATOR {
            return Err(AppError::ValidationError(format!(
                "Limite de {MAX_SHARED_VAULTS_PER_CREATOR} coffres partagés créés atteinte pour ce compte."
            )));
        }

        let mut tx = db.begin().await?;
        let id = uuid::Uuid::new_v4().to_string();

        sqlx::query("INSERT INTO shared_vaults (id, encrypted_name, created_by) VALUES (?, ?, ?)")
            .bind(&id)
            .bind(encrypted_name)
            .bind(creator_email)
            .execute(&mut *tx)
            .await?;

        sqlx::query("INSERT INTO shared_vault_members (shared_vault_id, member_email, sealed_vault_key, is_owner) VALUES (?, ?, ?, 1)")
            .bind(&id)
            .bind(creator_email)
            .bind(sealed_vault_key)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(id)
    }

    /// Liste les coffres partagés dont l'appelant est membre — `sealed_vault_key` renvoyée est
    /// TOUJOURS la sienne (jointure sur `member_email = ?`), jamais celle d'un autre membre.
    pub async fn list_for_member(db: &SqlitePool, member_email: &str) -> Result<Vec<SharedVaultView>, AppError> {
        sqlx::query_as::<_, SharedVaultView>(
            "SELECT sv.id, sv.encrypted_name, sv.created_by, sv.created_at, svm.sealed_vault_key, svm.is_owner
             FROM shared_vaults sv
             JOIN shared_vault_members svm ON svm.shared_vault_id = sv.id
             WHERE svm.member_email = ?
             ORDER BY sv.created_at DESC",
        )
        .bind(member_email)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Invite un nouveau membre — réservé au PROPRIÉTAIRE (`is_owner = 1` vérifié directement dans
    /// le WHERE de la sous-requête). `sealed_vault_key` doit déjà être scellé côté client pour la
    /// clé publique du nouveau membre AVANT cet appel (voir InviteSharedVaultMemberPayload) — le
    /// serveur ne fait que le stocker. Échoue si `member_email` est déjà membre (contrainte de clé
    /// primaire composite) plutôt que d'écraser silencieusement sa clé scellée existante.
    pub async fn invite_member(db: &SqlitePool, shared_vault_id: &str, caller_email: &str, member_email: &str, sealed_vault_key: &str) -> Result<(), AppError> {
        let is_owner: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM shared_vault_members WHERE shared_vault_id = ? AND member_email = ? AND is_owner = 1",
        )
        .bind(shared_vault_id)
        .bind(caller_email)
        .fetch_optional(db)
        .await?;
        if is_owner.is_none() {
            return Err(AppError::Forbidden);
        }

        // CORRECTIF : contrairement à toutes les autres collections de ce fichier (coffres
        // partagés par créateur, partages à usage limité par propriétaire, pièces jointes...),
        // rien ne plafonnait le nombre de membres d'UN coffre partagé — repéré lors d'une relecture
        // de sécurité, pas par un incident réel. Sans cette limite, `broadcast_to_members` (voir
        // handlers/shared_vault.rs) enverrait un événement WebSocket à un nombre de membres non
        // borné à CHAQUE modification d'entrée, et la table `shared_vault_members` pourrait croître
        // sans limite — un vecteur d'épuisement de ressources, même si peu probable dans ce
        // déploiement mono-tenant entre proches.
        let member_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM shared_vault_members WHERE shared_vault_id = ?",
        )
        .bind(shared_vault_id)
        .fetch_one(db)
        .await?;
        if member_count >= MAX_MEMBERS_PER_SHARED_VAULT {
            return Err(AppError::ValidationError(format!(
                "Limite de {MAX_MEMBERS_PER_SHARED_VAULT} membres atteinte pour ce coffre partagé."
            )));
        }

        let result = sqlx::query(
            "INSERT INTO shared_vault_members (shared_vault_id, member_email, sealed_vault_key, is_owner) VALUES (?, ?, ?, 0)",
        )
        .bind(shared_vault_id)
        .bind(member_email)
        .bind(sealed_vault_key)
        .execute(db)
        .await;

        match result {
            Ok(_) => Ok(()),
            // Violation de la clé primaire composite (shared_vault_id, member_email) : déjà membre.
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                Err(AppError::ValidationError("Cette personne est déjà membre de ce coffre partagé.".to_string()))
            }
            Err(e) => Err(AppError::from(e)),
        }
    }

    /// Liste les membres d'un coffre partagé — n'importe quel membre peut la consulter (pas
    /// réservé au propriétaire), jamais `sealed_vault_key` d'autrui (voir SharedVaultMemberView).
    pub async fn list_members(db: &SqlitePool, shared_vault_id: &str, caller_email: &str) -> Result<Vec<SharedVaultMemberView>, AppError> {
        let is_member: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM shared_vault_members WHERE shared_vault_id = ? AND member_email = ?",
        )
        .bind(shared_vault_id)
        .bind(caller_email)
        .fetch_optional(db)
        .await?;
        if is_member.is_none() {
            return Err(AppError::NotFound);
        }

        sqlx::query_as::<_, SharedVaultMemberView>(
            "SELECT member_email, is_owner, added_at FROM shared_vault_members WHERE shared_vault_id = ? ORDER BY added_at ASC",
        )
        .bind(shared_vault_id)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Variante SANS vérification d'autorisation de list_members() ci-dessus — réservée à un usage
    /// STRICTEMENT interne au serveur (diffusion d'un SyncEvent à tous les membres après une
    /// modification, voir handlers/shared_vault.rs::broadcast_to_members), jamais exposée
    /// directement à un appelant HTTP : il n'y a alors aucun "appelant" au sens d'une requête à
    /// authentifier, juste le serveur qui a besoin de savoir qui notifier.
    pub async fn list_all_members(db: &SqlitePool, shared_vault_id: &str) -> Result<Vec<SharedVaultMemberView>, AppError> {
        sqlx::query_as::<_, SharedVaultMemberView>(
            "SELECT member_email, is_owner, added_at FROM shared_vault_members WHERE shared_vault_id = ?",
        )
        .bind(shared_vault_id)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Un membre NON-propriétaire quitte le coffre de lui-même. Le propriétaire ne peut PAS quitter
    /// via cette voie (voir delete_vault ci-dessous, seule façon pour lui de s'en retirer) — un
    /// coffre partagé sans propriétaire (personne pour inviter/retirer des membres ou le supprimer)
    /// serait un état orphelin sans issue simple, volontairement rendu impossible plutôt que géré
    /// après coup.
    pub async fn leave(db: &SqlitePool, shared_vault_id: &str, member_email: &str) -> Result<(), AppError> {
        let res = sqlx::query(
            "DELETE FROM shared_vault_members WHERE shared_vault_id = ? AND member_email = ? AND is_owner = 0",
        )
        .bind(shared_vault_id)
        .bind(member_email)
        .execute(db)
        .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Le PROPRIÉTAIRE retire un autre membre (jamais lui-même — `is_owner = 0` dans le WHERE
    /// exclut structurellement ce cas, même si `target_email` désignait par erreur le propriétaire
    /// lui-même).
    pub async fn remove_member(db: &SqlitePool, shared_vault_id: &str, caller_email: &str, target_email: &str) -> Result<(), AppError> {
        let is_owner: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM shared_vault_members WHERE shared_vault_id = ? AND member_email = ? AND is_owner = 1",
        )
        .bind(shared_vault_id)
        .bind(caller_email)
        .fetch_optional(db)
        .await?;
        if is_owner.is_none() {
            return Err(AppError::Forbidden);
        }

        let res = sqlx::query(
            "DELETE FROM shared_vault_members WHERE shared_vault_id = ? AND member_email = ? AND is_owner = 0",
        )
        .bind(shared_vault_id)
        .bind(target_email)
        .execute(db)
        .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Supprime DÉFINITIVEMENT un coffre partagé entier (membres + entrées, via ON DELETE CASCADE)
    /// — réservé au créateur. C'est la SEULE façon pour le propriétaire de se "retirer" d'un coffre
    /// qu'il a créé (voir leave() ci-dessus) : pas de transfert de propriété dans cette première
    /// version.
    pub async fn delete_vault(db: &SqlitePool, shared_vault_id: &str, caller_email: &str) -> Result<(), AppError> {
        let res = sqlx::query("DELETE FROM shared_vaults WHERE id = ? AND created_by = ?")
            .bind(shared_vault_id)
            .bind(caller_email)
            .execute(db)
            .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Liste les entrées d'un coffre partagé — réservé à ses membres.
    pub async fn list_entries(db: &SqlitePool, shared_vault_id: &str, caller_email: &str) -> Result<Vec<SharedVaultEntry>, AppError> {
        let is_member: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM shared_vault_members WHERE shared_vault_id = ? AND member_email = ?",
        )
        .bind(shared_vault_id)
        .bind(caller_email)
        .fetch_optional(db)
        .await?;
        if is_member.is_none() {
            return Err(AppError::NotFound);
        }

        sqlx::query_as::<_, SharedVaultEntry>(
            "SELECT id, shared_vault_id, encrypted_site_name, encrypted_username, encrypted_login_email, encrypted_password, encrypted_preferred_login_type, encrypted_notes, encrypted_url, entry_type, encrypted_extra_fields, created_by, updated_at, version
             FROM shared_vault_entries WHERE shared_vault_id = ? ORDER BY updated_at DESC",
        )
        .bind(shared_vault_id)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Ajoute une entrée — réservé aux membres. `entry.expected_version` n'a pas de sens à la
    /// création (ignoré, comme VaultRepository::add).
    pub async fn add_entry(db: &SqlitePool, shared_vault_id: &str, caller_email: &str, entry: &SharedVaultEntryInput) -> Result<String, AppError> {
        let is_member: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM shared_vault_members WHERE shared_vault_id = ? AND member_email = ?",
        )
        .bind(shared_vault_id)
        .bind(caller_email)
        .fetch_optional(db)
        .await?;
        if is_member.is_none() {
            return Err(AppError::NotFound);
        }

        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO shared_vault_entries (id, shared_vault_id, encrypted_site_name, encrypted_username, encrypted_login_email, encrypted_password, encrypted_preferred_login_type, encrypted_notes, encrypted_url, entry_type, encrypted_extra_fields, created_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(shared_vault_id)
        .bind(&entry.encrypted_site_name)
        .bind(&entry.encrypted_username)
        .bind(&entry.encrypted_login_email)
        .bind(&entry.encrypted_password)
        .bind(&entry.encrypted_preferred_login_type)
        .bind(&entry.encrypted_notes)
        .bind(&entry.encrypted_url)
        .bind(&entry.entry_type)
        .bind(&entry.encrypted_extra_fields)
        .bind(caller_email)
        .execute(db)
        .await?;

        Ok(id)
    }

    /// Modifie une entrée — réservé aux membres (N'IMPORTE LEQUEL, pas seulement celui qui l'avait
    /// ajoutée : un coffre partagé est par nature une ressource commune). Détection de conflit
    /// d'édition identique à VaultRepository::update (voir son commentaire pour le raisonnement
    /// complet) — plus susceptible de survenir ici, plusieurs membres différents pouvant modifier
    /// la même entrée à quelques instants d'écart.
    pub async fn update_entry(db: &SqlitePool, shared_vault_id: &str, entry_id: &str, caller_email: &str, entry: &SharedVaultEntryInput) -> Result<(), AppError> {
        let is_member: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM shared_vault_members WHERE shared_vault_id = ? AND member_email = ?",
        )
        .bind(shared_vault_id)
        .bind(caller_email)
        .fetch_optional(db)
        .await?;
        if is_member.is_none() {
            return Err(AppError::NotFound);
        }

        let current_version: Option<i64> = sqlx::query_scalar(
            "SELECT version FROM shared_vault_entries WHERE id = ? AND shared_vault_id = ?",
        )
        .bind(entry_id)
        .bind(shared_vault_id)
        .fetch_optional(db)
        .await?;
        let Some(current_version) = current_version else {
            return Err(AppError::NotFound);
        };

        if let Some(expected) = entry.expected_version {
            if expected != current_version {
                return Err(AppError::Conflict(
                    "Cette entrée a été modifiée par un autre membre entre-temps — rechargez-la avant de réessayer.".to_string(),
                ));
            }
        }

        sqlx::query(
            "UPDATE shared_vault_entries
             SET encrypted_site_name = ?, encrypted_username = ?, encrypted_login_email = ?, encrypted_password = ?, encrypted_preferred_login_type = ?, encrypted_notes = ?, encrypted_url = ?, entry_type = ?, encrypted_extra_fields = ?, updated_at = CURRENT_TIMESTAMP, version = version + 1
             WHERE id = ? AND shared_vault_id = ?",
        )
        .bind(&entry.encrypted_site_name)
        .bind(&entry.encrypted_username)
        .bind(&entry.encrypted_login_email)
        .bind(&entry.encrypted_password)
        .bind(&entry.encrypted_preferred_login_type)
        .bind(&entry.encrypted_notes)
        .bind(&entry.encrypted_url)
        .bind(&entry.entry_type)
        .bind(&entry.encrypted_extra_fields)
        .bind(entry_id)
        .bind(shared_vault_id)
        .execute(db)
        .await?;

        Ok(())
    }

    /// Supprime DÉFINITIVEMENT une entrée — réservé aux membres, pas de corbeille dans cette
    /// première version (voir la migration pour le détail du choix de périmètre).
    pub async fn delete_entry(db: &SqlitePool, shared_vault_id: &str, entry_id: &str, caller_email: &str) -> Result<(), AppError> {
        let is_member: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM shared_vault_members WHERE shared_vault_id = ? AND member_email = ?",
        )
        .bind(shared_vault_id)
        .bind(caller_email)
        .fetch_optional(db)
        .await?;
        if is_member.is_none() {
            return Err(AppError::NotFound);
        }

        let res = sqlx::query("DELETE FROM shared_vault_entries WHERE id = ? AND shared_vault_id = ?")
            .bind(entry_id)
            .bind(shared_vault_id)
            .execute(db)
            .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }
}

// =========================================================================
// PARTAGE À USAGE LIMITÉ ("AVEUGLE") — voir migration 20260831000005_vault_blind_shares.sql et
// models.rs pour le détail du modèle. Même philosophie d'autorisation que SharingRepository/
// SharedVaultRepository : chaque condition d'accès encodée DIRECTEMENT dans le WHERE SQL.
// =========================================================================

/// Même raisonnement que MAX_SHARES_PER_OWNER (protection contre l'épuisement de stockage).
const MAX_BLIND_SHARES_PER_OWNER: i64 = 200;

pub struct BlindShareRepository;

impl BlindShareRepository {
    /// Crée un nouveau partage à usage limité — vérifie D'ABORD que `vault_id` appartient bien à
    /// `owner_email` ET n'est pas dans la corbeille (même garde que SharingRepository::share_entry).
    /// `remaining_uses` initialisé à `max_uses` — TOUJOURS une ligne fraîche (contrairement à
    /// SharingRepository::share_entry, pas d'upsert sur le couple (entrée, destinataire) : chaque
    /// octroi a son propre cycle de vie d'usages, renvoyer le même partage écraserait un compteur
    /// éventuellement déjà entamé).
    pub async fn create(
        db: &SqlitePool,
        vault_id: &str,
        owner_email: &str,
        shared_with_email: &str,
        sealed_site_name: &str,
        sealed_credentials: &str,
        max_uses: i64,
    ) -> Result<String, AppError> {
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM vault WHERE id = ? AND user_email = ? AND deleted_at IS NULL",
        )
        .bind(vault_id)
        .bind(owner_email)
        .fetch_optional(db)
        .await?;
        if exists.is_none() {
            return Err(AppError::NotFound);
        }

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault_blind_shares WHERE owner_email = ?")
            .bind(owner_email)
            .fetch_one(db)
            .await?;
        if count >= MAX_BLIND_SHARES_PER_OWNER {
            return Err(AppError::ValidationError(format!(
                "Limite de {MAX_BLIND_SHARES_PER_OWNER} partages à usage limité atteinte pour ce compte."
            )));
        }

        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO vault_blind_shares (id, vault_id, owner_email, shared_with_email, sealed_site_name, sealed_credentials, max_uses, remaining_uses)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(vault_id)
        .bind(owner_email)
        .bind(shared_with_email)
        .bind(sealed_site_name)
        .bind(sealed_credentials)
        .bind(max_uses)
        .bind(max_uses)
        .execute(db)
        .await?;

        Ok(id)
    }

    /// Les partages à usage limité actifs d'UNE entrée, vus par son PROPRIÉTAIRE — jamais les
    /// blobs scellés (voir VaultBlindShare).
    pub async fn list_for_entry(db: &SqlitePool, vault_id: &str, owner_email: &str) -> Result<Vec<VaultBlindShare>, AppError> {
        sqlx::query_as::<_, VaultBlindShare>(
            "SELECT id, shared_with_email, max_uses, remaining_uses, created_at FROM vault_blind_shares WHERE vault_id = ? AND owner_email = ? ORDER BY created_at DESC",
        )
        .bind(vault_id)
        .bind(owner_email)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Tout ce qui a été partagé EN USAGE LIMITÉ avec l'utilisateur courant — `sealed_site_name`
    /// EST inclus (librement consultable, ne consomme jamais d'usage), jamais `sealed_credentials`.
    pub async fn list_received(db: &SqlitePool, recipient_email: &str) -> Result<Vec<BlindShareReceivedView>, AppError> {
        sqlx::query_as::<_, BlindShareReceivedView>(
            "SELECT id, owner_email, sealed_site_name, max_uses, remaining_uses, created_at FROM vault_blind_shares WHERE shared_with_email = ? ORDER BY created_at DESC",
        )
        .bind(recipient_email)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// LE cœur de la protection : décrémente `remaining_uses` de façon ATOMIQUE (une seule requête
    /// UPDATE avec `remaining_uses > 0` directement dans son WHERE, jamais un SELECT puis un
    /// UPDATE séparés) avant de renvoyer `sealed_credentials` — sans cette atomicité, deux appels
    /// concurrents pourraient tous les deux lire `remaining_uses = 1`, tous les deux le décrémenter
    /// à 0, et tous les deux réussir alors qu'un seul usage était disponible (classique
    /// TOCTOU/race sur un compteur partagé). Vérifie aussi, via une sous-requête, que l'entrée
    /// source n'est pas dans la corbeille — même garde que SharingRepository::get_shared_entry —
    /// UNIQUEMENT ici (pas sur list_received ci-dessus) : un destinataire doit continuer à voir la
    /// LIGNE dans sa liste même si l'entrée source a depuis été supprimée, mais ne doit plus
    /// pouvoir en consommer le contenu.
    pub async fn consume_use(db: &SqlitePool, id: &str, recipient_email: &str) -> Result<BlindShareCredentialsView, AppError> {
        // Le décrément ET la lecture des identifiants scellés qui suit sont dans la MÊME
        // transaction — CORRECTIF (trouvé lors d'une relecture, pas par un test qui échouait) :
        // séparées en deux requêtes indépendantes, un `revoke()` concurrent aurait pu supprimer la
        // ligne ENTRE le décrément (qui aurait réussi, consommant un usage pour rien) et cette
        // lecture (qui aurait alors échoué avec une erreur de base de données générique au lieu
        // d'un 404 propre). Une transaction fait que SQLite sérialise cette écriture face à la
        // suppression concurrente d'un `revoke()` (verrouillage d'écriture, voir le mode WAL déjà
        // en place) plutôt que de simplement rendre l'incohérence moins probable.
        let mut tx = db.begin().await?;

        let res = sqlx::query(
            "UPDATE vault_blind_shares SET remaining_uses = remaining_uses - 1
             WHERE id = ? AND shared_with_email = ? AND remaining_uses > 0
             AND vault_id IN (SELECT id FROM vault WHERE deleted_at IS NULL)",
        )
        .bind(id)
        .bind(recipient_email)
        .execute(&mut *tx)
        .await?;

        if res.rows_affected() == 0 {
            // Distingue "n'existe pas / pas le destinataire / entrée source supprimée" (404,
            // MÊME traitement que SharingRepository::get_shared_entry pour ce dernier cas — voir
            // son propre commentaire) de "existe, entrée source toujours active, mais plus aucun
            // usage disponible" (message dédié) — un destinataire qui a déjà tout consommé doit
            // comprendre POURQUOI, pas recevoir une erreur générique. CORRECTIF : la première
            // version de cette requête de diagnostic ne réappliquait PAS la garde de corbeille,
            // donc une entrée source supprimée était à tort signalée comme "plus d'usage
            // disponible" plutôt que "introuvable" — repéré par
            // test_trashing_source_entry_blocks_use_but_keeps_listing.
            let still_usable_in_principle: Option<i64> = sqlx::query_scalar(
                "SELECT 1 FROM vault_blind_shares
                 WHERE id = ? AND shared_with_email = ?
                 AND vault_id IN (SELECT id FROM vault WHERE deleted_at IS NULL)",
            )
            .bind(id)
            .bind(recipient_email)
            .fetch_optional(&mut *tx)
            .await?;
            if still_usable_in_principle.is_some() {
                return Err(AppError::ValidationError("Plus aucun usage disponible pour ce partage.".to_string()));
            }
            return Err(AppError::NotFound);
        }

        let view = sqlx::query_as::<_, BlindShareCredentialsView>(
            "SELECT sealed_credentials, remaining_uses FROM vault_blind_shares WHERE id = ?",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(view)
    }

    /// Révoque un partage à usage limité — l'un OU l'autre côté peut y mettre fin (même principe
    /// que SharingRepository::revoke_share).
    pub async fn revoke(db: &SqlitePool, id: &str, caller_email: &str) -> Result<(), AppError> {
        let res = sqlx::query("DELETE FROM vault_blind_shares WHERE id = ? AND (owner_email = ? OR shared_with_email = ?)")
            .bind(id)
            .bind(caller_email)
            .bind(caller_email)
            .execute(db)
            .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }
}

// =========================================================================
// SIGNALEMENT DE BUG — voir migration 20260901000000_bug_reports.sql et models.rs pour le détail
// du modèle. `create()` est appelée depuis une route PUBLIQUE (voir handlers/bug_report.rs) : pas
// de `caller_email` à vérifier ici, contrairement à toutes les autres tables de ce fichier.
// =========================================================================

/// Plafond GLOBAL (pas par utilisateur, puisque la route est publique/anonyme) — une route
/// publique sans ce garde-fou pourrait voir sa table croître sans limite même avec le rate
/// limiting par IP déjà en place (voir main.rs), qui ralentit un abus mais ne l'empêche pas
/// totalement dans le temps. `pub(crate)` (pas juste privé) : réutilisée telle quelle par le test
/// de régression sur ce plafond dans handlers/bug_report.rs, pour ne jamais avoir à synchroniser
/// deux valeurs à la main si elle change un jour.
pub(crate) const MAX_BUG_REPORTS_TOTAL: i64 = 500;

pub struct BugReportRepository;

impl BugReportRepository {
    pub async fn create(db: &SqlitePool, payload: &CreateBugReportPayload) -> Result<String, AppError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM bug_reports")
            .fetch_one(db)
            .await?;
        if count >= MAX_BUG_REPORTS_TOTAL {
            return Err(AppError::ValidationError(
                "Trop de signalements en attente de traitement — réessaie plus tard.".to_string(),
            ));
        }

        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO bug_reports (id, reporter_email, description, app_version, platform) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&payload.reporter_email)
        .bind(&payload.description)
        .bind(&payload.app_version)
        .bind(&payload.platform)
        .execute(db)
        .await?;

        Ok(id)
    }

    /// Réservé au modérateur (vérifié dans le handler, comme le reste du panneau Administration).
    pub async fn list_all(db: &SqlitePool) -> Result<Vec<BugReportView>, AppError> {
        sqlx::query_as::<_, BugReportView>(
            "SELECT id, reporter_email, description, app_version, platform, created_at FROM bug_reports ORDER BY created_at DESC",
        )
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Supprime un signalement une fois traité — pas de statut "résolu" séparé dans cette première
    /// version, la suppression EST la façon de marquer "traité" (garde le panneau simple à trier).
    pub async fn delete(db: &SqlitePool, id: &str) -> Result<(), AppError> {
        let res = sqlx::query("DELETE FROM bug_reports WHERE id = ?")
            .bind(id)
            .execute(db)
            .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }
}