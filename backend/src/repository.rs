use sqlx::SqlitePool;
use crate::{models::{VaultEntry, VaultEntryInput, TrashedVaultEntry, PasswordHistoryEntry, ReencryptedHistoryEntry, VaultAttachment, VaultAttachmentInput, VaultAttachmentMeta, UserKeysInput, UserPublicKey, EmergencyContact, VaultShare, SharedWithMeEntry, SharedEntryView, SharedVaultView, SharedVaultMemberView, SharedVaultEntry, SharedVaultEntryInput, VaultBlindShare, BlindShareReceivedView, BlindShareCredentialsView, CreateBugReportPayload, BugReportView, CreateFeatureSuggestionPayload, FeatureSuggestionView,
ThemeProfilePayload, ThemeProfileView, SharedThemeProfileView}, error::AppError};

/// Historique des mots de passe : garde au plus ce nombre de versions PAR ENTRÉE — au-delà, les
/// plus anciennes sont purgées automatiquement (voir VaultRepository::archive_password_history).
/// Pas pensé pour une conservation illimitée, juste pour retrouver un mot de passe changé
/// récemment par erreur.
const MAX_HISTORY_PER_ENTRY: i64 = 20;

// =========================================================================
// RÉSOLUTION EMAIL -> ID — utilisé partout où le CLIENT désigne un tiers par email (inviter un
// contact d'urgence, partager une entrée, inviter un membre de coffre partagé...) : ce tiers n'a
// pas encore de `user_id` connu de l'appelant au moment de l'appel, contrairement à l'appelant
// lui-même (déjà résolu par le middleware, voir AuthUser::user_id). Centralisé ici plutôt que
// dupliqué dans chaque handler.
// =========================================================================
pub struct UserRepository;

impl UserRepository {
    /// `None` si aucun compte n'existe pour cet email — le handler appelant doit alors renvoyer
    /// une erreur explicite ("aucun compte avec cet email") plutôt que de laisser une contrainte
    /// FK échouer plus loin avec un message SQL brut.
    pub async fn find_id_by_email(db: &SqlitePool, email: &str) -> Result<Option<i64>, AppError> {
        sqlx::query_scalar("SELECT id FROM users WHERE email = ?")
            .bind(email)
            .fetch_optional(db)
            .await
            .map_err(AppError::from)
    }
}

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
    pub async fn get_all(db: &SqlitePool, user_id: i64, email: &str, limit: i64, offset: i64) -> Result<Vec<VaultEntry>, AppError> {
        // `query_as` mappe automatiquement les colonnes SQL vers les champs de la structure `VaultEntry`
        // "deleted_at IS NULL" : exclut les entrées passées à la corbeille (suppression douce).
        // Tri par is_favorite uniquement (seule métadonnée en clair pertinente) : les favoris
        // remontent en premier, le reste garde l'ordre d'insertion.
        // has_attachments : sous-requête EXISTS corrélée (une par ligne) plutôt qu'un JOIN — évite
        // toute duplication de ligne si une entrée a plusieurs pièces jointes (un JOIN classique
        // produirait alors une ligne PAR pièce jointe). Coût négligeable : indexée sur vault_id
        // (voir idx_vault_attachments_vault_id), et le nombre de pièces jointes par utilisateur
        // est plafonné (MAX_ATTACHMENTS_PER_USER, voir handlers/vault.rs).
        // `? AS user_email` : la colonne interne est désormais `vault.user_id`, mais VaultEntry
        // garde son champ `user_email` (réponse JSON inchangée) — inutile de JOINDRE `users` pour
        // ça sur la route la plus appelée de l'API, puisque cette valeur est TOUJOURS celle de
        // l'appelant lui-même (son propre coffre) : on la réinjecte directement comme colonne
        // littérale, aussi bon marché qu'une constante répétée sur chaque ligne.
        sqlx::query_as::<_, VaultEntry>(
        "SELECT id, encrypted_site_name, encrypted_username, encrypted_login_email, encrypted_password, encrypted_preferred_login_type, ? AS user_email, is_favorite, encrypted_folder, encrypted_notes, encrypted_url, entry_type, encrypted_extra_fields, updated_at, version, use_count,
                EXISTS(SELECT 1 FROM vault_attachments va WHERE va.vault_id = vault.id) AS has_attachments
         FROM vault
         WHERE user_id = ? AND deleted_at IS NULL
         ORDER BY is_favorite DESC LIMIT ? OFFSET ?"
        )
        .bind(email)
        .bind(user_id) // Filtre par l'utilisateur connecté
        .bind(limit)                   // Nombre maximum de résultats (Pagination)
        .bind(offset)                  // Nombre d'éléments à sauter (Pagination)
        // Exécute la requête, récupère toutes les lignes, et convertit l'erreur SQLx en erreur d'application via From/Into
        .fetch_all(db).await.map_err(AppError::from)
    }

    /// Récupère les entrées de la CORBEILLE (supprimées en douceur, pas encore purgées)
    /// pour un utilisateur spécifique, triées de la plus récemment supprimée à la plus ancienne.
    pub async fn get_trash(db: &SqlitePool, user_id: i64) -> Result<Vec<TrashedVaultEntry>, AppError> {
        sqlx::query_as::<_, TrashedVaultEntry>(
        "SELECT id, encrypted_site_name, encrypted_username, encrypted_login_email, encrypted_preferred_login_type, is_favorite, deleted_at, encrypted_folder
         FROM vault
         WHERE user_id = ? AND deleted_at IS NOT NULL
         ORDER BY deleted_at DESC"
        )
        .bind(user_id)
        .fetch_all(db).await.map_err(AppError::from)
    }

    // =========================================================================
    // 3. AJOUT D'UNE ENTRÉE (CREATE)
    // =========================================================================

    /// Insère un nouvel identifiant / mot de passe chiffré dans le coffre-fort.
    pub async fn add(db: &SqlitePool, user_id: i64, entry: VaultEntryInput) -> Result<(), AppError> {
        // Génère un identifiant unique universel (UUID v4) sous forme de chaîne de caractères
        let id = uuid::Uuid::new_v4().to_string();

        // Requête d'insertion standard
        sqlx::query("INSERT INTO vault (id, encrypted_site_name, encrypted_username, encrypted_login_email, encrypted_password, encrypted_preferred_login_type, user_id, is_favorite, encrypted_folder, encrypted_notes, encrypted_url, entry_type, encrypted_extra_fields) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(id)
            .bind(&entry.encrypted_site_name)
            .bind(&entry.encrypted_username)
            .bind(&entry.encrypted_login_email)
            .bind(&entry.encrypted_password) // Le mot de passe arrive déjà chiffré par le client (Zero-Knowledge)
            .bind(&entry.encrypted_preferred_login_type)
            .bind(user_id) // Sécurité : On force l'id de l'utilisateur connecté (résolu depuis le JWT)
            .bind(entry.is_favorite)
            .bind(&entry.encrypted_folder)
            .bind(&entry.encrypted_notes)
            .bind(&entry.encrypted_url)
            .bind(&entry.entry_type)
            .bind(&entry.encrypted_extra_fields)
            .execute(db).await.map_err(AppError::from)?; // Exécute et propage l'erreur si échec

        Ok(())
    }

    /// Variante GROUPÉE de add() pour DANS une transaction déjà ouverte (voir
    /// handlers/vault.rs::import_vault()) : permet d'importer plusieurs entrées de façon atomique
    /// — soit toutes sont insérées, soit aucune ne l'est (même principe que reencrypt() plus bas
    /// pour update_password()).
    ///
    /// CORRECTIF PERF (retour utilisateur, 2026-09-02) : import_vault() appelait auparavant une
    /// fonction de ce genre une fois PAR ENTRÉE, dans une boucle (un INSERT séparé par entrée
    /// importée). Sans coût réseau (SQLite est embarqué), mais un import de plusieurs
    /// centaines/milliers d'entrées représentait autant de requêtes internes séparées. Ici, un
    /// seul INSERT multi-lignes par lot via QueryBuilder.
    ///
    /// Découpé par lots de CHUNK_SIZE plutôt qu'un unique INSERT pour TOUTES les entrées d'un coup :
    /// SQLite plafonne le nombre de paramètres liés PAR REQUÊTE (SQLITE_MAX_VARIABLE_NUMBER,
    /// 32766 par défaut depuis SQLite 3.32, mais aussi bas que 999 sur d'anciennes builds) — avec
    /// 13 colonnes par entrée, MAX_VAULT_ENTRIES_PER_USER (5000) en un seul lot dépasserait 65 000
    /// paramètres, au-delà de la limite même moderne. 300 entrées/lot x 13 = 3 900 paramètres,
    /// confortablement sous la limite la plus basse connue.
    pub async fn add_many_in_tx(tx: &mut sqlx::SqliteConnection, user_id: i64, entries: &[VaultEntryInput]) -> Result<(), AppError> {
        const CHUNK_SIZE: usize = 300;
        for chunk in entries.chunks(CHUNK_SIZE) {
            let mut builder = sqlx::QueryBuilder::new(
                "INSERT INTO vault (id, encrypted_site_name, encrypted_username, encrypted_login_email, encrypted_password, encrypted_preferred_login_type, user_id, is_favorite, encrypted_folder, encrypted_notes, encrypted_url, entry_type, encrypted_extra_fields) "
            );
            builder.push_values(chunk, |mut b, entry| {
                let id = uuid::Uuid::new_v4().to_string();
                b.push_bind(id)
                    .push_bind(&entry.encrypted_site_name)
                    .push_bind(&entry.encrypted_username)
                    .push_bind(&entry.encrypted_login_email)
                    .push_bind(&entry.encrypted_password)
                    .push_bind(&entry.encrypted_preferred_login_type)
                    .push_bind(user_id)
                    .push_bind(entry.is_favorite)
                    .push_bind(&entry.encrypted_folder)
                    .push_bind(&entry.encrypted_notes)
                    .push_bind(&entry.encrypted_url)
                    .push_bind(&entry.entry_type)
                    .push_bind(&entry.encrypted_extra_fields);
            });
            builder.build().execute(&mut *tx).await.map_err(AppError::from)?;
        }
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
    pub async fn update(db: &SqlitePool, user_id: i64, id: &str, entry: VaultEntryInput) -> Result<(), AppError> {
        let mut tx = db.begin().await?;

        // Lu UNE SEULE FOIS, avant toute décision : sert à la fois à vérifier l'existence/
        // propriété (comme avant), à détecter un conflit de version, ET (si password_changed) à
        // récupérer la valeur à archiver dans l'historique — plutôt que trois requêtes séparées.
        let current: Option<(String, i64)> = sqlx::query_as(
            "SELECT encrypted_password, version FROM vault WHERE id = ? AND user_id = ? AND deleted_at IS NULL",
        )
        .bind(id)
        .bind(user_id)
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
            Self::archive_password_history(&mut tx, user_id, id, &old_encrypted_password).await?;
        }

        let res = sqlx::query(
        "UPDATE vault
         SET encrypted_site_name = ?, encrypted_username = ?, encrypted_login_email = ?, encrypted_password = ?, encrypted_preferred_login_type = ?, is_favorite = ?, encrypted_folder = ?, encrypted_notes = ?, encrypted_url = ?, entry_type = ?, encrypted_extra_fields = ?, updated_at = CURRENT_TIMESTAMP, version = version + 1
         WHERE id = ? AND user_id = ? AND deleted_at IS NULL"
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
        .bind(id)      // L'ID de l'élément à modifier
        .bind(user_id) // Sécurité cruciale : empêche de modifier l'élément d'un AUTRE utilisateur
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
        user_id: i64,
        vault_id: &str,
        old_encrypted_password: &str,
    ) -> Result<(), AppError> {
        let history_id = uuid::Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO vault_password_history (id, vault_id, user_id, encrypted_password) VALUES (?, ?, ?, ?)")
            .bind(&history_id)
            .bind(vault_id)
            .bind(user_id)
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
    /// `user_id` (présent sur chaque ligne d'historique dès l'archivage, voir
    /// archive_password_history) suffit à empêcher un utilisateur d'accéder à l'historique d'un
    /// autre — pas besoin d'une jointure supplémentaire vers `vault` pour vérifier la propriété.
    pub async fn get_history(db: &SqlitePool, user_id: i64, vault_id: &str, limit: i64) -> Result<Vec<PasswordHistoryEntry>, AppError> {
        sqlx::query_as::<_, PasswordHistoryEntry>(
            "SELECT id, vault_id, encrypted_password, changed_at
             FROM vault_password_history
             WHERE vault_id = ? AND user_id = ?
             ORDER BY changed_at DESC, rowid DESC LIMIT ?",
        )
        .bind(vault_id)
        .bind(user_id)
        .bind(limit)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// TOUT l'historique d'un utilisateur, tous dossiers/entrées confondus — utilisé UNIQUEMENT
    /// lors d'un changement de mot de passe MAÎTRE (voir ChangeMasterPasswordPayload), où chaque
    /// ligne doit être re-chiffrée avec la nouvelle clé, sans exception.
    pub async fn get_all_history_for_user(db: &SqlitePool, user_id: i64) -> Result<Vec<PasswordHistoryEntry>, AppError> {
        sqlx::query_as::<_, PasswordHistoryEntry>(
            "SELECT id, vault_id, encrypted_password, changed_at FROM vault_password_history WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Toutes les pièces jointes d'un utilisateur, CONTENU CHIFFRÉ COMPRIS.
    ///
    /// Réservée à la RÉCUPÉRATION (voir handlers/auth/account.rs::get_recovery_data) : c'est le
    /// seul flux où le client doit tout re-chiffrer SANS pouvoir passer par les routes d'export
    /// habituelles, lesquelles exigent le hash du mot de passe maître — précisément ce que
    /// l'utilisateur a oublié. Ailleurs, les pièces jointes se récupèrent une par une (voir
    /// list_attachments/get_attachment), pour ne pas charger des dizaines de mégaoctets sans raison.
    pub async fn get_all_attachments_for_user(db: &SqlitePool, user_id: i64) -> Result<Vec<VaultAttachment>, AppError> {
        sqlx::query_as::<_, VaultAttachment>(
            "SELECT id, vault_id, encrypted_filename, encrypted_content, content_size, created_at
             FROM vault_attachments WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    // NOTE : `count_history_for_user()` a été supprimée ici. Elle ne servait qu'au garde-fou du
    // changement de mot de passe, qui ne compte plus les lignes mais compare l'ENSEMBLE des
    // identifiants re-chiffrés à ceux réellement en base, et le fait DANS la transaction — voir
    // handlers/auth/account.rs::update_password et check_reencrypted_ids().

    /// Remplace, PAR LOTS, le mot de passe chiffré de plusieurs lignes d'historique par leur
    /// version re-chiffrée — pendant de reencrypt_many() ci-dessous, mais pour
    /// vault_password_history plutôt que vault.
    ///
    /// CORRECTIF PERF (audit cohérence/perf, 2026-09-16) : un changement de mot de passe MAÎTRE
    /// appelait auparavant cette fonction une fois PAR LIGNE d'historique, dans une boucle (voir
    /// handlers/auth/account.rs::update_password/complete_recovery) — jusqu'à
    /// MAX_HISTORY_PER_ENTRY (20) fois par entrée du coffre, potentiellement des milliers
    /// d'allers-retours SQL séquentiels pour un compte proche de MAX_VAULT_ENTRIES_PER_USER.
    /// Même principe de batching que add_many_in_tx : `UPDATE ... FROM (VALUES ...)` (SQLite
    /// ≥ 3.33) associe à chaque ligne sa PROPRE valeur, contrairement à un UPDATE classique qui ne
    /// peut écrire qu'une seule valeur partagée pour toutes les lignes filtrées par son WHERE.
    ///
    /// `user_id = ?` reste dans le WHERE (comme sur chaque ligne de l'ancienne boucle) : un id
    /// d'entrée ne suffit jamais à autoriser la modification, même reçu à l'intérieur d'un lot
    /// groupé — un id appartenant à un AUTRE utilisateur ne matche simplement aucune ligne.
    ///
    /// Le nombre total de lignes effectivement modifiées est comparé à `entries.len()` À LA FIN
    /// (et non ligne par ligne comme avant) : un seul id inconnu quelque part dans le lot fait
    /// échouer l'ensemble, exactement comme l'ancienne boucle (qui remontait NotFound dès la
    /// première ligne sans correspondance et annulait toute la transaction).
    pub async fn reencrypt_history_many(
        tx: &mut sqlx::SqliteConnection,
        user_id: i64,
        entries: &[ReencryptedHistoryEntry],
    ) -> Result<(), AppError> {
        if entries.is_empty() {
            return Ok(());
        }

        // Même taille de lot que add_many_in_tx : reste confortablement sous
        // SQLITE_LIMIT_COMPOUND_SELECT (500 par défaut — un VALUES multi-lignes compile en
        // interne comme un SELECT composé, une ligne par terme) autant que sous la limite de
        // paramètres liés.
        const CHUNK_SIZE: usize = 300;
        let mut total_affected: u64 = 0;

        for chunk in entries.chunks(CHUNK_SIZE) {
            // SQLite ne supporte PAS l'aliasing de colonnes façon `(VALUES ...) AS v(id, password)`
            // (testé : "near '(': syntax error") — on nomme les colonnes anonymes column1/column2
            // via un SELECT intermédiaire avant de les aliaser en `v` pour le WHERE.
            let mut builder = sqlx::QueryBuilder::new(
                "UPDATE vault_password_history SET encrypted_password = v.password \
                 FROM (SELECT column1 AS id, column2 AS password FROM ("
            );
            builder.push_values(chunk, |mut b, entry| {
                b.push_bind(&entry.id).push_bind(&entry.encrypted_password);
            });
            builder.push(")) AS v WHERE vault_password_history.id = v.id AND vault_password_history.user_id = ");
            builder.push_bind(user_id);

            let res = builder.build().execute(&mut *tx).await.map_err(AppError::from)?;
            total_affected += res.rows_affected();
        }

        if total_affected as usize != entries.len() {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Remplace, PAR LOTS, les champs chiffrés de plusieurs entrées EXISTANTES par leur version
    /// RE-CHIFFRÉE avec la nouvelle clé (après un changement de mot de passe maître). Ne touche
    /// PAS `is_favorite` (métadonnée en clair, non affectée par un changement de clé de
    /// chiffrement). Volontairement séparée de update() : sémantique différente (re-chiffrement
    /// forcé, appelée uniquement dans la transaction de changement de mot de passe, jamais par
    /// l'utilisateur pour une modification normale de contenu).
    ///
    /// Voir reencrypt_history_many() ci-dessus pour le détail du correctif de performance
    /// (batching via `UPDATE ... FROM (VALUES ...)`) et des garanties de sécurité conservées
    /// (scoping par user_id, échec global si un id est inconnu).
    pub async fn reencrypt_many(
        tx: &mut sqlx::SqliteConnection,
        user_id: i64,
        entries: &[crate::models::ReencryptedVaultEntry],
    ) -> Result<(), AppError> {
        if entries.is_empty() {
            return Ok(());
        }

        const CHUNK_SIZE: usize = 300;
        let mut total_affected: u64 = 0;

        for chunk in entries.chunks(CHUNK_SIZE) {
            let mut builder = sqlx::QueryBuilder::new(
                "UPDATE vault SET
                    encrypted_site_name = v.site_name,
                    encrypted_username = v.username,
                    encrypted_login_email = v.login_email,
                    encrypted_password = v.password,
                    encrypted_preferred_login_type = v.preferred_login_type,
                    encrypted_folder = v.folder,
                    encrypted_notes = v.notes,
                    encrypted_url = v.url,
                    encrypted_extra_fields = v.extra_fields
                 FROM (SELECT column1 AS id, column2 AS site_name, column3 AS username, column4 AS login_email,
                              column5 AS password, column6 AS preferred_login_type, column7 AS folder,
                              column8 AS notes, column9 AS url, column10 AS extra_fields
                       FROM ("
            );
            builder.push_values(chunk, |mut b, entry| {
                b.push_bind(&entry.id)
                    .push_bind(&entry.encrypted_site_name)
                    .push_bind(&entry.encrypted_username)
                    .push_bind(&entry.encrypted_login_email)
                    .push_bind(&entry.encrypted_password)
                    .push_bind(&entry.encrypted_preferred_login_type)
                    .push_bind(&entry.encrypted_folder)
                    .push_bind(&entry.encrypted_notes)
                    .push_bind(&entry.encrypted_url)
                    .push_bind(&entry.encrypted_extra_fields);
            });
            // SQLite ne supporte pas `(VALUES ...) AS v(col1, col2, ...)` (testé : "near '(':
            // syntax error") — les colonnes anonymes column1..column10 sont nommées par le SELECT
            // ci-dessus avant d'être aliasées en `v` ici.
            builder.push(
                ")) AS v \
                 WHERE vault.id = v.id AND vault.user_id = "
            );
            builder.push_bind(user_id);
            // Préservée à l'identique de l'ancienne version ligne-par-ligne : une entrée passée à
            // la corbeille n'est pas re-chiffrée par ce chemin (voir active_ids dans
            // handlers/auth/account.rs, qui n'exige de re-chiffrement que pour les entrées ACTIVES).
            builder.push(" AND vault.deleted_at IS NULL");

            let res = builder.build().execute(&mut *tx).await.map_err(AppError::from)?;
            total_affected += res.rows_affected();
        }

        if total_affected as usize != entries.len() {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Compte le nombre d'entrées ACTIVES d'un utilisateur — sert à faire respecter
    /// MAX_VAULT_ENTRIES_PER_USER (voir handlers/vault.rs::add_to_vault/import_vault). Liée à une
    /// transaction déjà ouverte plutôt qu'au pool directement : le compte ET l'écriture qui en
    /// dépend doivent se dérouler dans LA MÊME transaction, sinon deux requêtes concurrentes juste
    /// sous le plafond peuvent toutes les deux lire un compte encore valide puis toutes les deux
    /// écrire, dépassant silencieusement le plafond (SQLite sérialise les écritures d'une même
    /// transaction contre les autres transactions d'écriture, un simple SELECT hors transaction ne
    /// bénéficie d'aucune de ces garanties).
    pub async fn count_active_in_tx(tx: &mut sqlx::SqliteConnection, user_id: i64) -> Result<i64, AppError> {
        sqlx::query_scalar("SELECT COUNT(*) FROM vault WHERE user_id = ? AND deleted_at IS NULL")
            .bind(user_id)
            .fetch_one(tx)
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
    pub async fn delete(db: &sqlx::SqlitePool, user_id: i64, id: &str) -> Result<(), AppError> {
        // "deleted_at IS NULL" dans le WHERE : on ne "supprime" pas une entrée déjà supprimée
        // (renvoie NotFound plutôt que de rafraîchir silencieusement sa date de suppression).
        let res = sqlx::query("UPDATE vault SET deleted_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ? AND deleted_at IS NULL")
            .bind(id)
            .bind(user_id)
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
    pub async fn restore(db: &sqlx::SqlitePool, user_id: i64, id: &str) -> Result<(), AppError> {
        // "deleted_at IS NOT NULL" : on ne peut restaurer qu'une entrée effectivement en corbeille.
        let res = sqlx::query("UPDATE vault SET deleted_at = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL")
            .bind(id)
            .bind(user_id)
            .execute(db)
            .await?;

        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Supprime DÉFINITIVEMENT une entrée déjà présente dans la corbeille (vidage manuel).
    /// Contrairement à delete(), il n'y a ici aucun retour en arrière possible.
    pub async fn purge(db: &sqlx::SqlitePool, user_id: i64, id: &str) -> Result<(), AppError> {
        // "deleted_at IS NOT NULL" : sécurité supplémentaire — on ne purge que ce qui est déjà
        // dans la corbeille, jamais une entrée active par erreur d'appel.
        let res = sqlx::query("DELETE FROM vault WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL")
            .bind(id)
            .bind(user_id)
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
    pub async fn toggle_favorite(db: &SqlitePool, user_id: i64, id: &str) -> Result<(), AppError> {
        // Utilisation de l'opérateur SQL 'NOT' pour inverser directement le booléen en base de données
        let res = sqlx::query("UPDATE vault SET is_favorite = NOT is_favorite, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ? AND deleted_at IS NULL")
            .bind(id).bind(user_id).execute(db).await?;
            
        // Même sécurité : si 0 ligne modifiée, on lève une erreur 404.
        if res.rows_affected() == 0 {
             return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Incrémente le compteur d'utilisation d'une entrée (copie du mot de passe OU remplissage
    /// automatique, voir handlers/vault.rs::record_vault_entry_use) — retour utilisateur
    /// (2026-09-02), pour un tri "le plus utilisé" côté client. Ne touche NI updated_at NI
    /// version, contrairement à toggle_favorite() ci-dessus : un simple compteur d'usage n'est pas
    /// une modification de CONTENU, ne doit donc jamais déclencher un conflit d'édition
    /// (expected_version) ni faire paraître l'entrée "récemment modifiée" à tort.
    pub async fn record_use(db: &SqlitePool, user_id: i64, id: &str) -> Result<(), AppError> {
        let res = sqlx::query("UPDATE vault SET use_count = use_count + 1 WHERE id = ? AND user_id = ? AND deleted_at IS NULL")
            .bind(id).bind(user_id).execute(db).await?;

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
    /// filtré par `user_id` en plus de `vault_id`, comme absolument toutes les autres requêtes
    /// de ce fichier — sans ce filtre, ce comptage s'exécutait sur N'IMPORTE QUEL vault_id, y
    /// compris celui d'un AUTRE utilisateur (ex: obtenu via un partage, voir SharedWithMeEntry
    /// dans models.rs, qui expose légitimement le vault_id du propriétaire) : le message d'erreur
    /// "quota atteint" renvoyé AVANT toute vérification de propriété (voir add_attachment()
    /// ci-dessous, appelée après) formait un oracle révélant si l'entrée d'autrui avait déjà
    /// atteint son quota de pièces jointes — une information que l'appelant n'a aucun droit de
    /// connaître.
    /// Liée à une transaction déjà ouverte plutôt qu'au pool directement — voir count_active_in_tx
    /// plus haut pour le raisonnement : ce COUNT() de quota ET l'insertion qui en dépend
    /// (add_attachment_in_tx ci-dessous) doivent se dérouler dans LA MÊME transaction (voir
    /// add_vault_attachment dans handlers/vault.rs), sinon plusieurs ajouts concurrents juste sous
    /// le plafond peuvent tous lire un compte encore valide avant qu'aucun n'ait écrit.
    pub async fn count_attachments_for_entry_in_tx(tx: &mut sqlx::SqliteConnection, user_id: i64, vault_id: &str) -> Result<i64, AppError> {
        sqlx::query_scalar("SELECT COUNT(*) FROM vault_attachments WHERE vault_id = ? AND user_id = ?")
            .bind(vault_id)
            .bind(user_id)
            .fetch_one(tx)
            .await
            .map_err(AppError::from)
    }

    /// Compte TOUTES les pièces jointes d'un utilisateur, tous dossiers/entrées confondus — sert
    /// à faire respecter MAX_ATTACHMENTS_PER_USER (quota global, indépendant de l'entrée visée).
    pub async fn count_attachments_for_user_in_tx(tx: &mut sqlx::SqliteConnection, user_id: i64) -> Result<i64, AppError> {
        sqlx::query_scalar("SELECT COUNT(*) FROM vault_attachments WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(tx)
            .await
            .map_err(AppError::from)
    }

    /// Ajoute une pièce jointe à UNE entrée active du coffre. Vérifie D'ABORD que l'entrée existe,
    /// appartient à l'utilisateur ET n'est pas dans la corbeille — sinon `AppError::NotFound`
    /// plutôt qu'un rattachement silencieux à une entrée qui ne devrait plus être modifiable.
    pub async fn add_attachment_in_tx(tx: &mut sqlx::SqliteConnection, user_id: i64, vault_id: &str, input: &VaultAttachmentInput) -> Result<String, AppError> {
        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM vault WHERE id = ? AND user_id = ? AND deleted_at IS NULL",
        )
        .bind(vault_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        if exists.is_none() {
            return Err(AppError::NotFound);
        }

        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO vault_attachments (id, vault_id, user_id, encrypted_filename, encrypted_content, content_size) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(vault_id)
        .bind(user_id)
        .bind(&input.encrypted_filename)
        .bind(&input.encrypted_content)
        .bind(input.content_size)
        .execute(&mut *tx)
        .await?;

        Ok(id)
    }

    /// Liste les pièces jointes d'UNE entrée, SANS leur contenu (voir VaultAttachmentMeta) — la
    /// plus récente en premier.
    pub async fn list_attachments(db: &SqlitePool, user_id: i64, vault_id: &str) -> Result<Vec<VaultAttachmentMeta>, AppError> {
        sqlx::query_as::<_, VaultAttachmentMeta>(
            "SELECT id, encrypted_filename, content_size, created_at
             FROM vault_attachments
             WHERE vault_id = ? AND user_id = ?
             ORDER BY created_at DESC",
        )
        .bind(vault_id)
        .bind(user_id)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Récupère UNE pièce jointe complète (avec son contenu chiffré) — pour le téléchargement.
    /// `vault_id` ET `user_id` filtrés tous les deux : empêche de récupérer une pièce jointe
    /// via l'id d'une AUTRE entrée que celle indiquée dans l'URL, en plus de la protection
    /// habituelle par propriétaire.
    pub async fn get_attachment(db: &SqlitePool, user_id: i64, vault_id: &str, attachment_id: &str) -> Result<VaultAttachment, AppError> {
        sqlx::query_as::<_, VaultAttachment>(
            "SELECT id, vault_id, encrypted_filename, encrypted_content, content_size, created_at
             FROM vault_attachments
             WHERE id = ? AND vault_id = ? AND user_id = ?",
        )
        .bind(attachment_id)
        .bind(vault_id)
        .bind(user_id)
        .fetch_optional(db)
        .await?
        .ok_or(AppError::NotFound)
    }

    /// Supprime définitivement UNE pièce jointe — pas de corbeille pour les pièces jointes
    /// (contrairement aux entrées elles-mêmes) : un fichier joint supprimé l'est pour de bon.
    pub async fn delete_attachment(db: &SqlitePool, user_id: i64, vault_id: &str, attachment_id: &str) -> Result<(), AppError> {
        let res = sqlx::query("DELETE FROM vault_attachments WHERE id = ? AND vault_id = ? AND user_id = ?")
            .bind(attachment_id)
            .bind(vault_id)
            .bind(user_id)
            .execute(db)
            .await?;

        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Remplace, PAR LOTS, les deux champs chiffrés (nom ET contenu) de plusieurs pièces jointes
    /// EXISTANTES par leur version RE-CHIFFRÉE avec la nouvelle clé — pendant de
    /// reencrypt_many()/reencrypt_history_many() ci-dessus, mais pour vault_attachments, appelée
    /// uniquement dans la transaction de changement de mot de passe maître (voir
    /// handlers/auth/account.rs::update_password/complete_recovery). Voir reencrypt_history_many()
    /// pour le détail du correctif de performance et des garanties de sécurité conservées.
    ///
    /// Lot volontairement identique (300) plutôt qu'agrandi : `encrypted_content` peut être
    /// volumineuse (fichier joint re-chiffré en entier, jusqu'à ~10 Mo par pièce selon
    /// ReencryptedVaultAttachment::encrypted_content) — un lot plus grand construirait une requête
    /// d'autant plus lourde à assembler en mémoire côté serveur, sans gain supplémentaire une fois
    /// déjà loin de la latence réseau (SQLite est embarqué).
    pub async fn reencrypt_attachment_many(
        tx: &mut sqlx::SqliteConnection,
        user_id: i64,
        attachments: &[crate::models::ReencryptedVaultAttachment],
    ) -> Result<(), AppError> {
        if attachments.is_empty() {
            return Ok(());
        }

        const CHUNK_SIZE: usize = 300;
        let mut total_affected: u64 = 0;

        for chunk in attachments.chunks(CHUNK_SIZE) {
            // SQLite ne supporte pas `(VALUES ...) AS v(id, filename, content)` (testé : "near
            // '(': syntax error") — mêmes SELECT/colonnes anonymes intermédiaires que
            // reencrypt_many()/reencrypt_history_many() ci-dessus.
            let mut builder = sqlx::QueryBuilder::new(
                "UPDATE vault_attachments SET encrypted_filename = v.filename, encrypted_content = v.content \
                 FROM (SELECT column1 AS id, column2 AS filename, column3 AS content FROM ("
            );
            builder.push_values(chunk, |mut b, attachment| {
                b.push_bind(&attachment.id)
                    .push_bind(&attachment.encrypted_filename)
                    .push_bind(&attachment.encrypted_content);
            });
            builder.push(")) AS v WHERE vault_attachments.id = v.id AND vault_attachments.user_id = ");
            builder.push_bind(user_id);

            let res = builder.build().execute(&mut *tx).await.map_err(AppError::from)?;
            total_affected += res.rows_affected();
        }

        if total_affected as usize != attachments.len() {
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
    pub async fn upsert_user_keys(db: &SqlitePool, user_id: i64, input: &UserKeysInput) -> Result<(), AppError> {
        sqlx::query(
            "INSERT INTO user_keys (user_id, public_key, encrypted_private_key) VALUES (?, ?, ?)
             ON CONFLICT(user_id) DO UPDATE SET public_key = excluded.public_key, encrypted_private_key = excluded.encrypted_private_key",
        )
        .bind(user_id)
        .bind(&input.public_key)
        .bind(&input.encrypted_private_key)
        .execute(db)
        .await?;
        Ok(())
    }

    /// Sa PROPRE paire de clés (publique + privée CHIFFRÉE) — pour un utilisateur qui a besoin de
    /// déchiffrer sa propre clé privée (voir POST /emergency/contacts/{id}/request-access, où le
    /// CONTACT doit desceller la clé de coffre du propriétaire avec la sienne).
    pub async fn get_own_keys(db: &SqlitePool, user_id: i64) -> Result<UserKeysInput, AppError> {
        sqlx::query_as::<_, UserKeysInput>(
            "SELECT public_key, encrypted_private_key FROM user_keys WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_optional(db)
        .await?
        .ok_or(AppError::NotFound)
    }

    /// UNIQUEMENT la clé publique d'un autre utilisateur (voir GET /emergency/keys/{email}) — ce
    /// qu'il faut pour lui sceller quelque chose, jamais sa clé privée. Reste identifié par EMAIL
    /// (contrairement au reste de ce namespace) : c'est une recherche par un tiers dont on ne
    /// connaît que l'adresse (voir handlers/emergency.rs, sharing.rs, shared_vault.rs) — une
    /// jointure vers `users` résout l'id sans exposer la forme de la table `user_keys` à l'appelant.
    pub async fn get_public_key(db: &SqlitePool, email: &str) -> Result<UserPublicKey, AppError> {
        sqlx::query_as::<_, UserPublicKey>(
            "SELECT uk.public_key FROM user_keys uk JOIN users u ON u.id = uk.user_id WHERE u.email = ?"
        )
            .bind(email)
            .fetch_optional(db)
            .await?
            .ok_or(AppError::NotFound)
    }

    /// Désigne un nouveau contact de confiance — vérifie D'ABORD qu'aucune relation n'existe déjà
    /// pour ce couple (owner_id, contact_id), plutôt que de laisser la contrainte UNIQUE de
    /// la table échouer (même convention que le reste de ce backend, voir register()).
    ///
    /// CORRECTIF (course concurrente) : les deux lectures de garde-fou (doublon, plafond) ET
    /// l'insertion se déroulent désormais dans UNE SEULE transaction — sinon deux appels
    /// concurrents pourraient tous deux lire un état encore valide avant qu'aucun n'ait écrit,
    /// dépassant silencieusement MAX_EMERGENCY_CONTACTS_PER_OWNER (voir le même correctif pour
    /// MAX_VAULT_ENTRIES_PER_USER dans handlers/vault.rs::add_to_vault).
    pub async fn add_contact(db: &SqlitePool, owner_id: i64, contact_id: i64, waiting_period_days: i64) -> Result<String, AppError> {
        let mut tx = db.begin().await?;

        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM emergency_contacts WHERE owner_id = ? AND contact_id = ?",
        )
        .bind(owner_id)
        .bind(contact_id)
        .fetch_optional(&mut *tx)
        .await?;
        if exists.is_some() {
            return Err(AppError::Conflict("Ce contact de confiance existe déjà.".to_string()));
        }

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM emergency_contacts WHERE owner_id = ?")
            .bind(owner_id)
            .fetch_one(&mut *tx)
            .await?;
        if count >= MAX_EMERGENCY_CONTACTS_PER_OWNER {
            return Err(AppError::ValidationError(format!(
                "Limite de {MAX_EMERGENCY_CONTACTS_PER_OWNER} contacts de confiance atteinte pour ce compte."
            )));
        }

        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO emergency_contacts (id, owner_id, contact_id, waiting_period_days, status) VALUES (?, ?, ?, ?, 'pending')",
        )
        .bind(&id)
        .bind(owner_id)
        .bind(contact_id)
        .bind(waiting_period_days)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(id)
    }

    /// Contacts que CET utilisateur a désignés (il est owner) — "les gens en qui j'ai confiance".
    /// `EmergencyContact` garde ses champs `owner_email`/`contact_email` (réponse JSON inchangée) :
    /// deux jointures vers `users` les reconstituent depuis les id désormais stockés.
    pub async fn list_as_owner(db: &SqlitePool, owner_id: i64) -> Result<Vec<EmergencyContact>, AppError> {
        sqlx::query_as::<_, EmergencyContact>(
            "SELECT e.id, uo.email AS owner_email, uc.email AS contact_email, e.waiting_period_days, e.status, e.requested_at, e.available_at, e.created_at
             FROM emergency_contacts e
             JOIN users uo ON uo.id = e.owner_id
             JOIN users uc ON uc.id = e.contact_id
             WHERE e.owner_id = ? ORDER BY e.created_at DESC",
        )
        .bind(owner_id)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Relations où CET utilisateur est le contact désigné — "les comptes où on m'a fait confiance".
    pub async fn list_as_contact(db: &SqlitePool, contact_id: i64) -> Result<Vec<EmergencyContact>, AppError> {
        sqlx::query_as::<_, EmergencyContact>(
            "SELECT e.id, uo.email AS owner_email, uc.email AS contact_email, e.waiting_period_days, e.status, e.requested_at, e.available_at, e.created_at
             FROM emergency_contacts e
             JOIN users uo ON uo.id = e.owner_id
             JOIN users uc ON uc.id = e.contact_id
             WHERE e.contact_id = ? ORDER BY e.created_at DESC",
        )
        .bind(contact_id)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Une relation précise par id — SANS vérification d'appartenance (l'appelant, voir
    /// handlers/emergency.rs, doit vérifier lui-même que owner OU contact correspond à
    /// l'utilisateur authentifié selon l'action demandée).
    pub async fn get_by_id(db: &SqlitePool, id: &str) -> Result<EmergencyContact, AppError> {
        sqlx::query_as::<_, EmergencyContact>(
            "SELECT e.id, uo.email AS owner_email, uc.email AS contact_email, e.waiting_period_days, e.status, e.requested_at, e.available_at, e.created_at
             FROM emergency_contacts e
             JOIN users uo ON uo.id = e.owner_id
             JOIN users uc ON uc.id = e.contact_id
             WHERE e.id = ?",
        )
        .bind(id)
        .fetch_optional(db)
        .await?
        .ok_or(AppError::NotFound)
    }

    /// Renvoie (owner_id, owner_email, sealed_vault_key) UNIQUEMENT si l'accès est bien accordé À
    /// CET UTILISATEUR PRÉCIS — "contact_id = ? AND status = 'access_granted'" fait PARTIE de la
    /// requête SQL elle-même plutôt que d'être revérifié après coup côté Rust, pour qu'il soit
    /// STRUCTURELLEMENT impossible d'oublier ce contrôle. `sealed_vault_key` n'apparaît JAMAIS
    /// dans `EmergencyContact` (voir get_by_id/list_as_owner/list_as_contact ci-dessus/dessous) :
    /// s'il y figurait, un contact pourrait le récupérer via un simple listing AVANT même d'avoir
    /// demandé l'accès, et le desceller avec sa propre clé privée — contournant entièrement le
    /// délai d'attente et l'approbation du propriétaire, qui ne sont alors QUE des vérifications
    /// applicatives, pas cryptographiques. `owner_id` est renvoyé EN PLUS de `owner_email` (pas à
    /// la place) : le handler en a besoin pour lister le coffre du propriétaire
    /// (VaultRepository::get_all), qui n'accepte plus qu'un id.
    pub async fn get_granted_vault_key(db: &SqlitePool, id: &str, contact_id: i64) -> Result<(i64, String, String), AppError> {
        let row: Option<(i64, String, Option<String>)> = sqlx::query_as(
            "SELECT u.id, u.email, e.sealed_vault_key FROM emergency_contacts e
             JOIN users u ON u.id = e.owner_id
             WHERE e.id = ? AND e.contact_id = ? AND e.status = 'access_granted'",
        )
        .bind(id)
        .bind(contact_id)
        .fetch_optional(db)
        .await?;

        let (owner_id, owner_email, sealed_vault_key) = row.ok_or(AppError::NotFound)?;
        let sealed_vault_key = sealed_vault_key.ok_or(AppError::NotFound)?;
        Ok((owner_id, owner_email, sealed_vault_key))
    }

    /// Le CONTACT accepte l'invitation — seulement depuis 'pending'. "id + contact_id + status"
    /// tous filtrés dans le WHERE : 0 ligne affectée couvre indifféremment "id inconnu", "ce n'est
    /// pas vous le contact désigné" et "déjà accepté/pas encore invité" — 404 générique dans tous
    /// les cas, pas d'information à glaner en sondant les réponses.
    pub async fn accept(db: &SqlitePool, id: &str, contact_id: i64) -> Result<(), AppError> {
        let res = sqlx::query(
            "UPDATE emergency_contacts SET status = 'active' WHERE id = ? AND contact_id = ? AND status = 'pending'",
        )
        .bind(id)
        .bind(contact_id)
        .execute(db)
        .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Le CONTACT décline l'invitation — supprime carrément la relation (pas d'intérêt à garder
    /// une trace d'une invitation refusée).
    pub async fn decline(db: &SqlitePool, id: &str, contact_id: i64) -> Result<(), AppError> {
        let res = sqlx::query("DELETE FROM emergency_contacts WHERE id = ? AND contact_id = ? AND status = 'pending'")
            .bind(id)
            .bind(contact_id)
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
    pub async fn seed(db: &SqlitePool, id: &str, owner_id: i64, sealed_vault_key: &str) -> Result<(), AppError> {
        let res = sqlx::query("UPDATE emergency_contacts SET sealed_vault_key = ? WHERE id = ? AND owner_id = ?")
            .bind(sealed_vault_key)
            .bind(id)
            .bind(owner_id)
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
        contact_id: i64,
        requested_at: chrono::NaiveDateTime,
        available_at: chrono::NaiveDateTime,
    ) -> Result<(), AppError> {
        let res = sqlx::query(
            "UPDATE emergency_contacts
             SET status = 'access_requested', requested_at = ?, available_at = ?
             WHERE id = ? AND contact_id = ? AND status = 'active' AND sealed_vault_key IS NOT NULL",
        )
        .bind(requested_at)
        .bind(available_at)
        .bind(id)
        .bind(contact_id)
        .execute(db)
        .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Le PROPRIÉTAIRE approuve immédiatement une demande en cours, sans attendre la fin du délai.
    pub async fn approve(db: &SqlitePool, id: &str, owner_id: i64) -> Result<(), AppError> {
        let res = sqlx::query(
            "UPDATE emergency_contacts SET status = 'access_granted' WHERE id = ? AND owner_id = ? AND status = 'access_requested'",
        )
        .bind(id)
        .bind(owner_id)
        .execute(db)
        .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Le PROPRIÉTAIRE refuse une demande en cours — revient à 'active' (le contact reste
    /// désigné, juste sans accès accordé), pas de suppression de la relation elle-même.
    pub async fn reject(db: &SqlitePool, id: &str, owner_id: i64) -> Result<(), AppError> {
        let res = sqlx::query(
            "UPDATE emergency_contacts SET status = 'active', requested_at = NULL, available_at = NULL
             WHERE id = ? AND owner_id = ? AND status = 'access_requested'",
        )
        .bind(id)
        .bind(owner_id)
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
    ///
    /// DURCISSEMENT : `contact_id` fait partie du WHERE. Sans lui, n'importe quel compte connecté
    /// pouvait déclencher la transition d'état de N'IMPORTE QUELLE relation dont le délai était
    /// écoulé, simplement en devinant/énumérant un id. L'effet restait le même que ce qui se
    /// serait produit naturellement au prochain appel du vrai contact (et la clé scellée, elle,
    /// est de toute façon protégée par get_granted_vault_key, filtrée sur contact_id), donc ce
    /// n'était pas exploitable — mais une écriture déclenchable par un tiers sur la ligne d'autrui
    /// n'a aucune raison d'exister.
    pub async fn maybe_auto_grant(db: &SqlitePool, id: &str, contact_id: i64) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE emergency_contacts SET status = 'access_granted'
             WHERE id = ? AND contact_id = ? AND status = 'access_requested' AND available_at <= CURRENT_TIMESTAMP",
        )
        .bind(id)
        .bind(contact_id)
        .execute(db)
        .await?;
        Ok(())
    }

    /// Révoque une relation — l'un OU l'autre côté peut y mettre fin à tout moment (le propriétaire
    /// retire sa confiance, ou le contact se retire lui-même).
    pub async fn revoke(db: &SqlitePool, id: &str, caller_id: i64) -> Result<(), AppError> {
        let res = sqlx::query("DELETE FROM emergency_contacts WHERE id = ? AND (owner_id = ? OR contact_id = ?)")
            .bind(id)
            .bind(caller_id)
            .bind(caller_id)
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
    /// CORRECTIF (course concurrente) : les lectures de garde-fou (propriété, id existant,
    /// plafond) ET l'écriture finale se déroulent désormais dans UNE SEULE transaction — même
    /// raisonnement que EmergencyRepository::add_contact ci-dessus.
    pub async fn share_entry(db: &SqlitePool, vault_id: &str, owner_id: i64, shared_with_id: i64, sealed_entry: &str) -> Result<String, AppError> {
        let mut tx = db.begin().await?;

        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM vault WHERE id = ? AND user_id = ? AND deleted_at IS NULL",
        )
        .bind(vault_id)
        .bind(owner_id)
        .fetch_optional(&mut *tx)
        .await?;
        if exists.is_none() {
            return Err(AppError::NotFound);
        }

        // Réutilise l'id existant si un partage pour ce couple (entrée, destinataire) existe déjà,
        // plutôt que d'en générer un nouveau à chaque fois — évite de faire "disparaître" l'id
        // d'un partage déjà en cours côté client sur un simple re-partage après modification.
        let existing_id: Option<String> = sqlx::query_scalar(
            "SELECT id FROM vault_shares WHERE vault_id = ? AND shared_with_id = ?",
        )
        .bind(vault_id)
        .bind(shared_with_id)
        .fetch_optional(&mut *tx)
        .await?;

        // Le plafond ne s'applique QUE lors de la création d'une ligne réellement NOUVELLE — un
        // re-partage (mise à jour du blob d'un partage déjà existant) ne doit jamais être bloqué
        // par un plafond qui n'a de sens que pour limiter la CROISSANCE du nombre de partages.
        if existing_id.is_none() {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault_shares WHERE owner_id = ?")
                .bind(owner_id)
                .fetch_one(&mut *tx)
                .await?;
            if count >= MAX_SHARES_PER_OWNER {
                return Err(AppError::ValidationError(format!(
                    "Limite de {MAX_SHARES_PER_OWNER} partages atteinte pour ce compte."
                )));
            }
        }

        let id = existing_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        sqlx::query(
            "INSERT INTO vault_shares (id, vault_id, owner_id, shared_with_id, sealed_entry) VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(vault_id, shared_with_id) DO UPDATE SET sealed_entry = excluded.sealed_entry, updated_at = CURRENT_TIMESTAMP",
        )
        .bind(&id)
        .bind(vault_id)
        .bind(owner_id)
        .bind(shared_with_id)
        .bind(sealed_entry)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(id)
    }

    /// Liste les partages actifs d'UNE entrée, vus par son PROPRIÉTAIRE — jamais `sealed_entry`
    /// (voir VaultShare). Sert aussi à reseedEntryShares() côté client (lib/entrySharing.ts) pour
    /// savoir à qui re-sceller après une modification de l'entrée. `VaultShare` garde son champ
    /// `shared_with_email` (réponse JSON inchangée) : jointure vers `users` pour le reconstituer.
    pub async fn list_shares_for_entry(db: &SqlitePool, vault_id: &str, owner_id: i64) -> Result<Vec<VaultShare>, AppError> {
        sqlx::query_as::<_, VaultShare>(
            "SELECT s.id, u.email AS shared_with_email, s.created_at
             FROM vault_shares s JOIN users u ON u.id = s.shared_with_id
             WHERE s.vault_id = ? AND s.owner_id = ? ORDER BY s.created_at DESC",
        )
        .bind(vault_id)
        .bind(owner_id)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Liste tout ce qui a été partagé AVEC l'utilisateur courant, tous propriétaires confondus —
    /// jamais `sealed_entry` (voir SharedWithMeEntry).
    pub async fn list_shared_with_me(db: &SqlitePool, recipient_id: i64) -> Result<Vec<SharedWithMeEntry>, AppError> {
        sqlx::query_as::<_, SharedWithMeEntry>(
            "SELECT s.id, s.vault_id, u.email AS owner_email, s.created_at
             FROM vault_shares s JOIN users u ON u.id = s.owner_id
             WHERE s.shared_with_id = ? ORDER BY s.created_at DESC",
        )
        .bind(recipient_id)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Récupère le blob scellé d'UN partage précis — UNIQUEMENT pour son DESTINATAIRE.
    /// `shared_with_id = ?` est encodé DIRECTEMENT dans le WHERE (jamais une vérification a
    /// posteriori en Rust) — même pattern de sécurité que
    /// EmergencyRepository::get_granted_vault_key : rend l'autorisation structurellement
    /// impossible à oublier. Vérifie en plus, via une sous-requête, que l'entrée sous-jacente n'est
    /// pas dans la corbeille — un partage d'une entrée entre-temps supprimée ne doit plus être
    /// consultable, même si la ligne `vault_shares` existe encore (elle disparaîtra de toute façon
    /// à la purge définitive, voir ON DELETE CASCADE dans la migration, mais la corbeille laisse un
    /// délai avant purge pendant lequel l'entrée ne doit déjà plus être consultable via un partage).
    pub async fn get_shared_entry(db: &SqlitePool, share_id: &str, recipient_id: i64) -> Result<SharedEntryView, AppError> {
        sqlx::query_as::<_, SharedEntryView>(
            "SELECT u.email AS owner_email, s.sealed_entry FROM vault_shares s
             JOIN users u ON u.id = s.owner_id
             WHERE s.id = ? AND s.shared_with_id = ?
             AND s.vault_id IN (SELECT id FROM vault WHERE deleted_at IS NULL)",
        )
        .bind(share_id)
        .bind(recipient_id)
        .fetch_optional(db)
        .await?
        .ok_or(AppError::NotFound)
    }

    /// Révoque un partage — l'un OU l'autre côté peut y mettre fin (le propriétaire retire l'accès,
    /// ou le destinataire quitte le partage), même principe que EmergencyRepository::revoke.
    pub async fn revoke_share(db: &SqlitePool, share_id: &str, caller_id: i64) -> Result<(), AppError> {
        let res = sqlx::query("DELETE FROM vault_shares WHERE id = ? AND (owner_id = ? OR shared_with_id = ?)")
            .bind(share_id)
            .bind(caller_id)
            .bind(caller_id)
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
    /// CORRECTIF (course concurrente) : le plafond est désormais vérifié DANS la même transaction
    /// que les deux écritures — sinon deux créations concurrentes juste sous la limite pouvaient
    /// toutes deux lire un compte encore valide avant qu'aucune n'ait écrit.
    pub async fn create(db: &SqlitePool, creator_id: i64, encrypted_name: &str, sealed_vault_key: &str) -> Result<String, AppError> {
        let mut tx = db.begin().await?;

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM shared_vaults WHERE created_by_id = ?")
            .bind(creator_id)
            .fetch_one(&mut *tx)
            .await?;
        if count >= MAX_SHARED_VAULTS_PER_CREATOR {
            return Err(AppError::ValidationError(format!(
                "Limite de {MAX_SHARED_VAULTS_PER_CREATOR} coffres partagés créés atteinte pour ce compte."
            )));
        }

        let id = uuid::Uuid::new_v4().to_string();

        sqlx::query("INSERT INTO shared_vaults (id, encrypted_name, created_by_id) VALUES (?, ?, ?)")
            .bind(&id)
            .bind(encrypted_name)
            .bind(creator_id)
            .execute(&mut *tx)
            .await?;

        sqlx::query("INSERT INTO shared_vault_members (shared_vault_id, member_id, sealed_vault_key, is_owner) VALUES (?, ?, ?, 1)")
            .bind(&id)
            .bind(creator_id)
            .bind(sealed_vault_key)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(id)
    }

    /// Liste les coffres partagés dont l'appelant est membre — `sealed_vault_key` renvoyée est
    /// TOUJOURS la sienne (jointure sur `member_id = ?`), jamais celle d'un autre membre.
    /// `SharedVaultView.created_by` garde son champ (réponse JSON inchangée) : troisième jointure
    /// vers `users` pour le reconstituer depuis `shared_vaults.created_by_id`.
    pub async fn list_for_member(db: &SqlitePool, member_id: i64) -> Result<Vec<SharedVaultView>, AppError> {
        sqlx::query_as::<_, SharedVaultView>(
            "SELECT sv.id, sv.encrypted_name, u.email AS created_by, sv.created_at, svm.sealed_vault_key, svm.is_owner
             FROM shared_vaults sv
             JOIN shared_vault_members svm ON svm.shared_vault_id = sv.id
             JOIN users u ON u.id = sv.created_by_id
             WHERE svm.member_id = ?
             ORDER BY sv.created_at DESC",
        )
        .bind(member_id)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Invite un nouveau membre — réservé au PROPRIÉTAIRE (`is_owner = 1` vérifié directement dans
    /// le WHERE de la sous-requête). `sealed_vault_key` doit déjà être scellé côté client pour la
    /// clé publique du nouveau membre AVANT cet appel (voir InviteSharedVaultMemberPayload) — le
    /// serveur ne fait que le stocker. Échoue si `member_id` est déjà membre (contrainte de clé
    /// primaire composite) plutôt que d'écraser silencieusement sa clé scellée existante.
    /// CORRECTIF (course concurrente) : la vérification du plafond ET l'insertion se déroulent
    /// désormais dans UNE SEULE transaction — même raisonnement que create() ci-dessus.
    pub async fn invite_member(db: &SqlitePool, shared_vault_id: &str, caller_id: i64, member_id: i64, sealed_vault_key: &str) -> Result<(), AppError> {
        let mut tx = db.begin().await?;

        let is_owner: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM shared_vault_members WHERE shared_vault_id = ? AND member_id = ? AND is_owner = 1",
        )
        .bind(shared_vault_id)
        .bind(caller_id)
        .fetch_optional(&mut *tx)
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
        .fetch_one(&mut *tx)
        .await?;
        if member_count >= MAX_MEMBERS_PER_SHARED_VAULT {
            return Err(AppError::ValidationError(format!(
                "Limite de {MAX_MEMBERS_PER_SHARED_VAULT} membres atteinte pour ce coffre partagé."
            )));
        }

        let result = sqlx::query(
            "INSERT INTO shared_vault_members (shared_vault_id, member_id, sealed_vault_key, is_owner) VALUES (?, ?, ?, 0)",
        )
        .bind(shared_vault_id)
        .bind(member_id)
        .bind(sealed_vault_key)
        .execute(&mut *tx)
        .await;

        match result {
            Ok(_) => {
                tx.commit().await?;
                Ok(())
            }
            // Violation de la clé primaire composite (shared_vault_id, member_id) : déjà membre.
            Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                Err(AppError::ValidationError("Cette personne est déjà membre de ce coffre partagé.".to_string()))
            }
            Err(e) => Err(AppError::from(e)),
        }
    }

    /// Liste les membres d'un coffre partagé — n'importe quel membre peut la consulter (pas
    /// réservé au propriétaire), jamais `sealed_vault_key` d'autrui (voir SharedVaultMemberView).
    pub async fn list_members(db: &SqlitePool, shared_vault_id: &str, caller_id: i64) -> Result<Vec<SharedVaultMemberView>, AppError> {
        let is_member: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM shared_vault_members WHERE shared_vault_id = ? AND member_id = ?",
        )
        .bind(shared_vault_id)
        .bind(caller_id)
        .fetch_optional(db)
        .await?;
        if is_member.is_none() {
            return Err(AppError::NotFound);
        }

        sqlx::query_as::<_, SharedVaultMemberView>(
            "SELECT u.email AS member_email, svm.is_owner, svm.added_at
             FROM shared_vault_members svm JOIN users u ON u.id = svm.member_id
             WHERE svm.shared_vault_id = ? ORDER BY svm.added_at ASC",
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
            "SELECT u.email AS member_email, svm.is_owner, svm.added_at
             FROM shared_vault_members svm JOIN users u ON u.id = svm.member_id
             WHERE svm.shared_vault_id = ?",
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
    pub async fn leave(db: &SqlitePool, shared_vault_id: &str, member_id: i64) -> Result<(), AppError> {
        let res = sqlx::query(
            "DELETE FROM shared_vault_members WHERE shared_vault_id = ? AND member_id = ? AND is_owner = 0",
        )
        .bind(shared_vault_id)
        .bind(member_id)
        .execute(db)
        .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Le PROPRIÉTAIRE retire un autre membre (jamais lui-même — `is_owner = 0` dans le WHERE
    /// exclut structurellement ce cas, même si `target_id` désignait par erreur le propriétaire
    /// lui-même).
    pub async fn remove_member(db: &SqlitePool, shared_vault_id: &str, caller_id: i64, target_id: i64) -> Result<(), AppError> {
        let is_owner: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM shared_vault_members WHERE shared_vault_id = ? AND member_id = ? AND is_owner = 1",
        )
        .bind(shared_vault_id)
        .bind(caller_id)
        .fetch_optional(db)
        .await?;
        if is_owner.is_none() {
            return Err(AppError::Forbidden);
        }

        let res = sqlx::query(
            "DELETE FROM shared_vault_members WHERE shared_vault_id = ? AND member_id = ? AND is_owner = 0",
        )
        .bind(shared_vault_id)
        .bind(target_id)
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
    pub async fn delete_vault(db: &SqlitePool, shared_vault_id: &str, caller_id: i64) -> Result<(), AppError> {
        let res = sqlx::query("DELETE FROM shared_vaults WHERE id = ? AND created_by_id = ?")
            .bind(shared_vault_id)
            .bind(caller_id)
            .execute(db)
            .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }
        Ok(())
    }

    /// Liste les entrées d'un coffre partagé — réservé à ses membres. `SharedVaultEntry.created_by`
    /// garde son champ (réponse JSON inchangée) : jointure vers `users` pour le reconstituer.
    pub async fn list_entries(db: &SqlitePool, shared_vault_id: &str, caller_id: i64) -> Result<Vec<SharedVaultEntry>, AppError> {
        let is_member: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM shared_vault_members WHERE shared_vault_id = ? AND member_id = ?",
        )
        .bind(shared_vault_id)
        .bind(caller_id)
        .fetch_optional(db)
        .await?;
        if is_member.is_none() {
            return Err(AppError::NotFound);
        }

        sqlx::query_as::<_, SharedVaultEntry>(
            "SELECT e.id, e.shared_vault_id, e.encrypted_site_name, e.encrypted_username, e.encrypted_login_email, e.encrypted_password, e.encrypted_preferred_login_type, e.encrypted_notes, e.encrypted_url, e.entry_type, e.encrypted_extra_fields, u.email AS created_by, e.updated_at, e.version
             FROM shared_vault_entries e JOIN users u ON u.id = e.created_by_id
             WHERE e.shared_vault_id = ? ORDER BY e.updated_at DESC",
        )
        .bind(shared_vault_id)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Ajoute une entrée — réservé aux membres. `entry.expected_version` n'a pas de sens à la
    /// création (ignoré, comme VaultRepository::add).
    pub async fn add_entry(db: &SqlitePool, shared_vault_id: &str, caller_id: i64, entry: &SharedVaultEntryInput) -> Result<String, AppError> {
        let is_member: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM shared_vault_members WHERE shared_vault_id = ? AND member_id = ?",
        )
        .bind(shared_vault_id)
        .bind(caller_id)
        .fetch_optional(db)
        .await?;
        if is_member.is_none() {
            return Err(AppError::NotFound);
        }

        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO shared_vault_entries (id, shared_vault_id, encrypted_site_name, encrypted_username, encrypted_login_email, encrypted_password, encrypted_preferred_login_type, encrypted_notes, encrypted_url, entry_type, encrypted_extra_fields, created_by_id)
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
        .bind(caller_id)
        .execute(db)
        .await?;

        Ok(id)
    }

    /// Modifie une entrée — réservé aux membres (N'IMPORTE LEQUEL, pas seulement celui qui l'avait
    /// ajoutée : un coffre partagé est par nature une ressource commune). Détection de conflit
    /// d'édition identique à VaultRepository::update (voir son commentaire pour le raisonnement
    /// complet) — plus susceptible de survenir ici, plusieurs membres différents pouvant modifier
    /// la même entrée à quelques instants d'écart.
    pub async fn update_entry(db: &SqlitePool, shared_vault_id: &str, entry_id: &str, caller_id: i64, entry: &SharedVaultEntryInput) -> Result<(), AppError> {
        let is_member: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM shared_vault_members WHERE shared_vault_id = ? AND member_id = ?",
        )
        .bind(shared_vault_id)
        .bind(caller_id)
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
    pub async fn delete_entry(db: &SqlitePool, shared_vault_id: &str, entry_id: &str, caller_id: i64) -> Result<(), AppError> {
        let is_member: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM shared_vault_members WHERE shared_vault_id = ? AND member_id = ?",
        )
        .bind(shared_vault_id)
        .bind(caller_id)
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
    /// CORRECTIF (course concurrente) : propriété, plafond ET écriture se déroulent désormais dans
    /// UNE SEULE transaction — même raisonnement que SharingRepository::share_entry.
    pub async fn create(
        db: &SqlitePool,
        vault_id: &str,
        owner_id: i64,
        shared_with_id: i64,
        sealed_site_name: &str,
        sealed_credentials: &str,
        max_uses: i64,
    ) -> Result<String, AppError> {
        let mut tx = db.begin().await?;

        let exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM vault WHERE id = ? AND user_id = ? AND deleted_at IS NULL",
        )
        .bind(vault_id)
        .bind(owner_id)
        .fetch_optional(&mut *tx)
        .await?;
        if exists.is_none() {
            return Err(AppError::NotFound);
        }

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault_blind_shares WHERE owner_id = ?")
            .bind(owner_id)
            .fetch_one(&mut *tx)
            .await?;
        if count >= MAX_BLIND_SHARES_PER_OWNER {
            return Err(AppError::ValidationError(format!(
                "Limite de {MAX_BLIND_SHARES_PER_OWNER} partages à usage limité atteinte pour ce compte."
            )));
        }

        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO vault_blind_shares (id, vault_id, owner_id, shared_with_id, sealed_site_name, sealed_credentials, max_uses, remaining_uses)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(vault_id)
        .bind(owner_id)
        .bind(shared_with_id)
        .bind(sealed_site_name)
        .bind(sealed_credentials)
        .bind(max_uses)
        .bind(max_uses)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(id)
    }

    /// Les partages à usage limité actifs d'UNE entrée, vus par son PROPRIÉTAIRE — jamais les
    /// blobs scellés (voir VaultBlindShare, qui garde son champ `shared_with_email` : jointure
    /// vers `users` pour le reconstituer).
    pub async fn list_for_entry(db: &SqlitePool, vault_id: &str, owner_id: i64) -> Result<Vec<VaultBlindShare>, AppError> {
        sqlx::query_as::<_, VaultBlindShare>(
            "SELECT b.id, u.email AS shared_with_email, b.max_uses, b.remaining_uses, b.created_at
             FROM vault_blind_shares b JOIN users u ON u.id = b.shared_with_id
             WHERE b.vault_id = ? AND b.owner_id = ? ORDER BY b.created_at DESC",
        )
        .bind(vault_id)
        .bind(owner_id)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Tout ce qui a été partagé EN USAGE LIMITÉ avec l'utilisateur courant — `sealed_site_name`
    /// EST inclus (librement consultable, ne consomme jamais d'usage), jamais `sealed_credentials`.
    pub async fn list_received(db: &SqlitePool, recipient_id: i64) -> Result<Vec<BlindShareReceivedView>, AppError> {
        sqlx::query_as::<_, BlindShareReceivedView>(
            "SELECT b.id, u.email AS owner_email, b.sealed_site_name, b.max_uses, b.remaining_uses, b.created_at
             FROM vault_blind_shares b JOIN users u ON u.id = b.owner_id
             WHERE b.shared_with_id = ? ORDER BY b.created_at DESC",
        )
        .bind(recipient_id)
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
    pub async fn consume_use(db: &SqlitePool, id: &str, recipient_id: i64) -> Result<BlindShareCredentialsView, AppError> {
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
             WHERE id = ? AND shared_with_id = ? AND remaining_uses > 0
             AND vault_id IN (SELECT id FROM vault WHERE deleted_at IS NULL)",
        )
        .bind(id)
        .bind(recipient_id)
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
                 WHERE id = ? AND shared_with_id = ?
                 AND vault_id IN (SELECT id FROM vault WHERE deleted_at IS NULL)",
            )
            .bind(id)
            .bind(recipient_id)
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
    pub async fn revoke(db: &SqlitePool, id: &str, caller_id: i64) -> Result<(), AppError> {
        let res = sqlx::query("DELETE FROM vault_blind_shares WHERE id = ? AND (owner_id = ? OR shared_with_id = ?)")
            .bind(id)
            .bind(caller_id)
            .bind(caller_id)
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
    /// CORRECTIF (repéré en relecture, pas par un incident réel) : la version précédente faisait
    /// un `SELECT COUNT(*)` PUIS un `INSERT` séparés — un TOCTOU classique (deux requêtes
    /// concurrentes pourraient toutes les deux lire un compte encore sous la limite, puis toutes
    /// les deux insérer, dépassant MAX_BUG_REPORTS_TOTAL). Le même motif existe ailleurs dans ce
    /// fichier (MAX_SHARED_VAULTS_PER_CREATOR, MAX_BLIND_SHARES_PER_OWNER...) mais reste un risque
    /// accepté LÀ-BAS car ces routes exigent un compte authentifié — ICI, `create()` est appelée
    /// depuis une route PUBLIQUE/anonyme (voir handlers/bug_report.rs), donc bien plus exposée à
    /// des appels concurrents délibérés. `INSERT ... SELECT ... WHERE (SELECT COUNT...) < N` : UNE
    /// SEULE instruction SQL, atomique par nature (SQLite ne peut pas entrelacer l'exécution de
    /// deux instructions différentes sur la même table), élimine complètement la fenêtre de course
    /// plutôt que de la rendre juste moins probable.
    pub async fn create(db: &SqlitePool, payload: &CreateBugReportPayload) -> Result<String, AppError> {
        let id = uuid::Uuid::new_v4().to_string();
        let res = sqlx::query(
            "INSERT INTO bug_reports (id, reporter_email, description, app_version, platform, category)
             SELECT ?, ?, ?, ?, ?, ?
             WHERE (SELECT COUNT(*) FROM bug_reports) < ?",
        )
        .bind(&id)
        .bind(&payload.reporter_email)
        .bind(&payload.description)
        .bind(&payload.app_version)
        .bind(&payload.platform)
        .bind(&payload.category)
        .bind(MAX_BUG_REPORTS_TOTAL)
        .execute(db)
        .await?;

        if res.rows_affected() == 0 {
            return Err(AppError::ValidationError(
                "Trop de signalements en attente de traitement — réessaie plus tard.".to_string(),
            ));
        }

        Ok(id)
    }

    /// Réservé au SEUL Admin (vérifié dans le handler via user.is_admin(&state), PAS is_moderator
    /// — demande explicite de l'utilisateur, voir handlers/bug_report.rs).
    pub async fn list_all(db: &SqlitePool) -> Result<Vec<BugReportView>, AppError> {
        sqlx::query_as::<_, BugReportView>(
            "SELECT id, reporter_email, description, app_version, platform, category, created_at FROM bug_reports ORDER BY created_at DESC",
        )
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Supprime un signalement une fois traité — pas de statut "résolu" séparé dans cette première
    /// version, la suppression EST la façon de marquer "traité" (garde le panneau simple à trier).
    /// `RETURNING` (lecture + suppression en UNE requête atomique, même pattern déjà utilisé pour
    /// les ws_tickets/refresh tokens ailleurs dans ce fichier) : le handler s'en sert pour prévenir
    /// la personne par email si elle en avait laissé un — voir mailer::send_bug_report_resolved.
    pub async fn delete(db: &SqlitePool, id: &str) -> Result<DeletedBugReport, AppError> {
        let deleted: Option<DeletedBugReport> = sqlx::query_as::<_, DeletedBugReport>(
            "DELETE FROM bug_reports WHERE id = ? RETURNING reporter_email, description",
        )
        .bind(id)
        .fetch_optional(db)
        .await?;

        deleted.ok_or(AppError::NotFound)
    }
}

/// Résultat de BugReportRepository::delete() — juste ce qu'il faut pour, éventuellement, prévenir
/// la personne (voir handlers/bug_report.rs::delete_bug_report). Pas un type public de models.rs :
/// n'a de sens que comme valeur de retour interne à ce repository.
#[derive(sqlx::FromRow)]
pub struct DeletedBugReport {
    pub reporter_email: Option<String>,
    pub description: String,
}

// =========================================================================
// SUGGESTION DE FONCTIONNALITÉ — voir migration 20260902000002_feature_suggestions.sql et
// models.rs pour le détail du modèle. Contrairement à BugReportRepository::create ci-dessus,
// `create()` ici est appelée depuis une route AUTHENTIFIÉE (voir handlers/feature_suggestion.rs) :
// même style SELECT-COUNT-puis-INSERT (pas l'INSERT...SELECT...WHERE COUNT atomique de
// BugReportRepository) que MAX_SHARED_VAULTS_PER_CREATOR/MAX_BLIND_SHARES_PER_OWNER plus haut dans
// ce fichier — la fenêtre de course TOCTOU qu'un vrai compte authentifié pourrait exploiter en
// s'envoyant des requêtes concurrentes n'a ici aucun intérêt réel (au pire, quelques suggestions de
// plus que le plafond pour SON PROPRE compte, jamais un impact sur les autres utilisateurs).
// =========================================================================

/// Par auteur (pas global — cette route exige un compte, donc chaque abus reste imputable à un
/// seul compte plutôt qu'à épuiser une ressource partagée). `pub(crate)` (pas juste privé) :
/// réutilisée telle quelle par le test de régression sur ce plafond dans
/// handlers/feature_suggestion.rs, même raisonnement que MAX_BUG_REPORTS_TOTAL.
pub(crate) const MAX_FEATURE_SUGGESTIONS_PER_USER: i64 = 20;

/// CORRECTIF (repéré en relecture, pas par un incident réel) : contrairement à MAX_BUG_REPORTS_TOTAL,
/// cette table n'avait jusqu'ici AUCUN plafond global — seulement le plafond par auteur ci-dessus.
/// Sur une instance avec beaucoup de comptes (chacun pouvant en avoir jusqu'à
/// MAX_FEATURE_SUGGESTIONS_PER_USER en attente), la table pouvait quand même croître sans aucune
/// limite. Filet de sécurité supplémentaire, pas la défense principale (qui reste le plafond par
/// auteur ci-dessus) — largement au-dessus de tout usage légitime même à plusieurs dizaines de
/// comptes.
const MAX_FEATURE_SUGGESTIONS_TOTAL: i64 = 2000;

pub struct FeatureSuggestionRepository;

impl FeatureSuggestionRepository {
    /// CORRECTIF (course concurrente) : le plafond PAR AUTEUR est désormais vérifié dans LA MÊME
    /// transaction que l'écriture — même raisonnement que les autres plafonds de ce fichier
    /// (auparavant accepté comme risque mineur puisque auto-limité à un seul compte, mais fermé
    /// par cohérence maintenant que le motif est établi ailleurs). Le plafond GLOBAL ci-dessous
    /// reste, lui, la même insertion atomique en un seul statement (voir son commentaire).
    pub async fn create(db: &SqlitePool, author_id: i64, payload: &CreateFeatureSuggestionPayload) -> Result<String, AppError> {
        let mut tx = db.begin().await?;

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM feature_suggestions WHERE author_id = ?")
            .bind(author_id)
            .fetch_one(&mut *tx)
            .await?;
        if count >= MAX_FEATURE_SUGGESTIONS_PER_USER {
            return Err(AppError::ValidationError(format!(
                "Limite de {MAX_FEATURE_SUGGESTIONS_PER_USER} suggestions en attente atteinte pour ce compte — attends qu'elles soient examinées avant d'en envoyer d'autres."
            )));
        }

        let id = uuid::Uuid::new_v4().to_string();
        // Plafond GLOBAL (voir MAX_FEATURE_SUGGESTIONS_TOTAL) appliqué ICI via une insertion
        // atomique — même motif que BugReportRepository::create ci-dessus, une seule instruction
        // SQL qui protège une ressource partagée par TOUS les comptes.
        let res = sqlx::query(
            "INSERT INTO feature_suggestions (id, author_id, description)
             SELECT ?, ?, ?
             WHERE (SELECT COUNT(*) FROM feature_suggestions) < ?",
        )
        .bind(&id)
        .bind(author_id)
        .bind(&payload.description)
        .bind(MAX_FEATURE_SUGGESTIONS_TOTAL)
        .execute(&mut *tx)
        .await?;

        if res.rows_affected() == 0 {
            return Err(AppError::ValidationError(
                "Trop de suggestions en attente au total sur ce serveur — réessaie plus tard.".to_string(),
            ));
        }

        tx.commit().await?;
        Ok(id)
    }

    /// Réservé au SEUL Admin (vérifié dans le handler via user.is_admin(&state), même raisonnement
    /// que BugReportRepository::list_all — demande explicite de l'utilisateur). `FeatureSuggestionView`
    /// garde son champ `author_email` (réponse JSON inchangée) : jointure vers `users`.
    pub async fn list_all(db: &SqlitePool) -> Result<Vec<FeatureSuggestionView>, AppError> {
        sqlx::query_as::<_, FeatureSuggestionView>(
            "SELECT f.id, u.email AS author_email, f.description, f.created_at
             FROM feature_suggestions f JOIN users u ON u.id = f.author_id
             ORDER BY f.created_at DESC",
        )
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Supprime une suggestion une fois examinée — même choix que BugReportRepository::delete : pas
    /// de statut séparé, la suppression EST la façon de marquer "traité". Sert au handler pour,
    /// éventuellement, prévenir l'auteur par email (voir mailer::send_feature_suggestion_reviewed)
    /// — ici TOUJOURS un email réel (contrairement à bug_reports, author_id n'est jamais NULL, voir
    /// la migration).
    ///
    /// EN DEUX TEMPS (SELECT jointe puis DELETE), PAS `DELETE ... RETURNING` : `RETURNING` ne peut
    /// projeter que des colonnes de la table modifiée, jamais joindre `users` pour reconstituer
    /// l'email depuis `author_id` — la même transaction garantit malgré tout l'atomicité (personne
    /// d'autre ne peut supprimer cette ligne entre la lecture et l'écriture).
    pub async fn delete(db: &SqlitePool, id: &str) -> Result<DeletedFeatureSuggestion, AppError> {
        let mut tx = db.begin().await?;

        let found: Option<DeletedFeatureSuggestion> = sqlx::query_as::<_, DeletedFeatureSuggestion>(
            "SELECT u.email AS author_email, f.description
             FROM feature_suggestions f JOIN users u ON u.id = f.author_id
             WHERE f.id = ?",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
        let found = found.ok_or(AppError::NotFound)?;

        let res = sqlx::query("DELETE FROM feature_suggestions WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        if res.rows_affected() == 0 {
            return Err(AppError::NotFound);
        }

        tx.commit().await?;
        Ok(found)
    }
}

/// Résultat de FeatureSuggestionRepository::delete() — voir DeletedBugReport ci-dessus, même
/// raisonnement (juste ce qu'il faut pour prévenir l'auteur, pas un type public de models.rs).
#[derive(sqlx::FromRow)]
pub struct DeletedFeatureSuggestion {
    pub author_email: String,
    pub description: String,
}

// =========================================================================
// PERSONNALISATION DE THÈME (PROFILS) — voir migration
// 20260903000000_theme_customization_profiles.sql et models.rs pour le détail du modèle.
// Plusieurs profils nommés par compte, plafonnés à MAX_PROFILES_PER_USER SAUF pour l'Admin (voir
// create() ci-dessous) — retour utilisateur, 2026-09-03.
// =========================================================================

/// Plafond de profils de personnalisation pour un compte NON-admin (retour utilisateur,
/// 2026-09-03 : "limiter le nombre de profil à part pour l'administrateur") — l'Admin
/// (AuthUser::is_admin, voir handlers/theme_customization.rs) n'a aucune limite.
const MAX_PROFILES_PER_USER: i64 = 3;

pub struct ThemeProfileRepository;

impl ThemeProfileRepository {
    /// Tous les profils du compte, du plus ancien au plus récent — jamais ceux d'un AUTRE compte
    /// (scopé par user_id, comme partout ailleurs dans ce fichier).
    pub async fn list(db: &SqlitePool, user_id: i64) -> Result<Vec<ThemeProfileView>, AppError> {
        sqlx::query_as::<_, ThemeProfileView>(
            "SELECT id, name, background_hue, background_lightness, background_saturation, accent_hue, accent_lightness, accent_saturation,
                    danger_hue, danger_lightness, danger_saturation, success_hue, success_lightness, success_saturation,
                    favorite_hue, favorite_lightness, favorite_saturation, is_active
             FROM theme_customization_profiles WHERE user_id = ? AND pending_from_user_id IS NULL ORDER BY created_at ASC",
        )
        .bind(user_id)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// N'inclut jamais un partage encore EN ATTENTE reçu par ce compte (voir
    /// `pending_from_user_id`, migration 20260924000000) : tant qu'un cadeau n'est pas accepté, il
    /// ne doit pas manger sur le plafond de l'accepter éventuel (voir ThemeShareRepository::accept,
    /// qui appelle ce compte directement — pas via create() — pour ce contrôle). Liée à une
    /// transaction déjà ouverte plutôt qu'au pool directement (voir count_active_in_tx plus haut
    /// pour le raisonnement) : les deux appelants (create() et ThemeShareRepository::accept)
    /// vérifient désormais ce plafond DANS la même transaction que leur écriture.
    async fn count(tx: &mut sqlx::SqliteConnection, user_id: i64) -> Result<i64, AppError> {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM theme_customization_profiles WHERE user_id = ? AND pending_from_user_id IS NULL")
            .bind(user_id)
            .fetch_one(tx)
            .await?;
        Ok(count)
    }

    /// `is_admin_caller` (voir AuthUser::is_admin, calculé dans le handler — jamais recalculé ici,
    /// ce module ne connaît pas AppState) désactive le plafond. Nouveau profil jamais actif à la
    /// création (voir activate() ci-dessous pour ça, une action séparée et explicite).
    /// CORRECTIF (course concurrente) : le plafond ET l'insertion se déroulent désormais dans UNE
    /// SEULE transaction.
    pub async fn create(db: &SqlitePool, user_id: i64, payload: &ThemeProfilePayload, is_admin_caller: bool) -> Result<ThemeProfileView, AppError> {
        let mut tx = db.begin().await?;

        if !is_admin_caller {
            let existing = Self::count(&mut tx, user_id).await?;
            if existing >= MAX_PROFILES_PER_USER {
                return Err(AppError::ValidationError(format!(
                    "Limite de {MAX_PROFILES_PER_USER} profils de personnalisation atteinte — supprime-en un avant d'en créer un nouveau."
                )));
            }
        }

        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO theme_customization_profiles
                (id, user_id, name, background_hue, background_lightness, background_saturation,
                 accent_hue, accent_lightness, accent_saturation, danger_hue, danger_lightness, danger_saturation,
                 success_hue, success_lightness, success_saturation, favorite_hue, favorite_lightness, favorite_saturation, is_active)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
        )
        .bind(&id)
        .bind(user_id)
        .bind(&payload.name)
        .bind(payload.background_hue)
        .bind(payload.background_lightness)
        .bind(payload.background_saturation)
        .bind(payload.accent_hue)
        .bind(payload.accent_lightness)
        .bind(payload.accent_saturation)
        .bind(payload.danger_hue)
        .bind(payload.danger_lightness)
        .bind(payload.danger_saturation)
        .bind(payload.success_hue)
        .bind(payload.success_lightness)
        .bind(payload.success_saturation)
        .bind(payload.favorite_hue)
        .bind(payload.favorite_lightness)
        .bind(payload.favorite_saturation)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(ThemeProfileView {
            id,
            name: payload.name.clone(),
            background_hue: payload.background_hue,
            background_lightness: payload.background_lightness,
            background_saturation: payload.background_saturation,
            accent_hue: payload.accent_hue,
            accent_lightness: payload.accent_lightness,
            accent_saturation: payload.accent_saturation,
            danger_hue: payload.danger_hue,
            danger_lightness: payload.danger_lightness,
            danger_saturation: payload.danger_saturation,
            success_hue: payload.success_hue,
            success_lightness: payload.success_lightness,
            success_saturation: payload.success_saturation,
            favorite_hue: payload.favorite_hue,
            favorite_lightness: payload.favorite_lightness,
            favorite_saturation: payload.favorite_saturation,
            is_active: false,
        })
    }

    /// `false` si aucun profil avec cet id n'appartient à ce compte (jamais un profil d'un AUTRE
    /// compte — voir `WHERE id = ? AND user_id = ?`) : le handler renvoie alors 404, jamais une
    /// mise à jour silencieuse d'une ligne inexistante ou étrangère.
    pub async fn update(db: &SqlitePool, user_id: i64, id: &str, payload: &ThemeProfilePayload) -> Result<bool, AppError> {
        let result = sqlx::query(
            "UPDATE theme_customization_profiles SET
                name = ?, background_hue = ?, background_lightness = ?, background_saturation = ?,
                accent_hue = ?, accent_lightness = ?, accent_saturation = ?,
                danger_hue = ?, danger_lightness = ?, danger_saturation = ?,
                success_hue = ?, success_lightness = ?, success_saturation = ?,
                favorite_hue = ?, favorite_lightness = ?, favorite_saturation = ?
             WHERE id = ? AND user_id = ? AND pending_from_user_id IS NULL",
        )
        .bind(&payload.name)
        .bind(payload.background_hue)
        .bind(payload.background_lightness)
        .bind(payload.background_saturation)
        .bind(payload.accent_hue)
        .bind(payload.accent_lightness)
        .bind(payload.accent_saturation)
        .bind(payload.danger_hue)
        .bind(payload.danger_lightness)
        .bind(payload.danger_saturation)
        .bind(payload.success_hue)
        .bind(payload.success_lightness)
        .bind(payload.success_saturation)
        .bind(payload.favorite_hue)
        .bind(payload.favorite_lightness)
        .bind(payload.favorite_saturation)
        .bind(id)
        .bind(user_id)
        .execute(db)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn delete(db: &SqlitePool, user_id: i64, id: &str) -> Result<bool, AppError> {
        let result = sqlx::query("DELETE FROM theme_customization_profiles WHERE id = ? AND user_id = ? AND pending_from_user_id IS NULL")
            .bind(id)
            .bind(user_id)
            .execute(db)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Active CE profil et désactive tous les autres du même compte, de façon atomique (jamais
    /// deux profils actifs en même temps pour un compte). Vérifie l'appartenance AVANT toute
    /// écriture : si l'id n'appartient pas à ce compte, la transaction est abandonnée (`return`
    /// sans commit — rollback implicite au drop de `tx`) sans avoir désactivé les profils
    /// existants du compte pour rien.
    pub async fn activate(db: &SqlitePool, user_id: i64, id: &str) -> Result<bool, AppError> {
        let mut tx = db.begin().await?;

        let exists: Option<(String,)> = sqlx::query_as("SELECT id FROM theme_customization_profiles WHERE id = ? AND user_id = ? AND pending_from_user_id IS NULL")
            .bind(id)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
        if exists.is_none() {
            return Ok(false);
        }

        sqlx::query("UPDATE theme_customization_profiles SET is_active = 0 WHERE user_id = ? AND pending_from_user_id IS NULL")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE theme_customization_profiles SET is_active = 1 WHERE id = ? AND user_id = ?")
            .bind(id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(true)
    }
}

// =========================================================================
// PARTAGE DE PROFIL AVEC UN AUTRE UTILISATEUR — voir migration
// 20260924000000_fuse_shared_theme_profiles.sql et models.rs pour le détail du modèle. PAS de
// crypto (contrairement à SharingRepository pour le coffre) : une personnalisation de thème n'a
// rien à protéger, un partage est juste une ligne EN CLAIR en attente d'acceptation.
//
// Un partage EN ATTENTE est une ligne ORDINAIRE de theme_customization_profiles, déjà possédée
// par le DESTINATAIRE (`user_id`), avec `pending_from_user_id` renseigné tant qu'il n'est pas
// encore accepté (NULL = profil normal). Accepter devient un simple UPDATE qui efface cette
// colonne sur la ligne déjà là — plus de table séparée, plus de copie vers un nouvel id.
// =========================================================================

pub struct ThemeShareRepository;

impl ThemeShareRepository {
    /// Partage UN des profils du compte appelant (vérifie D'ABORD qu'il lui appartient bien ET
    /// qu'il n'est pas lui-même un partage encore en attente — comme ThemeProfileRepository::
    /// update/delete, mêmes garde-fous) avec `to_email` — copie ses valeurs telles quelles au
    /// moment du partage dans une NOUVELLE ligne possédée par le destinataire (pas un lien live
    /// vers le profil source). `None` si `profile_id` n'appartient pas au compte appelant, OU si
    /// `to_email` ne correspond à aucun compte existant (vérifié explicitement plutôt que de
    /// laisser échouer la contrainte FK — message d'erreur clair côté handler dans les deux cas,
    /// jamais une erreur SQL brute).
    pub async fn share(db: &SqlitePool, from_id: i64, profile_id: &str, to_email: &str) -> Result<Option<String>, AppError> {
        let profile: Option<ThemeProfileView> = sqlx::query_as(
            "SELECT id, name, background_hue, background_lightness, background_saturation, accent_hue, accent_lightness, accent_saturation,
                    danger_hue, danger_lightness, danger_saturation, success_hue, success_lightness, success_saturation,
                    favorite_hue, favorite_lightness, favorite_saturation, is_active
             FROM theme_customization_profiles WHERE id = ? AND user_id = ? AND pending_from_user_id IS NULL",
        )
        .bind(profile_id)
        .bind(from_id)
        .fetch_optional(db)
        .await?;
        let Some(profile) = profile else { return Ok(None) };

        // `to_email` reste un email (c'est ce que le client soumet, voir SharedThemeProfilePayload)
        // — résolu ici en id, plutôt qu'en amont dans le handler : cette fonction faisait déjà
        // cette vérification d'existence avant conversion, seul le SELECT change (id au lieu de 1).
        let recipient_id: Option<i64> = sqlx::query_scalar("SELECT id FROM users WHERE email = ?")
            .bind(to_email)
            .fetch_optional(db)
            .await?;
        let Some(to_id) = recipient_id else {
            return Ok(None);
        };

        // Volontairement AUCUN contrôle de plafond ici : un cadeau en attente ne doit pas bloquer
        // l'expéditeur ni compter contre le destinataire tant qu'il n'est pas accepté (voir
        // ThemeProfileRepository::count, qui exclut ces lignes) — le plafond ne s'applique qu'au
        // moment d'accept() ci-dessous, où le destinataire choisit réellement de le garder.
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO theme_customization_profiles
                (id, user_id, name, background_hue, background_lightness, background_saturation,
                 accent_hue, accent_lightness, accent_saturation, danger_hue, danger_lightness, danger_saturation,
                 success_hue, success_lightness, success_saturation, favorite_hue, favorite_lightness, favorite_saturation,
                 is_active, pending_from_user_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
        )
        .bind(&id)
        .bind(to_id)
        .bind(&profile.name)
        .bind(profile.background_hue)
        .bind(profile.background_lightness)
        .bind(profile.background_saturation)
        .bind(profile.accent_hue)
        .bind(profile.accent_lightness)
        .bind(profile.accent_saturation)
        .bind(profile.danger_hue)
        .bind(profile.danger_lightness)
        .bind(profile.danger_saturation)
        .bind(profile.success_hue)
        .bind(profile.success_lightness)
        .bind(profile.success_saturation)
        .bind(profile.favorite_hue)
        .bind(profile.favorite_lightness)
        .bind(profile.favorite_saturation)
        .bind(from_id)
        .execute(db)
        .await?;

        Ok(Some(id))
    }

    /// Tous les partages EN ATTENTE reçus par le compte appelant, du plus récent au plus ancien.
    pub async fn list_received(db: &SqlitePool, to_id: i64) -> Result<Vec<SharedThemeProfileView>, AppError> {
        sqlx::query_as::<_, SharedThemeProfileView>(
            "SELECT t.id, u.email AS from_email, t.name, t.background_hue, t.background_lightness, t.background_saturation,
                    t.accent_hue, t.accent_lightness, t.accent_saturation, t.danger_hue, t.danger_lightness, t.danger_saturation,
                    t.success_hue, t.success_lightness, t.success_saturation, t.favorite_hue, t.favorite_lightness, t.favorite_saturation
             FROM theme_customization_profiles t JOIN users u ON u.id = t.pending_from_user_id
             WHERE t.user_id = ? AND t.pending_from_user_id IS NOT NULL ORDER BY t.created_at DESC",
        )
        .bind(to_id)
        .fetch_all(db)
        .await
        .map_err(AppError::from)
    }

    /// Accepte un partage reçu : efface `pending_from_user_id` sur la ligne déjà possédée par le
    /// destinataire (soumis au même plafond que ThemeProfileRepository::create — `is_admin_caller`,
    /// même raison ; voir ThemeProfileRepository::count, qui exclut déjà les lignes en attente du
    /// décompte). `None` si le partage n'existe pas / n'est pas adressé à ce compte. `Err(...)` si
    /// le plafond de profils est atteint (le partage reste alors en attente, pas supprimé — le
    /// destinataire peut réessayer après avoir libéré de la place, voir
    /// handlers/theme_customization.rs). CORRECTIF (course concurrente) : l'existence, le plafond
    /// ET l'écriture se déroulent désormais dans UNE SEULE transaction.
    pub async fn accept(db: &SqlitePool, id: &str, to_id: i64, is_admin_caller: bool) -> Result<Option<ThemeProfileView>, AppError> {
        let mut tx = db.begin().await?;

        let exists: Option<(i64,)> = sqlx::query_as(
            "SELECT 1 FROM theme_customization_profiles WHERE id = ? AND user_id = ? AND pending_from_user_id IS NOT NULL",
        )
        .bind(id)
        .bind(to_id)
        .fetch_optional(&mut *tx)
        .await?;
        if exists.is_none() {
            return Ok(None);
        }

        if !is_admin_caller {
            // ThemeProfileRepository::count est privée, mais visible ici : les deux structs vivent
            // dans le même module `repository`, la visibilité Rust est scopée au module, pas au type.
            let existing = ThemeProfileRepository::count(&mut tx, to_id).await?;
            if existing >= MAX_PROFILES_PER_USER {
                return Err(AppError::ValidationError(format!(
                    "Limite de {MAX_PROFILES_PER_USER} profils de personnalisation atteinte — supprime-en un avant d'accepter ce partage."
                )));
            }
        }

        sqlx::query(
            "UPDATE theme_customization_profiles SET pending_from_user_id = NULL WHERE id = ? AND user_id = ? AND pending_from_user_id IS NOT NULL",
        )
        .bind(id)
        .bind(to_id)
        .execute(&mut *tx)
        .await?;

        let created: ThemeProfileView = sqlx::query_as(
            "SELECT id, name, background_hue, background_lightness, background_saturation, accent_hue, accent_lightness, accent_saturation,
                    danger_hue, danger_lightness, danger_saturation, success_hue, success_lightness, success_saturation,
                    favorite_hue, favorite_lightness, favorite_saturation, is_active
             FROM theme_customization_profiles WHERE id = ?",
        )
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(Some(created))
    }

    /// Refuse/retire un partage EN ATTENTE — L'UN OU L'AUTRE côté peut y mettre fin (l'expéditeur
    /// annule, ou le destinataire décline), même raisonnement que SharingRepository::revoke_share
    /// pour le coffre. `pending_from_user_id IS NOT NULL` est une garde CRITIQUE : sans elle, cette
    /// requête pourrait supprimer un profil déjà accepté (normal) du destinataire, puisque
    /// `user_id = caller_id` redeviendrait vrai après acceptation. `false` si `id` n'existe pas, si
    /// le partage a déjà été accepté, ou s'il n'implique ni `caller_id` comme expéditeur NI comme
    /// destinataire.
    pub async fn decline(db: &SqlitePool, id: &str, caller_id: i64) -> Result<bool, AppError> {
        let result = sqlx::query(
            "DELETE FROM theme_customization_profiles
             WHERE id = ? AND pending_from_user_id IS NOT NULL AND (pending_from_user_id = ? OR user_id = ?)",
        )
        .bind(id)
        .bind(caller_id)
        .bind(caller_id)
        .execute(db)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}

// =========================================================================
// TESTS — reencrypt_many / reencrypt_history_many / reencrypt_attachment_many
// =========================================================================
// Chemin critique (changement de mot de passe maître) réécrit en 2026-09 pour batcher ce qui
// était auparavant une boucle d'UPDATE un par un (voir handlers/auth/account.rs). Les tests
// existants de ce handler exercent la correction fonctionnelle avec 1 seule ligne, ce qui ne
// suffit PAS à couvrir : (1) le découpage en lots de CHUNK_SIZE (300) — une seule ligne ne
// traverse jamais une frontière de lot — et (2) l'isolation par utilisateur À L'INTÉRIEUR du
// nouveau SQL (`UPDATE ... FROM (VALUES ...)`), un terrain plus propice à une erreur de jointure
// silencieuse qu'un WHERE ligne par ligne. Vu qu'une régression ici perdrait des mots de passe
// de façon PERMANENTE et SILENCIEUSE (ré-chiffrement avec la mauvaise valeur, jamais détecté nulle
// part ensuite), ces deux angles sont testés directement contre le repository, sans passer par
// toute la pile HTTP (plus rapide : des centaines de lignes sans repasser par Argon2/JSON).
#[cfg(test)]
mod reencrypt_batch_tests {
    use super::*;
    use crate::models::{ReencryptedVaultEntry, ReencryptedHistoryEntry, ReencryptedVaultAttachment};
    use sqlx::sqlite::SqlitePoolOptions;

    async fn build_test_pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connexion à la BDD de test");
        sqlx::migrate!("./migrations").run(&pool).await.expect("migrations");
        pool
    }

    async fn seed_user(pool: &SqlitePool, email: &str) -> i64 {
        sqlx::query_scalar("INSERT INTO users (email, password_hash) VALUES (?, ?) RETURNING id")
            .bind(email)
            .bind("hash_non_pertinent")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn seed_vault_entry(pool: &SqlitePool, user_id: i64, id: &str) {
        sqlx::query(
            "INSERT INTO vault (id, encrypted_site_name, encrypted_password, encrypted_preferred_login_type, user_id)
             VALUES (?, 'site_initial', 'pw_initial', 'email', ?)"
        )
        .bind(id)
        .bind(user_id)
        .execute(pool)
        .await
        .unwrap();
    }

    /// RÉGRESSION PERF/SÉCURITÉ : un changement de mot de passe pour un compte proche de
    /// MAX_VAULT_ENTRIES_PER_USER traverse PLUSIEURS lots de CHUNK_SIZE (300) — ce test en couvre
    /// 3 (300 + 300 + 50 = 650) et vérifie que CHAQUE ligne, y compris la toute première et la
    /// toute dernière de chaque lot, reçoit bien SA PROPRE valeur re-chiffrée (pas celle d'une
    /// ligne voisine — le risque propre à `UPDATE ... FROM (VALUES ...)`, un simple `UPDATE ... SET
    /// x = ?` ne pourrait par construction écrire qu'UNE seule valeur partagée par toutes les
    /// lignes filtrées).
    #[tokio::test]
    async fn test_reencrypt_many_applies_distinct_values_across_chunk_boundaries() {
        let pool = build_test_pool().await;
        let user_id = seed_user(&pool, "multi@example.com").await;

        const N: usize = 650;
        let mut ids = Vec::with_capacity(N);
        for i in 0..N {
            let id = format!("entry-{i}");
            seed_vault_entry(&pool, user_id, &id).await;
            ids.push(id);
        }

        let payload: Vec<ReencryptedVaultEntry> = ids.iter().map(|id| ReencryptedVaultEntry {
            id: id.clone(),
            encrypted_site_name: format!("site-{id}"),
            encrypted_username: None,
            encrypted_login_email: None,
            encrypted_password: format!("pw-{id}"),
            encrypted_preferred_login_type: "email".to_string(),
            encrypted_folder: None,
            encrypted_notes: None,
            encrypted_url: None,
            encrypted_extra_fields: None,
        }).collect();

        let mut tx = pool.begin().await.unwrap();
        VaultRepository::reencrypt_many(&mut tx, user_id, &payload).await.expect("le ré-chiffrement en lots doit réussir");
        tx.commit().await.unwrap();

        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT id, encrypted_site_name, encrypted_password FROM vault WHERE user_id = ? ORDER BY id"
        )
        .bind(user_id)
        .fetch_all(&pool)
        .await
        .unwrap();

        assert_eq!(rows.len(), N, "aucune ligne ne doit être perdue ni dupliquée");
        for (id, site_name, password) in rows {
            assert_eq!(site_name, format!("site-{id}"), "ligne {id} : mauvaise valeur (contamination entre lignes/lots ?)");
            assert_eq!(password, format!("pw-{id}"), "ligne {id} : mauvaise valeur (contamination entre lignes/lots ?)");
        }
    }

    /// RÉGRESSION SÉCURITÉ CRITIQUE : `UPDATE ... FROM (VALUES ...)` doit rester scopé par
    /// `user_id` exactement comme l'ancienne boucle ligne par ligne (`WHERE id = ? AND
    /// user_id = ?`). Simule un id qui, par bug côté client ou tentative malveillante,
    /// désignerait l'entrée d'un AUTRE utilisateur : la ligne de la victime ne doit JAMAIS être
    /// modifiée, et l'opération entière doit échouer (id inconnu pour l'appelant).
    #[tokio::test]
    async fn test_reencrypt_many_never_touches_another_users_row() {
        let pool = build_test_pool().await;
        let attacker_id = seed_user(&pool, "attacker@example.com").await;
        let victim_id = seed_user(&pool, "victim@example.com").await;
        seed_vault_entry(&pool, victim_id, "victim-entry").await;

        let payload = vec![ReencryptedVaultEntry {
            id: "victim-entry".to_string(), // n'appartient PAS à attacker@example.com
            encrypted_site_name: "site_pirate".to_string(),
            encrypted_username: None,
            encrypted_login_email: None,
            encrypted_password: "pw_pirate".to_string(),
            encrypted_preferred_login_type: "email".to_string(),
            encrypted_folder: None,
            encrypted_notes: None,
            encrypted_url: None,
            encrypted_extra_fields: None,
        }];

        let mut tx = pool.begin().await.unwrap();
        let result = VaultRepository::reencrypt_many(&mut tx, attacker_id, &payload).await;
        assert!(result.is_err(), "un id n'appartenant pas à l'appelant doit échouer, pas être appliqué silencieusement");
        tx.rollback().await.unwrap();

        let victim_password: String = sqlx::query_scalar("SELECT encrypted_password FROM vault WHERE id = 'victim-entry'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(victim_password, "pw_initial", "la ligne de la victime ne doit avoir SUBI AUCUNE modification");
    }

    /// Même angle "franchit un lot" que le test vault ci-dessus, mais pour vault_password_history
    /// (SQL séparé, donc risque de typo/erreur distinct) — 350 lignes traversent la frontière du
    /// premier lot de 300.
    #[tokio::test]
    async fn test_reencrypt_history_many_applies_distinct_values_across_chunk_boundary() {
        let pool = build_test_pool().await;
        let user_id = seed_user(&pool, "histmulti@example.com").await;
        seed_vault_entry(&pool, user_id, "owner-entry").await;

        const N: usize = 350;
        let mut ids = Vec::with_capacity(N);
        for i in 0..N {
            let id = format!("hist-{i}");
            sqlx::query(
                "INSERT INTO vault_password_history (id, vault_id, user_id, encrypted_password) VALUES (?, 'owner-entry', ?, 'old_pw')"
            )
            .bind(&id)
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
            ids.push(id);
        }

        let payload: Vec<ReencryptedHistoryEntry> = ids.iter().map(|id| ReencryptedHistoryEntry {
            id: id.clone(),
            encrypted_password: format!("new-{id}"),
        }).collect();

        let mut tx = pool.begin().await.unwrap();
        VaultRepository::reencrypt_history_many(&mut tx, user_id, &payload).await.expect("doit réussir");
        tx.commit().await.unwrap();

        let rows: Vec<(String, String)> = sqlx::query_as("SELECT id, encrypted_password FROM vault_password_history ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(rows.len(), N);
        for (id, password) in rows {
            assert_eq!(password, format!("new-{id}"), "ligne {id} : mauvaise valeur");
        }
    }

    /// Même angle, pour vault_attachments (troisième SQL séparé).
    #[tokio::test]
    async fn test_reencrypt_attachment_many_applies_distinct_values_across_chunk_boundary() {
        let pool = build_test_pool().await;
        let user_id = seed_user(&pool, "attmulti@example.com").await;
        seed_vault_entry(&pool, user_id, "owner-entry").await;

        const N: usize = 350;
        let mut ids = Vec::with_capacity(N);
        for i in 0..N {
            let id = format!("att-{i}");
            sqlx::query(
                "INSERT INTO vault_attachments (id, vault_id, user_id, encrypted_filename, encrypted_content, content_size) VALUES (?, 'owner-entry', ?, 'old_name', 'old_content', 1)"
            )
            .bind(&id)
            .bind(user_id)
            .execute(&pool)
            .await
            .unwrap();
            ids.push(id);
        }

        let payload: Vec<ReencryptedVaultAttachment> = ids.iter().map(|id| ReencryptedVaultAttachment {
            id: id.clone(),
            encrypted_filename: format!("name-{id}"),
            encrypted_content: format!("content-{id}"),
        }).collect();

        let mut tx = pool.begin().await.unwrap();
        VaultRepository::reencrypt_attachment_many(&mut tx, user_id, &payload).await.expect("doit réussir");
        tx.commit().await.unwrap();

        let rows: Vec<(String, String, String)> = sqlx::query_as("SELECT id, encrypted_filename, encrypted_content FROM vault_attachments ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(rows.len(), N);
        for (id, filename, content) in rows {
            assert_eq!(filename, format!("name-{id}"), "ligne {id} : mauvais nom de fichier");
            assert_eq!(content, format!("content-{id}"), "ligne {id} : mauvais contenu");
        }
    }
}