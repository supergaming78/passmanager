// =========================================================================
// TÂCHES DE FOND (CRON) ET BOOTSTRAP DE DÉMARRAGE
// =========================================================================
// Regroupe tout ce qui n'est PAS le chemin de requête HTTP normal : le nettoyage périodique
// (appelé en boucle par la tâche `tokio::spawn` dans main.rs) et le bootstrap admin (appelé une
// fois au démarrage). Extrait de main.rs pour que ce dernier reste centré sur le bootstrap de
// l'application (router, état, écoute réseau) plutôt que sur cette logique métier annexe.

use tracing::{info, error};

/// Supprime définitivement de la base de données tous les Refresh Tokens expirés.
pub async fn cleanup_expired_tokens(db: &sqlx::SqlitePool) {
    // IMPORTANT : on utilise STRFTIME au même format ISO ('%Y-%m-%dT%H:%M:%SZ') que celui utilisé
    // partout ailleurs (login, refresh...) pour stocker expires_at. L'ancienne version comparait
    // avec DATETIME('now','utc') qui produit "2026-07-27 10:00:00" (espace) au lieu de
    // "2026-07-27T10:00:00Z" (T + Z) — une comparaison de CHAÎNES entre ces deux formats échoue
    // silencieusement pour les tokens qui expirent le jour même (le nettoyage les ratait d'un jour).
    let result = sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < STRFTIME('%Y-%m-%dT%H:%M:%SZ', 'now')")
        .execute(db)
        .await;

    // Si la requête réussit et qu'au moins une ligne a été supprimée, on l'écrit dans les logs de maintenance
    if let Ok(res) = result {
        let count = res.rows_affected();
        if count > 0 {
            info!("Audit Système : Nettoyage de {} jetons expirés complété.", count);
        }
    }
}

/// Purge DÉFINITIVEMENT les entrées du coffre passées à la corbeille depuis plus de 30 jours.
/// `deleted_at` est toujours écrit via CURRENT_TIMESTAMP (format natif SQLite, "espace" et non
/// "T"/"Z"), et DATETIME('now', '-30 days') produit ce MÊME format — contrairement au bug corrigé
/// sur `cleanup_expired_tokens`, la comparaison ici est cohérente des deux côtés.
pub async fn purge_old_trashed_vault_entries(db: &sqlx::SqlitePool) {
    let result = sqlx::query("DELETE FROM vault WHERE deleted_at IS NOT NULL AND deleted_at < DATETIME('now', '-30 days')")
        .execute(db)
        .await;

    if let Ok(res) = result {
        let count = res.rows_affected();
        if count > 0 {
            info!("Corbeille : {} entrée(s) du coffre purgée(s) définitivement après 30 jours.", count);
        }
    }
}

/// Supprime les tickets WebSocket expirés (voir handlers/sync.rs::create_ws_ticket) jamais
/// consommés — sans purge, un client qui demande un ticket puis n'ouvre jamais la connexion
/// laisserait une ligne morte en BDD indéfiniment (elle expire de toute façon après 60s côté
/// utilisation, ceci n'est qu'un nettoyage de ménage).
pub async fn cleanup_expired_ws_tickets(db: &sqlx::SqlitePool) {
    let result = sqlx::query("DELETE FROM ws_tickets WHERE expires_at < STRFTIME('%Y-%m-%dT%H:%M:%SZ', 'now')")
        .execute(db)
        .await;

    if let Ok(res) = result {
        let count = res.rows_affected();
        if count > 0 {
            info!("Nettoyage de {} ticket(s) WebSocket expiré(s).", count);
        }
    }
}

/// Durée de conservation du journal d'audit EN BASE DE DONNÉES, en jours.
///
/// Choisie volontairement courte (demande explicite de l'utilisateur) : sans purge, `audit_logs`
/// grossissait indéfiniment — chaque connexion, copie de mot de passe, partage... y ajoute une
/// ligne à vie, alourdissant la base ET chaque sauvegarde.
///
/// IMPORTANT — ceci ne détruit PAS la trace d'audit : chaque entrée est AUSSI émise dans le
/// journal structuré de l'application (voir state.rs::log_audit, `info!(target: "audit", ...)`),
/// écrit dans les fichiers de log du serveur avec sa propre rotation. Cette purge ne réduit donc
/// que la fenêtre consultable depuis l'application (`GET /audit` et `GET /audit/me`) ; l'historique
/// plus ancien reste disponible dans les fichiers de log pour une investigation.
///
/// Contrepartie à connaître : au-delà de cette fenêtre, l'écran "Historique" ne montre plus rien —
/// par exemple, au retour de trois semaines d'absence, impossible d'y vérifier qui s'est connecté
/// pendant ce temps. Augmenter cette seule constante suffit à allonger la rétention.
const AUDIT_LOG_RETENTION_DAYS: i64 = 10;

/// Purge les entrées du journal d'audit plus vieilles que `AUDIT_LOG_RETENTION_DAYS`.
///
/// `created_at` est écrit par CURRENT_TIMESTAMP (format natif SQLite : "AAAA-MM-JJ HH:MM:SS",
/// avec une ESPACE) et `DATETIME('now', '-N days')` produit exactement le MÊME format — la
/// comparaison de chaînes est donc cohérente des deux côtés. C'est précisément le piège qui avait
/// causé un bug sur `cleanup_expired_tokens` (voir son commentaire) : là-bas `expires_at` est
/// stocké au format ISO "T...Z", incompatible avec DATETIME(). Ne pas transposer l'un à l'autre.
pub async fn purge_old_audit_logs(db: &sqlx::SqlitePool) {
    let cutoff = format!("-{AUDIT_LOG_RETENTION_DAYS} days");

    let result = sqlx::query("DELETE FROM audit_logs WHERE created_at < DATETIME('now', ?)")
        .bind(&cutoff)
        .execute(db)
        .await;

    match result {
        Ok(res) => {
            let count = res.rows_affected();
            if count > 0 {
                info!(
                    "Journal d'audit : {} entrée(s) purgée(s) après {} jours de conservation (elles restent dans les fichiers de log).",
                    count, AUDIT_LOG_RETENTION_DAYS
                );
            }
        }
        // Volontairement non bloquant, comme les autres nettoyages : un échec ne doit jamais
        // interrompre le cycle de maintenance, mais ne doit pas non plus passer inaperçu.
        Err(e) => error!("Échec de la purge du journal d'audit : {:?}", e),
    }
}

/// Nombre maximal d'adresses distinctes conservées PAR COMPTE dans `account_ip_history`.
///
/// Contrairement au journal d'audit, cette table n'a volontairement PAS de limite de temps : c'est
/// tout son intérêt (savoir qu'une adresse était déjà connue il y a six mois). La borne est donc en
/// nombre, pas en durée — elle n'existe que pour empêcher une croissance sans fin si un attaquant
/// fait tourner ses adresses. 500 dépasse de très loin l'usage réel : même une connexion mobile
/// qui change d'adresse à chaque session met des années à l'atteindre.
const MAX_IPS_PER_ACCOUNT: i64 = 500;

/// Élague `account_ip_history` en gardant les `MAX_IPS_PER_ACCOUNT` adresses les plus récemment
/// vues de chaque compte.
///
/// Élaguer ici plutôt qu'à chaque écriture est délibéré : `record_ip_seen()` est appelée sur le
/// chemin critique de CHAQUE connexion, et y ajouter un DELETE avec sous-requête coûterait à
/// chaque fois pour un cas qui ne se produit presque jamais.
///
/// `last_seen DESC, rowid DESC` : `last_seen` n'a qu'une précision à la seconde en SQLite, donc
/// deux adresses vues dans la même seconde seraient départagées arbitrairement sans second
/// critère — même motif que la fenêtre glissante de `trusted_device_ips`.
pub async fn prune_account_ip_history(db: &sqlx::SqlitePool) {
    let result = sqlx::query(
        "DELETE FROM account_ip_history WHERE rowid NOT IN (
             SELECT rowid FROM account_ip_history AS keep
              WHERE keep.user_email = account_ip_history.user_email
              ORDER BY keep.last_seen DESC, keep.rowid DESC
              LIMIT ?
         )",
    )
    .bind(MAX_IPS_PER_ACCOUNT)
    .execute(db)
    .await;

    match result {
        Ok(res) => {
            let count = res.rows_affected();
            if count > 0 {
                info!(
                    "Historique IP : {} adresse(s) élaguée(s) au-delà des {} plus récentes par compte.",
                    count, MAX_IPS_PER_ACCOUNT
                );
            }
        }
        Err(e) => error!("Échec de l'élagage de l'historique IP : {:?}", e),
    }
}

/// Supprime les comptes jamais vérifiés (voir handlers/auth/register.rs) trop anciens : sans ça,
/// quelqu'un pourrait s'inscrire avec l'email de quelqu'un d'autre et squatter indéfiniment cette
/// adresse (le vrai propriétaire se heurterait à un conflit d'inscription pour toujours). 24h
/// laisse largement le temps de cliquer un lien reçu par email.
pub async fn cleanup_stale_unverified_accounts(db: &sqlx::SqlitePool) {
    let result = sqlx::query(
        "DELETE FROM users WHERE email_verified = 0 AND created_at < DATETIME('now', '-24 hours')"
    )
        .execute(db)
        .await;

    if let Ok(res) = result {
        let count = res.rows_affected();
        if count > 0 {
            info!("Nettoyage de {} compte(s) jamais vérifié(s) après 24h.", count);
        }
    }
}

/// Laisse SQLite mettre à jour ses statistiques de planification (`PRAGMA optimize`).
///
/// OPTIMISATION : sans statistiques, le planificateur de requêtes choisit ses index sur de simples
/// heuristiques ("cet index est probablement sélectif"). C'est sans conséquence sur une base
/// quasi vide, mais dès qu'un coffre grossit — ou qu'un compte pèse beaucoup plus lourd que les
/// autres — ces suppositions peuvent l'amener à préférer un index moins efficace. `PRAGMA optimize`
/// est la forme recommandée depuis SQLite 3.18 : il ne lance un `ANALYZE` que sur les tables dont
/// les statistiques sont réellement absentes ou périmées, et ne fait donc RIEN la plupart du temps
/// (coût nul en régime établi, contrairement à un `ANALYZE` complet qu'il ne faut pas planifier
/// aveuglément).
///
/// Appelé dans le même cycle de 30 minutes que les nettoyages ci-dessus (voir main.rs) : aucune
/// tâche supplémentaire, et la fréquence est largement suffisante pour ce type de statistiques.
pub async fn optimize_query_planner(db: &sqlx::SqlitePool) {
    if let Err(e) = sqlx::query("PRAGMA optimize").execute(db).await {
        // Volontairement non bloquant : ce n'est qu'une optimisation, jamais une condition de
        // bon fonctionnement — on trace et on continue.
        error!("Échec de PRAGMA optimize (sans conséquence fonctionnelle) : {:?}", e);
    }
}

/// Promeut modérateur le compte correspondant à `admin_email` (ADMIN_EMAIL), s'il existe déjà —
/// voir aussi handlers/auth/register.rs::register(), qui gère le cas symétrique où le compte
/// s'inscrit APRÈS que la variable d'environnement a été définie. Extraite en fonction séparée
/// (plutôt qu'inline dans `main()`, jamais exécuté par les tests) pour rester testable.
/// Ce compte reste par ailleurs LE SEUL "Admin" (voir `AuthUser::is_admin()`, calculé — jamais
/// stocké) : cette fonction ne fait que garantir qu'il passe aussi la porte "au moins modérateur",
/// pas qu'il devienne un second admin.
pub async fn promote_configured_admin(db: &sqlx::SqlitePool, admin_email: &str) {
    let result = sqlx::query("UPDATE users SET is_moderator = 1 WHERE email = ?")
        .bind(admin_email)
        .execute(db)
        .await;

    match result {
        Ok(res) if res.rows_affected() > 0 => {
            info!("Compte Admin promu modérateur via ADMIN_EMAIL : {}", admin_email);
        }
        Ok(_) => {
            info!("ADMIN_EMAIL défini ({}) mais aucun compte correspondant pour l'instant — sera promu automatiquement à l'inscription.", admin_email);
        }
        Err(e) => {
            error!("Échec de la promotion admin via ADMIN_EMAIL : {:?}", e);
        }
    }
}

// =========================================================================
// TESTS
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn build_test_pool() -> sqlx::SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("connexion à la BDD de test");

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .expect("échec des migrations sur la BDD de test");

        pool
    }

    /// Régression du bug de format de date corrigé : un token qui expire AUJOURD'HUI (donc
    /// même partie date que 'now', ce qui faisait échouer l'ancienne comparaison de chaînes
    /// DATETIME('now','utc') vs le format ISO 'T...Z' stocké) doit bien être nettoyé, tout en
    /// laissant intact un token encore valide.
    #[tokio::test]
    async fn test_cleanup_expired_tokens_removes_expired_even_same_day() {
        let pool = build_test_pool().await;
        sqlx::query("INSERT INTO users (email, password_hash) VALUES (?, ?)")
            .bind("cleanup@example.com")
            .bind("hash_non_pertinent")
            .execute(&pool)
            .await
            .unwrap();

        // Expiré il y a 1 minute, LE JOUR MÊME (c'est précisément le cas que l'ancien bug ratait)
        let expired_today = (chrono::Utc::now() - chrono::Duration::minutes(1))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        sqlx::query("INSERT INTO refresh_tokens (token, user_email, device_id, expires_at, is_persistent) VALUES (?, ?, ?, ?, ?)")
            .bind("token-expire-aujourdhui")
            .bind("cleanup@example.com")
            .bind("device-expire")
            .bind(&expired_today)
            .bind(false)
            .execute(&pool)
            .await
            .unwrap();

        // Encore valide (expire dans 1h)
        let valid_later = (chrono::Utc::now() + chrono::Duration::hours(1))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        sqlx::query("INSERT INTO refresh_tokens (token, user_email, device_id, expires_at, is_persistent) VALUES (?, ?, ?, ?, ?)")
            .bind("token-encore-valide")
            .bind("cleanup@example.com")
            .bind("device-valide")
            .bind(&valid_later)
            .bind(false)
            .execute(&pool)
            .await
            .unwrap();

        cleanup_expired_tokens(&pool).await;

        let remaining_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(remaining_count, 1, "seul le token encore valide doit rester après le nettoyage");

        let remaining_token: String = sqlx::query_scalar("SELECT token FROM refresh_tokens")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(remaining_token, "token-encore-valide");
    }

    /// purge_old_trashed_vault_entries() doit supprimer DÉFINITIVEMENT une entrée en corbeille
    /// depuis plus de 30 jours, mais laisser intactes celles supprimées plus récemment.
    #[tokio::test]
    async fn test_purge_old_trashed_vault_entries_removes_only_entries_older_than_30_days() {
        let pool = build_test_pool().await;
        sqlx::query("INSERT INTO users (email, password_hash) VALUES (?, ?)")
            .bind("trashowner@example.com")
            .bind("hash_non_pertinent")
            .execute(&pool)
            .await
            .unwrap();

        // Entrée passée à la corbeille il y a 40 jours -> doit être purgée
        sqlx::query(
            "INSERT INTO vault (id, encrypted_site_name, encrypted_password, encrypted_preferred_login_type, user_email, deleted_at)
             VALUES (?, ?, ?, ?, ?, DATETIME('now', '-40 days'))"
        )
        .bind("id-vieux-dechet")
        .bind("VieuxSite")
        .bind("chiffre")
        .bind("email")
        .bind("trashowner@example.com")
        .execute(&pool)
        .await
        .unwrap();

        // Entrée passée à la corbeille il y a seulement 5 jours -> doit rester (encore récupérable)
        sqlx::query(
            "INSERT INTO vault (id, encrypted_site_name, encrypted_password, encrypted_preferred_login_type, user_email, deleted_at)
             VALUES (?, ?, ?, ?, ?, DATETIME('now', '-5 days'))"
        )
        .bind("id-recent-dechet")
        .bind("SiteRecent")
        .bind("chiffre")
        .bind("email")
        .bind("trashowner@example.com")
        .execute(&pool)
        .await
        .unwrap();

        // Entrée ACTIVE (pas dans la corbeille) -> ne doit jamais être touchée par cette purge
        sqlx::query(
            "INSERT INTO vault (id, encrypted_site_name, encrypted_password, encrypted_preferred_login_type, user_email)
             VALUES (?, ?, ?, ?, ?)"
        )
        .bind("id-actif")
        .bind("SiteActif")
        .bind("chiffre")
        .bind("email")
        .bind("trashowner@example.com")
        .execute(&pool)
        .await
        .unwrap();

        purge_old_trashed_vault_entries(&pool).await;

        let remaining_ids: Vec<String> = sqlx::query_scalar("SELECT id FROM vault ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(
            remaining_ids,
            vec!["id-actif".to_string(), "id-recent-dechet".to_string()],
            "seule l'entrée vieille de 40 jours dans la corbeille doit avoir été purgée"
        );
    }

    /// cleanup_expired_ws_tickets() doit supprimer un ticket expiré mais laisser un ticket
    /// encore valide intact.
    #[tokio::test]
    async fn test_cleanup_expired_ws_tickets_removes_only_expired() {
        let pool = build_test_pool().await;
        sqlx::query("INSERT INTO users (email, password_hash) VALUES (?, ?)")
            .bind("wsticketowner@example.com")
            .bind("hash_non_pertinent")
            .execute(&pool)
            .await
            .unwrap();

        let expired_at = (chrono::Utc::now() - chrono::Duration::minutes(1)).format("%Y-%m-%dT%H:%M:%SZ").to_string();
        sqlx::query("INSERT INTO ws_tickets (ticket_hash, user_email, expires_at) VALUES (?, ?, ?)")
            .bind("hash-expire")
            .bind("wsticketowner@example.com")
            .bind(expired_at)
            .execute(&pool)
            .await
            .unwrap();

        let valid_at = (chrono::Utc::now() + chrono::Duration::minutes(1)).format("%Y-%m-%dT%H:%M:%SZ").to_string();
        sqlx::query("INSERT INTO ws_tickets (ticket_hash, user_email, expires_at) VALUES (?, ?, ?)")
            .bind("hash-valide")
            .bind("wsticketowner@example.com")
            .bind(valid_at)
            .execute(&pool)
            .await
            .unwrap();

        cleanup_expired_ws_tickets(&pool).await;

        let remaining: Vec<String> = sqlx::query_scalar("SELECT ticket_hash FROM ws_tickets")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(remaining, vec!["hash-valide".to_string()], "seul le ticket encore valide doit rester");
    }

    /// cleanup_stale_unverified_accounts() doit supprimer un compte non vérifié inscrit il y a
    /// plus de 24h, mais laisser intacts un compte non vérifié récent et un compte vérifié ancien.
    #[tokio::test]
    async fn test_cleanup_stale_unverified_accounts_removes_only_old_unverified() {
        let pool = build_test_pool().await;

        sqlx::query("INSERT INTO users (email, password_hash, email_verified, created_at) VALUES (?, ?, 0, DATETIME('now', '-2 days'))")
            .bind("stale-unverified@example.com")
            .bind("hash")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (email, password_hash, email_verified, created_at) VALUES (?, ?, 0, DATETIME('now'))")
            .bind("fresh-unverified@example.com")
            .bind("hash")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (email, password_hash, email_verified, created_at) VALUES (?, ?, 1, DATETIME('now', '-2 days'))")
            .bind("old-but-verified@example.com")
            .bind("hash")
            .execute(&pool)
            .await
            .unwrap();

        cleanup_stale_unverified_accounts(&pool).await;

        let remaining: Vec<String> = sqlx::query_scalar("SELECT email FROM users ORDER BY email")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(
            remaining,
            vec!["fresh-unverified@example.com".to_string(), "old-but-verified@example.com".to_string()],
            "seul le compte non vérifié ET vieux de plus de 24h doit avoir été supprimé"
        );
    }

    /// purge_old_audit_logs() ne doit supprimer QUE les entrées au-delà de la fenêtre de
    /// conservation, et laisser intactes les récentes (celles que l'écran "Historique" affiche).
    #[tokio::test]
    async fn test_purge_old_audit_logs_removes_only_entries_past_retention() {
        let pool = build_test_pool().await;
        sqlx::query("INSERT INTO users (email, password_hash) VALUES (?, ?)")
            .bind("audit-retention@example.com")
            .bind("hash_non_pertinent")
            .execute(&pool)
            .await
            .unwrap();

        // Une entrée nettement au-delà de la fenêtre, une nettement en deçà, et une pile à la
        // limite mais du bon côté (la veille de l'échéance) — cette dernière garde le test honnête
        // si quelqu'un remplace `<` par `<=` ou se trompe d'un jour.
        let cases: [(&str, i64); 3] = [
            ("VIEUX", AUDIT_LOG_RETENTION_DAYS + 5),
            ("LIMITE_OK", AUDIT_LOG_RETENTION_DAYS - 1),
            ("RECENT", 0),
        ];
        for (action, days_ago) in cases {
            sqlx::query(
                "INSERT INTO audit_logs (user_email, action, ip_address, created_at)
                 VALUES (?, ?, ?, DATETIME('now', ?))"
            )
            .bind("audit-retention@example.com")
            .bind(action)
            .bind("127.0.0.1")
            .bind(format!("-{days_ago} days"))
            .execute(&pool)
            .await
            .unwrap();
        }

        purge_old_audit_logs(&pool).await;

        let remaining: Vec<String> = sqlx::query_scalar("SELECT action FROM audit_logs ORDER BY action")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(
            remaining,
            vec!["LIMITE_OK".to_string(), "RECENT".to_string()],
            "seule l'entrée au-delà de la fenêtre de conservation doit être purgée"
        );
    }

    /// optimize_query_planner() ne doit jamais échouer ni paniquer sur une base normale.
    #[tokio::test]
    async fn test_optimize_query_planner_runs_without_error() {
        let pool = build_test_pool().await;
        optimize_query_planner(&pool).await; // ne doit pas paniquer
        let still_usable: i64 = sqlx::query_scalar("SELECT 1").fetch_one(&pool).await.unwrap();
        assert_eq!(still_usable, 1, "la base doit rester parfaitement utilisable après PRAGMA optimize");
    }

    /// RÉGRESSION DE PERFORMANCE : verrouille les deux gains mesurés par la migration
    /// 20260903080000_vault_covering_index.sql, qu'un simple remaniement d'index ferait perdre
    /// SILENCIEUSEMENT (aucun test fonctionnel ne verrait la différence — seule la latence
    /// changerait). On interroge directement le planificateur de SQLite via EXPLAIN QUERY PLAN.
    #[tokio::test]
    async fn test_vault_index_avoids_temp_sort_and_covers_sync_check() {
        let pool = build_test_pool().await;

        // 1. Le listage du coffre (GET /vault) ne doit plus trier dans une table temporaire.
        // EXPLAIN QUERY PLAN renvoie 4 colonnes (id, parent, notused, detail) — seule `detail`
        // contient le texte du plan.
        let list_plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
            "EXPLAIN QUERY PLAN
             SELECT id, is_favorite FROM vault
             WHERE user_email = 'a' AND deleted_at IS NULL
             ORDER BY is_favorite DESC LIMIT 100"
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        let list_plan = list_plan.into_iter().map(|r| r.3).collect::<Vec<_>>().join(" | ");
        assert!(
            !list_plan.contains("TEMP B-TREE"),
            "le listage du coffre ne doit pas retrier en table temporaire — plan obtenu : {list_plan}"
        );

        // 2. La vérification de synchro (appelée en boucle par chaque appareil) doit se satisfaire
        // de l'index seul, sans jamais ouvrir la table.
        let sync_plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
            "EXPLAIN QUERY PLAN
             SELECT COUNT(*), MAX(updated_at) FROM vault
             WHERE user_email = 'a' AND deleted_at IS NULL"
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        let sync_plan = sync_plan.into_iter().map(|r| r.3).collect::<Vec<_>>().join(" | ");
        assert!(
            sync_plan.contains("COVERING INDEX"),
            "la vérification de synchro doit être servie par un index couvrant — plan obtenu : {sync_plan}"
        );
    }

    /// promote_configured_admin() doit promouvoir le compte correspondant s'il existe déjà,
    /// et ne rien casser (pas de panique) si aucun compte ne correspond encore à ADMIN_EMAIL.
    #[tokio::test]
    async fn test_promote_configured_admin_promotes_existing_account() {
        let pool = build_test_pool().await;
        sqlx::query("INSERT INTO users (email, password_hash) VALUES (?, ?)")
            .bind("futureadmin@example.com")
            .bind("hash_non_pertinent")
            .execute(&pool)
            .await
            .unwrap();

        // Aucun compte ne correspond encore : ne doit pas paniquer
        promote_configured_admin(&pool, "personne-inscrite@example.com").await;

        promote_configured_admin(&pool, "futureadmin@example.com").await;

        let is_moderator: bool = sqlx::query_scalar("SELECT is_moderator FROM users WHERE email = ?")
            .bind("futureadmin@example.com")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(is_moderator, "le compte correspondant à ADMIN_EMAIL doit être promu modérateur");
    }
}
