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
