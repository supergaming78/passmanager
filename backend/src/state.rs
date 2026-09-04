use jsonwebtoken::{EncodingKey, DecodingKey};
use std::{collections::HashMap, sync::{Arc, Mutex}};
use tracing::{info, error};
use crate::{config::Config, models};

// =========================================================================
// ÉTAT GLOBAL DE L'APPLICATION (APPLICATION STATE)
// =========================================================================

/// Cette structure contient toutes les ressources partagées qui doivent être
/// accessibles par les différents gestionnaires de routes (handlers) de l'API.
pub struct AppState {
    pub db: sqlx::SqlitePool,       // Le pool de connexions à la base de données SQLite
    pub encoding_key: EncodingKey,  // Clé pour générer/signer les jetons JWT
    pub decoding_key: DecodingKey,  // Clé pour lire/valider les jetons JWT
    pub app_env: String,            // L'environnement (ex: "production", "development")
    pub config: Config,             // La configuration globale chargée au démarrage
    // Canal broadcast EN MÉMOIRE (jamais persisté) : diffuse un SyncEvent à toutes les connexions
    // WebSocket ouvertes quand un utilisateur modifie son coffre, pour que ses AUTRES appareils
    // sachent se re-synchroniser sans avoir à interroger check_sync en boucle (polling).
    pub sync_tx: tokio::sync::broadcast::Sender<models::SyncEvent>,
    // Diffusé une seule fois, au tout début de l'arrêt du serveur (voir main.rs::shutdown_signal()) :
    // permet à chaque connexion WebSocket longue durée (handlers/sync.rs::handle_socket) de se
    // fermer proprement d'elle-même, plutôt que de bloquer with_graceful_shutdown() jusqu'au
    // timeout forcé (SIGKILL par Docker) si des appareils étaient connectés au moment de l'arrêt.
    pub shutdown_tx: tokio::sync::broadcast::Sender<()>,
    // Compteur de connexions WebSocket actives par utilisateur (voir handlers/sync.rs), pour
    // empêcher l'accumulation illimitée de connexions (buggées ou abusives) sur le canal
    // broadcast partagé ci-dessus.
    pub ws_connections: Arc<Mutex<HashMap<String, u32>>>,
    // Base de géolocalisation hors ligne, chargée UNE fois au démarrage et gardée en mémoire
    // (voir geoip.rs). Inerte tant que GEOIP_DATABASE_PATH n'est pas configuré. Aucune requête
    // réseau n'est émise, ni au chargement ni à la consultation.
    pub geoip: Arc<crate::geoip::GeoIpResolver>,
}

impl AppState {
    /// Service d'enregistrement des logs d'audit de sécurité.
    /// Écrit l'action dans la console de log structurée et l'insère simultanément
    /// en base de données pour un suivi immuable des accès utilisateurs.
    pub async fn log_audit(&self, email: &str, action: &str, ip: String, user_agent: Option<String>) {
        // Log d'information ciblé
        info!(target: "audit", user = %email, action = %action, ip = %ip, agent = ?user_agent);

        // Copie prise AVANT que `ip` ne soit consommé par le bind de l'insertion ci-dessous.
        let ip_for_history = ip.clone();

        // Insertion en BDD de l'historique d'action (contient l'appareil / l'User-Agent de l'appelant)
        // CORRECTIF : un échec ici (BDD verrouillée/disque plein/etc.) était auparavant totalement
        // silencieux — GET /audit afficherait alors un historique incomplet sans que rien, nulle
        // part dans les logs, ne signale que des entrées manquent. On journalise désormais l'échec
        // (le message d'audit lui-même reste dans le log structuré ci-dessus dans tous les cas,
        // donc rien n'est perdu même si l'écriture en base échoue).
        if let Err(e) = sqlx::query("INSERT INTO audit_logs (user_email, action, ip_address, user_agent) VALUES (?, ?, ?, ?)")
            .bind(email)
            .bind(action)
            .bind(ip)
            .bind(user_agent)
            .execute(&self.db)
            .await
        {
            error!(target: "audit", user = %email, action = %action, error = %e, "échec de l'insertion en base de l'entrée d'audit (le log structuré ci-dessus reste, lui, disponible)");
        }

        self.record_ip_seen(email, action, &ip_for_history).await;
    }

    /// Mémorise qu'une adresse a été vue pour un compte — table `account_ip_history`, qui SURVIT à
    /// la purge du journal d'audit (voir la migration 20260904120000_account_ip_history.sql).
    ///
    /// Séparé de l'insertion ci-dessus parce que les deux répondent à des questions différentes :
    /// `audit_logs` garde des ÉVÉNEMENTS récents en détail, celle-ci garde une MÉMOIRE longue et
    /// compacte des adresses. Sans elle, une adresse revenant tous les quinze jours paraîtrait
    /// neuve à chaque fois — précisément le cas qu'on cherche à repérer.
    ///
    /// Le décompte succès/échec est le vrai signal : beaucoup d'échecs PUIS une réussite depuis la
    /// même adresse est la signature d'une intrusion réussie par tâtonnement, qu'une IP nue ne
    /// permet pas de distinguer d'un usage normal.
    ///
    /// Best-effort, comme l'insertion d'audit : une écriture qui échoue ne doit jamais faire
    /// échouer l'action de l'utilisateur (une connexion, typiquement). La clé étrangère vers
    /// `users` fait aussi qu'un événement concernant un compte inexistant est simplement ignoré.
    async fn record_ip_seen(&self, email: &str, action: &str, ip: &str) {
        let is_success = matches!(action, "LOGIN" | "LOGIN_SUCCESS" | "LOGIN_SUCCESS_REMEMBER" | "LOGIN_SUCCESS_SESSION");
        let is_failure = matches!(
            action,
            "LOGIN_FAILED" | "LOGIN_BLOCKED_TOO_MANY_ATTEMPTS" | "LOGIN_BLOCKED_UNVERIFIED" | "LOGIN_BLOCKED_SUSPENDED"
        );

        // `first_seen` n'est PAS touché par le UPDATE : c'est toute sa valeur — savoir depuis quand
        // cette adresse existe pour ce compte. `last_seen` et les compteurs, eux, avancent.
        let result = sqlx::query(
            "INSERT INTO account_ip_history                  (user_email, ip_address, first_seen, last_seen, event_count, success_count, failure_count)              VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1, ?, ?)              ON CONFLICT(user_email, ip_address) DO UPDATE SET                  last_seen = CURRENT_TIMESTAMP,                  event_count = event_count + 1,                  success_count = success_count + excluded.success_count,                  failure_count = failure_count + excluded.failure_count",
        )
        .bind(email)
        .bind(ip)
        .bind(i64::from(is_success))
        .bind(i64::from(is_failure))
        .execute(&self.db)
        .await;

        if let Err(e) = result {
            error!(target: "audit", user = %email, error = %e, "échec de la mise à jour de l'historique IP du compte");
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

    /// log_audit() doit insérer une ligne exploitable dans audit_logs.
    #[tokio::test]
    async fn test_log_audit_inserts_a_row() {
        let pool = build_test_pool().await;
        sqlx::query("INSERT INTO users (email, password_hash) VALUES (?, ?)")
            .bind("audituser@example.com")
            .bind("hash_non_pertinent")
            .execute(&pool)
            .await
            .unwrap();

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
        let state = AppState {
            encoding_key: EncodingKey::from_secret(config.jwt_secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(config.jwt_secret.as_bytes()),
            app_env: config.app_env.clone(),
            db: pool,
            config,
            sync_tx: tokio::sync::broadcast::channel(16).0,
            shutdown_tx: tokio::sync::broadcast::channel(1).0,
            ws_connections: Default::default(),
            geoip: Arc::new(crate::geoip::GeoIpResolver::load(None)),
        };

        state.log_audit("audituser@example.com", "TEST_ACTION", "127.0.0.1".to_string(), Some("test-agent".to_string())).await;

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE user_email = ? AND action = ?")
            .bind("audituser@example.com")
            .bind("TEST_ACTION")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(count, 1, "log_audit doit insérer exactement une ligne en BDD");
    }
}
