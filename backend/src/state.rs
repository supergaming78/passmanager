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
}

impl AppState {
    /// Service d'enregistrement des logs d'audit de sécurité.
    /// Écrit l'action dans la console de log structurée et l'insère simultanément
    /// en base de données pour un suivi immuable des accès utilisateurs.
    pub async fn log_audit(&self, email: &str, action: &str, ip: String, user_agent: Option<String>) {
        // Log d'information ciblé
        info!(target: "audit", user = %email, action = %action, ip = %ip, agent = ?user_agent);

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
