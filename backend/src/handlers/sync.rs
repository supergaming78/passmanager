use axum::{
    extract::{ws::{WebSocket, WebSocketUpgrade, Message}, State, Query},
    response::IntoResponse,
    Json,
};
use std::sync::Arc;
use serde::Deserialize;
use sqlx::Row;
use crate::{AppState, error::AppError, crypto, middleware::AuthUser};

// --- SYNCHRONISATION TEMPS RÉEL (WEBSOCKET) ---
//
// Ce canal ne sert QUE de signal de réveil : "quelque chose a changé dans ton coffre, va
// re-synchroniser via les routes REST habituelles" (GET /vault, GET /api/vault/sync...). Il ne
// transporte JAMAIS de contenu chiffré ni de données du coffre — ça garde le modèle
// Zero-Knowledge intact et évite de dupliquer toute la logique d'auth/pagination ici.
//
// AUTHENTIFICATION PAR TICKET À USAGE UNIQUE (`?ticket=...`), PAS PAR L'ACCESS TOKEN DIRECT :
// L'API WebSocket native des navigateurs ne permet PAS de définir l'en-tête `Authorization` lors
// de l'ouverture d'une connexion (contrainte du standard, pas un choix de conception ici) — un
// secret doit donc transiter dans l'URL. Plutôt que d'y mettre l'access token JWT complet (qui
// reste valide sur TOUTE l'API REST pendant ~10 min et pourrait fuiter via des logs
// d'infrastructure intermédiaires — proxy, load balancer, APM), le client échange d'abord son
// access token contre un ticket à usage unique et très courte durée de vie (60s) via
// POST /ws/ticket (authentifié normalement, par en-tête Authorization). Un ticket qui fuiterait
// dans des logs ne serait donc utilisable ni une seconde fois, ni pour appeler le reste de l'API.
//
// RÉ-AUTHENTIFICATION EN COURS DE CONNEXION : le ticket n'est vérifié qu'à l'ouverture, jamais
// ré-évalué pendant la durée de vie (potentiellement longue) de la connexion WebSocket. C'est un
// choix assumé, pas un oubli : c'est exactement le même modèle que le reste de l'API REST, où
// `AuthUser` (middleware.rs) ne revérifie à chaque requête que la signature du JWT et l'existence
// du compte, jamais une éventuelle révocation d'appareil entre-temps. La fenêtre d'exposition
// réelle reste bornée par la durée de vie courte des access tokens (10 min par défaut), et le
// canal ne transporte de toute façon qu'un signal, jamais de contenu du coffre.

/// Nombre maximum de connexions WebSocket simultanées autorisées par utilisateur, tous appareils
/// confondus. Protection contre l'accumulation incontrôlée de connexions (buggées ou abusives) :
/// chaque connexion garde un `subscribe()` ouvert sur le canal broadcast partagé (voir AppState).
const MAX_WS_CONNECTIONS_PER_USER: u32 = 10;

#[derive(Deserialize)]
pub struct WsAuthParams {
    pub ticket: String, // Ticket à usage unique obtenu via POST /ws/ticket, PAS l'access token
}

/// Échange l'access token du client (Bearer, comme pour le reste du REST) contre un ticket à
/// usage unique et de très courte durée de vie, destiné exclusivement à l'ouverture de `/ws`
/// (voir le commentaire en tête de fichier). Seul le hash SHA-256 du ticket est stocké en BDD —
/// même logique que `refresh_tokens.token` — pour qu'une fuite de la base ne permette pas de le
/// rejouer.
pub async fn create_ws_ticket(
    State(state): State<Arc<AppState>>,
    user: AuthUser,
) -> Result<impl IntoResponse, AppError> {
    let ticket = crypto::create_refresh_token();
    let ticket_hash = crypto::hash_token(&ticket);
    let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(60))
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string();

    sqlx::query("INSERT INTO ws_tickets (ticket_hash, user_email, expires_at) VALUES (?, ?, ?)")
        .bind(&ticket_hash)
        .bind(&user.email)
        .bind(&expires_at)
        .execute(&state.db)
        .await?;

    Ok(Json(serde_json::json!({ "ticket": ticket, "expires_in": 60 })))
}

/// Point d'entrée HTTP qui bascule la connexion en WebSocket après authentification par ticket.
pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Query(params): Query<WsAuthParams>,
) -> Result<impl IntoResponse, AppError> {
    let ticket_hash = crypto::hash_token(&params.ticket);

    // Lecture + suppression atomique (RETURNING), même principe que refresh() pour les refresh
    // tokens : le ticket ne peut servir qu'UNE SEULE fois, qu'il soit valide ou déjà expiré.
    let row = sqlx::query(
        "DELETE FROM ws_tickets
         WHERE ticket_hash = ?
         AND expires_at > STRFTIME('%Y-%m-%dT%H:%M:%SZ', 'now')
         RETURNING user_email"
    )
    .bind(&ticket_hash)
    .fetch_optional(&state.db)
    .await?;

    let email: String = match row {
        Some(r) => r.get("user_email"),
        None => return Err(AppError::SessionExpired),
    };

    // Limite de connexions simultanées par utilisateur (voir MAX_WS_CONNECTIONS_PER_USER).
    // Le compteur est incrémenté ET le garde qui le décrémentera est construit ICI, d'un seul
    // tenant (voir WsConnectionGuard::acquire) — CORRECTIF : l'incrément se faisait auparavant ici
    // mais le garde n'était créé que DANS handle_socket, qui ne s'exécute QUE si l'upgrade aboutit
    // vraiment. Si la connexion mourait entre la réponse 101 et l'upgrade effectif, le compteur
    // n'était jamais décrémenté ; au bout de MAX_WS_CONNECTIONS_PER_USER occurrences, le compte ne
    // pouvait PLUS JAMAIS ouvrir de WebSocket jusqu'au redémarrage du serveur. En le déplaçant
    // dans la closure passée à on_upgrade, le garde est détruit — donc le compteur décrémenté —
    // même si cette closure n'est jamais appelée et se contente d'être libérée.
    let guard = WsConnectionGuard::acquire(&state, &email)?;

    // Abonnement au signal d'arrêt AVANT l'upgrade : voir handle_socket() plus bas et le
    // commentaire sur with_graceful_shutdown() dans main.rs.
    let shutdown_rx = state.shutdown_tx.subscribe();

    Ok(ws.on_upgrade(move |socket| handle_socket(socket, state, email, shutdown_rx, guard)))
}

/// Décrémente le compteur de connexions WebSocket actives de l'utilisateur à la fin de
/// handle_socket(), quel que soit le chemin de sortie (déconnexion normale, erreur, arrêt du
/// serveur...) — implémenté via `Drop` pour ne jamais l'oublier sur un des multiples `break`.
struct WsConnectionGuard {
    state: Arc<AppState>,
    email: String,
}

impl WsConnectionGuard {
    /// Réserve une place dans le quota de connexions de cet utilisateur et renvoie le garde qui la
    /// rendra. Incrément et construction du garde sont indissociables : tout chemin de sortie
    /// après un `Ok(...)` détruira le garde, donc décrémentera — voir l'appel dans ws_handler().
    fn acquire(state: &Arc<AppState>, email: &str) -> Result<Self, AppError> {
        // `unwrap_or_else(|e| e.into_inner())` plutôt que `.unwrap()` : un Mutex de la lib standard
        // devient EMPOISONNÉ si un thread panique en le tenant, et tout `.lock().unwrap()` ultérieur
        // paniquerait à son tour — plus aucune connexion WebSocket possible jusqu'au redémarrage,
        // et pire, la panique du Drop ci-dessous surviendrait pendant un déroulement de pile
        // (double panique = abort du processus entier). Les données protégées ici ne sont qu'un
        // compteur ; les reprendre telles quelles après une panique est sans danger.
        let mut connections = state.ws_connections.lock().unwrap_or_else(|e| e.into_inner());
        let count = connections.entry(email.to_string()).or_insert(0);
        if *count >= MAX_WS_CONNECTIONS_PER_USER {
            return Err(AppError::Conflict("Trop de connexions WebSocket actives pour ce compte".to_string()));
        }
        *count += 1;
        drop(connections);

        Ok(Self { state: state.clone(), email: email.to_string() })
    }
}

impl Drop for WsConnectionGuard {
    fn drop(&mut self) {
        // Même raisonnement que dans acquire() ci-dessus pour le Mutex empoisonné — ici c'est
        // encore plus important : paniquer dans un Drop pendant un déroulement de pile abort le
        // processus.
        let mut connections = self.state.ws_connections.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = connections.get_mut(&self.email) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                connections.remove(&self.email);
            }
        }
    }
}

/// Boucle de vie d'une connexion WebSocket : relaie les SyncEvent destinés à cet utilisateur,
/// et se termine proprement à la déconnexion du client (fermeture explicite, erreur réseau...)
/// OU à l'arrêt du serveur (voir la branche `shutdown_rx` ci-dessous).
async fn handle_socket(
    mut socket: WebSocket,
    state: Arc<AppState>,
    email: String,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    // Réservé par ws_handler() AVANT l'upgrade et transmis ici pour qu'il vive aussi longtemps que
    // la connexion — voir WsConnectionGuard::acquire().
    _guard: WsConnectionGuard,
) {
    let mut rx = state.sync_tx.subscribe();

    loop {
        tokio::select! {
            // Un événement de synchro a été diffusé quelque part dans l'app
            event = rx.recv() => {
                match event {
                    Ok(evt) if evt.user_email == email => {
                        // Filtre : seuls les événements de CET utilisateur l'intéressent (le
                        // canal est partagé par tous les utilisateurs connectés).
                        let is_session_revoked = evt.event_type == "SESSION_REVOKED";
                        let payload = match serde_json::to_string(&evt) {
                            Ok(p) => p,
                            Err(_) => continue,
                        };
                        if socket.send(Message::Text(payload.into())).await.is_err() {
                            break; // Le client a fermé la connexion pendant l'envoi
                        }
                        // logout_all_devices() (devices.rs) a révoqué toutes les sessions de cet
                        // utilisateur : contrairement aux autres événements (simple signal de
                        // resynchronisation), celui-ci doit fermer la connexion elle-même, sinon
                        // elle resterait ouverte indéfiniment malgré la révocation — le ticket
                        // n'est vérifié qu'à l'ouverture (voir le commentaire en tête de fichier),
                        // rien d'autre ne la fermerait avant la déconnexion volontaire du client.
                        if is_session_revoked {
                            let _ = socket.send(Message::Close(None)).await;
                            break;
                        }
                    }
                    Ok(_) => continue, // Événement pour un AUTRE utilisateur : ignoré
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue, // Voir commentaire sur la capacité du canal dans main.rs
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            // Messages entrants du client (ping/pong gérés automatiquement par axum, on ne
            // s'intéresse ici qu'à détecter une fermeture explicite ou une erreur réseau).
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {} // Autres types de message (ping/pong/binaire) : ignorés
                }
            }
            // Le serveur a reçu un signal d'arrêt (Ctrl+C, SIGTERM de Docker...). Sans cette
            // branche, cette boucle ne se termine JAMAIS de son propre chef — elle n'attend que
            // le client ou une erreur réseau — et `axum::serve(...).with_graceful_shutdown(...)`
            // resterait bloqué à attendre la fin de CETTE tâche jusqu'au timeout forcé (SIGKILL)
            // si un appareil était connecté au moment de l'arrêt. On ferme donc proprement ici.
            _ = shutdown_rx.recv() => {
                let _ = socket.send(Message::Close(None)).await;
                break;
            }
        }
    }
}

// =========================================================================
// TESTS SUR LES TICKETS WEBSOCKET
// =========================================================================
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
        })
    }

    async fn register_test_user(state: &Arc<AppState>, email: &str) {
        sqlx::query("INSERT INTO users (email, password_hash, email_verified) VALUES (?, ?, 1)")
            .bind(email)
            .bind("hash_non_pertinent_pour_ce_test")
            .execute(&state.db)
            .await
            .expect("l'insertion de l'utilisateur de test doit réussir");
    }

    /// create_ws_ticket() doit produire un ticket dont seul le hash est stocké en BDD (jamais
    /// le ticket en clair), avec une expiration future.
    #[tokio::test]
    async fn test_create_ws_ticket_stores_only_the_hash() {
        let state = build_test_state().await;
        let email = "wsticket@example.com";
        register_test_user(&state, email).await;

        let result = create_ws_ticket(State(state.clone()), AuthUser { email: email.to_string(), is_moderator: false })
            .await
            .expect("la création du ticket doit réussir");
        let value = read_json_body(result.into_response()).await;
        let ticket = value["ticket"].as_str().expect("un ticket doit être renvoyé").to_string();

        let stored_hash: String = sqlx::query_scalar("SELECT ticket_hash FROM ws_tickets WHERE user_email = ?")
            .bind(email)
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_ne!(stored_hash, ticket, "la BDD ne doit jamais stocker le ticket en clair");
        assert_eq!(stored_hash, crypto::hash_token(&ticket), "la BDD doit stocker le hash SHA-256 du ticket");
    }

    /// Un ticket doit être à usage unique : la première consommation (simulée directement en
    /// BDD, comme le ferait ws_handler) doit le supprimer, une deuxième tentative doit échouer.
    #[tokio::test]
    async fn test_ws_ticket_is_single_use() {
        let state = build_test_state().await;
        let email = "singleuse@example.com";
        register_test_user(&state, email).await;

        let result = create_ws_ticket(State(state.clone()), AuthUser { email: email.to_string(), is_moderator: false })
            .await
            .expect("la création du ticket doit réussir");
        let ticket = read_json_body(result.into_response()).await["ticket"].as_str().unwrap().to_string();
        let ticket_hash = crypto::hash_token(&ticket);

        // Première consommation : doit trouver et supprimer la ligne
        let row = sqlx::query(
            "DELETE FROM ws_tickets WHERE ticket_hash = ? AND expires_at > STRFTIME('%Y-%m-%dT%H:%M:%SZ', 'now') RETURNING user_email"
        )
        .bind(&ticket_hash)
        .fetch_optional(&state.db)
        .await
        .unwrap();
        assert!(row.is_some(), "la première consommation du ticket doit réussir");

        // Deuxième consommation (rejeu) : la ligne n'existe plus
        let replay = sqlx::query(
            "DELETE FROM ws_tickets WHERE ticket_hash = ? AND expires_at > STRFTIME('%Y-%m-%dT%H:%M:%SZ', 'now') RETURNING user_email"
        )
        .bind(&ticket_hash)
        .fetch_optional(&state.db)
        .await
        .unwrap();
        assert!(replay.is_none(), "rejouer un ticket déjà consommé doit échouer");
    }

    /// La requête de consommation d'un ticket JAMAIS émis ne doit rien trouver — même requête
    /// SQL que ws_handler(), qui n'est pas directement testable ici : `WebSocketUpgrade` ne peut
    /// pas être construit à la main hors d'une vraie requête HTTP avec en-têtes d'upgrade.
    #[tokio::test]
    async fn test_consuming_unknown_ticket_finds_nothing() {
        let state = build_test_state().await;
        let row = sqlx::query(
            "DELETE FROM ws_tickets WHERE ticket_hash = ? AND expires_at > STRFTIME('%Y-%m-%dT%H:%M:%SZ', 'now') RETURNING user_email"
        )
        .bind(crypto::hash_token("ticket-jamais-emis"))
        .fetch_optional(&state.db)
        .await
        .unwrap();
        assert!(row.is_none(), "un ticket jamais émis ne doit jamais être accepté");
    }

    async fn read_json_body(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("lecture du corps de la réponse");
        serde_json::from_slice(&bytes).expect("le corps doit être du JSON valide")
    }
}
