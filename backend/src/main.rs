// `middleware as axum_middleware` : le module local `middleware.rs` (voir `mod middleware;` plus
// bas, AuthUser & co) occupe déjà ce nom — évite un conflit E0255 entre les deux.
use axum::{routing::{post, get, put, patch, delete}, Router, http::header::*, http::{HeaderName, HeaderValue, StatusCode}, extract::{DefaultBodyLimit, Request, State, ConnectInfo}, middleware as axum_middleware, response::Response, error_handling::HandleErrorLayer, BoxError, Json};
use sqlx::sqlite::{SqlitePoolOptions, SqliteConnectOptions};
use std::{sync::Arc, sync::Mutex, collections::HashMap, net::{SocketAddr, IpAddr}, str::FromStr, time::Duration};
use tower::ServiceBuilder;
use tower_http::{cors::{CorsLayer, AllowOrigin}, trace::TraceLayer, set_header::SetResponseHeaderLayer, compression::CompressionLayer};
use jsonwebtoken::{EncodingKey, DecodingKey};
mod config;
use crate::config::Config;
use tracing::info;
use tower_governor::GovernorLayer;
use tower_governor::key_extractor::{KeyExtractor, PeerIpKeyExtractor, SmartIpKeyExtractor};
use tower_governor::errors::GovernorError;

// Déclaration des modules qui composent l'application
mod crypto;
mod mailer;
mod models;
mod handlers;
mod middleware;
mod error;
mod repository;
mod state;
mod maintenance;
pub use state::AppState;

// =========================================================================
// FONCTION PRINCIPALE (ASYNC MAIN)
// =========================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ecriture volontairement la toute premiere ligne de main(). Constate en conteneur
    // (Docker Desktop / WSL2, pas en execution native Windows) : sans aucune ecriture sur
    // stdout/stderr avant que le process n'ouvre son port d'ecoute, le conteneur se termine
    // silencieusement (exit code 0, zero sortie, duree de vie ~100ms) de facon reproductible.
    // Cause exacte non confirmee (piste : course au demarrage cote reseau virtualise WSL2),
    // mais cette ecriture precoce sur stderr (non bufferise, contrairement a stdout hors TTY)
    // suffit a l'eviter de facon fiable sur plusieurs demarrages consecutifs testes.
    eprintln!("backend: starting up...");

    // Charge les variables d'environnement depuis un fichier `.env` s'il existe
    dotenvy::dotenv().ok();

    // Initialise et valide la configuration de l'application
    let config = Config::from_env();

    // Configuration du système de logs "tournant" : crée un fichier `server.json` par jour dans
    // `./logs`. CORRECTIF DISQUE (repéré en relecture, pas par un incident réel — mais l'espace
    // disque disponible est très limité sur le serveur cible) : `rolling::daily(dir, prefix)`, la
    // fonction utilitaire SIMPLE utilisée auparavant, crée bien un nouveau fichier chaque jour mais
    // n'en supprime JAMAIS d'anciens — ./logs aurait grossi INDÉFINIMENT, un fichier de plus par
    // jour, pour toujours. `RollingFileAppender::builder().max_log_files(14)` : mêmes fichiers
    // produits (même préfixe "server.json", même rotation quotidienne), mais purge automatiquement
    // le plus ancien dès qu'un 15e existerait — 14 jours de logs (~2 semaines) largement suffisant
    // pour diagnostiquer un problème récent, sans laisser ce dossier grossir sans fin.
    let file_appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("server.json")
        .max_log_files(14)
        .build("./logs")
        .expect("échec de l'initialisation du système de logs tournant (./logs)");
    // Rend l'écriture dans le fichier asynchrone (non-bloquante pour le thread principal)
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // CORRECTIF OPÉRATIONNEL (repéré face à un vrai déploiement Portainer bloqué en "Restarting"
    // sans le moindre log visible) : jusqu'ici, `.with_writer(non_blocking)` seul envoyait TOUS
    // les logs applicatifs UNIQUEMENT dans le fichier `./logs/` À L'INTÉRIEUR du conteneur —
    // jamais sur stdout/stderr, qui est la SEULE chose que `docker logs`/Portainer capturent.
    // Résultat concret : même une app qui tourne PARFAITEMENT ne montrerait jamais rien dans
    // Portainer, et pire, un plantage AU DÉMARRAGE (ex: permissions refusées sur le volume
    // ./data, un scénario réel documenté dans le README) devenait totalement invisible depuis
    // l'outil que quiconque déploie via Portainer utiliserait en premier pour diagnostiquer.
    // `.and(std::io::stdout)` (voir MakeWriterExt) : écrit le MÊME flux aux DEUX destinations —
    // le fichier tournant reste pour un historique persistant/analyse ultérieure, stdout pour une
    // visibilité immédiate via `docker logs`/Portainer, sans perdre l'un pour l'autre.
    use tracing_subscriber::fmt::writer::MakeWriterExt;
    let dual_writer = non_blocking.and(std::io::stdout);

    // Initialisation du sous-système de logs au format JSON pour l'analyse automatisée
    tracing_subscriber::fmt()
        .with_writer(dual_writer)
        .json()
        .with_current_span(true)
        .with_span_list(true)
        .init();

    // Récupération des secrets de configuration
    let db_url = &config.database_url;
    let jwt_secret = &config.jwt_secret;

    // `create_if_missing(true)` plus bas crée le FICHIER de BDD s'il manque, mais jamais les
    // dossiers PARENTS manquants (ex: DATABASE_URL=sqlite:data/vault.db si "data/" n'existe pas
    // encore) — sans ce correctif, un tout premier `cargo run` local (en dehors de Docker, où le
    // Dockerfile crée déjà /app/data explicitement) échoue avec une erreur SQLite peu explicite.
    if let Some(path) = sqlite_file_path(db_url) {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
    }

    // Configuration avancée de la connexion SQLite pour maximiser la sécurité et la vitesse
    let conn_options = SqliteConnectOptions::from_str(db_url)?
        .create_if_missing(true) // Crée automatiquement le fichier de BDD s'il n'existe pas
        .busy_timeout(std::time::Duration::from_secs(5)) // Évite le verrouillage immédiat en écriture
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal) // Mode "Write-Ahead Logging" performant pour les accès concurrents
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        // `PRAGMA foreign_keys` est PAR CONNEXION en SQLite (jamais persisté dans le fichier) —
        // sqlx l'active déjà par défaut sur chaque connexion du pool, mais on le rend explicite
        // ici : c'est de lui que dépendent les `ON UPDATE/DELETE CASCADE` (ex: update_email(),
        // qui compte sur la propagation automatique vers `vault`/`refresh_tokens`/etc.), donc ce
        // n'est pas le genre de comportement qu'on veut laisser reposer sur un défaut implicite
        // d'une lib tierce qui pourrait changer un jour.
        .foreign_keys(true);

    // Initialisation du Pool de connexions. Le nombre de connexions n'aide QUE la contention en
    // LECTURE (le mode WAL les gère bien) : SQLite reste de toute façon à un seul écrivain à la
    // fois, augmenter ce nombre n'accélère donc pas les écritures. 10 reste très raisonnable pour
    // l'usage visé (un utilisateur + son app + son extension, potentiellement quelques comptes).
    let db = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(conn_options)
        .await?;

    // Exécute automatiquement les fichiers SQL de migration contenus dans le dossier `./migrations`
    sqlx::migrate!("./migrations").run(&db).await?;

    // Bootstrap admin (voir Config::admin_email / ADMIN_EMAIL) : couvre le cas d'un compte déjà
    // inscrit AVANT que la variable d'environnement ne soit définie — register() gère lui-même
    // le cas d'une inscription APRÈS (voir handlers/auth/register.rs::register()).
    if let Some(admin_email) = &config.admin_email {
        maintenance::promote_configured_admin(&db, admin_email).await;
    }

    // -------------------------------------------------------------------------
    // CRON JOB / TÂCHE DE FOND (NETTOYAGE) — voir maintenance.rs
    // -------------------------------------------------------------------------
    let db_for_cleanup = db.clone();
    // Lance un thread asynchrone indépendant (Worker) en arrière-plan
    tokio::spawn(async move {
        // Crée un intervalle qui se déclenche toutes les 1800 secondes (30 minutes)
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(1800));
        loop {
            interval.tick().await; // Attend le prochain cycle
            // Exécute le nettoyage des jetons expirés en base de données
            maintenance::cleanup_expired_tokens(&db_for_cleanup).await;
            maintenance::purge_old_trashed_vault_entries(&db_for_cleanup).await;
            maintenance::cleanup_expired_ws_tickets(&db_for_cleanup).await;
            maintenance::cleanup_stale_unverified_accounts(&db_for_cleanup).await;
        }
    });

    // Centralisation de l'état de l'application enveloppé dans un Arc (pointeur partagé sécurisé)
    // Canal broadcast pour la synchro temps réel (voir AppState::sync_tx). Capacité de 1024 :
    // si un consommateur (une connexion WebSocket) prend trop de retard, les plus vieux messages
    // sont abandonnés pour lui (RecvError::Lagged) plutôt que de bloquer les autres — ce n'est
    // qu'un signal de réveil, pas un flux de données à livrer garanti, donc c'est sans danger :
    // le client concerné se reconnectera et re-synchronisera via les routes REST habituelles.
    let (sync_tx, _) = tokio::sync::broadcast::channel::<models::SyncEvent>(1024);
    // Capacité 1 suffit : diffusé une seule fois, juste avant que with_graceful_shutdown()
    // commence à attendre les connexions en cours (voir plus bas et handlers/sync.rs).
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

    let state = Arc::new(AppState {
        db,
        encoding_key: EncodingKey::from_secret(jwt_secret.as_bytes()),
        decoding_key: DecodingKey::from_secret(jwt_secret.as_bytes()),
        app_env: config.app_env.clone(),
        config: config.clone(),
        sync_tx,
        shutdown_tx: shutdown_tx.clone(),
        ws_connections: Arc::new(Mutex::new(HashMap::new())),
    });

    let app = build_router(state);

    // -------------------------------------------------------------------------
    // DÉMARRAGE DU SERVEUR
    // -------------------------------------------------------------------------
    let addr = config.get_addr();
    println!("🚀 Serveur démarré en mode [{}] sur {}", config.app_env, addr);

    // Initialise l'écouteur TCP sur l'adresse et le port définis
    let listener = tokio::net::TcpListener::bind(addr).await?;
    // Démarre l'écoute et sert l'application web via Axum.
    // `with_graceful_shutdown` laisse les requêtes en cours se terminer proprement
    // au lieu de les couper brutalement à la réception d'un SIGINT/SIGTERM
    // (essentiel en conteneur : Docker/k8s envoient un SIGTERM à l'arrêt/déploiement).
    //
    // IMPORTANT : une connexion WebSocket (handlers/sync.rs) est volontairement longue durée et
    // n'attend NI un signal d'arrêt NI rien d'autre que la déconnexion du client ou une erreur
    // réseau — sans le `shutdown_tx.send(())` ci-dessous, un appareil connecté au moment d'un
    // `docker stop` ferait attendre with_graceful_shutdown() indéfiniment (jusqu'au SIGKILL
    // forcé par Docker) au lieu de couper proprement dans les temps. On diffuse donc le signal
    // AVANT de laisser with_graceful_shutdown() attendre la fin des connexions en cours, pour
    // que chaque handle_socket() en cours ait la chance de se fermer proprement de lui-même.
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            let _ = shutdown_tx.send(());
        })
        .await?;

    Ok(())
}

/// Extracteur de clé de rate limiting dont le comportement bascule à l'exécution selon
/// `Config::trust_proxy_headers`, plutôt que de coder en dur l'un des deux extracteurs fournis
/// par `tower_governor` : `GovernorConfigBuilder` fige le type de l'extracteur à la
/// COMPILATION (paramètre générique, voir tower_governor::governor::GovernorConfigBuilder), donc
/// un seul type concret doit couvrir les deux cas plutôt que de dupliquer toute la construction
/// du routeur derrière un `if`.
///
/// - `trust_proxy_headers == false` (défaut) : délègue à [`PeerIpKeyExtractor`], qui lit l'IP du
///   pair TCP direct. C'est le seul choix sûr sans reverse proxy devant ce backend — un client
///   qui parle directement au serveur ne peut pas mentir sur cette IP.
/// - `trust_proxy_headers == true` : délègue à [`SmartIpKeyExtractor`], qui lit
///   `X-Forwarded-For`/`X-Real-Ip`/`Forwarded`. À n'activer QUE derrière un reverse proxy de
///   confiance qui écrase systématiquement ces en-têtes avant de les transmettre — sinon
///   n'importe quel client peut les positionner lui-même pour obtenir un budget de rate limiting
///   séparé à volonté, contournant entièrement la protection (voir Config::trust_proxy_headers).
#[derive(Clone, Copy)]
struct ConfigurableIpKeyExtractor {
    trust_proxy_headers: bool,
}

impl KeyExtractor for ConfigurableIpKeyExtractor {
    type Key = std::net::IpAddr;

    fn extract<T>(&self, req: &axum::http::Request<T>) -> Result<Self::Key, GovernorError> {
        if self.trust_proxy_headers {
            SmartIpKeyExtractor.extract(req)
        } else {
            PeerIpKeyExtractor.extract(req)
        }
    }
}

/// Middleware qui RÉÉCRIT l'extension `ConnectInfo<SocketAddr>` de la requête avec l'IP réelle du
/// client, lue dans `X-Forwarded-For`/`X-Real-Ip` — uniquement si `Config::trust_proxy_headers`
/// est activé (même garde-fou que [`ConfigurableIpKeyExtractor`] ci-dessus, pour la même raison :
/// sans reverse proxy de confiance qui écrase ces en-têtes, n'importe quel client pourrait s'y
/// attribuer l'IP de son choix).
///
/// CORRECTIF (repéré par l'utilisateur lui-même face à un vrai déploiement derrière Nginx Proxy
/// Manager — voir la conversation du 2026-09-01) : `ConfigurableIpKeyExtractor` ne corrige QUE la
/// clé utilisée par le rate limiter (tower_governor) — chaque HANDLER, lui, continue de recevoir
/// `ConnectInfo<SocketAddr>` directement via l'extracteur Axum standard pour tout ce qui est
/// ENREGISTRÉ EN BASE ou AFFICHÉ à l'utilisateur : IP dans le journal d'audit, IP associée à un
/// appareil de confiance (voir handlers/auth/session.rs::record_device_ip_and_maybe_alert),
/// alertes "nouvel appareil/nouvelle IP". Derrière un reverse proxy, `ConnectInfo` ne voit QUE
/// l'IP du proxy — IDENTIQUE pour CHAQUE requête de CHAQUE client réel, quel qu'il soit. Résultat
/// concret avant ce correctif : historique de sécurité et appareils de confiance rendus inutiles
/// (impossible de distinguer un vrai nouvel appareil d'un autre, toutes les IP enregistrées étant
/// la même).
///
/// Plutôt que de modifier individuellement CHAQUE handler (des dizaines, listés ci-dessus) pour
/// leur faire lire l'en-tête eux-mêmes, ce middleware réécrit directement l'extension que TOUS
/// consultent déjà de la même façon — correctif centralisé en un seul endroit, aucun changement
/// nécessaire dans les handlers ni dans leurs tests (qui insèrent `ConnectInfo` manuellement, voir
/// `test_addr()` plus bas). Le port de l'adresse réécrite est arbitraire (0) : aucun handler de ce
/// projet ne lit jamais le port de `ConnectInfo`, seulement `.ip()`.
async fn rewrite_client_ip_from_proxy_headers(State(state): State<Arc<AppState>>, mut req: Request, next: axum_middleware::Next) -> Response {
    if state.config.trust_proxy_headers {
        let forwarded_ip = req.headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            // X-Forwarded-For peut contenir une chaîne "client, proxy1, proxy2, ..." si plusieurs
            // proxys se sont succédé — le PREMIER élément est le client d'origine, seul cas
            // pertinent ici (un unique reverse proxy de confiance, NPM, juste devant ce backend).
            .and_then(|v| v.split(',').next())
            .map(|v| v.trim())
            .and_then(|v| v.parse::<IpAddr>().ok())
            .or_else(|| {
                req.headers()
                    .get("x-real-ip")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.trim().parse::<IpAddr>().ok())
            });

        if let Some(ip) = forwarded_ip {
            req.extensions_mut().insert(ConnectInfo(SocketAddr::new(ip, 0)));
        }
    }
    next.run(req).await
}

/// Construit le Router complet de l'application : routes, rate limiting par palier, CORS,
/// limites de taille de requête (globale + overrides par route), en-têtes de sécurité,
/// compression, timeout. Extrait de `main()` pour être réutilisable tel quel par les tests
/// d'intégration de bout en bout (voir le module `tests` en bas de ce fichier) : sans cette
/// extraction, ces tests ne pourraient exercer que les handlers pris isolément (comme le fait déjà
/// chaque module de tests unitaires du projet), jamais la VRAIE pile de middlewares Tower qui les
/// enveloppe en production (rate limiting, limites de taille par route, CORS, en-têtes...).
fn build_router(state: Arc<AppState>) -> Router {
    // Configuration de la limitation de requêtes (Rate Limiting), en PLUSIEURS paliers plutôt
    // qu'un seul budget partagé pour toute l'API :
    //
    // 1. `sensitive_governor` : le plus strict, réservé aux endpoints qui peuvent servir à du
    //    brute-force/credential-stuffing OU à énumérer des comptes (register, login,
    //    forgot/reset-password, verify-email). Limite aussi, en creux, la RAM consommée par des
    //    hachages Argon2 concurrents (chacun ~46 Mo, voir crypto.rs::hash_password) : avec
    //    burst=8, au pire 8 hachages simultanés (~370 Mo) au lieu d'un potentiel burst plus large.
    //    Le burst d'origine (3) déclenchait des 429 en usage normal : le flux 2FA à lui seul
    //    consomme 2 jetons (login -> verify-device -> re-login), et une seule faute de frappe au
    //    mot de passe suffisait alors à épuiser tout le budget.
    // 2. `auth_governor` : le reste du groupe /auth (logout, refresh, verify-device, email,
    //    password) — moins sensible, mais toujours limité pour éviter qu'un appel anodin et
    //    bon marché n'épuise un budget partagé avec les routes sensibles ci-dessus.
    // 3. `global_governor` : appliqué à TOUTE l'API (voir plus bas), là où il n'y avait
    //    auparavant AUCUNE limite en dehors de /auth — un token volé (ou un client buggé)
    //    pouvait marteler /vault, /devices, /ws/ticket... sans aucune limite de débit.
    //
    // NOTE : ces trois limiteurs sont des seaux à jetons EN MÉMOIRE qui se rechargent tout seuls
    // (voir la crate `governor`) — un 429 se résorbe d'ordinaire en quelques secondes, jamais
    // besoin de redémarrer le serveur pour "le débloquer". Le client lit désormais l'en-tête
    // `Retry-After` que tower_governor renvoie par défaut pour l'indiquer explicitement (voir
    // api/client.ts::formatErrorMessage) plutôt que d'afficher un `Erreur HTTP 429` muet.
    // Extracteur de clé partagé par les trois paliers ci-dessous : IP du pair TCP direct par
    // défaut, ou en-têtes de reverse proxy si explicitement activé (voir ConfigurableIpKeyExtractor
    // et Config::trust_proxy_headers plus haut).
    let ip_key_extractor = ConfigurableIpKeyExtractor {
        trust_proxy_headers: state.config.trust_proxy_headers,
    };
    let sensitive_governor = Arc::new(
        tower_governor::governor::GovernorConfigBuilder::default()
            .per_second(4)
            .burst_size(8)
            .key_extractor(ip_key_extractor)
            .finish()
            .unwrap()
    );
    // Palier DÉDIÉ à POST /bug-reports — CORRECTIF (demande explicite de l'utilisateur) : cette
    // route partageait auparavant sensitive_governor (4 req/s, réservé au brute-force sur des
    // endpoints d'authentification — register/login/reset...), un seuil pensé pour empêcher de
    // deviner un mot de passe, pas pour un usage familial normal. Plusieurs personnes derrière la
    // MÊME IP (box internet partagée) signalant un bug à quelques secondes d'écart pouvaient se
    // bloquer mutuellement. Deux fois plus permissif que sensitive_governor, mais toujours bien EN
    // DEÇÀ de global_governor (40/s) — cette route reste publique/anonyme, un abus délibéré (voir
    // aussi MAX_BUG_REPORTS_TOTAL et son insertion atomique, repository.rs) doit rester coûteux.
    let bug_report_governor = Arc::new(
        tower_governor::governor::GovernorConfigBuilder::default()
            .per_second(8)
            .burst_size(16)
            .key_extractor(ip_key_extractor)
            .finish()
            .unwrap()
    );
    let auth_governor = Arc::new(
        tower_governor::governor::GovernorConfigBuilder::default()
            .per_second(15)
            .burst_size(30)
            .key_extractor(ip_key_extractor)
            .finish()
            .unwrap()
    );
    let global_governor = Arc::new(
        tower_governor::governor::GovernorConfigBuilder::default()
            .per_second(40)
            .burst_size(80)
            .key_extractor(ip_key_extractor)
            .finish()
            .unwrap()
    );

    // -------------------------------------------------------------------------
    // CONFIGURATION DES CORS (SÉCURITÉ NAVIGATEUR)
    // -------------------------------------------------------------------------
    let cors = CorsLayer::new()
        // Autorise l'app web ET l'extension navigateur, configurées via ALLOWED_ORIGINS.
        // Chaque origine invalide (mal formée) dans la liste est ignorée silencieusement au parsing
        // plutôt que de faire planter le serveur au démarrage.
        .allow_origin(AllowOrigin::list(
            state.config.allowed_origins.iter()
                .filter_map(|o| o.parse::<axum::http::HeaderValue>().ok())
                .collect::<Vec<_>>()
        ))
        // Autorise les méthodes HTTP standards nécessaires au CRUD
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST, axum::http::Method::PUT, axum::http::Method::DELETE, axum::http::Method::PATCH])
        // Autorise le transit des en-têtes essentiels. PAS de `Cookie` : l'authentification se
        // fait exclusivement par en-tête `Authorization: Bearer` (voir middleware.rs), jamais par
        // cookie — l'inclure n'apportait donc rien, juste de la surface de configuration inutile.
        .allow_headers([CONTENT_TYPE, AUTHORIZATION])
        // `allow_credentials` ne concerne que l'envoi de cookies/identifiants navigateur
        // (fetch avec `credentials: 'include'`) : sans usage de cookies, il n'y a rien à
        // autoriser ici, et le laisser à `true` était une combinaison CORS inutilement permissive.
        .allow_credentials(false)
        // `Retry-After` (ajouté par défaut par tower_governor sur un 429, voir sensitive/auth/
        // global_governor ci-dessus) est un en-tête de réponse NON standard au sens CORS — sans
        // l'exposer explicitement ici, fetch() côté client ne peut PAS le lire sur une requête
        // cross-origin (ce qu'est TOUJOURS une requête de l'app vers ce backend), même si le
        // serveur l'envoie bien : le client retombe alors sur un message générique sans pouvoir
        // dire à l'utilisateur combien de temps attendre (voir api/client.ts::formatErrorMessage).
        .expose_headers([RETRY_AFTER]);

    // -------------------------------------------------------------------------
    // ROUTAGE ET DÉCLARATION DES ENDPOINTS DE L'API
    // -------------------------------------------------------------------------
    Router::new()
        // --- Groupe des routes d'Authentification (/auth/...) ---
        .nest("/auth", Router::new()
            // Routes sensibles : brute-force de mot de passe ou de code, ou énumération de
            // comptes. Isolées dans leur propre sous-routeur pour leur appliquer un rate limiter
            // dédié, plus strict que le reste de /auth (voir sensitive_governor plus haut).
            .merge(Router::new()
                .route("/register", post(handlers::register)) // Inscription
                .route("/login", post(handlers::login)) // Connexion initiale
                .route("/verify-email", post(handlers::verify_email)) // Confirmation du code envoyé à l'inscription
                .route("/resend-verification", post(handlers::resend_verification_email)) // Renvoi du code si expiré/perdu
                .route("/forgot-password", post(handlers::request_password_reset)) // Demande de reset par email
                .route("/reset-password", post(handlers::confirm_password_reset)) // Validation finale du reset
                // CORRECTIF SÉCURITÉ : /verify-device (redemption d'un code 2FA à 6 chiffres) vivait
                // auparavant hors de ce sous-routeur, ne bénéficiant que du auth_governor plus large
                // (15 req/s, rafale 30) — incohérent avec le raisonnement même de ce groupe (routes
                // où deviner un code/mot de passe est le risque direct). Le verrou MAX_CODE_ATTEMPTS
                // (5) restait le vrai garde-fou, mais un attaquant pouvait quand même brûler jusqu'à
                // 30 tentatives d'un coup avant qu'il ne s'active.
                .route("/verify-device", post(handlers::verify_2fa_and_register_device)) // Validation du code MFA/2FA
                // CORRECTIF SÉCURITÉ : /email vivait auparavant hors de ce sous-routeur (juste
                // auth_governor, 15 req/s) alors que son handler vérifie un hash Argon2 fourni par
                // l'appelant (voir update_email() dans account.rs) — un access token volé/fuité
                // (pas besoin du mot de passe maître pour ÇA, juste d'un Bearer valide) offrait donc
                // ~3,75x plus d'essais/seconde qu'un attaquant anonyme sur /login pour deviner le
                // hash de mot de passe correspondant. Alignée sur le même palier que /login.
                .route("/email", put(handlers::update_email)) // Modification de l'adresse email
                .route_layer(GovernorLayer::new(sensitive_governor.clone())))
            .route("/logout", post(handlers::logout)) // Déconnexion d'un seul appareil (révoque son refresh token)
            .route("/refresh", post(handlers::refresh)) // Renouvellement de l'Access Token via Refresh Token
            // /password isolée dans son propre sous-routeur : ChangeMasterPasswordPayload peut
            // contenir TOUT le coffre re-chiffré, ENTRÉES + PIÈCES JOINTES. Pire cas réel :
            // entrées ≈ MAX_VAULT_ENTRIES_PER_USER (5000, voir vault.rs) x 5 champs chiffrés x
            // 8192 caractères max (models.rs) ≈ 195 Mo ; pièces jointes ≈ MAX_ATTACHMENTS_PER_USER
            // (50, voir vault.rs) x 10 000 000 caractères max d'encrypted_content (models.rs) ≈
            // 500 Mo. Ensemble, le pire cas théorique dépasse 512 Mo — un plafond volontairement
            // soft : un compte qui sature à la fois le nombre max d'entrées ET de pièces jointes
            // en même temps (cas extrême, peu probable pour un usage personnel/petite équipe)
            // devra libérer de la place avant de changer son mot de passe maître, plutôt que
            // d'imposer une limite illimitée ou un mécanisme de re-chiffrement incrémental bien
            // plus complexe pour un cas quasiment jamais atteint en pratique.
            // `route_layer` n'affecte que les routes déjà ajoutées à CE sous-routeur (donc
            // uniquement /password ici), pas le reste de /auth. CORRECTIF SÉCURITÉ : même
            // raisonnement que pour /email ci-dessus (vérification Argon2 d'un hash fourni par
            // l'appelant) — /password ne bénéficiait avant que du auth_governor plus large.
            .merge(Router::new()
                .route("/password", put(handlers::update_password))
                .route_layer(DefaultBodyLimit::max(512 * 1024 * 1024))
                .route_layer(GovernorLayer::new(sensitive_governor.clone())))
            // Rate limiter appliqué à TOUT le groupe /auth ; les routes sensibles ci-dessus
            // cumulent donc les deux limiteurs (le plus strict des deux s'applique de fait).
            .layer(GovernorLayer::new(auth_governor)))

        // --- Groupe des routes du Coffre-fort (/vault/...) ---
        .nest("/vault", Router::new()
            // Une même route "/" peut accepter du GET (lister) ou du POST (ajouter)
            .route("/", get(handlers::get_vault).post(handlers::add_to_vault))
            // Route dynamique avec paramètre d'URL (id d'une entrée de mot de passe)
            .route("/{id}", put(handlers::update_vault_entry).delete(handlers::delete_vault_entry))
            // Route pour mettre ou enlever un élément des favoris
            .route("/{id}/favorite", patch(handlers::toggle_favorite))
            // Historique des mots de passe d'une entrée (voir handlers/vault.rs)
            .route("/{id}/history", get(handlers::get_vault_entry_history))
            // Pièces jointes chiffrées d'une entrée (voir handlers/vault.rs). Isolées dans leur
            // propre sous-routeur : un fichier chiffré+base64 peut atteindre ~10 Mo (voir
            // models.rs::VaultAttachmentInput), bien au-delà de la limite globale de 256 Ko
            // plus bas — l'override s'applique aussi à GET/DELETE (corps vide de toute façon),
            // plus simple que d'éclater le même chemin entre plusieurs Router::route().
            .route("/{id}/attachments/{attachment_id}", get(handlers::get_vault_attachment).delete(handlers::delete_vault_attachment))
            .merge(Router::new()
                .route("/{id}/attachments", get(handlers::get_vault_attachments).post(handlers::add_vault_attachment))
                .route_layer(DefaultBodyLimit::max(16 * 1024 * 1024)))
            // Corbeille : lister, restaurer, ou purger définitivement une entrée supprimée
            .route("/trash", get(handlers::get_trash))
            .route("/{id}/restore", post(handlers::restore_vault_entry))
            .route("/{id}/permanent", delete(handlers::permanently_delete_vault_entry))
            // /import isolée dans son propre sous-routeur, même raison que /auth/password : un
            // import peut contenir jusqu'à MAX_VAULT_ENTRIES_PER_USER entrées d'un coup (pire cas
            // ≈ 195 Mo, voir le commentaire sur /auth/password plus haut), la limite globale de
            // 256 Ko plus bas la couperait sinon.
            .merge(Router::new()
                .route("/import", post(handlers::import_vault))
                .route_layer(DefaultBodyLimit::max(256 * 1024 * 1024))))
            .route("/api/vault/sync", get(handlers::check_sync))
            .route("/api/vault/sync-check", get(handlers::check_sync)) // Alias historique, même handler que /sync (voir commentaire dans handlers.rs)
            // Exige le hash du mot de passe maître dans le corps (voir ExportVaultPayload) :
            // une requête GET classique n'a pas de corps de façon standard, POST convient mieux
            // ici et évite en plus de faire transiter ce hash dans une URL/des logs.
            .route("/vault/export", post(handlers::export_vault))
            .route("/vault/history/export", post(handlers::export_vault_history))

        // --- Routes générales de l'API ---
        .route("/health", get(handlers::health_check)) // Healthcheck pour load balancer/orchestrateur (Docker, k8s...)
        .route("/public-config", get(handlers::get_public_config)) // Réglages globaux lisibles SANS authentification (voir handlers/common.rs) — utilisé par l'écran de connexion
        // Échange l'access token (Bearer classique) contre un ticket WS à usage unique — voir
        // le commentaire en tête de handlers/sync.rs pour le pourquoi de cette indirection.
        .route("/ws/ticket", post(handlers::create_ws_ticket))
        .route("/ws", get(handlers::ws_handler)) // Synchronisation temps réel entre appareils (authentifiée par ticket, pas par l'access token)
        .route("/me", get(handlers::get_me)) // Récupérer le profil de l'utilisateur connecté
        .route("/audit", get(handlers::get_audit_logs)) // Admin/modérateur : historique de TOUS les comptes
        .route("/audit/me", get(handlers::get_my_audit_logs)) // Self-service : historique du compte connecté seulement
        // Gestion admin/modérateur des comptes (voir handlers/admin.rs pour le détail exact des
        // droits — is_moderator au minimum, certaines réservées à AuthUser::is_admin()).
        .route("/admin/users", get(handlers::list_users)) // Lister tous les comptes — lecture seule, reste sur global_governor
        // CORRECTIF SÉCURITÉ : ces 6 routes MUTENT un autre compte (changement de rôle/email,
        // révocation de sessions, suppression définitive, réglage extension) et ne bénéficiaient
        // avant que du global_governor (40 req/s, rafale 80) — largement assez pour qu'un
        // token modérateur/admin volé/fuité supprime ou déconnecte un grand nombre de comptes
        // avant que quiconque ne réagisse. Alignées sur le même palier strict que /login : un
        // usage normal du panneau Administration (quelques clics à la suite) reste largement sous
        // la rafale de 8, un abus massif ne l'est plus.
        .merge(Router::new()
            .route("/admin/users/{email}/role", put(handlers::update_user_role)) // Promouvoir/rétrograder un modérateur (Admin uniquement)
            .route("/admin/users/{email}/email", put(handlers::admin_update_user_email)) // Changer l'email d'un AUTRE compte (jamais le mot de passe maître)
            .route("/admin/users/{email}/extension-email-change", put(handlers::update_extension_email_change_setting)) // Autoriser/interdire le changement d'email via l'extension, pour CE compte
            .route("/admin/users/extension-email-change-all", put(handlers::update_extension_email_change_setting_all)) // Idem, pour TOUS les comptes d'un coup (Admin uniquement)
            .route("/admin/users/{email}/server-choice", put(handlers::update_server_choice_in_settings)) // Autoriser/interdire le choix du serveur dans les Réglages, pour CE compte (Admin uniquement)
            .route("/admin/users/server-choice-all", put(handlers::update_server_choice_in_settings_all)) // Idem, pour TOUS les comptes d'un coup (Admin uniquement)
            .route("/admin/server-choice-at-login", put(handlers::update_server_choice_at_login)) // Réglage GLOBAL : visibilité du lien "Configurer le serveur" avant connexion (Admin uniquement)
            .route("/admin/users/{email}/revoke-sessions", post(handlers::revoke_user_sessions)) // Déconnecter un compte à distance
            .route("/admin/users/{email}", delete(handlers::delete_user)) // Supprimer définitivement un compte
            .route_layer(GovernorLayer::new(sensitive_governor.clone())))
        .route("/devices", get(handlers::list_devices)) // Lister ses appareils de confiance
        .route("/devices/{device_id}", delete(handlers::revoke_device)) // Révoquer un appareil (+ coupe sa session)
        .route("/devices/limit", put(handlers::update_device_limit)) // Modifier le plafond d'appareils de confiance
        .route("/devices/logout-all", post(handlers::logout_all_devices)) // Déconnexion totale volontaire (tous appareils)

        // Accès d'urgence (voir handlers/emergency.rs et docs/API.md pour le flux complet) —
        // Zero-Knowledge de bout en bout, le serveur ne relaie que des clés publiques et des blobs
        // déjà scellés côté client.
        .route("/emergency/keys", put(handlers::upsert_keys)) // Enregistre/remplace sa propre paire de clés X25519
        .route("/emergency/keys/me", get(handlers::get_own_keys)) // Ses PROPRES clés (publique + privée chiffrée)
        .route("/emergency/keys/{email}", get(handlers::get_public_key)) // Clé PUBLIQUE d'un AUTRE utilisateur (jamais la privée)
        .route("/emergency/contacts", get(handlers::list_contacts_as_owner).post(handlers::add_contact)) // Contacts que j'ai désignés
        .route("/emergency/granted-to-me", get(handlers::list_granted_to_me)) // Comptes où on m'a désigné comme contact
        .route("/emergency/contacts/{id}", delete(handlers::revoke_contact)) // Révoque une relation (les deux côtés peuvent)
        .route("/emergency/contacts/{id}/accept", post(handlers::accept_contact)) // Le contact accepte l'invitation
        .route("/emergency/contacts/{id}/decline", post(handlers::decline_contact)) // Le contact la refuse
        .route("/emergency/contacts/{id}/seed", put(handlers::seed_contact)) // Le propriétaire scelle sa clé de coffre pour ce contact
        .route("/emergency/contacts/{id}/request-access", post(handlers::request_access)) // Le contact démarre le délai d'attente
        .route("/emergency/contacts/{id}/approve", post(handlers::approve_access)) // Le propriétaire approuve immédiatement
        .route("/emergency/contacts/{id}/reject", post(handlers::reject_access)) // Le propriétaire refuse pendant le délai
        .route("/emergency/contacts/{id}/vault", get(handlers::get_emergency_vault)) // Le contact consulte le coffre (lecture seule)

        // Partage sécurisé d'une entrée (voir handlers/sharing.rs et docs/API.md) — même
        // construction Zero-Knowledge que l'accès d'urgence ci-dessus (réutilise /emergency/keys/*
        // pour les clés publiques), mais INSTANTANÉ : pas de délai d'attente ni de machine à états.
        .route("/vault/{id}/shares", get(handlers::list_shares_for_entry).post(handlers::share_entry)) // Lister/créer un partage pour cette entrée
        .route("/shares/shared-with-me", get(handlers::list_shared_with_me)) // Tout ce qui m'a été partagé
        .route("/shares/{id}", get(handlers::get_shared_entry).delete(handlers::revoke_share)) // Récupérer le blob scellé / révoquer

        // Coffres partagés familiaux (voir handlers/shared_vault.rs et docs/API.md) — S'AJOUTE au
        // partage d'entrée 1-vers-1 ci-dessus, ne le remplace pas. Même construction
        // Zero-Knowledge (réutilise /emergency/keys/* pour les clés publiques), mais une clé
        // SYMÉTRIQUE partagée par tous les membres : une modification est visible EN DIRECT par
        // tous, pas de re-partage individuel à chaque changement.
        .route("/shared-vaults", get(handlers::list_shared_vaults).post(handlers::create_shared_vault)) // Lister mes coffres partagés / en créer un
        .route("/shared-vaults/{id}", delete(handlers::delete_shared_vault)) // Supprimer définitivement (propriétaire uniquement)
        .route("/shared-vaults/{id}/members", get(handlers::list_shared_vault_members).post(handlers::invite_shared_vault_member)) // Lister/inviter (invitation = propriétaire uniquement)
        .route("/shared-vaults/{id}/members/{email}", delete(handlers::remove_shared_vault_member)) // Retirer un membre (soi-même = quitter, sinon propriétaire uniquement)
        .route("/shared-vaults/{id}/entries", get(handlers::list_shared_vault_entries).post(handlers::add_shared_vault_entry)) // Lister/ajouter une entrée
        .route("/shared-vaults/{id}/entries/{entry_id}", put(handlers::update_shared_vault_entry).delete(handlers::delete_shared_vault_entry)) // Modifier/supprimer une entrée

        // Partage à usage limité ("aveugle", voir handlers/blind_share.rs et docs/API.md) —
        // S'AJOUTE aux deux mécanismes de partage ci-dessus, ne remplace ni l'un ni l'autre. Le
        // destinataire ne voit jamais l'identifiant ni le mot de passe (seulement le nom du site),
        // et ne peut "utiliser" le partage qu'un nombre de fois limité (défaut 1) — compteur
        // décrémenté ATOMIQUEMENT côté serveur à chaque appel de /use.
        .route("/vault/{id}/blind-shares", get(handlers::list_blind_shares_for_entry).post(handlers::create_blind_share)) // Lister/créer un partage à usage limité pour cette entrée
        .route("/blind-shares/shared-with-me", get(handlers::list_blind_shares_received)) // Tout ce qui m'a été partagé en usage limité
        .route("/blind-shares/{id}/use", post(handlers::use_blind_share)) // Consomme UN usage, renvoie les identifiants scellés
        .route("/blind-shares/{id}", delete(handlers::revoke_blind_share)) // Révoquer (l'un ou l'autre côté, à tout moment)

        // Signalement de bug (voir handlers/bug_report.rs) — POST est PUBLIC (accessible même sans
        // connexion, voir models.rs) : sur bug_report_governor (voir sa déclaration plus haut pour
        // le raisonnement — deux fois plus permissif que sensitive_governor, mais toujours PAS
        // global_governor, cette route publique/anonyme doit rester plus protégée que le reste de
        // l'API). GET/DELETE restent réservés au SEUL Admin — PAS un modérateur (vérifié dans le
        // handler via user.is_admin(&state), demande explicite de l'utilisateur) — et sur
        // global_governor, comme le reste du panneau Administration en lecture (voir /admin/users
        // GET plus haut).
        .merge(Router::new()
            .route("/bug-reports", post(handlers::create_bug_report))
            .route_layer(GovernorLayer::new(bug_report_governor)))
        .route("/admin/bug-reports", get(handlers::list_bug_reports)) // Admin SEUL : tous les signalements
        .route("/admin/bug-reports/{id}", delete(handlers::delete_bug_report)) // Admin SEUL : marquer traité (suppression)

        // Application des middlewares globaux de Tower
        // CORRECTIF SÉCURITÉ (voir rewrite_client_ip_from_proxy_headers ci-dessus) : ajoutée EN
        // PREMIER (donc la couche la plus INTERNE, la plus proche des routes/handlers) pour que
        // TraceLayer juste après logue déjà la bonne IP, et que tout ce qui suit voie la même
        // correction — peu importe l'ordre exact vis-à-vis des autres couches ci-dessous, elle
        // s'exécute de toute façon avant que le moindre handler n'extraie `ConnectInfo`.
        .layer(axum_middleware::from_fn_with_state(state.clone(), rewrite_client_ip_from_proxy_headers))
        .layer(TraceLayer::new_for_http()) // Génère des logs automatiques pour chaque requête HTTP reçue
        // Limite globale de taille de requête : 256 Ko, généreux pour une entrée de coffre chiffrée
        // (voir MAX_ENCRYPTED_FIELD_LEN dans models.rs, 8 Ko par champ x quelques champs), mais
        // empêche un client malveillant/buggé d'envoyer un corps de requête disproportionné avant
        // même que la validation applicative (models.rs) n'ait la moindre chance de s'exécuter.
        .layer(DefaultBodyLimit::max(256 * 1024))
        // En-têtes de sécurité HTTP, sur TOUTES les réponses (défense en profondeur — impact
        // limité pour une API JSON pure, mais coût quasi nul). `if_not_present` : n'écrase jamais
        // un en-tête qu'un handler aurait explicitement défini lui-même. Strict-Transport-Security
        // est sans danger même si le service tourne en clair derrière un reverse proxy : les
        // navigateurs ignorent cet en-tête reçu sur une connexion non-HTTPS.
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("referrer-policy"),
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ))
        .layer(SetResponseHeaderLayer::if_not_present(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=63072000; includeSubDomains"),
        ))
        // Compresse les réponses JSON volumineuses (ex: listage du coffre, jusqu'à 100 entrées x
        // plusieurs champs de 8 Ko) — coût CPU négligeable comparé au gain de bande passante/latence.
        .layer(CompressionLayer::new())
        // Rate limiter global : couvre désormais TOUT le reste de l'API (voir global_governor
        // plus haut), là où il n'y avait auparavant aucune limite en dehors de /auth.
        .layer(GovernorLayer::new(global_governor))
        // Délai maximum de 30s par requête : sans ça, rien ne borne le temps d'une requête dont
        // l'envoi SMTP traînerait (register/login/forgot-password/verify appellent tous un envoi
        // d'email de façon SYNCHRONE avant de répondre) — une connexion SMTP qui ne répond plus
        // bloquerait cette requête indéfiniment. SANS IMPACT sur `/ws` : une fois la connexion
        // WebSocket upgradée, sa boucle de vie (handlers/sync.rs::handle_socket) tourne dans une
        // tâche à part, hors du `Service::call` que ce timeout chronomètre — seule la poignée de
        // main HTTP initiale (rapide) y est soumise. `ServiceBuilder` regroupe les deux couches en
        // UNE seule (au lieu de deux `.layer()` séparés) pour garantir l'ordre correct : sans
        // `HandleErrorLayer` englobant `.timeout()`, un dépassement de délai ferait paniquer le
        // service au lieu de renvoyer une réponse 408 propre.
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|err: BoxError| async move {
                    if err.is::<tower::timeout::error::Elapsed>() {
                        (StatusCode::REQUEST_TIMEOUT, Json(serde_json::json!({ "error": "La requête a pris trop de temps" })))
                    } else {
                        (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Erreur interne inattendue" })))
                    }
                }))
                .timeout(Duration::from_secs(30))
        )
        // `cors` DERNIER (donc le plus À L'EXTÉRIEUR de toutes les couches ci-dessus) : n'importe
        // quel rejet généré par une couche interne — 429 du rate limiter, 408 du timeout, 500 du
        // HandleErrorLayer — doit quand même repasser par ici pour recevoir l'en-tête
        // Access-Control-Allow-Origin. Sans ça (ordre testé et corrigé : `cors` était avant le
        // rate limiter), un navigateur/webview qui essuie une telle réponse SANS en-tête CORS la
        // bloque intégralement avant que le JS ne la voie — fetch() échoue alors avec une erreur
        // réseau générique ("Failed to fetch"), indiscernable côté client d'un serveur réellement
        // injoignable (symptôme observé : l'app affiche "impossible de contacter le serveur" alors
        // qu'il répond parfaitement, le souci n'étant qu'un rejet 429 sans en-tête CORS).
        .layer(cors)
        .with_state(state) // Injection de l'état global partagé dans toutes les routes
}

/// Extrait le chemin de fichier d'une DATABASE_URL SQLite (ex: "sqlite:data/vault.db?mode=rwc"
/// -> Some("data/vault.db")), ou `None` si elle ne pointe vers aucun fichier réel (base en
/// mémoire ":memory:", ou chaîne qui n'est pas une URL SQLite reconnue) — dans ce cas il n'y a
/// simplement aucun dossier parent à créer.
fn sqlite_file_path(url: &str) -> Option<std::path::PathBuf> {
    let without_scheme = url.strip_prefix("sqlite://").or_else(|| url.strip_prefix("sqlite:"))?;
    let without_query = without_scheme.split('?').next().unwrap_or(without_scheme);
    if without_query.is_empty() || without_query == ":memory:" {
        return None;
    }
    Some(std::path::PathBuf::from(without_query))
}

/// Attend un Ctrl+C (SIGINT) ou un SIGTERM (envoyé par Docker/k8s à l'arrêt) pour déclencher
/// l'arrêt propre du serveur. Sur Windows, seul Ctrl+C est disponible (pas de notion de SIGTERM).
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Impossible d'installer le handler Ctrl+C");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Impossible d'installer le handler SIGTERM")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Signal d'arrêt reçu, fermeture propre du serveur en cours...");
}

// =========================================================================
// TESTS D'INTÉGRATION DE BOUT EN BOUT (VRAI ROUTER + VRAIE PILE DE MIDDLEWARES)
// =========================================================================
// Contrairement aux tests unitaires de chaque module de handlers (qui appellent les fonctions
// handler directement, court-circuitant toute la pile Tower — voir le commentaire équivalent dans
// handlers/auth/session.rs), ceux-ci envoient une VRAIE requête HTTP à travers le VRAI Router
// construit par build_router() via `tower::ServiceExt::oneshot` : rate limiting, limites de
// taille de requête (globale ET overrides par route), CORS, en-têtes de sécurité inclus. Sans ça,
// rien ne prouvait que ces couches de middleware fonctionnaient comme prévu sur le serveur
// réellement démarré plutôt que sur les handlers pris isolément.
#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt; // .oneshot()
    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use sqlx::sqlite::SqlitePoolOptions;

    #[test]
    fn test_sqlite_file_path_extracts_path_and_strips_query_string() {
        assert_eq!(
            sqlite_file_path("sqlite:data/vault.db?mode=rwc"),
            Some(std::path::PathBuf::from("data/vault.db"))
        );
    }

    #[test]
    fn test_sqlite_file_path_handles_double_slash_scheme() {
        assert_eq!(
            sqlite_file_path("sqlite://data/vault.db"),
            Some(std::path::PathBuf::from("data/vault.db"))
        );
    }

    #[test]
    fn test_sqlite_file_path_returns_none_for_in_memory_database() {
        // Utilisé par TOUS les tests du projet (build_test_state() dans chaque module) : aucun
        // dossier parent à créer pour une base qui n'existe jamais sur disque.
        assert_eq!(sqlite_file_path("sqlite::memory:"), None);
    }

    #[test]
    fn test_sqlite_file_path_returns_none_for_non_sqlite_url() {
        assert_eq!(sqlite_file_path("postgres://localhost/db"), None);
    }

    /// Adresse de test à insérer dans les extensions de chaque requête forgée à la main (voir
    /// les deux tests plus bas) : en production, `main()` fournit `ConnectInfo<SocketAddr>` via
    /// `into_make_service_with_connect_info()` — GovernorLayer (rate limiting, voir
    /// build_router()) en dépend pour identifier le client par IP. `Router::oneshot()` en test ne
    /// passe PAS par cette étape, donc sans cette extension insérée manuellement, GovernorLayer
    /// échoue AVANT même d'atteindre la limite de taille que ces tests visent à vérifier — un 500
    /// masquerait alors le vrai comportement testé (peu importe le status attendu, il serait
    /// "accidentellement" différent de 413 pour la mauvaise raison).
    fn test_addr() -> ConnectInfo<std::net::SocketAddr> {
        ConnectInfo("127.0.0.1:12345".parse().unwrap())
    }

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
            encoding_key: EncodingKey::from_secret(config.jwt_secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(config.jwt_secret.as_bytes()),
            app_env: config.app_env.clone(),
            db: pool,
            config,
            sync_tx: tokio::sync::broadcast::channel(16).0,
            shutdown_tx: tokio::sync::broadcast::channel(1).0,
            ws_connections: Default::default(),
        })
    }

    /// Même chose que build_test_state(), mais `trust_proxy_headers: true` — pour les deux tests
    /// de rewrite_client_ip_from_proxy_headers() ci-dessous qui doivent vérifier le comportement
    /// UNE FOIS ce réglage activé (déploiement derrière un reverse proxy de confiance).
    async fn build_test_state_with_proxy_trust() -> Arc<AppState> {
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
            trust_proxy_headers: true,
        };

        Arc::new(AppState {
            encoding_key: EncodingKey::from_secret(config.jwt_secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(config.jwt_secret.as_bytes()),
            app_env: config.app_env.clone(),
            db: pool,
            config,
            sync_tx: tokio::sync::broadcast::channel(16).0,
            shutdown_tx: tokio::sync::broadcast::channel(1).0,
            ws_connections: Default::default(),
        })
    }

    /// Petit handler de test qui renvoie l'IP vue via `ConnectInfo<SocketAddr>` — sert à observer
    /// de l'EXTÉRIEUR l'effet de rewrite_client_ip_from_proxy_headers() sur ce que les VRAIS
    /// handlers de l'application reçoivent, sans dépendre d'aucun d'entre eux en particulier.
    async fn echo_connect_info_ip(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> String {
        addr.ip().to_string()
    }

    /// Comportement par défaut (`trust_proxy_headers: false`) : un `X-Forwarded-For` falsifié ne
    /// doit avoir AUCUN effet sur ce que les handlers voient via `ConnectInfo` — seule l'IP du
    /// pair TCP direct compte, exactement comme pour ConfigurableIpKeyExtractor plus haut (même
    /// garde-fou, même raison : sans reverse proxy de confiance confirmé, ce serait un moyen
    /// trivial de falsifier son IP dans le journal d'audit / les appareils de confiance).
    #[tokio::test]
    async fn test_rewrite_client_ip_ignores_forwarded_header_by_default() {
        let state = build_test_state().await;
        let app = Router::new()
            .route("/echo-ip", get(echo_connect_info_ip))
            .layer(axum_middleware::from_fn_with_state(state.clone(), rewrite_client_ip_from_proxy_headers))
            .with_state(state);

        let mut request = Request::builder()
            .uri("/echo-ip")
            .header("x-forwarded-for", "203.0.113.9")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(test_addr());

        let response = app.oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            &body[..],
            b"127.0.0.1",
            "trust_proxy_headers=false doit ignorer X-Forwarded-For : les handlers doivent voir l'IP du pair TCP direct, inchangée"
        );
    }

    /// RÉGRESSION (voir la conversation du 2026-09-01 — bug repéré par l'utilisateur lui-même face
    /// à un vrai déploiement derrière Nginx Proxy Manager) : une fois `trust_proxy_headers` activé,
    /// les handlers doivent voir la VRAIE IP du client (via X-Forwarded-For), pas celle du reverse
    /// proxy — sinon l'historique de sécurité et les appareils de confiance enregistrent la même
    /// IP pour tout le monde, les rendant inutiles.
    #[tokio::test]
    async fn test_rewrite_client_ip_trusts_forwarded_header_when_enabled() {
        let state = build_test_state_with_proxy_trust().await;
        let app = Router::new()
            .route("/echo-ip", get(echo_connect_info_ip))
            .layer(axum_middleware::from_fn_with_state(state.clone(), rewrite_client_ip_from_proxy_headers))
            .with_state(state);

        let mut request = Request::builder()
            .uri("/echo-ip")
            .header("x-forwarded-for", "203.0.113.9")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(test_addr());

        let response = app.oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            &body[..],
            b"203.0.113.9",
            "trust_proxy_headers=true doit faire voir aux handlers l'IP de X-Forwarded-For, pas celle du proxy"
        );
    }

    /// Avec plusieurs IP dans X-Forwarded-For ("client, proxy1, proxy2"), seule la PREMIÈRE (le
    /// client d'origine) doit être retenue — pas la dernière, qui serait celle du dernier proxy.
    #[tokio::test]
    async fn test_rewrite_client_ip_takes_first_ip_of_forwarded_chain() {
        let state = build_test_state_with_proxy_trust().await;
        let app = Router::new()
            .route("/echo-ip", get(echo_connect_info_ip))
            .layer(axum_middleware::from_fn_with_state(state.clone(), rewrite_client_ip_from_proxy_headers))
            .with_state(state);

        let mut request = Request::builder()
            .uri("/echo-ip")
            .header("x-forwarded-for", "203.0.113.9, 192.168.1.21")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(test_addr());

        let response = app.oneshot(request).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"203.0.113.9", "doit retenir le PREMIER maillon de la chaîne (le client d'origine), pas le dernier (le proxy)");
    }

    /// VÉRIFICATION : la limite de taille de requête GLOBALE (256 Ko, voir build_router()) doit
    /// réellement être appliquée par le VRAI Router pour une route qui n'a PAS d'override — POST
    /// /auth/register n'en a pas. Un corps de 300 Ko doit être rejeté en 413 Payload Too Large
    /// avant même d'atteindre la moindre logique applicative (peu importe que le contenu envoyé
    /// soit un JSON valide ou non : le dépassement de taille est détecté pendant la lecture du
    /// corps, avant son parsing).
    #[tokio::test]
    async fn test_global_body_limit_rejects_oversized_request_on_unoverridden_route() {
        let state = build_test_state().await;
        let app = build_router(state);

        let oversized_body = "a".repeat(300_000); // > 256 Ko (262 144 octets), bien en dessous des 256 Mo de l'override
        let mut request = Request::builder()
            .method("POST")
            .uri("/auth/register")
            .header("content-type", "application/json")
            .body(Body::from(oversized_body))
            .unwrap();
        request.extensions_mut().insert(test_addr());

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "un corps de 300 Ko sur une route SANS override doit être rejeté par la limite globale de 256 Ko"
        );
    }

    /// VÉRIFICATION : l'override de taille (512 Mo, voir build_router()) sur PUT /auth/password
    /// doit réellement lever la limite au-delà des 256 Ko globaux. Rien ne prouvait jusqu'ici que
    /// la superposition `route_layer` (override, plus interne) / `layer` (global, plus externe)
    /// fonctionne dans le bon sens sur le VRAI Router assemblé — l'inverser silencieusement
    /// bloquerait un changement de mot de passe légitime sur un coffre volumineux (voir le
    /// commentaire détaillé sur /auth/password dans build_router()).
    #[tokio::test]
    async fn test_password_route_override_allows_oversized_request_past_global_limit() {
        let state = build_test_state().await;
        let email = "bodylimit@example.com";

        // Utilisateur réel en BDD + JWT valide : nécessaire pour que AuthUser (premier extracteur
        // de update_password(), avant Json) laisse passer la requête jusqu'à la lecture du corps —
        // sinon AuthUser court-circuiterait AVANT que quoi que ce soit ne touche au corps, et ce
        // test ne prouverait rien sur la limite de taille elle-même.
        let hash = crate::crypto::hash_password("mot_de_passe_test_123", &state.config.password_pepper).unwrap();
        sqlx::query("INSERT INTO users (email, password_hash, email_verified) VALUES (?, ?, 1)")
            .bind(email)
            .bind(hash)
            .execute(&state.db)
            .await
            .unwrap();
        let token = crate::crypto::create_jwt(email, &state.encoding_key, 600).unwrap();

        // Payload volumineux (> 256 Ko) mais structurellement valide : plusieurs entrées
        // re-chiffrées avec un contenu proche du max autorisé par champ (voir models.rs). Peu
        // importe qu'il ne corresponde pas exactement au coffre réel de l'utilisateur (0 entrée
        // active ici) — la validation applicative peut très bien rejeter la requête ENSUITE
        // (ex: "re-chiffrement incomplet"), ce test ne vérifie que la couche de taille, pas la
        // logique métier de update_password().
        let entries: Vec<_> = (0..40).map(|i| serde_json::json!({
            "id": format!("id-{i}"),
            "encrypted_site_name": "x".repeat(8000),
            "encrypted_username": null,
            "encrypted_login_email": null,
            "encrypted_password": "y",
            "encrypted_preferred_login_type": "email"
        })).collect();
        let body = serde_json::json!({
            "old_master_password_hash": "mot_de_passe_test_123",
            "new_master_password_hash": "nouveau_mot_de_passe_456",
            "reencrypted_entries": entries
        }).to_string();
        assert!(body.len() > 256 * 1024, "le corps de test doit dépasser la limite globale de 256 Ko pour être significatif");

        let app = build_router(state);
        let mut request = Request::builder()
            .method("PUT")
            .uri("/auth/password")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(body))
            .unwrap();
        request.extensions_mut().insert(test_addr());

        let response = app.oneshot(request).await.unwrap();
        assert_ne!(
            response.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "PUT /auth/password doit accepter un corps > 256 Ko grâce à son override à 512 Mo, jamais le rejeter en 413"
        );
    }

    /// RÉGRESSION CRITIQUE : un rejet du rate limiter global (429) doit quand même porter
    /// l'en-tête Access-Control-Allow-Origin — voir le commentaire détaillé sur l'ordre des
    /// couches dans build_router() (`cors` doit envelopper GovernorLayer, pas l'inverse). Sans ce
    /// header, un navigateur/webview bloque la réponse avant même que le JS ne la voie : fetch()
    /// échoue alors avec une erreur réseau générique, indiscernable côté client d'un serveur
    /// réellement injoignable, au lieu du vrai 429 exploitable (ex: pour afficher "réessaie dans
    /// quelques secondes").
    #[tokio::test]
    async fn test_rate_limit_rejection_still_carries_cors_header() {
        let state = build_test_state().await;
        let app = build_router(state);

        // global_governor : 40/s, burst 80 (voir build_router()) — un lot de 90 requêtes rapides
        // sur une route SANS gouverneur dédié (/health, en dehors de /auth) doit épuiser le burst
        // et déclencher au moins un 429 avant que le token bucket n'ait le temps de se recharger
        // (toutes ces requêtes s'exécutent en mémoire via oneshot(), sans latence réseau réelle).
        let mut saw_429_with_cors_header = false;
        for _ in 0..90 {
            let mut request = Request::builder()
                .method("GET")
                .uri("/health")
                .header("origin", "http://localhost:5173") // doit matcher allowed_origins du test
                .body(Body::empty())
                .unwrap();
            request.extensions_mut().insert(test_addr());

            let response = app.clone().oneshot(request).await.unwrap();
            if response.status() == StatusCode::TOO_MANY_REQUESTS {
                assert!(
                    response.headers().get("access-control-allow-origin").is_some(),
                    "un rejet 429 doit porter l'en-tête CORS, sinon le navigateur/webview le bloque avant que le JS ne le voie"
                );
                saw_429_with_cors_header = true;
                break;
            }
        }

        assert!(
            saw_429_with_cors_header,
            "le rate limiter global doit finir par rejeter en 429 avec ce volume de requêtes (sinon ce test ne prouve rien)"
        );
    }

    /// Comportement par défaut (`trust_proxy_headers: false`) : un en-tête `X-Forwarded-For`
    /// falsifié par le client ne doit avoir AUCUN effet sur la clé de rate limiting, seule l'IP
    /// du pair TCP direct compte. C'est ce qui protège contre le contournement du rate limiting
    /// par un client qui s'attribuerait une IP différente à chaque requête, tant qu'aucun reverse
    /// proxy de confiance n'est confirmé en amont (voir Config::trust_proxy_headers).
    #[test]
    fn test_configurable_ip_key_extractor_ignores_forwarded_header_by_default() {
        let extractor = ConfigurableIpKeyExtractor { trust_proxy_headers: false };
        let mut request = Request::builder()
            .header("x-forwarded-for", "203.0.113.9")
            .body(())
            .unwrap();
        request.extensions_mut().insert(test_addr());

        let key = extractor.extract(&request).expect("doit extraire une IP");
        assert_eq!(
            key,
            "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
            "trust_proxy_headers=false doit ignorer X-Forwarded-For et retenir l'IP du pair TCP direct"
        );
    }

    /// Une fois `trust_proxy_headers` explicitement activé (déploiement derrière un reverse
    /// proxy de confiance qui pose lui-même cet en-tête), l'extracteur doit bien lire
    /// `X-Forwarded-For` — sinon activer le réglage n'aurait aucun effet observable.
    #[test]
    fn test_configurable_ip_key_extractor_trusts_forwarded_header_when_enabled() {
        let extractor = ConfigurableIpKeyExtractor { trust_proxy_headers: true };
        let mut request = Request::builder()
            .header("x-forwarded-for", "203.0.113.9")
            .body(())
            .unwrap();
        request.extensions_mut().insert(test_addr());

        let key = extractor.extract(&request).expect("doit extraire une IP");
        assert_eq!(
            key,
            "203.0.113.9".parse::<std::net::IpAddr>().unwrap(),
            "trust_proxy_headers=true doit privilégier X-Forwarded-For sur l'IP du pair TCP direct"
        );
    }
}
