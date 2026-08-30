use std::env;
use std::net::SocketAddr;

// =========================================================================
// 1. STRUCTURE DE CONFIGURATION
// =========================================================================

/// Cette structure regroupe toutes les variables de configuration de l'application.
/// Le fait de dériver `Clone` permet de copier facilement cette configuration 
/// pour la partager entre les différents modules ou threads (par exemple avec Axum).
#[derive(Clone)]
pub struct Config {
    pub database_url: String,                // URL de connexion à la base de données (PostgreSQL, MySQL, etc.)
    pub jwt_secret: String,                  // Clé secrète pour signer et vérifier les jetons JWT
    pub port: u16,                           // Port d'écoute du serveur web (ex: 3000)
    pub app_env: String,                     // Environnement de l'application ("development", "production", "test")
    pub access_token_seconds: u64,          // Durée de validité du jeton d'accès (Access Token) en secondes
    pub refresh_token_hours: i64,           // Durée de validité du jeton de rafraîchissement (Refresh Token) en heures
    pub refresh_token_short_seconds: i64,   // Version courte ou temporaire du refresh token (en secondes)
    pub password_pepper: String,             // Chaîne secrète globale ajoutée aux mots de passe avant le hachage
    pub smtp_host: String,                   // Hôte du serveur de messagerie SMTP (ex: smtp.gmail.com)
    pub smtp_user: String,                   // Identifiant / Email pour se connecter au serveur SMTP
    pub smtp_pass: String,                   // Mot de passe ou jeton d'application pour le serveur SMTP
    pub allowed_origins: Vec<String>,        // Origines autorisées en CORS (app web, extension chrome/firefox, etc.)
    // Email promu administrateur automatiquement (voir main.rs::promote_configured_admin() et
    // handlers/auth.rs::register()) — remplace le besoin de modifier la BDD à la main pour
    // obtenir les droits admin. `None` si la variable n'est pas définie : aucun bootstrap auto.
    pub admin_email: Option<String>,
    // Si `true`, le rate limiting (voir main.rs::build_router()) fait confiance aux en-têtes
    // `X-Forwarded-For`/`X-Real-Ip`/`Forwarded` pour identifier l'IP réelle du client plutôt que
    // l'IP du pair TCP direct. DANGEREUX à activer sans un reverse proxy de confiance placé EN
    // AMONT qui écrase systématiquement ces en-têtes avant de les faire suivre : sans un tel
    // proxy, n'importe quel client peut positionner lui-même ces en-têtes pour se voir attribuer
    // un budget de rate limiting distinct à volonté, contournant entièrement la protection.
    // `false` par défaut : comportement actuel inchangé (IP du pair TCP direct) tant que cette
    // variable n'est pas explicitement activée.
    pub trust_proxy_headers: bool,
}

// =========================================================================
// 2. IMPLÉMENTATION DES MÉTHODES DE CONFIGURATION
// =========================================================================

impl Config {
    /// Charge les configurations depuis les variables d'environnement du système.
    /// Si une variable obligatoire manque ou est invalide, le programme s'arrête (panic).
    pub fn from_env() -> Self {
        
        // 1. Charger l'environnement de l'application en premier (Défaut : "development" si non spécifié)
        let app_env = env::var("APP_ENV").unwrap_or_else(|_| "development".to_string());
        
        // 2. URL de la base de données : Obligatoire. L'application crashe si elle est absente.
        let database_url = env::var("DATABASE_URL")
            .expect("DATABASE_URL doit être définie (Variable d'env ou fichier .env)");

        // 3. Configuration du service d'email (SMTP)
        // Si l'hôte SMTP n'est pas fourni, on utilise Gmail par défaut.
        let smtp_host = env::var("SMTP_HOST").unwrap_or_else(|_| "smtp.gmail.com".to_string());
        // L'utilisateur et le mot de passe SMTP sont obligatoires pour envoyer des mails.
        let smtp_user = env::var("SMTP_USER").expect("SMTP_USER manquant");
        let smtp_pass = env::var("SMTP_PASS").expect("SMTP_PASS manquant");
        
        // 4. Variables de Sécurité Critique (Poivre et Secret JWT)
        let password_pepper = env::var("PASSWORD_PEPPER").expect("PASSWORD_PEPPER manquant");
        let jwt_secret = env::var("JWT_SECRET").expect("JWT_SECRET manquant");
        
        // Sécurité stricte : En production, le secret JWT ne peut PAS être court.
        if app_env == "production" && jwt_secret.len() < 32 {
            panic!("Le JWT_SECRET doit faire au moins 32 caractères en production !");
        }
        
        // Validation globale de l'entropie au démarrage :
        // On s'assure que le poivre et la clé JWT font au moins 256 bits (32 caractères) pour éviter les attaques par force brute.
        if password_pepper.len() < 32 || jwt_secret.len() < 32 {
            panic!("SÉCURITÉ CRITIQUE : PASSWORD_PEPPER et JWT_SECRET doivent faire au moins 32 caractères.");
        }

        // 5. Configuration du réseau (Port)
        // On lit le PORT, si absent on prend "3000". On tente ensuite de le convertir en entier u16.
        let port = env::var("PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse::<u16>()
            .expect("PORT doit être un nombre valide");

        // 6. Récupération des durées de validité des jetons (avec valeurs de secours / fallback)
        
        // Durée du jeton d'accès (par défaut : 600 secondes = 10 minutes)
        let access_token_seconds = env::var("ACCESS_TOKEN_SECONDS")
            .unwrap_or_else(|_| "600".to_string())
            .parse().unwrap_or(600);

        // Durée du refresh token classique (par défaut : 24 heures)
        let refresh_token_hours = env::var("REFRESH_TOKEN_HOURS")
            .unwrap_or_else(|_| "24".to_string())
            .parse().unwrap_or(24);

        // Durée du refresh token court (par défaut : 5 secondes)
        let refresh_token_short_seconds = env::var("REFRESH_TOKEN_SHORT_SECONDS")
            .unwrap_or_else(|_| "5".to_string())
            .parse().unwrap_or(5);

        // 7. Origines autorisées en CORS : liste séparée par des virgules.
        // Exemple : "http://localhost:5173,chrome-extension://abcdefghijk,moz-extension://xyz"
        // Par défaut, uniquement le frontend de dev local (Vite).
        let allowed_origins: Vec<String> = env::var("ALLOWED_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:5173".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // 8. Email à promouvoir automatiquement administrateur (voir Self::admin_email).
        // Optionnelle : aucun défaut, `None` si absente (pas de bootstrap admin).
        let admin_email = env::var("ADMIN_EMAIL").ok().map(|e| e.to_lowercase());

        // 9. Confiance aux en-têtes de reverse proxy pour le rate limiting (voir
        // Self::trust_proxy_headers). Par défaut à `false` : SEUL "true" (insensible à la casse)
        // l'active, pour qu'une valeur absente ou mal orthographiée reste sans danger.
        let trust_proxy_headers = env::var("TRUST_PROXY_HEADERS")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        // Instanciation et renvoi de la structure Config avec toutes les données chargées
        Self {
            database_url,
            jwt_secret,
            password_pepper,
            port,
            app_env,
            access_token_seconds,
            refresh_token_hours,
            refresh_token_short_seconds,
            smtp_host,
            smtp_user,
            smtp_pass,
            allowed_origins,
            admin_email,
            trust_proxy_headers,
        }
    }

    /// Fonction utilitaire pour transformer le port numérique en une adresse Socket utilisable par Axum.
    /// Elle écoute sur l'adresse générique IP v4 0.0.0.0.
    pub fn get_addr(&self) -> SocketAddr {
        // Note : En Docker, utiliser [0, 0, 0, 0] au lieu de [127, 0, 0, 1] (localhost) 
        // est indispensable pour que le conteneur puisse recevoir les requêtes provenant de l'extérieur.
        SocketAddr::from(([0, 0, 0, 0], self.port))
    }
}

// =========================================================================
// TESTS SUR LE CHARGEMENT DE LA CONFIGURATION
// =========================================================================
// ATTENTION : les variables d'environnement sont un état GLOBAL au processus. Ce test est
// volontairement le seul de tout le projet à appeler Config::from_env() et à manipuler ces
// clés précises — pour éviter toute interférence avec d'autres tests qui tourneraient en
// parallèle dans le même processus (tous les autres tests construisent un Config directement,
// à la main, sans passer par les variables d'environnement).
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_env_parses_allowed_origins_and_applies_defaults() {
        // Variables obligatoires (from_env panique sinon)
        std::env::set_var("DATABASE_URL", "sqlite::memory:");
        std::env::set_var("SMTP_USER", "test@example.com");
        std::env::set_var("SMTP_PASS", "unused");
        std::env::set_var("PASSWORD_PEPPER", "un_pepper_de_test_au_moins_32_caracteres");
        std::env::set_var("JWT_SECRET", "un_secret_jwt_de_test_au_moins_32_caracteres");
        std::env::set_var("ALLOWED_ORIGINS", "http://localhost:5173, chrome-extension://abc123");
        // On s'assure que ces variables optionnelles n'interfèrent pas avec les valeurs par défaut testées
        std::env::remove_var("APP_ENV");
        std::env::remove_var("PORT");
        std::env::remove_var("SMTP_HOST");
        std::env::remove_var("ADMIN_EMAIL");
        std::env::remove_var("TRUST_PROXY_HEADERS");

        let config = Config::from_env();

        assert_eq!(config.app_env, "development", "app_env doit valoir 'development' par défaut");
        assert_eq!(config.port, 3000, "le port doit valoir 3000 par défaut");
        assert_eq!(config.smtp_host, "smtp.gmail.com", "smtp_host doit valoir gmail par défaut");
        assert_eq!(
            config.allowed_origins,
            vec!["http://localhost:5173".to_string(), "chrome-extension://abc123".to_string()],
            "ALLOWED_ORIGINS doit être découpé par virgule, avec les espaces superflus retirés"
        );
        assert_eq!(config.admin_email, None, "admin_email doit être absent par défaut (pas de bootstrap admin)");
        assert!(!config.trust_proxy_headers, "trust_proxy_headers doit être désactivé par défaut (comportement sûr sans reverse proxy)");

        // Nettoyage pour ne pas polluer d'éventuels autres tests dans le même processus
        for key in ["DATABASE_URL", "SMTP_USER", "SMTP_PASS", "PASSWORD_PEPPER", "JWT_SECRET", "ALLOWED_ORIGINS"] {
            std::env::remove_var(key);
        }

        // TRUST_PROXY_HEADERS doit être activé par "true", insensible à la casse (ex: "True",
        // valeur qu'un opérateur pourrait taper à la main dans un .env) — et rester désactivé
        // pour toute autre valeur non reconnue plutôt que de paniquer.
        std::env::set_var("DATABASE_URL", "sqlite::memory:");
        std::env::set_var("SMTP_USER", "test@example.com");
        std::env::set_var("SMTP_PASS", "unused");
        std::env::set_var("PASSWORD_PEPPER", "un_pepper_de_test_au_moins_32_caracteres");
        std::env::set_var("JWT_SECRET", "un_secret_jwt_de_test_au_moins_32_caracteres");
        std::env::set_var("TRUST_PROXY_HEADERS", "True");

        let config_with_proxy_trust = Config::from_env();
        assert!(config_with_proxy_trust.trust_proxy_headers, "TRUST_PROXY_HEADERS='True' doit activer la confiance aux en-têtes de proxy");

        for key in ["DATABASE_URL", "SMTP_USER", "SMTP_PASS", "PASSWORD_PEPPER", "JWT_SECRET", "TRUST_PROXY_HEADERS"] {
            std::env::remove_var(key);
        }

        // ADMIN_EMAIL doit être chargée et normalisée en minuscules (même convention que les
        // emails stockés en BDD, voir handlers/auth.rs — sinon une comparaison exacte plus tard
        // échouerait sur une simple différence de casse). Vérifié DANS ce même test (pas un
        // second #[test]) : voir le commentaire en tête de fichier sur l'état global des
        // variables d'environnement partagé entre tests exécutés en parallèle.
        std::env::set_var("DATABASE_URL", "sqlite::memory:");
        std::env::set_var("SMTP_USER", "test@example.com");
        std::env::set_var("SMTP_PASS", "unused");
        std::env::set_var("PASSWORD_PEPPER", "un_pepper_de_test_au_moins_32_caracteres");
        std::env::set_var("JWT_SECRET", "un_secret_jwt_de_test_au_moins_32_caracteres");
        std::env::set_var("ADMIN_EMAIL", "Owner@Example.com");

        let config_with_admin = Config::from_env();
        assert_eq!(config_with_admin.admin_email, Some("owner@example.com".to_string()));

        for key in ["DATABASE_URL", "SMTP_USER", "SMTP_PASS", "PASSWORD_PEPPER", "JWT_SECRET", "ADMIN_EMAIL"] {
            std::env::remove_var(key);
        }
    }
}