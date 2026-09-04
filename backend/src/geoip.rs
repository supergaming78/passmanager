//! Géolocalisation d'adresses IP **entièrement hors ligne**.
//!
//! # Pourquoi ce module existe sous cette forme
//!
//! Localiser une IP se fait d'ordinaire en appelant une API tierce. Dans un gestionnaire de mots
//! de passe à divulgation nulle, ce serait contradictoire : le serveur enverrait à une entreprise
//! inconnue la liste des adresses de ses utilisateurs — c'est-à-dire, dans le temps, la carte de
//! leurs déplacements et de leurs habitudes. Le chiffrement du coffre protégerait le contenu
//! pendant qu'un canal annexe divulguerait le contexte.
//!
//! Ici, la résolution se fait contre un fichier local au format MMDB. **Aucune requête réseau
//! n'est émise, ni au démarrage ni à la consultation** : `maxminddb` ne fait que lire un fichier
//! (voir `cargo tree`, aucune dépendance HTTP). Une adresse consultée ne quitte donc jamais le
//! serveur, et un observateur du réseau ne peut rien déduire des consultations.
//!
//! # Le fichier de données
//!
//! Optionnel. Sans `GEOIP_DATABASE_PATH`, la géolocalisation est simplement absente et le reste
//! de l'application fonctionne à l'identique — c'est le comportement par défaut, choisi pour
//! qu'une installation existante ne casse pas et ne télécharge rien à l'insu de son propriétaire.
//!
//! Voir `README.md` pour où récupérer une base libre (DB-IP Lite ne demande aucun compte).
//!
//! # Précision, et ce qu'il ne faut pas en conclure
//!
//! Une géolocalisation d'IP est une **estimation**, pas une position. Un VPN affiche le pays de son
//! serveur ; une connexion mobile est souvent rattachée à la ville d'un équipement opérateur à des
//! centaines de kilomètres de l'utilisateur ; le CGNAT partage une même adresse entre des milliers
//! d'abonnés. C'est utile pour repérer un pays manifestement improbable, jamais pour affirmer où
//! quelqu'un se trouvait. L'interface le dit à l'écran.

use std::net::IpAddr;
use std::path::Path;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Ce qu'on sait d'une adresse, une fois résolue.
///
/// Volontairement pauvre : pays, et ville si la base en contient une. Ni coordonnées, ni fuseau,
/// ni code postal — une base « City » en fournit, mais les afficher donnerait une fausse
/// impression de précision sur une donnée qui n'en a pas, et constituerait une collecte plus
/// intrusive sans bénéfice pour ce qu'on cherche (repérer un pays improbable).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IpLocation {
    /// Code pays ISO à deux lettres, ex. "FR". Sert aussi à afficher un drapeau côté client.
    pub country_code: Option<String>,
    /// Nom du pays dans la langue disponible (français si la base le propose, anglais sinon).
    pub country_name: Option<String>,
    /// Ville, uniquement si la base en contient (les bases « Country », plus légères, n'en ont pas).
    pub city: Option<String>,
}

/// Base MMDB chargée en mémoire, ou rien si aucune n'est configurée.
///
/// Le chemin est conservé même quand le chargement échoue, pour permettre une nouvelle tentative
/// plus tard — voir `lookup()`.
pub struct GeoIpResolver {
    path: Option<String>,
    state: RwLock<ResolverState>,
}

struct ResolverState {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
    /// Instant avant lequel on ne retente pas d'ouvrir le fichier. Évite de marteler le disque à
    /// chaque consultation quand la base est absente pour de bon.
    next_retry: Option<Instant>,
}

/// Délai entre deux tentatives d'ouverture quand la base est configurée mais introuvable.
/// Assez court pour qu'un fichier posé pendant que le serveur tourne soit pris en compte
/// rapidement, assez long pour ne rien marteler.
const RETRY_AFTER: Duration = Duration::from_secs(60);

impl GeoIpResolver {
    /// Charge la base depuis le chemin donné, ou renvoie un résolveur inerte si `path` est `None`.
    ///
    /// Un chemin configuré mais illisible n'est **pas** une erreur fatale : le serveur démarre sans
    /// géolocalisation plutôt que de refuser de démarrer. Un gestionnaire de mots de passe
    /// injoignable est un problème bien plus grave qu'une colonne manquante dans un écran
    /// d'administration. L'échec est journalisé bruyamment pour ne pas passer inaperçu.
    ///
    /// La base est lue **une fois** et gardée en mémoire (quelques Mo pour une base pays) : aucune
    /// ouverture de fichier ni allocation par consultation.
    pub fn load(path: Option<&str>) -> Self {
        let path = path.map(str::to_string);
        let reader = path.as_deref().and_then(open_database);
        Self {
            state: RwLock::new(ResolverState {
                next_retry: reader.is_none().then(|| Instant::now() + RETRY_AFTER),
                reader,
            }),
            path,
        }
    }

    /// Vrai si une base est réellement chargée — permet à l'interface de distinguer « pas de base
    /// configurée » de « base configurée, mais cette adresse est introuvable ».
    pub fn is_enabled(&self) -> bool {
        self.state.read().is_ok_and(|s| s.reader.is_some())
    }

    /// Résout une adresse. `None` si aucune base, si l'adresse est mal formée, si elle est privée,
    /// ou si la base ne la connaît pas.
    ///
    /// Les adresses privées sont écartées avant toute lecture : aucune base ne les référence (elles
    /// désignent un réseau local, pas un lieu), et les interroger ne ferait que produire du bruit.
    ///
    /// Réessaie d'ouvrir le fichier s'il était absent au démarrage. C'est le cas courant d'un
    /// déploiement en conteneurs : le service qui télécharge la base et celui qui la lit démarrent
    /// en parallèle, et le second gagne souvent la course. Sans cette reprise, il faudrait
    /// redémarrer le serveur à la main — une étape invisible, qu'on ne devine qu'après coup.
    pub fn lookup(&self, ip: &str) -> Option<IpLocation> {
        // L'analyse d'abord : inutile de prendre un verrou pour une adresse privée ou mal formée.
        let parsed: IpAddr = ip.parse().ok()?;
        if is_private(&parsed) {
            return None;
        }

        self.retry_load_if_needed();

        let state = self.state.read().ok()?;
        let reader = state.reader.as_ref()?;
        let record: maxminddb::geoip2::City = reader.lookup(parsed).ok()?.decode().ok()??;

        // `Names` est une struct à champs typés, pas une table de langues : on prend le français
        // quand la base le fournit, l'anglais sinon. Les bases libres ne traduisent pas tout ;
        // sans ce repli, la colonne serait vide pour une bonne partie des pays.
        let pick = |names: &maxminddb::geoip2::Names| -> Option<String> {
            names.french.or(names.english).map(str::to_string)
        };

        let location = IpLocation {
            country_code: record.country.iso_code.map(str::to_string),
            country_name: pick(&record.country.names),
            city: pick(&record.city.names),
        };

        // Une base « Country » ne contient pas de villes, et une adresse peut être présente sans
        // qu'aucun nom ne soit renseigné : dans ce cas il n'y a rien à afficher, autant le dire
        // par None plutôt que de renvoyer une coquille vide que le client devrait re-tester.
        if location.country_code.is_none() && location.country_name.is_none() && location.city.is_none() {
            return None;
        }
        Some(location)
    }

    /// Retente l'ouverture si une base est configurée, pas encore chargée, et que le délai est
    /// écoulé. Sort immédiatement dans le cas courant (base chargée, ou aucune configurée) en ne
    /// prenant qu'un verrou de LECTURE : le verrou d'écriture n'est demandé que pour la tentative
    /// elle-même, qui est rare.
    fn retry_load_if_needed(&self) {
        let Some(path) = self.path.as_deref() else { return };

        {
            let Ok(state) = self.state.read() else { return };
            if state.reader.is_some() {
                return;
            }
            match state.next_retry {
                Some(at) if Instant::now() < at => return,
                _ => {}
            }
        }

        let Ok(mut state) = self.state.write() else { return };
        // Re-vérification sous le verrou d'écriture : une autre requête a pu charger la base
        // entre-temps, et il serait absurde de relire 8 Mo pour rien.
        if state.reader.is_some() {
            return;
        }
        state.next_retry = Some(Instant::now() + RETRY_AFTER);
        if let Some(reader) = open_database(path) {
            state.reader = Some(reader);
        }
    }
}

/// Ouvre le fichier et journalise le résultat. Séparé de `load()` pour être réutilisable par la
/// reprise différée sans dupliquer les messages.
fn open_database(path: &str) -> Option<maxminddb::Reader<Vec<u8>>> {
    match maxminddb::Reader::open_readfile(Path::new(path)) {
        Ok(reader) => {
            info!(
                "Géolocalisation hors ligne active : base « {} » chargée ({} entrées, build {}). Aucune requête réseau ne sera émise.",
                reader.metadata().database_type,
                reader.metadata().node_count,
                reader.metadata().build_epoch
            );
            Some(reader)
        }
        Err(e) => {
            warn!(
                "GEOIP_DATABASE_PATH est défini (« {} ») mais la base n'a pas pu être lue : {}. Le serveur fonctionne SANS géolocalisation ; si le fichier arrive plus tard, il sera pris en compte automatiquement (nouvelle tentative au plus toutes les {} s).",
                path,
                e,
                RETRY_AFTER.as_secs()
            );
            None
        }
    }
}

/// Adresses qui ne désignent aucun lieu : boucle locale, réseaux privés RFC 1918, lien-local,
/// ULA IPv6. Écartées avant toute consultation de la base.
fn is_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 (adresses locales uniques) et fe80::/10 (lien-local) : `std` n'expose pas
                // encore de prédicat stable pour l'une ni l'autre, d'où le test sur les octets.
                || (v6.octets()[0] & 0xfe) == 0xfc
                || (v6.octets()[0] == 0xfe && (v6.octets()[1] & 0xc0) == 0x80)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sans base configurée, tout doit rester silencieux et inerte — c'est le comportement par
    /// défaut de toute installation qui n'a rien demandé.
    #[test]
    fn test_resolver_without_database_is_inert() {
        let resolver = GeoIpResolver::load(None);
        assert!(!resolver.is_enabled());
        assert_eq!(resolver.lookup("8.8.8.8"), None);
    }

    /// Un chemin invalide ne doit PAS empêcher le serveur de démarrer : mieux vaut un écran
    /// d'administration sans colonne « Origine » qu'un gestionnaire de mots de passe injoignable.
    #[test]
    fn test_invalid_database_path_degrades_instead_of_failing() {
        let resolver = GeoIpResolver::load(Some("/chemin/qui/n/existe/pas.mmdb"));
        assert!(!resolver.is_enabled(), "une base illisible doit laisser le résolveur inerte");
        assert_eq!(resolver.lookup("8.8.8.8"), None);
    }

    /// Les adresses sans lieu doivent être écartées AVANT la base : les interroger ne produirait
    /// que du bruit, et sur un serveur derrière un reverse proxy mal configuré, elles sont
    /// justement ce qu'on voit partout.
    #[test]
    fn test_addresses_without_a_location_are_rejected() {
        for ip in [
            "127.0.0.1",      // boucle locale
            "10.0.0.5",       // RFC 1918
            "192.168.1.42",   // RFC 1918
            "172.16.0.1",     // RFC 1918
            "169.254.10.10",  // lien-local IPv4
            "::1",            // boucle locale IPv6
            "fd00::1",        // ULA IPv6
            "fe80::1",        // lien-local IPv6
        ] {
            assert!(is_private(&ip.parse().unwrap()), "{ip} devrait être considérée comme sans lieu");
        }

        for ip in ["8.8.8.8", "203.0.113.7", "2001:4860:4860::8888"] {
            assert!(!is_private(&ip.parse().unwrap()), "{ip} est une adresse publique");
        }
    }

    /// Chemin d'une VRAIE base MMDB, si l'environnement en fournit une.
    ///
    /// Les autres tests de ce module ne prouvent que les cas dégradés (pas de base, base illisible,
    /// adresse sans lieu) — utiles, mais aucun ne démontre qu'une résolution réussie fonctionne.
    /// Celui-ci le fait dès qu'une base est disponible via `GEOIP_TEST_DATABASE`, et se contente
    /// de passer sinon : personne ne doit avoir à télécharger 8 Mo pour lancer `cargo test`.
    fn test_database_path() -> Option<String> {
        std::env::var("GEOIP_TEST_DATABASE").ok().filter(|p| Path::new(p).exists())
    }

    /// Résolution réelle contre une base MMDB : c'est le seul test qui prouve que le décodage,
    /// le choix de la langue et la lecture des champs fonctionnent ensemble.
    #[test]
    fn test_real_database_resolves_known_addresses() {
        let Some(path) = test_database_path() else {
            eprintln!("GEOIP_TEST_DATABASE non défini : test de résolution réelle ignoré.");
            return;
        };

        let resolver = GeoIpResolver::load(Some(&path));
        assert!(resolver.is_enabled(), "la base de test doit se charger");

        // Adresses dont l'attribution pays est stable et publiquement documentée.
        for (ip, expected_country) in [("8.8.8.8", "US"), ("1.1.1.1", "AU")] {
            let found = resolver.lookup(ip).unwrap_or_else(|| panic!("{ip} devrait être résolue"));
            assert_eq!(
                found.country_code.as_deref(),
                Some(expected_country),
                "{ip} devrait être attribuée à {expected_country}"
            );
            assert!(found.country_name.is_some(), "{ip} devrait avoir un nom de pays lisible");
        }

        // Une base chargée ne doit PAS se mettre à géolocaliser des adresses privées : c'est
        // exactement ce qu'on voit partout derrière un reverse proxy mal configuré.
        assert_eq!(resolver.lookup("192.168.1.1"), None, "une adresse privée n'a pas de lieu, même avec une base chargée");
        assert_eq!(resolver.lookup("127.0.0.1"), None);
    }

    /// Une entrée mal formée ne doit jamais faire paniquer : cette chaîne vient de la base de
    /// données, donc en dernier ressort d'un en-tête de requête quand TRUST_PROXY_HEADERS est actif.
    #[test]
    fn test_malformed_address_is_ignored() {
        let resolver = GeoIpResolver::load(None);
        assert_eq!(resolver.lookup("pas-une-ip"), None);
        assert_eq!(resolver.lookup(""), None);
    }
}

#[cfg(test)]
mod deferred_load_tests {
    use super::*;

    /// LE scénario d'un déploiement en conteneurs : le service qui télécharge la base et celui qui
    /// la lit démarrent en parallèle, et le second gagne souvent la course. Sans reprise différée,
    /// il faudrait redémarrer le serveur à la main — une étape invisible, qu'on ne devine qu'après
    /// coup, et qui a réellement fait croire la fonctionnalité cassée.
    #[test]
    fn test_database_appearing_after_startup_is_picked_up() {
        let Some(source) = std::env::var("GEOIP_TEST_DATABASE").ok().filter(|p| Path::new(p).exists()) else {
            eprintln!("GEOIP_TEST_DATABASE non défini : test de reprise différée ignoré.");
            return;
        };

        // Un chemin qui n'existe PAS encore, comme au démarrage du conteneur.
        let dir = std::env::temp_dir().join(format!("geoip-differe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cible = dir.join("base.mmdb");
        let _ = std::fs::remove_file(&cible);

        let resolver = GeoIpResolver::load(Some(cible.to_str().unwrap()));
        assert!(!resolver.is_enabled(), "au démarrage, sans fichier, le résolveur est inerte");
        assert_eq!(resolver.lookup("8.8.8.8"), None, "rien à résoudre tant que le fichier est absent");

        // Le conteneur de téléchargement termine son travail APRÈS.
        std::fs::copy(&source, &cible).unwrap();

        // Sans intervention, la reprise attendrait RETRY_AFTER. On rembobine l'échéance pour ne pas
        // faire durer le test une minute — c'est le comportement de reprise qu'on teste, pas
        // l'horloge.
        resolver.state.write().unwrap().next_retry = None;

        let trouve = resolver.lookup("8.8.8.8");
        assert!(trouve.is_some(), "le fichier arrivé après coup doit être pris en compte sans redémarrage");
        assert_eq!(trouve.unwrap().country_code.as_deref(), Some("US"));
        assert!(resolver.is_enabled(), "la base doit désormais être signalée comme active");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// La reprise ne doit pas marteler le disque : tant que le délai n'est pas écoulé, aucune
    /// nouvelle tentative n'a lieu.
    #[test]
    fn test_retry_is_rate_limited() {
        let resolver = GeoIpResolver::load(Some("/base/absente.mmdb"));
        let echeance = resolver.state.read().unwrap().next_retry;
        assert!(echeance.is_some(), "un chemin configuré mais absent doit programmer une reprise");

        resolver.lookup("8.8.8.8");
        assert_eq!(
            resolver.state.read().unwrap().next_retry,
            echeance,
            "une consultation avant l'échéance ne doit pas reprogrammer ni retenter"
        );
    }
}
