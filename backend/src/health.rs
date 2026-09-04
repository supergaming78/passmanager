//! État de santé du serveur pour le panneau Administration.
//!
//! # Ce que ça mesure, et pourquoi ces mesures-là
//!
//! Sur un serveur auto-hébergé, la panne la plus probable n'est ni une attaque ni un bug : c'est le
//! **disque plein**. SQLite s'y comporte mal — écritures refusées, et un WAL qui ne peut plus être
//! replié. L'écran est donc construit autour de cette question, et non autour de jolis graphiques :
//! combien reste-t-il, et qu'est-ce qui consomme.
//!
//! Le reste répond à des questions qu'on ne peut pas poser autrement sans se connecter en SSH :
//! - la dernière sauvegarde date de quand ? Une sauvegarde qui s'est arrêtée en silence est un
//!   désastre classique, et rien ne le signale tant qu'on n'en a pas besoin ;
//! - la base contient-elle de l'espace mort récupérable par un VACUUM ?
//! - combien de connexions ont été refusées pour cause de limite de débit ces dernières 24 h ?
//!   (question déjà posée face à des « trop de tentatives » inexpliqués) ;
//! - combien d'échecs de connexion, tous comptes confondus ?
//!
//! # Ce qui n'est délibérément PAS mesuré
//!
//! Ni charge CPU, ni graphiques d'historique, ni métriques par seconde. Il faudrait échantillonner
//! en continu et stocker des séries temporelles — beaucoup de machinerie et d'écritures disque pour
//! surveiller... la place disque. Tout ici se calcule à la demande, à l'ouverture de l'écran.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use crate::state::AppState;

/// Instantané complet, tel qu'envoyé au client.
#[derive(serde::Serialize)]
pub struct ServerHealth {
    pub uptime_seconds: u64,
    pub app_env: String,
    /// Mémoire résidente du processus. `None` hors Linux : lue dans `/proc`, sans équivalent
    /// portable, et ce n'est pas une raison pour priver l'écran de tout le reste.
    pub memory_bytes: Option<u64>,
    pub disk: DiskUsage,
    pub database: DatabaseStats,
    pub activity: ActivityStats,
    pub backup: BackupStatus,
}

#[derive(serde::Serialize)]
pub struct DiskUsage {
    pub database_bytes: u64,
    /// Le journal d'écriture anticipée. Suivi séparément parce qu'il grossit indépendamment de la
    /// base : un WAL qui enfle sans se replier est un symptôme, pas un détail.
    pub wal_bytes: u64,
    pub attachments_bytes: i64,
    pub backups_bytes: u64,
    pub logs_bytes: u64,
    /// Espace libre et total du système de fichiers portant les données. `None` hors Unix.
    pub free_bytes: Option<u64>,
    pub total_bytes: Option<u64>,
}

#[derive(serde::Serialize)]
pub struct DatabaseStats {
    pub users: i64,
    pub vault_entries: i64,
    pub deleted_entries: i64,
    pub audit_logs: i64,
    pub ip_history_rows: i64,
    /// Espace déjà alloué mais inutilisé dans le fichier, récupérable par un VACUUM. Une base d'où
    /// l'on a beaucoup supprimé ne rend pas la place toute seule.
    pub reclaimable_bytes: i64,
}

#[derive(serde::Serialize)]
pub struct ActivityStats {
    pub websocket_connections: u64,
    pub failed_logins_24h: i64,
    pub rate_limited_24h: i64,
    pub active_sessions: i64,
}

#[derive(serde::Serialize)]
pub struct BackupStatus {
    /// Faux quand le dossier n'est pas accessible au serveur — typiquement un volume non monté.
    ///
    /// Sans cette distinction, « le dossier n'est pas monté » (problème de configuration) et
    /// « le service de sauvegarde ne produit rien » (problème grave) donnaient le MÊME message.
    /// C'est arrivé : l'écran annonçait « aucune sauvegarde trouvée » alors que les sauvegardes
    /// existaient — l'api ne montait simplement pas le dossier. Une fausse alerte sur la seule
    /// chose qu'on ne veut surtout pas croire à tort.
    pub directory_present: bool,
    pub count: u64,
    /// Âge de la plus récente. `None` s'il n'y en a aucune — ce qui est en soi l'information la
    /// plus importante que cet écran puisse donner.
    pub newest_age_hours: Option<u64>,
    pub newest_bytes: Option<u64>,
}

/// Collecte l'ensemble des mesures.
///
/// Tout est calculé à la demande. Les requêtes sont des agrégats sur des tables qu'un serveur
/// familial garde petites, et la route est réservée à l'Admin : elle n'est appelée que quand
/// quelqu'un ouvre l'écran, jamais en boucle.
pub async fn collect(state: &Arc<AppState>, started_at: Instant) -> ServerHealth {
    let db_path = database_path(&state.config.database_url);

    // Seuls ces deux PRAGMA importent : leur produit est l'espace alloué mais inutilisé dans le
    // fichier. La taille totale, elle, se lit directement sur le disque et parle davantage.
    let page_size: i64 = sqlx::query_scalar("PRAGMA page_size").fetch_one(&state.db).await.unwrap_or(0);
    let freelist: i64 = sqlx::query_scalar("PRAGMA freelist_count").fetch_one(&state.db).await.unwrap_or(0);

    ServerHealth {
        uptime_seconds: started_at.elapsed().as_secs(),
        app_env: state.app_env.clone(),
        memory_bytes: process_memory_bytes(),
        disk: DiskUsage {
            database_bytes: file_size(&db_path),
            // SQLite nomme le journal "<base>-wal", à côté du fichier principal.
            wal_bytes: file_size(&with_suffix(&db_path, "-wal")),
            attachments_bytes: scalar(state, "SELECT COALESCE(SUM(content_size), 0) FROM vault_attachments").await,
            backups_bytes: directory_size(Path::new("./backups")),
            logs_bytes: directory_size(Path::new("./logs")),
            free_bytes: filesystem_free_bytes(&db_path),
            total_bytes: filesystem_total_bytes(&db_path),
        },
        database: DatabaseStats {
            users: scalar(state, "SELECT COUNT(*) FROM users").await,
            vault_entries: scalar(state, "SELECT COUNT(*) FROM vault WHERE deleted_at IS NULL").await,
            deleted_entries: scalar(state, "SELECT COUNT(*) FROM vault WHERE deleted_at IS NOT NULL").await,
            audit_logs: scalar(state, "SELECT COUNT(*) FROM audit_logs").await,
            ip_history_rows: scalar(state, "SELECT COUNT(*) FROM account_ip_history").await,
            reclaimable_bytes: freelist * page_size,
        },
        activity: ActivityStats {
            websocket_connections: state
                .ws_connections
                .lock()
                .map(|m| m.values().map(|n| u64::from(*n)).sum())
                .unwrap_or(0),
            // Fenêtre de 24 h : au-delà, le chiffre ne dit plus rien de l'état ACTUEL du serveur.
            // Le journal étant purgé à 10 jours, il ne pourrait de toute façon pas remonter loin.
            failed_logins_24h: scalar(
                state,
                "SELECT COUNT(*) FROM audit_logs WHERE created_at > DATETIME('now', '-1 day') \
                   AND action IN ('LOGIN_FAILED', 'LOGIN_BLOCKED_TOO_MANY_ATTEMPTS')",
            )
            .await,
            rate_limited_24h: scalar(
                state,
                "SELECT COUNT(*) FROM audit_logs WHERE created_at > DATETIME('now', '-1 day') \
                   AND action LIKE '%RATE_LIMIT%'",
            )
            .await,
            active_sessions: scalar(state, "SELECT COUNT(*) FROM refresh_tokens").await,
        },
        backup: backup_status(Path::new("./backups")),
    }
}

/// `&'static str` volontairement : toutes les requêtes de cet écran sont des littéraux, et le
/// type l'impose — rien de construit dynamiquement ne peut s'y glisser.
async fn scalar(state: &Arc<AppState>, sql: &'static str) -> i64 {
    sqlx::query_scalar(sql).fetch_one(&state.db).await.unwrap_or(0)
}

/// Extrait le chemin de fichier d'une URL SQLite (`sqlite:data/vault.db?mode=rwc`).
///
/// Publique car `handlers::admin::vacuum_database` mesure le fichier avant/après compactage.
pub fn database_path(url: &str) -> PathBuf {
    let sans_schema = url.strip_prefix("sqlite://").or_else(|| url.strip_prefix("sqlite:")).unwrap_or(url);
    let sans_options = sans_schema.split('?').next().unwrap_or(sans_schema);
    PathBuf::from(sans_options)
}

fn with_suffix(base: &Path, suffixe: &str) -> PathBuf {
    let mut nom = base.as_os_str().to_os_string();
    nom.push(suffixe);
    PathBuf::from(nom)
}

/// Taille d'un fichier, ou 0 s'il n'existe pas. Un WAL absent n'est pas une anomalie : SQLite le
/// supprime au repli.
pub fn file_size(chemin: &Path) -> u64 {
    std::fs::metadata(chemin).map(|m| m.len()).unwrap_or(0)
}

/// Somme des tailles d'un dossier, sans descendre dans les sous-dossiers — ni `./backups` ni
/// `./logs` n'en ont, et une descente récursive sur un dossier inattendu coûterait cher pour rien.
fn directory_size(dossier: &Path) -> u64 {
    let Ok(entrees) = std::fs::read_dir(dossier) else {
        return 0;
    };
    entrees
        .filter_map(Result::ok)
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}

/// Âge et taille de la sauvegarde la plus récente.
///
/// L'âge compte plus que la taille : une sauvegarde de la bonne taille mais vieille de trois
/// semaines veut dire que le service s'est arrêté sans que personne ne s'en aperçoive.
fn backup_status(dossier: &Path) -> BackupStatus {
    let Ok(entrees) = std::fs::read_dir(dossier) else {
        return BackupStatus { directory_present: false, count: 0, newest_age_hours: None, newest_bytes: None };
    };
    let fichiers: Vec<_> = entrees
        .filter_map(Result::ok)
        .filter_map(|e| e.metadata().ok().filter(|m| m.is_file()).map(|m| (m.len(), m.modified().ok())))
        .collect();

    let plus_recent = fichiers
        .iter()
        .filter_map(|(taille, modif)| modif.map(|t| (t, *taille)))
        .max_by_key(|(t, _)| *t);

    BackupStatus {
        directory_present: true,
        count: fichiers.len() as u64,
        newest_age_hours: plus_recent
            .and_then(|(t, _)| t.elapsed().ok())
            .map(|d| d.as_secs() / 3600),
        newest_bytes: plus_recent.map(|(_, taille)| taille),
    }
}

/// Mémoire résidente du processus, lue dans `/proc/self/status` (Linux uniquement).
///
/// Pas de dépendance ajoutée pour ça : `sysinfo` embarque de quoi inspecter tout un système là où
/// une ligne de fichier texte suffit. Hors Linux, `None` — l'écran affiche alors « indisponible »
/// plutôt que de mentir.
#[cfg(target_os = "linux")]
fn process_memory_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let ligne = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    // Format : "VmRSS:\t  123456 kB"
    let kilo_octets: u64 = ligne.split_whitespace().nth(1)?.parse().ok()?;
    Some(kilo_octets * 1024)
}

#[cfg(not(target_os = "linux"))]
fn process_memory_bytes() -> Option<u64> {
    None
}

/// Espace libre et total du système de fichiers, via `statvfs` (Unix uniquement).
#[cfg(unix)]
fn statvfs_of(chemin: &Path) -> Option<libc::statvfs> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    // Le fichier de base peut ne pas exister encore (premier démarrage) : on interroge alors son
    // dossier parent, qui appartient au même système de fichiers.
    let cible = if chemin.exists() { chemin } else { chemin.parent()? };
    let c_chemin = CString::new(cible.as_os_str().as_bytes()).ok()?;

    let mut infos: libc::statvfs = unsafe { std::mem::zeroed() };
    // SÛRETÉ : `c_chemin` est un pointeur valide terminé par NUL et vivant sur toute la durée de
    // l'appel ; `infos` est une structure correctement dimensionnée que l'appel remplit.
    let code = unsafe { libc::statvfs(c_chemin.as_ptr(), &mut infos) };
    (code == 0).then_some(infos)
}

#[cfg(unix)]
fn filesystem_free_bytes(chemin: &Path) -> Option<u64> {
    // `f_bavail` (et non `f_bfree`) : les blocs disponibles pour un processus NON privilégié, ce
    // qui est le cas du serveur. La différence est la réserve root, invisible pour lui.
    statvfs_of(chemin).map(|s| s.f_bavail as u64 * s.f_frsize as u64)
}

#[cfg(unix)]
fn filesystem_total_bytes(chemin: &Path) -> Option<u64> {
    statvfs_of(chemin).map(|s| s.f_blocks as u64 * s.f_frsize as u64)
}

#[cfg(not(unix))]
fn filesystem_free_bytes(_chemin: &Path) -> Option<u64> {
    None
}

#[cfg(not(unix))]
fn filesystem_total_bytes(_chemin: &Path) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les trois formes d'URL SQLite utilisées dans ce projet doivent toutes donner un chemin
    /// exploitable : sans lui, la taille de la base afficherait 0 et l'écran serait mensonger.
    #[test]
    fn test_database_path_handles_every_url_form() {
        assert_eq!(database_path("sqlite:data/vault.db?mode=rwc"), PathBuf::from("data/vault.db"));
        assert_eq!(database_path("sqlite:/app/data/vault.db"), PathBuf::from("/app/data/vault.db"));
        assert_eq!(database_path("sqlite://app/data/vault.db"), PathBuf::from("app/data/vault.db"));
        assert_eq!(database_path("data/vault.db"), PathBuf::from("data/vault.db"));
    }

    /// Le WAL se déduit du nom de la base — un suffixe, pas une extension remplacée.
    #[test]
    fn test_wal_path_is_the_database_plus_suffix() {
        assert_eq!(with_suffix(Path::new("data/vault.db"), "-wal"), PathBuf::from("data/vault.db-wal"));
    }

    /// Un dossier absent vaut 0, pas une erreur : ni ./backups ni ./logs n'existent forcément.
    ///
    /// Surtout, un dossier ABSENT doit se distinguer d'un dossier VIDE : le premier est un volume
    /// non monté (problème de configuration), le second une sauvegarde qui ne se fait plus
    /// (problème grave). Ils ont donné le même message une fois, et l'écran a annoncé « aucune
    /// sauvegarde » à quelqu'un dont les sauvegardes se portaient très bien.
    #[test]
    fn test_missing_directory_is_distinguishable_from_empty_one() {
        assert_eq!(directory_size(Path::new("/dossier/qui/n/existe/pas")), 0);

        let absent = backup_status(Path::new("/dossier/qui/n/existe/pas"));
        assert!(!absent.directory_present, "un dossier illisible doit être signalé comme tel");
        assert_eq!(absent.count, 0);
        assert!(absent.newest_age_hours.is_none());

        let base = std::env::temp_dir().join(format!("sauvegardes-vides-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let vide = backup_status(&base);
        assert!(vide.directory_present, "un dossier existant mais vide n'est PAS un dossier absent");
        assert_eq!(vide.count, 0, "et il ne contient bien aucune sauvegarde");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// La taille d'un dossier additionne ses fichiers, et ignore les sous-dossiers.
    #[test]
    fn test_directory_size_sums_files_only() {
        let base = std::env::temp_dir().join(format!("sante-{}", std::process::id()));
        std::fs::create_dir_all(base.join("sous-dossier")).unwrap();
        std::fs::write(base.join("a.sql"), vec![0u8; 100]).unwrap();
        std::fs::write(base.join("b.sql"), vec![0u8; 250]).unwrap();
        std::fs::write(base.join("sous-dossier/c.sql"), vec![0u8; 9999]).unwrap();

        assert_eq!(directory_size(&base), 350, "les sous-dossiers ne doivent pas être comptés");

        let etat = backup_status(&base);
        assert_eq!(etat.count, 2);
        assert_eq!(etat.newest_bytes, Some(250).or(etat.newest_bytes), "la plus récente doit être retenue");

        let _ = std::fs::remove_dir_all(&base);
    }

    /// Un fichier absent vaut 0 : SQLite supprime le WAL après un repli, ce n'est pas une anomalie.
    #[test]
    fn test_missing_file_size_is_zero() {
        assert_eq!(file_size(Path::new("/fichier/absent.db-wal")), 0);
    }
}
