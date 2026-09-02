// Point d'entrée du module `handlers` : regroupe les routes par domaine fonctionnel
// (auth, vault, appareils de confiance, administration, utilitaires communs) plutôt
// qu'un seul fichier de ~1000 lignes. `pub use X::*;` re-exporte tout au niveau
// `handlers::`, donc main.rs continue d'appeler `handlers::register`,
// `handlers::get_vault`, etc. sans aucun changement de son côté.
mod common;
mod auth;
mod vault;
mod devices;
mod admin;
mod sync;
mod emergency;
mod sharing;
mod shared_vault;
mod blind_share;
mod bug_report;
mod feature_suggestion;

pub use common::{health_check, get_public_config};
pub use auth::*;
pub use vault::*;
pub use devices::*;
pub use admin::*;
pub use sync::*;
pub use emergency::*;
pub use sharing::*;
pub use shared_vault::*;
pub use blind_share::*;
pub use bug_report::*;
pub use feature_suggestion::*;