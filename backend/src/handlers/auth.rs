// Agrégateur du domaine "authentification", découpé en 3 responsabilités distinctes qui
// n'avaient plus grand-chose en commun une fois regroupées dans un seul fichier de ~1700 lignes :
//   - register.rs : création de compte, vérification d'email, renvoi de code
//   - session.rs  : login, 2FA, rafraîchissement de session, déconnexion
//   - account.rs  : mot de passe, email, profil, réinitialisation de compte
// `pub use X::*;` re-exporte tout au niveau `handlers::auth::`, donc `handlers.rs` (et par
// extension main.rs, qui appelle `handlers::register`, `handlers::login`, etc.) n'a rien à
// changer de son côté — exactement le même principe que handlers.rs applique déjà pour
// regrouper auth/vault/devices/admin/sync sous `handlers::`.
mod register;
mod session;
mod account;

pub use register::*;
pub use session::*;
pub use account::*;

/// Nombre maximum de tentatives autorisées pour un code 2FA / vérification / reset avant que
/// celui-ci soit invalidé automatiquement (protection contre le bruteforce d'un code à 6
/// chiffres) — partagé par les trois sous-modules ci-dessus, chacun l'utilisant pour un code
/// différent (2FA de connexion, confirmation d'email, réinitialisation de mot de passe).
pub(super) const MAX_CODE_ATTEMPTS: i64 = 5;

// Distinguent les 3 flux qui partagent la table `tfa_codes` (voir models.rs::TfaCode et la
// migration 20260806000000_tfa_codes_purpose.sql) : sans ce distinguo, un code généré pour un
// flux pouvait écraser et valider un AUTRE flux concurrent pour le même email (ex: un code de
// reset de mot de passe qui validait accidentellement une vérification d'email).
pub(super) const PURPOSE_EMAIL_VERIFICATION: &str = "email_verification";
pub(super) const PURPOSE_LOGIN_2FA: &str = "login_2fa";
pub(super) const PURPOSE_PASSWORD_RESET: &str = "password_reset";

/// Anti-bruteforce PAR COMPTE sur `/auth/login` (voir session.rs::login()) — distinct du
/// rate limiting par IP (main.rs), qui seul ne protège pas un compte ciblé par un attaquant
/// changeant d'IP. Au-delà de ce nombre d'échecs consécutifs, le compte est bloqué (même avec
/// le bon mot de passe) tant que `FAILED_LOGIN_WINDOW_MINUTES` ne s'est pas écoulé depuis le
/// DERNIER échec — une connexion réussie remet le compteur à zéro.
pub(super) const MAX_FAILED_LOGIN_ATTEMPTS: i64 = 5;
pub(super) const FAILED_LOGIN_WINDOW_MINUTES: i64 = 15;
