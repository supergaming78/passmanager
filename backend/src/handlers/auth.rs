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

/// Durées de vie des codes envoyés par email, par flux. Extraites en constantes parce que le
/// cooldown anti-email-bombing ci-dessous en DÉRIVE l'instant d'émission (voir
/// is_code_within_cooldown) — les avoir en dur à deux endroits ferait silencieusement diverger
/// le calcul du cooldown de la durée réelle.
pub(super) const RESET_CODE_LIFETIME_MINUTES: i64 = 15;
pub(super) const VERIFICATION_CODE_LIFETIME_MINUTES: i64 = 30;

/// Délai minimum entre deux envois d'un même type de code à une MÊME adresse.
pub(super) const EMAIL_RESEND_COOLDOWN_SECONDS: i64 = 60;

/// Vrai si un code de ce `purpose` a été émis pour cet email il y a moins de
/// `EMAIL_RESEND_COOLDOWN_SECONDS` — protection anti-email-bombing des routes qui expédient un
/// email vers une adresse choisie par l'appelant (`/auth/forgot-password`,
/// `/auth/resend-verification`). Le rate limiting de main.rs est PAR IP : il ne protège pas une
/// adresse ciblée par un attaquant qui change d'IP, alors que chaque requête coûte un vrai email.
///
/// N'ajoute AUCUNE colonne : la durée de vie d'un code étant fixe (`lifetime_minutes`), la
/// condition « émis il y a moins de X » s'écrit exactement « expire dans plus de
/// (durée de vie - X) ». Un code absent ou déjà expiré n'est jamais en cooldown.
pub(super) async fn is_code_within_cooldown(
    state: &crate::AppState,
    email: &str,
    purpose: &str,
    lifetime_minutes: i64,
) -> Result<bool, crate::error::AppError> {
    let threshold = format!("+{} seconds", lifetime_minutes * 60 - EMAIL_RESEND_COOLDOWN_SECONDS);

    let recent: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM tfa_codes
         WHERE email = ? AND purpose = ?
         AND expires_at > STRFTIME('%Y-%m-%dT%H:%M:%SZ', 'now', ?)",
    )
    .bind(email)
    .bind(purpose)
    .bind(&threshold)
    .fetch_optional(&state.db)
    .await?;

    Ok(recent.is_some())
}
