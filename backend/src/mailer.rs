// =========================================================================
// SERVICES D'ENVOI D'E-MAILS (SMTP)
// =========================================================================
// Anciennement regroupé avec le hachage/JWT dans un seul `security.rs` — séparé pour que ce
// fichier ne fasse qu'une chose : construire et envoyer des e-mails via SMTP. Voir crypto.rs
// pour tout ce qui est calcul cryptographique pur (hachage, signature, comparaison).

use lettre::transport::smtp::authentication::Credentials;
use lettre::message::Mailbox;
use lettre::{Message, AsyncSmtpTransport, Tokio1Executor};
use lettre::AsyncTransport;
use tracing::error;

use crate::error::AppError;

/// Parse l'adresse d'un DESTINATAIRE en `Mailbox`, sans jamais paniquer sur une entrée malformée.
/// `validator` (utilisé pour valider les emails en amont, voir models.rs) et le parseur d'adresse
/// de `lettre` n'ont pas rigoureusement les mêmes critères d'acceptation — rien ne garantit qu'un
/// email jugé valide par l'un le soit aussi par l'autre. Sans cette fonction, un `.parse().unwrap()`
/// direct sur `to_email` (donnée fournie par le client via le payload de la requête) ferait
/// paniquer la tâche en cours au moindre désaccord entre les deux, plutôt que de renvoyer une
/// erreur HTTP propre.
fn parse_recipient(email: &str) -> Result<Mailbox, AppError> {
    email.parse().map_err(|_| AppError::ValidationError("Format d'email invalide".to_string()))
}

/// Parse l'adresse d'un EXPÉDITEUR (toujours dérivée de `SMTP_USER`, jamais d'une entrée client)
/// en `Mailbox`. Séparée de `parse_recipient()` ci-dessus pour un message d'erreur adapté : un
/// échec ici signale une mauvaise configuration côté serveur (`SMTP_USER`), pas une donnée
/// utilisateur invalide.
fn parse_sender(display_name_and_address: String) -> Result<Mailbox, AppError> {
    display_name_and_address.parse()
        .map_err(|_| AppError::Internal("Adresse d'expéditeur invalide (SMTP_USER mal configuré)".to_string()))
}

/// Envoie un e-mail contenant le code de double authentification (2FA).
pub async fn send_tfa_email(to_email: &str, code: &str, config: &crate::config::Config) -> Result<(), AppError> {
    // Construction du contenu et des entêtes de l'email
    let email = Message::builder()
        .from(parse_sender(format!("Mon App <{}>", config.smtp_user))?)
        .to(parse_recipient(to_email)?)
        .subject("Votre code de sécurité")
        .body(format!("Bonjour,\n\nVotre code de vérification est : {}\nCe code expire dans 5 minutes.", code))
        .map_err(|_| AppError::Internal("Erreur construction email".to_string()))?;

    // Configuration des identifiants de connexion au serveur de messagerie
    let creds = Credentials::new(config.smtp_user.clone(), config.smtp_pass.clone());

    // Initialisation du client de transport SMTP asynchrone lié au runtime Tokio
    let mailer: AsyncSmtpTransport<Tokio1Executor> =
        AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
            .map_err(|_| AppError::Internal("Erreur hôte SMTP".to_string()))?
            .credentials(creds)
            .build();

    // Envoi effectif de l'email de manière asynchrone (.await)
    // CORRECTIF : eprintln!() écrivait sur stderr brut, en dehors du pipeline tracing_subscriber
    // JSON que main.rs met en place (voir ./logs/server.json) — l'erreur n'apparaissait donc nulle
    // part dans les logs réellement exploités par les opérateurs. error!() ci-dessous s'intègre au
    // même pipeline que le reste de l'app.
    mailer.send(email).await.map_err(|e| {
        error!(target: "mailer", error = ?e, "échec d'envoi de l'e-mail 2FA");
        AppError::Internal("Échec de l'envoi de l'e-mail".to_string())
    })?;

    Ok(())
}

/// Envoie un e-mail d'alerte immédiate en cas d'activité suspecte sur le compte.
pub async fn send_security_alert(to_email: &str, message_content: &str, config: &crate::config::Config) -> Result<(), AppError> {
    let email = Message::builder()
        .from(parse_sender(format!("Sécurité Mon App <{}>", config.smtp_user))?)
        .to(parse_recipient(to_email)?)
        .subject("Alerte de sécurité - Votre compte")
        .body(format!("Bonjour,\n\nCeci est une notification automatique : {}\n\nSi vous n'êtes pas à l'origine de cette action, contactez le support immédiatement.", message_content))
        .map_err(|_| AppError::Internal("Erreur construction email".to_string()))?;

    // Initialise le mailer SMTP
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
        .map_err(|_| AppError::Internal("Erreur hôte SMTP".to_string()))?
        .credentials(Credentials::new(config.smtp_user.clone(), config.smtp_pass.clone()))
        .build();

    // Envoie l'alerte
    // CORRECTIF : l'erreur SMTP réelle était auparavant totalement jetée (`|_|`) — impossible de
    // diagnostiquer une panne d'envoi (identifiants expirés, relais qui rejette...) depuis les logs.
    mailer.send(email).await.map_err(|e| {
        error!(target: "mailer", error = ?e, "échec d'envoi de l'alerte de sécurité");
        AppError::Internal("Échec envoi alerte".to_string())
    })?;
    Ok(())
}

/// Fonction utilitaire privée (interne) pour centraliser et factoriser la création du client SMTP.
fn get_mailer(config: &crate::config::Config) -> Result<AsyncSmtpTransport<Tokio1Executor>, AppError> {
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
        .map_err(|_| AppError::Internal("Hôte SMTP invalide".into()))?
        .credentials(Credentials::new(config.smtp_user.clone(), config.smtp_pass.clone()))
        .build();

    Ok(mailer) // Retourne le client SMTP prêt à l'emploi
}

/// Envoie le code de confirmation d'email à l'inscription (voir handlers/auth/register.rs).
/// Tant que ce code n'a pas été validé via /auth/verify-email, le compte reste `email_verified
/// = false` et login() le refuse — empêche quelqu'un de s'inscrire avec l'email de quelqu'un
/// d'autre et de bloquer silencieusement sa vraie inscription.
pub async fn send_verification_email(to_email: &str, code: &str, config: &crate::config::Config) -> Result<(), AppError> {
    let email = Message::builder()
        .from(parse_sender(format!("Mon App <{}>", config.smtp_user))?)
        .to(parse_recipient(to_email)?)
        .subject("Confirmez votre adresse email")
        .body(format!("Bonjour,\n\nVotre code de confirmation d'inscription est : {}\nCe code expire dans 30 minutes. Si vous n'êtes pas à l'origine de cette inscription, ignorez cet e-mail.", code))
        .map_err(|_| AppError::Internal("Erreur construction email".to_string()))?;

    let mailer = get_mailer(config)?;
    mailer.send(email).await.map_err(|e| {
        error!(target: "mailer", error = ?e, "échec d'envoi de l'email de vérification");
        AppError::Internal("Échec envoi email de vérification".to_string())
    })?;

    Ok(())
}

/// Envoie un e-mail critique pour la réinitialisation du mot de passe maître (perte de données).
pub async fn send_reset_email(to_email: &str, code: &str, config: &crate::config::Config) -> Result<(), AppError> {
    let email = Message::builder()
        .from(parse_sender(format!("Support Mon App <{}>", config.smtp_user))?)
        .to(parse_recipient(to_email)?)
        .subject("Réinitialisation de votre mot de passe maître")
        .body(format!("Bonjour,\n\nVotre code : {}\n\nATTENTION : Cela supprimera définitivement vos données de coffre-fort.", code))
        .map_err(|_| AppError::Internal("Erreur construction email".to_string()))?;

    // Utilisation de la fonction utilitaire partagée définie juste au-dessus pour éviter la répétition de code
    let mailer = get_mailer(config)?;

    // Envoi de l'e-mail de réinitialisation
    mailer.send(email).await.map_err(|e| {
        error!(target: "mailer", error = ?e, "échec d'envoi de l'email de réinitialisation");
        AppError::Internal("Échec envoi reset".to_string())
    })?;

    Ok(())
}

// =========================================================================
// TESTS
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// RÉGRESSION : parse_recipient() ne doit JAMAIS paniquer sur une entrée malformée — c'est
    /// exactement le bug qu'avait l'ancien `.parse().unwrap()` direct sur `to_email` (donnée
    /// fournie par le client via le payload de la requête, ex: register()/forgot-password()).
    /// Elle doit renvoyer une erreur applicative propre à la place.
    #[test]
    fn test_parse_recipient_rejects_malformed_address_without_panicking() {
        let result = parse_recipient("ceci-nest-pas-un-email");
        assert!(matches!(result, Err(AppError::ValidationError(_))), "une adresse malformée doit être rejetée proprement, jamais paniquer");
    }

    /// Une adresse valide doit toujours être acceptée (non-régression du chemin normal).
    #[test]
    fn test_parse_recipient_accepts_valid_address() {
        let result = parse_recipient("utilisateur@example.com");
        assert!(result.is_ok(), "une adresse email valide doit être acceptée");
    }

    /// Même garde-fou côté expéditeur (dérivé de SMTP_USER, pas d'une entrée client) : une
    /// valeur mal configurée doit renvoyer une erreur interne, jamais paniquer.
    #[test]
    fn test_parse_sender_rejects_malformed_address_without_panicking() {
        let result = parse_sender("Mon App <pas-une-adresse>".to_string());
        assert!(matches!(result, Err(AppError::Internal(_))), "un SMTP_USER mal configuré doit être signalé proprement, jamais paniquer");
    }

    #[test]
    fn test_parse_sender_accepts_valid_address() {
        let result = parse_sender("Mon App <noreply@example.com>".to_string());
        assert!(result.is_ok(), "une adresse d'expéditeur valide doit être acceptée");
    }
}
