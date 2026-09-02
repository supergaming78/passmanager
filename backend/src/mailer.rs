// =========================================================================
// SERVICES D'ENVOI D'E-MAILS (SMTP)
// =========================================================================
// Anciennement regroupé avec le hachage/JWT dans un seul `security.rs` — séparé pour que ce
// fichier ne fasse qu'une chose : construire et envoyer des e-mails via SMTP. Voir crypto.rs
// pour tout ce qui est calcul cryptographique pur (hachage, signature, comparaison).

use lettre::transport::smtp::authentication::Credentials;
use lettre::message::{Mailbox, MultiPart, SinglePart, header::ContentType};
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

// -------------------------------------------------------------------------
// GABARIT HTML (CORRECTIF, 2026-09-02 : les emails n'étaient qu'en texte brut, avec un nom
// d'expéditeur générique "Mon App" au lieu de "PassManager")
// -------------------------------------------------------------------------
// Un seul gabarit partagé par tous les emails ci-dessous plutôt qu'un HTML dupliqué dans chaque
// fonction — cohérence visuelle garantie, un seul endroit à modifier si le design doit changer.
// Styles en LIGNE, mise en page par `<table>` : les clients email (Gmail, Outlook...) ignorent ou
// tronquent souvent une balise <style> globale et ne supportent qu'un sous-ensemble ancien de CSS
// — c'est la norme du secteur pour un rendu fiable partout, pas juste une préférence de style.
// `MultiPart::alternative()` : envoie TOUJOURS aussi un repli texte brut à côté du HTML (voir
// build_email() plus bas) — un client qui ne rend pas le HTML (ou un lecteur d'écran) affiche ce
// repli, jamais un email vide/cassé.

const BRAND_COLOR: &str = "#4f46e5"; // indigo-600 — même couleur que le reste de l'app (voir
                                      // frontend(app)/extension : bg-indigo-600 partout).

/// Enveloppe le CONTENU (déjà en HTML) dans l'en-tête/pied de page communs à tous les emails.
fn html_wrapper(body_html: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="fr">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="margin:0; padding:0; background-color:#f4f4f6; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f4f6; padding:32px 16px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px; background-color:#ffffff; border-radius:12px; overflow:hidden;">
        <tr>
          <td style="background-color:{BRAND_COLOR}; padding:20px 32px;">
            <span style="color:#ffffff; font-size:18px; font-weight:600;">🔐 PassManager</span>
          </td>
        </tr>
        <tr>
          <td style="padding:32px; color:#1f2933; font-size:15px; line-height:1.6;">
            {body_html}
          </td>
        </tr>
        <tr>
          <td style="padding:16px 32px; background-color:#fafafa; border-top:1px solid #eeeeee;">
            <p style="margin:0; color:#9aa1ab; font-size:12px;">Si tu n'es pas à l'origine de cette action, tu peux ignorer cet email en toute sécurité.</p>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"#
    )
}

/// Bloc visuel pour un CODE à saisir (2FA, vérification, reset) — grand, espacé, monospace :
/// nettement plus lisible qu'un code noyé dans une phrase, et copiable en un clic sur mobile
/// (le bloc entier est sélectionnable).
fn code_box(code: &str) -> String {
    format!(
        r#"<div style="background-color:#f4f4f7; border-radius:8px; padding:20px; text-align:center; margin:20px 0;">
  <span style="font-family:'SF Mono',Consolas,monospace; font-size:32px; font-weight:700; letter-spacing:6px; color:{BRAND_COLOR};">{code}</span>
</div>"#
    )
}

/// Construit un `Message` avec DEUX représentations (texte brut + HTML, voir `MultiPart::alternative`
/// ci-dessus) — remplace l'ancien `.body(plain_text)` unique dans chaque fonction `send_*` ci-dessous.
fn build_email(from: Mailbox, to: Mailbox, subject: &str, plain_text: String, html_body: String) -> Result<Message, AppError> {
    Message::builder()
        .from(from)
        .to(to)
        .subject(subject)
        .multipart(
            MultiPart::alternative()
                .singlepart(SinglePart::builder().header(ContentType::TEXT_PLAIN).body(plain_text))
                .singlepart(SinglePart::builder().header(ContentType::TEXT_HTML).body(html_wrapper(&html_body))),
        )
        .map_err(|_| AppError::Internal("Erreur construction email".to_string()))
}

/// Envoie un e-mail contenant le code de double authentification (2FA).
pub async fn send_tfa_email(to_email: &str, code: &str, config: &crate::config::Config) -> Result<(), AppError> {
    let email = build_email(
        parse_sender(format!("PassManager <{}>", config.smtp_user))?,
        parse_recipient(to_email)?,
        "Votre code de sécurité",
        format!("Bonjour,\n\nVotre code de vérification est : {code}\nCe code expire dans 5 minutes."),
        format!(
            "<p>Bonjour,</p><p>Voici ton code de vérification pour te connecter :</p>{}<p style=\"color:#6b7280; font-size:13px;\">Ce code expire dans <strong>5 minutes</strong>.</p>",
            code_box(code)
        ),
    )?;

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
    let email = build_email(
        parse_sender(format!("Sécurité PassManager <{}>", config.smtp_user))?,
        parse_recipient(to_email)?,
        "Alerte de sécurité - Votre compte",
        format!("Bonjour,\n\nCeci est une notification automatique : {message_content}\n\nSi vous n'êtes pas à l'origine de cette action, contactez le support immédiatement."),
        format!(
            "<p>Bonjour,</p><p style=\"background-color:#fef2f2; border-left:3px solid #dc2626; padding:12px 16px; border-radius:4px; color:#991b1b;\">⚠️ {message_content}</p><p>Si tu n'es pas à l'origine de cette action, change ton mot de passe maître immédiatement et contacte la personne qui héberge ce serveur.</p>"
        ),
    )?;

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
    let email = build_email(
        parse_sender(format!("PassManager <{}>", config.smtp_user))?,
        parse_recipient(to_email)?,
        "Confirmez votre adresse email",
        format!("Bonjour,\n\nVotre code de confirmation d'inscription est : {code}\nCe code expire dans 30 minutes. Si vous n'êtes pas à l'origine de cette inscription, ignorez cet e-mail."),
        format!(
            "<p>Bonjour,</p><p>Bienvenue sur PassManager ! Confirme ton adresse email avec ce code :</p>{}<p style=\"color:#6b7280; font-size:13px;\">Ce code expire dans <strong>30 minutes</strong>. Si tu n'es pas à l'origine de cette inscription, tu peux simplement ignorer cet email.</p>",
            code_box(code)
        ),
    )?;

    let mailer = get_mailer(config)?;
    mailer.send(email).await.map_err(|e| {
        error!(target: "mailer", error = ?e, "échec d'envoi de l'email de vérification");
        AppError::Internal("Échec envoi email de vérification".to_string())
    })?;

    Ok(())
}

/// Envoie un e-mail critique pour la réinitialisation du mot de passe maître (perte de données).
pub async fn send_reset_email(to_email: &str, code: &str, config: &crate::config::Config) -> Result<(), AppError> {
    let email = build_email(
        parse_sender(format!("Support PassManager <{}>", config.smtp_user))?,
        parse_recipient(to_email)?,
        "Réinitialisation de votre mot de passe maître",
        format!("Bonjour,\n\nVotre code : {code}\n\nATTENTION : Cela supprimera définitivement vos données de coffre-fort."),
        format!(
            "<p>Bonjour,</p><p>Voici ton code de réinitialisation :</p>{}<p style=\"background-color:#fffbeb; border-left:3px solid #d97706; padding:12px 16px; border-radius:4px; color:#92400e;\"><strong>⚠️ Attention :</strong> réinitialiser ton mot de passe maître supprimera <strong>définitivement</strong> les données de ton coffre-fort — elles ne peuvent pas être déchiffrées sans l'ancien mot de passe.</p>",
            code_box(code)
        ),
    )?;

    // Utilisation de la fonction utilitaire partagée définie juste au-dessus pour éviter la répétition de code
    let mailer = get_mailer(config)?;

    // Envoi de l'e-mail de réinitialisation
    mailer.send(email).await.map_err(|e| {
        error!(target: "mailer", error = ?e, "échec d'envoi de l'email de réinitialisation");
        AppError::Internal("Échec envoi reset".to_string())
    })?;

    Ok(())
}

/// Prévient la personne qui a signalé un bug (si elle a laissé son email) que le modérateur l'a
/// marqué traité — voir handlers/bug_report.rs::delete_bug_report, appelée en `let _ =` (best
/// effort, ne fait jamais échouer la suppression elle-même si l'envoi rate).
pub async fn send_bug_report_resolved(to_email: &str, description_snippet: &str, config: &crate::config::Config) -> Result<(), AppError> {
    let email = build_email(
        parse_sender(format!("PassManager <{}>", config.smtp_user))?,
        parse_recipient(to_email)?,
        "Ton signalement de bug a été traité",
        format!("Bonjour,\n\nLe bug que tu avais signalé (\"{description_snippet}\") a été marqué comme traité.\n\nMerci pour ton signalement !"),
        format!(
            "<p>Bonjour,</p><p>Le bug que tu avais signalé a été marqué comme traité :</p><p style=\"background-color:#f4f4f7; border-radius:8px; padding:12px 16px; font-style:italic; color:#4b5563;\">\"{description_snippet}\"</p><p>Merci pour ton signalement ! 🙏</p>"
        ),
    )?;

    let mailer = get_mailer(config)?;
    mailer.send(email).await.map_err(|e| {
        error!(target: "mailer", error = ?e, "échec d'envoi de l'email de suivi de signalement de bug");
        AppError::Internal("Échec envoi suivi signalement".to_string())
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

    /// RÉGRESSION : build_email() doit produire un message multipart/alternative (texte brut +
    /// HTML), pas juste l'un ou l'autre — un client qui ne rend pas le HTML doit quand même
    /// afficher un contenu lisible (voir le commentaire en tête de fichier sur MultiPart::alternative).
    #[test]
    fn test_build_email_produces_both_plain_and_html_parts() {
        let email = build_email(
            parse_sender("PassManager <noreply@example.com>".to_string()).unwrap(),
            parse_recipient("utilisateur@example.com").unwrap(),
            "Sujet de test",
            "Contenu en texte brut".to_string(),
            "<p>Contenu en HTML</p>".to_string(),
        )
        .unwrap();
        let formatted = String::from_utf8_lossy(&email.formatted()).to_string();
        assert!(formatted.contains("Contenu en texte brut"), "le repli texte brut doit être présent");
        assert!(formatted.contains("Contenu en HTML"), "le contenu HTML doit être présent");
        assert!(formatted.contains("multipart/alternative"), "doit être un message multipart/alternative");
    }

    /// RÉGRESSION : le nom d'expéditeur générique "Mon App" (oublié d'un gabarit précédent) ne
    /// doit plus apparaître — toutes les fonctions send_* doivent utiliser "PassManager" (ou une
    /// variante préfixée, ex: "Support PassManager").
    #[test]
    fn test_code_box_contains_the_code() {
        let html = code_box("123456");
        assert!(html.contains("123456"), "le bloc de code doit contenir le code fourni");
    }
}
