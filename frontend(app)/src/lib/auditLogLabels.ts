// Traduit les codes d'action bruts de l'historique d'audit (voir backend/src/state.rs::log_audit
// et tous ses points d'appel) en libellés lisibles pour components/SecurityHistorySettings.tsx.
// Volontairement un simple dictionnaire avec repli sur le code brut si absent — une action future
// ajoutée côté backend sans mise à jour de ce fichier reste affichée (juste moins joliment), plutôt
// que de faire disparaître silencieusement une entrée de l'historique de sécurité de l'utilisateur.

const ACTION_LABELS: Record<string, string> = {
  // Connexion
  LOGIN_SUCCESS_SESSION: "Connexion réussie",
  LOGIN_SUCCESS_REMEMBER: "Connexion réussie (« se souvenir de moi »)",
  LOGIN_FAILED: "Tentative de connexion échouée",
  LOGIN_BLOCKED_UNVERIFIED: "Connexion bloquée (email non vérifié)",
  REFRESH_TOKEN_EXPIRED: "Session expirée",
  LOGIN_NEW_IP_DETECTED: "Connexion depuis une nouvelle adresse IP",

  // Appareils de confiance
  DEVICE_REVOKED: "Appareil de confiance révoqué",
  DEVICE_LIMIT_CHANGED: "Plafond d'appareils de confiance modifié",
  LOGOUT_ALL_DEVICES: "Déconnexion de tous les appareils",

  // Coffre
  VAULT_ADD: "Entrée ajoutée au coffre",
  VAULT_UPDATE: "Entrée du coffre modifiée",
  VAULT_DELETE: "Entrée envoyée à la corbeille",
  VAULT_RESTORE: "Entrée restaurée depuis la corbeille",
  VAULT_PURGE: "Entrée supprimée définitivement",
  VAULT_TOGGLE_FAVORITE: "Favori basculé",
  VAULT_EXPORT: "Coffre exporté",
  VAULT_HISTORY_EXPORT: "Historique de mots de passe exporté",
  VAULT_IMPORT: "Entrées importées dans le coffre",
  VAULT_ATTACHMENT_ADD: "Pièce jointe ajoutée",
  VAULT_ATTACHMENT_DELETE: "Pièce jointe supprimée",

  // Partage d'entrée
  VAULT_SHARE_ENTRY: "Entrée partagée avec un autre compte",
  VAULT_SHARE_VIEW: "Entrée partagée consultée",
  VAULT_SHARE_REVOKE: "Partage d'entrée révoqué",

  // Accès d'urgence
  EMERGENCY_CONTACT_ADD: "Contact d'urgence ajouté",
  EMERGENCY_CONTACT_ACCEPT: "Invitation de contact d'urgence acceptée",
  EMERGENCY_CONTACT_REVOKE: "Contact d'urgence révoqué",
  EMERGENCY_ACCESS_REQUEST: "Accès d'urgence demandé",
  EMERGENCY_ACCESS_APPROVE: "Accès d'urgence approuvé",
  EMERGENCY_ACCESS_REJECT: "Accès d'urgence refusé",
  EMERGENCY_VAULT_VIEW: "Coffre consulté via un accès d'urgence",

  // Administration (visibles seulement si CE compte a lui-même été la cible d'une action admin)
  ADMIN_ROLE_GRANTED: "Rôle modérateur accordé",
  ADMIN_ROLE_REVOKED: "Rôle modérateur retiré",
  ADMIN_SESSIONS_REVOKED: "Sessions déconnectées par un administrateur",
  ADMIN_DELETED_USER_ACCOUNT: "Compte supprimé par un administrateur",
  ADMIN_EMAIL_CHANGED: "Email modifié par un administrateur",
  EXTENSION_EMAIL_CHANGE_ENABLED: "Changement d'email via l'extension autorisé par un administrateur",
  EXTENSION_EMAIL_CHANGE_DISABLED: "Changement d'email via l'extension retiré par un administrateur",
  EXTENSION_EMAIL_CHANGE_ENABLED_ALL: "Changement d'email via l'extension autorisé pour tous les comptes",
  EXTENSION_EMAIL_CHANGE_DISABLED_ALL: "Changement d'email via l'extension retiré pour tous les comptes",
};

/** Libellé français pour un code d'action — repli sur le code brut si inconnu (voir commentaire
 * en tête de fichier). */
export function auditActionLabel(action: string): string {
  return ACTION_LABELS[action] ?? action;
}
