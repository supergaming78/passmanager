// Types miroir des payloads/réponses du backend (voir backend/src/models.rs et docs/API.md).
// `master_password_hash` partout ci-dessous n'est JAMAIS le mot de passe maître en clair — c'est
// le hash d'authentification dérivé côté client (voir src-tauri/src/crypto.rs::derive_keys()),
// exactement ce que le backend attend (voir AuthPayload côté serveur).

export interface RegisterPayload {
  email: string;
  master_password_hash: string;
  device_id: string;
  remember_me?: boolean;
  max_trusted_devices?: number;
}

export interface LoginPayload {
  email: string;
  master_password_hash: string;
  device_id: string;
  remember_me?: boolean;
}

export interface VerifyEmailPayload {
  email: string;
  code: string;
}

export interface ResendVerificationPayload {
  email: string;
}

export interface VerifyTfaPayload {
  email: string;
  code: string;
  device_id: string;
  device_name?: string;
}

export interface RefreshPayload {
  refresh_token: string;
}

// --- Synchronisation temps réel (WebSocket) ---

/** Réponse de POST /ws/ticket : jeton à usage unique et très courte durée de vie (60s),
 * échangé contre l'access token pour ouvrir /ws — voir sync.rs côté backend pour le pourquoi de
 * cette indirection (l'API WebSocket des navigateurs ne permet pas d'en-tête Authorization). */
export interface WsTicketResponse {
  ticket: string;
  expires_in: number;
}

/** Événement reçu sur la connexion WebSocket — voir models.rs::SyncEvent côté backend.
 * `user_email` n'est JAMAIS inclus (voir #[serde(skip)] côté backend) : le filtrage par
 * utilisateur est déjà fait côté serveur avant l'envoi, pas la peine de le renvoyer au client. */
export interface SyncEvent {
  event_type: string;
}

// --- Coffre-fort ---
// TOUS les champs `encrypted_*` sont des blobs chiffrés (voir src-tauri/src/crypto.rs) — le
// serveur ne les lit, ne les trie et ne les compare jamais. Ces types représentent la forme
// CHIFFRÉE telle qu'échangée avec le backend ; voir lib/vaultCrypto.ts pour la forme déchiffrée
// utilisée par l'UI.

export interface VaultEntryInput {
  encrypted_site_name: string;
  encrypted_username?: string | null;
  encrypted_login_email?: string | null;
  encrypted_password: string;
  encrypted_preferred_login_type: string;
  is_favorite: boolean;
  encrypted_folder?: string | null;
  encrypted_notes?: string | null;
  encrypted_url?: string | null;
  /** Type d'entrée dédié ("login"/"card"/"identity"/"note") — métadonnée EN CLAIR, comme
   * is_favorite. Optionnel côté client : un client plus ancien qui l'omet crée une entrée "login"
   * (voir default_entry_type() côté backend). */
  entry_type?: string;
  /** Blob JSON chiffré contenant les champs additionnels spécifiques au type (voir
   * lib/vaultCrypto.ts::PlainVaultEntry.extraFields) — jamais interprété par le serveur. */
  encrypted_extra_fields?: string | null;
  /** Vrai UNIQUEMENT si le mot de passe a réellement été changé dans le formulaire (pas à chaque
   * simple modification de site/dossier/notes/url) — voir handlers/vault.rs côté backend.
   * Détermine si l'ancien mot de passe chiffré doit être archivé dans l'historique. */
  password_changed?: boolean;
  /** Détection de conflit d'édition — le `version` reçu la dernière fois que cette entrée a été
   * chargée (voir VaultEntry.version). Si différent de la valeur actuelle en base au moment du
   * PUT, le serveur refuse la modification (409) plutôt que de l'écraser silencieusement. */
  expected_version?: number | null;
}

export interface VaultEntry extends VaultEntryInput {
  id: string;
  user_email: string;
  /** Toujours présent dans une réponse serveur (contrairement à VaultEntryInput où il est
   * optionnel côté soumission, pour la rétrocompatibilité). */
  entry_type: string;
  updated_at: string;
  /** Compteur incrémenté à chaque modification — voir expected_version ci-dessus. */
  version: number;
  /** Vrai si cette entrée a au moins une pièce jointe (calculé à la volée côté serveur). */
  has_attachments: boolean;
  /** Nombre de fois où cette entrée a été utilisée (copie du mot de passe ou remplissage
   * automatique — voir api/client.ts::recordVaultEntryUse) — pour le tri "le plus utilisé". */
  use_count: number;
}

/** Entrée dans la corbeille (GET /vault/trash) — PAS de encrypted_password ni user_email, voir
 * TrashedVaultEntry côté backend : pas besoin du mot de passe pour un écran "à restaurer ou
 * purger", seulement de quoi identifier l'entrée. */
export interface TrashedVaultEntry {
  id: string;
  encrypted_site_name: string;
  encrypted_username?: string | null;
  encrypted_login_email?: string | null;
  encrypted_preferred_login_type: string;
  is_favorite: boolean;
  deleted_at: string;
  encrypted_folder?: string | null;
}

/** Une entrée déjà re-chiffrée par prepare_password_change() (voir api/tauri.ts), prête à
 * envoyer dans ChangeMasterPasswordPayload.reencrypted_entries — PAS de is_favorite ici, cette
 * métadonnée en clair n'est pas affectée par un changement de clé de chiffrement. */
export interface ReencryptedVaultEntry {
  id: string;
  encrypted_site_name: string;
  encrypted_username?: string | null;
  encrypted_login_email?: string | null;
  encrypted_password: string;
  encrypted_preferred_login_type: string;
  encrypted_folder?: string | null;
  encrypted_notes?: string | null;
  encrypted_url?: string | null;
  /** `entry_type` n'a pas besoin d'être re-chiffré (déjà en clair) — seul ce blob l'est, comme les
   * autres champs `encrypted_*` ci-dessus. */
  encrypted_extra_fields?: string | null;
}

/** Pièce jointe soumise par le client (POST /vault/{id}/attachments) — nom de fichier ET contenu
 * CHIFFRÉS côté client (voir lib/vaultAttachments.ts). `content_size` : SEULE métadonnée en clair,
 * la taille en octets du fichier ORIGINAL avant chiffrement (fournie par le client, pour
 * l'affichage — pas vérifiable par le serveur). */
export interface VaultAttachmentInput {
  encrypted_filename: string;
  encrypted_content: string;
  content_size: number;
}

/** Métadonnées d'une pièce jointe SANS son contenu (GET /vault/{id}/attachments, listing). */
export interface VaultAttachmentMeta {
  id: string;
  encrypted_filename: string;
  content_size: number;
  created_at: string;
}

/** Pièce jointe complète, avec son contenu chiffré (GET /vault/{id}/attachments/{attachment_id}). */
export interface VaultAttachment extends VaultAttachmentMeta {
  vault_id: string;
  encrypted_content: string;
}

/** Une ligne d'historique de mot de passe (GET /vault/{id}/history, POST /vault/history/export). */
export interface PasswordHistoryEntry {
  id: string;
  vault_id: string;
  encrypted_password: string;
  changed_at: string;
}

/** Une ligne d'historique déjà re-chiffrée, prête à envoyer dans
 * ChangeMasterPasswordPayload.reencrypted_history. */
export interface ReencryptedHistoryEntry {
  id: string;
  encrypted_password: string;
}

/** Une pièce jointe déjà re-chiffrée par prepare_password_change(), prête à envoyer dans
 * ChangeMasterPasswordPayload.reencrypted_attachments — même principe que ReencryptedVaultEntry/
 * ReencryptedHistoryEntry, mais pour vault_attachments (nom de fichier ET contenu ensemble). */
export interface ReencryptedVaultAttachment {
  id: string;
  encrypted_filename: string;
  encrypted_content: string;
}

// --- Compte ---

export interface MeResponse {
  email: string;
  /** Droits de modérateur — voir SettingsView.tsx, qui gate la section "Serveur" et le formulaire
   * de changement d'email dessus (avec can_change_email_via_extension). */
  is_moderator: boolean;
  max_trusted_devices: number;
  /** Autorisation à changer son email DEPUIS L'EXTENSION NAVIGATEUR — voir SettingsView.tsx, qui
   * masque le formulaire de changement d'email tant que ni ce champ ni is_moderator ne sont vrais. */
  can_change_email_via_extension: boolean;
  /** Vrai UNIQUEMENT pour le compte ADMIN_EMAIL (il n'existe qu'UN SEUL "Admin") — pas encore
   * utilisé côté popup (pas d'écran Administration ici), présent pour rester synchronisé avec la
   * forme réelle de GET /me côté backend. */
  is_admin: boolean;
}

export interface ChangeMasterPasswordPayload {
  old_master_password_hash: string;
  new_master_password_hash: string;
  reencrypted_entries: ReencryptedVaultEntry[];
  reencrypted_history: ReencryptedHistoryEntry[];
  reencrypted_attachments: ReencryptedVaultAttachment[];
}

export interface UpdateEmailPayload {
  new_email: string;
  master_password_hash: string;
}

// --- Administration (réservé aux comptes is_moderator, voir GET /me) ---

export interface AdminUserView {
  email: string;
  is_moderator: boolean;
  email_verified: boolean;
  created_at: string;
  max_trusted_devices: number;
  can_change_email_via_extension: boolean;
  /** Vrai UNIQUEMENT pour le compte ADMIN_EMAIL — pas encore utilisé côté popup (pas d'écran
   * Administration ici), présent pour rester synchronisé avec la forme réelle de GET /admin/users. */
  is_admin: boolean;
}

export interface UpdateUserRolePayload {
  is_moderator: boolean;
}

export interface AuditLog {
  id: number;
  user_email: string;
  action: string;
  ip_address: string;
  user_agent: string | null;
  created_at: string;
}

// --- Appareils de confiance ---

export interface TrustedDevice {
  device_id: string;
  device_name: string | null;
  created_at: string;
  last_used_at: string;
  /** Dernière IP connue pour cet appareil — `null` si aucune n'a encore été enregistrée
   * (appareil approuvé avant l'ajout de ce suivi, voir backend/migrations/20260831000000). */
  last_ip: string | null;
}

export interface UpdateDeviceLimitPayload {
  new_limit: number;
  master_password_hash: string;
}

// --- Accès d'urgence (voir src-tauri/src/emergency.rs pour le chiffrement, lib/emergencyAccess.ts
// côté frontend pour l'orchestration) — Zero-Knowledge de bout en bout, le serveur ne relaie que
// des clés publiques et des blobs déjà scellés côté client. ---

/** Paire de clés X25519 — `encrypted_private_key` est CHIFFRÉE côté client avec la clé du coffre,
 * le serveur ne la voit jamais en clair. */
export interface UserKeysInput {
  public_key: string;
  encrypted_private_key: string;
}

/** Réponse de GET /emergency/keys/{email} — UNIQUEMENT la clé publique de cet utilisateur. */
export interface UserPublicKey {
  public_key: string;
}

export interface AddEmergencyContactPayload {
  contact_email: string;
  waiting_period_days: number;
}

export interface SeedEmergencyKeyPayload {
  sealed_vault_key: string;
}

/** Une relation d'accès d'urgence — voir docs/API.md pour la machine à états complète de `status`.
 * PAS de `sealed_vault_key` ici (volontairement, voir backend/src/repository.rs) : ce blob ne
 * transite QUE via GET /emergency/contacts/{id}/vault, une fois l'accès réellement accordé. */
export interface EmergencyContact {
  id: string;
  owner_email: string;
  contact_email: string;
  waiting_period_days: number;
  status: "pending" | "active" | "access_requested" | "access_granted";
  requested_at: string | null;
  available_at: string | null;
  created_at: string;
}

/** Réponse de GET /emergency/contacts/{id}/vault — le coffre complet (lecture seule) d'un
 * propriétaire ayant accordé l'accès d'urgence, avec le blob scellé nécessaire pour en retrouver
 * la clé de déchiffrement. */
export interface EmergencyVaultView {
  sealed_vault_key: string;
  entries: VaultEntry[];
}

// --- Partage sécurisé d'une entrée — même construction Zero-Knowledge que l'accès d'urgence
// ci-dessus (boîte scellée X25519, réutilise UserPublicKey/user_keys), mais INSTANTANÉ : pas de
// délai d'attente ni de machine à états. Voir lib/entrySharing.ts. ---

export interface ShareEntryPayload {
  shared_with_email: string;
  sealed_entry: string;
}

/** Vue propriétaire d'un partage (GET /vault/{id}/shares) — PAS de `sealed_entry` ici
 * (volontairement, voir backend\src\repository.rs) : ce blob ne transite QUE via GET /shares/{id},
 * réservé au destinataire. */
export interface VaultShare {
  id: string;
  shared_with_email: string;
  created_at: string;
}

/** Vue destinataire d'un partage (GET /shares/shared-with-me) — même raison, jamais
 * `sealed_entry`. */
export interface SharedWithMeEntry {
  id: string;
  vault_id: string;
  owner_email: string;
  created_at: string;
}

/** Réponse de GET /shares/{id} — LE seul endpoint à exposer `sealed_entry`. */
export interface SharedEntryView {
  owner_email: string;
  sealed_entry: string;
}

// --- Coffres partagés familiaux — S'AJOUTE au partage d'entrée 1-vers-1 ci-dessus, ne le remplace
// pas. Clé SYMÉTRIQUE partagée par tous les membres (scellée individuellement pour chacun) plutôt
// qu'un blob par destinataire : une modification est visible EN DIRECT par tous. Voir
// lib/sharedVault.ts et backend\docs\API.md#endpoints--coffres-partagés-familiaux. ---

export interface CreateSharedVaultPayload {
  encrypted_name: string;
  sealed_vault_key: string;
}

/** Vue d'un coffre partagé pour l'appelant (GET /shared-vaults) — `sealed_vault_key` est TOUJOURS
 * la copie de l'appelant, jamais celle d'un autre membre. */
export interface SharedVaultView {
  id: string;
  encrypted_name: string;
  created_by: string;
  created_at: string;
  sealed_vault_key: string;
  is_owner: boolean;
}

export interface InviteSharedVaultMemberPayload {
  member_email: string;
  sealed_vault_key: string;
}

/** Jamais `sealed_vault_key` ici : la clé scellée d'un membre n'est déchiffrable que par lui. */
export interface SharedVaultMemberView {
  member_email: string;
  is_owner: boolean;
  added_at: string;
}

export interface SharedVaultEntryInput {
  encrypted_site_name: string;
  encrypted_username?: string | null;
  encrypted_login_email?: string | null;
  encrypted_password: string;
  encrypted_preferred_login_type: string;
  encrypted_notes?: string | null;
  encrypted_url?: string | null;
  entry_type: string;
  encrypted_extra_fields?: string | null;
  expected_version?: number | null;
}

export interface SharedVaultEntry {
  id: string;
  shared_vault_id: string;
  encrypted_site_name: string;
  encrypted_username: string | null;
  encrypted_login_email: string | null;
  encrypted_password: string;
  encrypted_preferred_login_type: string;
  encrypted_notes: string | null;
  encrypted_url: string | null;
  entry_type: string;
  encrypted_extra_fields: string | null;
  created_by: string;
  updated_at: string;
  version: number;
}

// --- Partage à usage limité ("aveugle") — S'AJOUTE au partage d'entrée classique ET aux coffres
// partagés familiaux ci-dessus, ne remplace ni l'un ni l'autre. Le destinataire ne voit JAMAIS
// l'identifiant ni le mot de passe (seulement le nom du site) et ne peut "utiliser" le partage
// qu'un nombre de fois limité (défaut 1). Voir lib/blindShare.ts et
// backend\docs\API.md#endpoints--partage-à-usage-limité. ---

export interface CreateBlindSharePayload {
  shared_with_email: string;
  sealed_site_name: string;
  sealed_credentials: string;
  max_uses: number;
}

/** Vue propriétaire (GET /vault/{id}/blind-shares) — jamais les blobs scellés. */
export interface VaultBlindShare {
  id: string;
  shared_with_email: string;
  max_uses: number;
  remaining_uses: number;
  created_at: string;
}

/** Vue destinataire (GET /blind-shares/shared-with-me) — `sealed_site_name` EST inclus (librement
 * consultable, ne consomme jamais d'usage), jamais `sealed_credentials`. */
export interface BlindShareReceivedView {
  id: string;
  owner_email: string;
  sealed_site_name: string;
  max_uses: number;
  remaining_uses: number;
  created_at: string;
}

/** Réponse de POST /blind-shares/{id}/use — LE seul endpoint à exposer `sealed_credentials`. */
export interface BlindShareCredentialsView {
  sealed_credentials: string;
  remaining_uses: number;
}

// --- Import / export du coffre ---

export interface ImportVaultPayload {
  entries: VaultEntryInput[];
}

export interface ExportVaultPayload {
  master_password_hash: string;
}

/** Réponse de connexion réussie (appareil déjà de confiance) — voir handlers/auth/session.rs::login(). */
export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  expires_in: number;
}

/** Réponse quand l'appareil n'est PAS encore de confiance : un code 2FA vient d'être envoyé par email. */
export interface TfaRequiredResponse {
  status: "2FA_REQUIRED";
}

// --- Personnalisation de thème, en PROFILS (voir handlers/theme_customization.rs côté backend) ---

/** Teintes en degrés (0-359), luminosités/saturations en pourcentage (0-100) — toute la
 * dérivation de palette (chroma native Tailwind MULTIPLIÉE par la saturation, décalage de
 * luminosité relatif) reste côté client, voir lib/customTheme.ts. Pas de mode clair/sombre
 * séparé : déduit de `background_lightness`. */
export interface ThemeProfileView {
  id: string;
  name: string;
  background_hue: number;
  background_lightness: number;
  /** 0 = gris pur (`background_hue` ignoré), 100 = couleur de fond la plus vive possible — voir
   * lib/customTheme.ts::applyBackground. */
  background_saturation: number;
  accent_hue: number;
  accent_lightness: number;
  accent_saturation: number;
  danger_hue: number;
  danger_lightness: number;
  danger_saturation: number;
  success_hue: number;
  success_lightness: number;
  success_saturation: number;
  favorite_hue: number;
  favorite_lightness: number;
  favorite_saturation: number;
  /** Au plus UN profil actif à la fois par compte (voir activateThemeProfile côté client). */
  is_active: boolean;
}

export type ThemeProfilePayload = Omit<ThemeProfileView, "id" | "is_active">;

/** Erreur générique renvoyée par le backend, voir error.rs::AppError::into_response(). */
export interface ApiErrorBody {
  error: string;
}

/** Levée par le client API pour toute réponse HTTP non-2xx — porte le statut ET le message
 * renvoyé par le backend, pour que l'UI puisse afficher quelque chose de pertinent. */
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}
