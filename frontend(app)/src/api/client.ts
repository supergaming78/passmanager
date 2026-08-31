// Client HTTP typé vers le backend — un fetch() par route, jamais de logique de construction
// d'URL/gestion d'erreur dupliquée ailleurs dans l'app (voir request() ci-dessous).

import { getBackendUrl } from "../lib/settings";
import {
  ApiError,
  type AddEmergencyContactPayload,
  type AdminUpdateEmailPayload,
  type AdminUserView,
  type ApiErrorBody,
  type AuditLog,
  type AuthTokens,
  type ChangeMasterPasswordPayload,
  type EmergencyContact,
  type EmergencyVaultView,
  type ExportVaultPayload,
  type ImportVaultPayload,
  type LoginPayload,
  type MeResponse,
  type PasswordHistoryEntry,
  type RefreshPayload,
  type RegisterPayload,
  type ResendVerificationPayload,
  type SeedEmergencyKeyPayload,
  type ShareEntryPayload,
  type SharedEntryView,
  type SharedWithMeEntry,
  type TfaRequiredResponse,
  type TrashedVaultEntry,
  type TrustedDevice,
  type UpdateDeviceLimitPayload,
  type UpdateEmailPayload,
  type UpdateExtensionEmailChangePayload,
  type UpdateUserRolePayload,
  type UserKeysInput,
  type UserPublicKey,
  type VaultAttachment,
  type VaultAttachmentInput,
  type VaultAttachmentMeta,
  type VaultEntry,
  type VaultEntryInput,
  type VaultShare,
  type VerifyEmailPayload,
  type VerifyTfaPayload,
  type WsTicketResponse,
  type CreateSharedVaultPayload,
  type SharedVaultView,
  type InviteSharedVaultMemberPayload,
  type SharedVaultMemberView,
  type SharedVaultEntry,
  type SharedVaultEntryInput,
  type CreateBlindSharePayload,
  type VaultBlindShare,
  type BlindShareReceivedView,
  type BlindShareCredentialsView,
  type CreateBugReportPayload,
  type BugReportView,
} from "./types";

/**
 * Effectue une requête JSON vers le backend et retourne le corps déjà parsé. Lève une ApiError
 * (avec le statut HTTP et le message renvoyé par le backend, voir error.rs côté serveur) pour
 * toute réponse non-2xx — centralise cette gestion pour que chaque fonction ci-dessous reste une
 * simple déclaration de route, sans répéter la logique d'erreur.
 */
async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${getBackendUrl()}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
    });
  } catch {
    // fetch() elle-même a échoué (avant même une réponse HTTP) : serveur éteint, mauvaise URL de
    // backend (voir lib/settings.ts), ou requête bloquée par CORS. Le message natif du navigateur
    // ("Failed to fetch") ne dit rien d'exploitable à l'utilisateur — on le remplace par quelque
    // chose d'actionnable plutôt que de laisser l'appelant retomber sur un message générique.
    throw new ApiError(0, `Impossible de contacter le serveur à ${getBackendUrl()} — vérifie qu'il est démarré et que l'adresse est correcte.`);
  }

  // 204 No Content / 200 sans corps (register() renvoie "OK" en texte brut, pas du JSON) :
  // on ne tente de parser du JSON QUE s'il y a effectivement un corps à lire.
  const text = await response.text();
  const body = text ? safeJsonParse(text) : undefined;

  if (!response.ok) {
    const message = isApiErrorBody(body) ? body.error : formatErrorMessage(response);
    throw new ApiError(response.status, message);
  }

  return body as T;
}

/**
 * Message de repli quand le backend ne renvoie pas de corps `{ error }` exploitable (voir
 * isApiErrorBody ci-dessous) — cas notamment de `429 Too Many Requests`, produit par le
 * rate limiter Tower (voir main.rs::build_router côté serveur) qui ne renvoie qu'un corps
 * texte générique, pas du JSON. Un simple "Erreur HTTP 429" ne dit pas à l'utilisateur qu'il
 * suffit d'attendre quelques secondes — le serveur envoie pourtant déjà un en-tête `Retry-After`
 * (en secondes, ajouté par défaut par tower_governor) qu'on exploite ici pour donner un message
 * actionnable plutôt qu'un code d'erreur brut.
 */
function formatErrorMessage(response: Response): string {
  if (response.status === 429) {
    const retryAfter = Number(response.headers.get("retry-after"));
    const wait = Number.isFinite(retryAfter) && retryAfter > 0 ? Math.ceil(retryAfter) : null;
    return wait
      ? `Trop de tentatives — réessaie dans ${wait} seconde${wait > 1 ? "s" : ""}.`
      : "Trop de tentatives — réessaie dans quelques secondes.";
  }
  return `Erreur HTTP ${response.status}`;
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined; // ex: le corps "OK" en texte brut de register() — pas une erreur
  }
}

function isApiErrorBody(value: unknown): value is ApiErrorBody {
  return typeof value === "object" && value !== null && "error" in value;
}

function authHeaders(accessToken: string): HeadersInit {
  return { Authorization: `Bearer ${accessToken}` };
}

// --- Inscription & vérification d'email ---

export function register(payload: RegisterPayload): Promise<void> {
  return request<void>("/auth/register", { method: "POST", body: JSON.stringify(payload) });
}

export function verifyEmail(payload: VerifyEmailPayload): Promise<void> {
  return request<void>("/auth/verify-email", { method: "POST", body: JSON.stringify(payload) });
}

export function resendVerification(payload: ResendVerificationPayload): Promise<void> {
  return request<void>("/auth/resend-verification", { method: "POST", body: JSON.stringify(payload) });
}

// --- Connexion & 2FA ---

/**
 * Renvoie soit des tokens (appareil déjà de confiance), soit `{status: "2FA_REQUIRED"}` (un code
 * vient d'être envoyé par email). Utiliser `isTfaRequired()` pour distinguer les deux côté appelant.
 */
export function login(payload: LoginPayload): Promise<AuthTokens | TfaRequiredResponse> {
  return request<AuthTokens | TfaRequiredResponse>("/auth/login", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function isTfaRequired(result: AuthTokens | TfaRequiredResponse): result is TfaRequiredResponse {
  return "status" in result && result.status === "2FA_REQUIRED";
}

/**
 * Valide le code 2FA et enregistre l'appareil comme "de confiance" — ne renvoie PAS de tokens
 * directement (voir handlers/auth/session.rs::verify_2fa_and_register_device() côté backend) :
 * l'appelant doit ensuite rappeler login(), qui réussira cette fois (appareil désormais reconnu).
 */
export function verifyDevice(payload: VerifyTfaPayload): Promise<void> {
  return request<void>("/auth/verify-device", { method: "POST", body: JSON.stringify(payload) });
}

export function refresh(payload: RefreshPayload): Promise<AuthTokens> {
  return request<AuthTokens>("/auth/refresh", { method: "POST", body: JSON.stringify(payload) });
}

export function logout(payload: RefreshPayload): Promise<void> {
  return request<void>("/auth/logout", { method: "POST", body: JSON.stringify(payload) });
}

// --- Synchronisation temps réel (WebSocket) ---

export function createWsTicket(accessToken: string): Promise<WsTicketResponse> {
  return request<WsTicketResponse>("/ws/ticket", { method: "POST", headers: authHeaders(accessToken) });
}

// --- Mot de passe oublié ---

export function forgotPassword(email: string): Promise<void> {
  return request<void>("/auth/forgot-password", { method: "POST", body: JSON.stringify({ email }) });
}

export function resetPassword(payload: {
  email: string;
  code: string;
  new_master_password_hash: string;
}): Promise<void> {
  return request<void>("/auth/reset-password", { method: "POST", body: JSON.stringify(payload) });
}

// --- Coffre-fort (routes authentifiées) ---
// Chaque fonction lève une ApiError avec status 401 si l'access token est expiré/invalide —
// voir state/AuthContext.tsx::authorizedRequest() pour la logique de rafraîchissement
// automatique qui enveloppe ces appels, plutôt que de la dupliquer ici route par route.

export function getVault(accessToken: string, limit = 100, offset = 0): Promise<VaultEntry[]> {
  return request<VaultEntry[]>(`/vault?limit=${limit}&offset=${offset}`, {
    headers: authHeaders(accessToken),
  });
}

// Le serveur plafonne TOUJOURS `limit` à 100 par page, quoi que le client demande (voir
// PaginationParams::effective_limit côté backend) — un simple appel getVault() sans boucle
// tronque donc silencieusement tout coffre de plus de 100 entrées. Utilisé partout où il faut
// la liste COMPLÈTE (l'écran principal du coffre, la sauvegarde chiffrée automatique/manuelle) :
// contrairement à exportVault() ci-dessous, ceci ne redemande pas le mot de passe maître, donc
// ne convient PAS pour un export explicite à froid (voir ExportVaultPayload).
export async function getFullVault(accessToken: string): Promise<VaultEntry[]> {
  const pageSize = 100;
  const all: VaultEntry[] = [];
  let offset = 0;
  for (;;) {
    const page = await getVault(accessToken, pageSize, offset);
    all.push(...page);
    if (page.length < pageSize) break;
    offset += pageSize;
  }
  return all;
}

export function addToVault(accessToken: string, entry: VaultEntryInput): Promise<void> {
  return request<void>("/vault", {
    method: "POST",
    headers: authHeaders(accessToken),
    body: JSON.stringify(entry),
  });
}

export function updateVaultEntry(accessToken: string, id: string, entry: VaultEntryInput): Promise<void> {
  return request<void>(`/vault/${encodeURIComponent(id)}`, {
    method: "PUT",
    headers: authHeaders(accessToken),
    body: JSON.stringify(entry),
  });
}

export function deleteVaultEntry(accessToken: string, id: string): Promise<void> {
  return request<void>(`/vault/${encodeURIComponent(id)}`, {
    method: "DELETE",
    headers: authHeaders(accessToken),
  });
}

export function toggleFavorite(accessToken: string, id: string): Promise<void> {
  return request<void>(`/vault/${encodeURIComponent(id)}/favorite`, {
    method: "PATCH",
    headers: authHeaders(accessToken),
  });
}

export function getTrash(accessToken: string): Promise<TrashedVaultEntry[]> {
  return request<TrashedVaultEntry[]>("/vault/trash", { headers: authHeaders(accessToken) });
}

export function restoreVaultEntry(accessToken: string, id: string): Promise<void> {
  return request<void>(`/vault/${encodeURIComponent(id)}/restore`, {
    method: "POST",
    headers: authHeaders(accessToken),
  });
}

export function permanentlyDeleteVaultEntry(accessToken: string, id: string): Promise<void> {
  return request<void>(`/vault/${encodeURIComponent(id)}/permanent`, {
    method: "DELETE",
    headers: authHeaders(accessToken),
  });
}

export function importVault(accessToken: string, payload: ImportVaultPayload): Promise<{ imported: number }> {
  return request<{ imported: number }>("/vault/import", {
    method: "POST",
    headers: authHeaders(accessToken),
    body: JSON.stringify(payload),
  });
}

export function exportVault(accessToken: string, payload: ExportVaultPayload): Promise<VaultEntry[]> {
  return request<VaultEntry[]>("/vault/export", {
    method: "POST",
    headers: authHeaders(accessToken),
    body: JSON.stringify(payload),
  });
}

export function getVaultEntryHistory(accessToken: string, id: string): Promise<PasswordHistoryEntry[]> {
  return request<PasswordHistoryEntry[]>(`/vault/${encodeURIComponent(id)}/history`, {
    headers: authHeaders(accessToken),
  });
}

export function exportVaultHistory(accessToken: string, payload: ExportVaultPayload): Promise<PasswordHistoryEntry[]> {
  return request<PasswordHistoryEntry[]>("/vault/history/export", {
    method: "POST",
    headers: authHeaders(accessToken),
    body: JSON.stringify(payload),
  });
}

// --- Pièces jointes chiffrées (voir lib/vaultAttachments.ts pour le chiffrement/déchiffrement) ---

export function addVaultAttachment(accessToken: string, vaultId: string, attachment: VaultAttachmentInput): Promise<{ id: string }> {
  return request<{ id: string }>(`/vault/${encodeURIComponent(vaultId)}/attachments`, {
    method: "POST",
    headers: authHeaders(accessToken),
    body: JSON.stringify(attachment),
  });
}

export function getVaultAttachments(accessToken: string, vaultId: string): Promise<VaultAttachmentMeta[]> {
  return request<VaultAttachmentMeta[]>(`/vault/${encodeURIComponent(vaultId)}/attachments`, {
    headers: authHeaders(accessToken),
  });
}

export function getVaultAttachment(accessToken: string, vaultId: string, attachmentId: string): Promise<VaultAttachment> {
  return request<VaultAttachment>(`/vault/${encodeURIComponent(vaultId)}/attachments/${encodeURIComponent(attachmentId)}`, {
    headers: authHeaders(accessToken),
  });
}

export function deleteVaultAttachment(accessToken: string, vaultId: string, attachmentId: string): Promise<void> {
  return request<void>(`/vault/${encodeURIComponent(vaultId)}/attachments/${encodeURIComponent(attachmentId)}`, {
    method: "DELETE",
    headers: authHeaders(accessToken),
  });
}

// --- Compte (routes authentifiées) ---

export function getMe(accessToken: string): Promise<MeResponse> {
  return request<MeResponse>("/me", { headers: authHeaders(accessToken) });
}

/** Historique de sécurité SELF-SERVICE — contrairement à getAuditLogs() ci-dessous (réservé aux
 * admins, tous comptes confondus), ne renvoie que les entrées du compte connecté (voir GET
 * /audit/me côté backend, scopé via user_email dans la requête SQL elle-même). */
export function getMyAuditLogs(accessToken: string): Promise<AuditLog[]> {
  return request<AuditLog[]>("/audit/me", { headers: authHeaders(accessToken) });
}

export function updatePassword(accessToken: string, payload: ChangeMasterPasswordPayload): Promise<void> {
  return request<void>("/auth/password", {
    method: "PUT",
    headers: authHeaders(accessToken),
    body: JSON.stringify(payload),
  });
}

export function updateEmail(accessToken: string, payload: UpdateEmailPayload): Promise<void> {
  return request<void>("/auth/email", {
    method: "PUT",
    headers: authHeaders(accessToken),
    body: JSON.stringify(payload),
  });
}

// --- Appareils de confiance (routes authentifiées) ---

export function listDevices(accessToken: string): Promise<TrustedDevice[]> {
  return request<TrustedDevice[]>("/devices", { headers: authHeaders(accessToken) });
}

export function revokeDevice(accessToken: string, deviceId: string): Promise<void> {
  return request<void>(`/devices/${encodeURIComponent(deviceId)}`, {
    method: "DELETE",
    headers: authHeaders(accessToken),
  });
}

export function updateDeviceLimit(accessToken: string, payload: UpdateDeviceLimitPayload): Promise<void> {
  return request<void>("/devices/limit", {
    method: "PUT",
    headers: authHeaders(accessToken),
    body: JSON.stringify(payload),
  });
}

export function logoutAllDevices(accessToken: string): Promise<void> {
  return request<void>("/devices/logout-all", {
    method: "POST",
    headers: authHeaders(accessToken),
  });
}

// --- Accès d'urgence (voir lib/emergencyAccess.ts pour l'orchestration côté client) ---

export function upsertEmergencyKeys(accessToken: string, payload: UserKeysInput): Promise<void> {
  return request<void>("/emergency/keys", {
    method: "PUT",
    headers: authHeaders(accessToken),
    body: JSON.stringify(payload),
  });
}

export function getOwnEmergencyKeys(accessToken: string): Promise<UserKeysInput> {
  return request<UserKeysInput>("/emergency/keys/me", { headers: authHeaders(accessToken) });
}

export function getPublicKey(accessToken: string, email: string): Promise<UserPublicKey> {
  return request<UserPublicKey>(`/emergency/keys/${encodeURIComponent(email)}`, { headers: authHeaders(accessToken) });
}

export function addEmergencyContact(accessToken: string, payload: AddEmergencyContactPayload): Promise<{ id: string }> {
  return request<{ id: string }>("/emergency/contacts", {
    method: "POST",
    headers: authHeaders(accessToken),
    body: JSON.stringify(payload),
  });
}

export function listEmergencyContactsAsOwner(accessToken: string): Promise<EmergencyContact[]> {
  return request<EmergencyContact[]>("/emergency/contacts", { headers: authHeaders(accessToken) });
}

export function listEmergencyGrantedToMe(accessToken: string): Promise<EmergencyContact[]> {
  return request<EmergencyContact[]>("/emergency/granted-to-me", { headers: authHeaders(accessToken) });
}

export function acceptEmergencyContact(accessToken: string, id: string): Promise<void> {
  return request<void>(`/emergency/contacts/${encodeURIComponent(id)}/accept`, {
    method: "POST",
    headers: authHeaders(accessToken),
  });
}

export function declineEmergencyContact(accessToken: string, id: string): Promise<void> {
  return request<void>(`/emergency/contacts/${encodeURIComponent(id)}/decline`, {
    method: "POST",
    headers: authHeaders(accessToken),
  });
}

export function seedEmergencyContact(accessToken: string, id: string, payload: SeedEmergencyKeyPayload): Promise<void> {
  return request<void>(`/emergency/contacts/${encodeURIComponent(id)}/seed`, {
    method: "PUT",
    headers: authHeaders(accessToken),
    body: JSON.stringify(payload),
  });
}

export function requestEmergencyAccess(accessToken: string, id: string): Promise<void> {
  return request<void>(`/emergency/contacts/${encodeURIComponent(id)}/request-access`, {
    method: "POST",
    headers: authHeaders(accessToken),
  });
}

export function approveEmergencyAccess(accessToken: string, id: string): Promise<void> {
  return request<void>(`/emergency/contacts/${encodeURIComponent(id)}/approve`, {
    method: "POST",
    headers: authHeaders(accessToken),
  });
}

export function rejectEmergencyAccess(accessToken: string, id: string): Promise<void> {
  return request<void>(`/emergency/contacts/${encodeURIComponent(id)}/reject`, {
    method: "POST",
    headers: authHeaders(accessToken),
  });
}

export function getEmergencyVault(accessToken: string, id: string): Promise<EmergencyVaultView> {
  return request<EmergencyVaultView>(`/emergency/contacts/${encodeURIComponent(id)}/vault`, { headers: authHeaders(accessToken) });
}

export function revokeEmergencyContact(accessToken: string, id: string): Promise<void> {
  return request<void>(`/emergency/contacts/${encodeURIComponent(id)}`, {
    method: "DELETE",
    headers: authHeaders(accessToken),
  });
}

// --- Partage sécurisé d'une entrée (voir lib/entrySharing.ts pour l'orchestration côté client) ---

export function shareVaultEntry(accessToken: string, vaultId: string, payload: ShareEntryPayload): Promise<{ id: string }> {
  return request<{ id: string }>(`/vault/${encodeURIComponent(vaultId)}/shares`, {
    method: "POST",
    headers: authHeaders(accessToken),
    body: JSON.stringify(payload),
  });
}

export function listVaultEntryShares(accessToken: string, vaultId: string): Promise<VaultShare[]> {
  return request<VaultShare[]>(`/vault/${encodeURIComponent(vaultId)}/shares`, { headers: authHeaders(accessToken) });
}

export function listSharedWithMe(accessToken: string): Promise<SharedWithMeEntry[]> {
  return request<SharedWithMeEntry[]>("/shares/shared-with-me", { headers: authHeaders(accessToken) });
}

export function getSharedEntry(accessToken: string, shareId: string): Promise<SharedEntryView> {
  return request<SharedEntryView>(`/shares/${encodeURIComponent(shareId)}`, { headers: authHeaders(accessToken) });
}

export function revokeShare(accessToken: string, shareId: string): Promise<void> {
  return request<void>(`/shares/${encodeURIComponent(shareId)}`, {
    method: "DELETE",
    headers: authHeaders(accessToken),
  });
}

// --- Coffres partagés familiaux (voir lib/sharedVault.ts pour l'orchestration côté client) ---

export function createSharedVault(accessToken: string, payload: CreateSharedVaultPayload): Promise<{ id: string }> {
  return request<{ id: string }>("/shared-vaults", {
    method: "POST",
    headers: authHeaders(accessToken),
    body: JSON.stringify(payload),
  });
}

export function listSharedVaults(accessToken: string): Promise<SharedVaultView[]> {
  return request<SharedVaultView[]>("/shared-vaults", { headers: authHeaders(accessToken) });
}

export function deleteSharedVault(accessToken: string, id: string): Promise<void> {
  return request<void>(`/shared-vaults/${encodeURIComponent(id)}`, {
    method: "DELETE",
    headers: authHeaders(accessToken),
  });
}

export function inviteSharedVaultMember(accessToken: string, id: string, payload: InviteSharedVaultMemberPayload): Promise<void> {
  return request<void>(`/shared-vaults/${encodeURIComponent(id)}/members`, {
    method: "POST",
    headers: authHeaders(accessToken),
    body: JSON.stringify(payload),
  });
}

export function listSharedVaultMembers(accessToken: string, id: string): Promise<SharedVaultMemberView[]> {
  return request<SharedVaultMemberView[]>(`/shared-vaults/${encodeURIComponent(id)}/members`, { headers: authHeaders(accessToken) });
}

export function removeSharedVaultMember(accessToken: string, id: string, memberEmail: string): Promise<void> {
  return request<void>(`/shared-vaults/${encodeURIComponent(id)}/members/${encodeURIComponent(memberEmail)}`, {
    method: "DELETE",
    headers: authHeaders(accessToken),
  });
}

export function listSharedVaultEntries(accessToken: string, id: string): Promise<SharedVaultEntry[]> {
  return request<SharedVaultEntry[]>(`/shared-vaults/${encodeURIComponent(id)}/entries`, { headers: authHeaders(accessToken) });
}

export function addSharedVaultEntry(accessToken: string, id: string, payload: SharedVaultEntryInput): Promise<{ id: string }> {
  return request<{ id: string }>(`/shared-vaults/${encodeURIComponent(id)}/entries`, {
    method: "POST",
    headers: authHeaders(accessToken),
    body: JSON.stringify(payload),
  });
}

export function updateSharedVaultEntry(accessToken: string, id: string, entryId: string, payload: SharedVaultEntryInput): Promise<void> {
  return request<void>(`/shared-vaults/${encodeURIComponent(id)}/entries/${encodeURIComponent(entryId)}`, {
    method: "PUT",
    headers: authHeaders(accessToken),
    body: JSON.stringify(payload),
  });
}

export function deleteSharedVaultEntry(accessToken: string, id: string, entryId: string): Promise<void> {
  return request<void>(`/shared-vaults/${encodeURIComponent(id)}/entries/${encodeURIComponent(entryId)}`, {
    method: "DELETE",
    headers: authHeaders(accessToken),
  });
}

// --- Partage à usage limité (voir lib/blindShare.ts pour l'orchestration côté client) ---

export function createBlindShare(accessToken: string, vaultId: string, payload: CreateBlindSharePayload): Promise<{ id: string }> {
  return request<{ id: string }>(`/vault/${encodeURIComponent(vaultId)}/blind-shares`, {
    method: "POST",
    headers: authHeaders(accessToken),
    body: JSON.stringify(payload),
  });
}

export function listBlindSharesForEntry(accessToken: string, vaultId: string): Promise<VaultBlindShare[]> {
  return request<VaultBlindShare[]>(`/vault/${encodeURIComponent(vaultId)}/blind-shares`, { headers: authHeaders(accessToken) });
}

export function listBlindSharesReceived(accessToken: string): Promise<BlindShareReceivedView[]> {
  return request<BlindShareReceivedView[]>("/blind-shares/shared-with-me", { headers: authHeaders(accessToken) });
}

export function useBlindShare(accessToken: string, id: string): Promise<BlindShareCredentialsView> {
  return request<BlindShareCredentialsView>(`/blind-shares/${encodeURIComponent(id)}/use`, {
    method: "POST",
    headers: authHeaders(accessToken),
  });
}

export function revokeBlindShare(accessToken: string, id: string): Promise<void> {
  return request<void>(`/blind-shares/${encodeURIComponent(id)}`, {
    method: "DELETE",
    headers: authHeaders(accessToken),
  });
}

// --- Signalement de bug — PUBLIC, aucun `accessToken` en paramètre (voir models.rs côté backend :
// route accessible même sans être connecté, un bug qui empêche justement de se connecter doit
// pouvoir être signalé depuis l'app elle-même). ---

export function createBugReport(payload: CreateBugReportPayload): Promise<{ id: string }> {
  return request<{ id: string }>("/bug-reports", { method: "POST", body: JSON.stringify(payload) });
}

// --- Administration (routes authentifiées, réservées à is_moderator — voir GET /me) ---
// Le serveur revérifie is_moderator (et is_admin pour certaines) lui-même à chaque appel (voir
// handlers/admin.rs côté backend) : masquer ces boutons côté client (voir components/AdminRoute.tsx) est une commodité d'UX, jamais
// la barrière de sécurité elle-même.

export function getAuditLogs(accessToken: string): Promise<AuditLog[]> {
  return request<AuditLog[]>("/audit", { headers: authHeaders(accessToken) });
}

export function listAllUsers(accessToken: string): Promise<AdminUserView[]> {
  return request<AdminUserView[]>("/admin/users", { headers: authHeaders(accessToken) });
}

export function updateUserRole(accessToken: string, targetEmail: string, payload: UpdateUserRolePayload): Promise<void> {
  return request<void>(`/admin/users/${encodeURIComponent(targetEmail)}/role`, {
    method: "PUT",
    headers: authHeaders(accessToken),
    body: JSON.stringify(payload),
  });
}

/** Change l'email d'un AUTRE compte (jamais le mot de passe maître ni la clé du coffre) — voir
 * backend/src/handlers/admin.rs::admin_update_user_email(). Refusé si `targetEmail` est le compte
 * de l'appelant lui-même (utiliser updateEmail() pour son propre compte). */
export function adminUpdateUserEmail(accessToken: string, targetEmail: string, payload: AdminUpdateEmailPayload): Promise<void> {
  return request<void>(`/admin/users/${encodeURIComponent(targetEmail)}/email`, {
    method: "PUT",
    headers: authHeaders(accessToken),
    body: JSON.stringify(payload),
  });
}

/** Autorise/interdit le changement d'email DEPUIS L'EXTENSION NAVIGATEUR pour UN compte précis —
 * voir backend/src/handlers/admin.rs::update_extension_email_change_setting(). */
export function updateExtensionEmailChange(accessToken: string, targetEmail: string, payload: UpdateExtensionEmailChangePayload): Promise<void> {
  return request<void>(`/admin/users/${encodeURIComponent(targetEmail)}/extension-email-change`, {
    method: "PUT",
    headers: authHeaders(accessToken),
    body: JSON.stringify(payload),
  });
}

/** Même réglage, mais appliqué à TOUS les comptes d'un coup. */
export function updateExtensionEmailChangeAll(accessToken: string, payload: UpdateExtensionEmailChangePayload): Promise<void> {
  return request<void>("/admin/users/extension-email-change-all", {
    method: "PUT",
    headers: authHeaders(accessToken),
    body: JSON.stringify(payload),
  });
}

export function revokeUserSessions(accessToken: string, targetEmail: string): Promise<void> {
  return request<void>(`/admin/users/${encodeURIComponent(targetEmail)}/revoke-sessions`, {
    method: "POST",
    headers: authHeaders(accessToken),
  });
}

export function deleteUser(accessToken: string, targetEmail: string): Promise<void> {
  return request<void>(`/admin/users/${encodeURIComponent(targetEmail)}`, {
    method: "DELETE",
    headers: authHeaders(accessToken),
  });
}

export function listBugReports(accessToken: string): Promise<BugReportView[]> {
  return request<BugReportView[]>("/admin/bug-reports", { headers: authHeaders(accessToken) });
}

export function deleteBugReport(accessToken: string, id: string): Promise<void> {
  return request<void>(`/admin/bug-reports/${encodeURIComponent(id)}`, {
    method: "DELETE",
    headers: authHeaders(accessToken),
  });
}

// authHeaders exporté pour d'éventuels futurs modules authentifiés qui n'auraient pas leur propre
// fonction dédiée ici.
export { authHeaders };
