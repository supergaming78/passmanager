// Changement d'adresse email — équivalent réduit de AuthContext.tsx::changeEmail côté desktop.
// Ne change PAS la clé de coffre (contrairement au mot de passe maître, hors périmètre de cette
// popup) : pas de re-chiffrement nécessaire, juste re-confirmation du mot de passe + reconnexion.

import * as api from "../api/client";
import * as wasmCrypto from "./wasmCrypto";
import type { AuthorizedRequest } from "./session";

/**
 * update_email() invalide TOUTES les sessions liées au compte côté serveur, y compris celle-ci —
 * contrairement au desktop (qui tente une reconnexion automatique silencieuse), l'appelant doit
 * systématiquement rediriger vers l'écran de connexion avec le nouvel email après cet appel : plus
 * simple et plus sûr qu'une reconnexion automatique depuis ce contexte, et couvre aussi le cas rare
 * où un 2FA serait redemandé (appareil jamais utilisé avec ce nouvel email).
 */
export async function changeEmail(
  currentEmail: string,
  newEmail: string,
  currentPassword: string,
  authorizedRequest: AuthorizedRequest,
): Promise<void> {
  const { authHashHex } = await wasmCrypto.deriveKeys(currentEmail, currentPassword);
  await authorizedRequest((token) => api.updateEmail(token, { new_email: newEmail, master_password_hash: authHashHex }));
}
