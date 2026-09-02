// Enregistrement des utilisations d'une entrée (copie du mot de passe, remplissage automatique) —
// retour utilisateur (2026-09-02), pour le tri "le plus utilisé" (voir pages/Vault.tsx::sortBy et
// VaultEntry.use_count côté backend).

import * as api from "../api/client";

type AuthorizedRequest = <T,>(fn: (accessToken: string) => Promise<T>) => Promise<T>;

/** Signale une utilisation de `entryId` — appelée à la copie du mot de passe (voir Vault.tsx) ET
 * au remplissage automatique côté extension (pas pertinent côté app desktop, qui ne remplit rien
 * dans une page web). Volontairement `void`-appelée par les appelants (jamais `await`ée avant de
 * continuer) : l'action réelle de l'utilisateur (copier, remplir) doit rester instantanée, un
 * aller-retour réseau pour un simple compteur ne doit jamais la ralentir. Échec silencieux
 * (`catch(() => {})`) — un compteur d'usage manqué n'est jamais grave au point de perturber
 * l'utilisateur avec une erreur. */
export function recordEntryUse(authorizedRequest: AuthorizedRequest, entryId: string): void {
  void authorizedRequest((token) => api.recordVaultEntryUse(token, entryId)).catch(() => {});
}
