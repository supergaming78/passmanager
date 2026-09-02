// Enregistrement des utilisations d'une entrée (copie du mot de passe, remplissage automatique) —
// retour utilisateur (2026-09-02), pour le tri "le plus utilisé" — voir
// frontend(app)/src/lib/vaultUsage.ts pour l'équivalent desktop, même raisonnement.

import * as api from "../api/client";

type AuthorizedRequest = <T,>(fn: (accessToken: string) => Promise<T>) => Promise<T>;

/** Signale une utilisation de `entryId` — appelée à la copie du mot de passe ET au remplissage
 * automatique réussi (voir App.tsx::handleCopy/handleFill), décidés comme équivalents (au final,
 * les deux servent le même mot de passe). Volontairement `void`-appelée par les appelants (jamais
 * `await`ée avant de continuer) : l'action réelle doit rester instantanée. Échec silencieux. */
export function recordEntryUse(authorizedRequest: AuthorizedRequest, entryId: string): void {
  void authorizedRequest((token) => api.recordVaultEntryUse(token, entryId)).catch(() => {});
}
