// Suspend temporairement le verrouillage par perte de focus (voir state/AuthContext.tsx et
// lib/settings.ts::getLockOnFocusLossDelaySeconds) pendant qu'une boîte de dialogue NATIVE ouverte
// par CETTE app (export/import de fichier, voir lib/vaultFile.ts) est affichée à l'écran — ouvrir
// un tel dialogue fait perdre le focus à la fenêtre principale aussi sûrement qu'un alt-tab, mais
// ce n'est pas un "abandon" de l'app qui doit déclencher une redemande du mot de passe maître.
//
// Compteur plutôt qu'un simple booléen : supporte des appels imbriqués sans qu'une fin prématurée
// (l'un des deux dialogues se referme avant l'autre) ne réactive le verrouillage trop tôt.
let suppressionCount = 0;

export function isFocusLossLockSuppressed(): boolean {
  return suppressionCount > 0;
}

/** Enveloppe une opération qui ouvre un dialogue natif — incrémente/décrémente automatiquement la
 * suspension, même si l'opération lève une erreur ou est annulée par l'utilisateur. */
export async function withFocusLossLockSuppressed<T>(fn: () => Promise<T>): Promise<T> {
  suppressionCount += 1;
  try {
    return await fn();
  } finally {
    suppressionCount -= 1;
  }
}
