// Détection de doublons à l'import — purement côté client, car le serveur ne voit jamais le
// contenu en clair (architecture Zero-Knowledge) : `import_vault` côté backend est volontairement
// additif (il n'écrase jamais une entrée existante), donc c'est à l'app d'éviter d'empiler des
// copies d'une même entrée si l'utilisateur réimporte un fichier déjà importé, ou un export
// d'un autre appareil qui recoupe en partie le coffre actuel.

import type { ExportableEntry } from "./vaultFile";
import type { PlainVaultEntry } from "./vaultCrypto";

export type DuplicateStatus = "none" | "exact" | "conflict";

function normalize(value: string): string {
  return value.trim().toLowerCase();
}

/** Deux entrées désignent le même identifiant de connexion si leur "username" ou leur
 * "loginEmail" coïncide (en ignorant casse/espaces) — ou si les deux sont vides des deux côtés
 * (entrée anonyme, seul le site compte alors). */
function sameIdentifier(a: ExportableEntry, b: ExportableEntry): boolean {
  const aUsername = normalize(a.username);
  const bUsername = normalize(b.username);
  const aEmail = normalize(a.loginEmail);
  const bEmail = normalize(b.loginEmail);

  if (aUsername && bUsername) return aUsername === bUsername;
  if (aEmail && bEmail) return aEmail === bEmail;
  return !aUsername && !bUsername && !aEmail && !bEmail;
}

export interface DuplicateMatch {
  status: DuplicateStatus;
  /** L'id de l'entrée EXISTANTE trouvée en conflit/doublon — null si "none". Sert à proposer
   * "remplacer l'existant" plutôt que "l'ignorer"/"l'ajouter en double" (voir ImportExportBar.tsx). */
  matchedId: string | null;
}

/** Compare une entrée importée au coffre déjà présent (déchiffré) :
 * - "exact"    : même site + même identifiant + même mot de passe -> copie inutile.
 * - "conflict" : même site + même identifiant mais mot de passe différent -> à vérifier par
 *                l'utilisateur (l'import n'écrasera jamais l'entrée existante par défaut, il en
 *                créera une seconde s'il est coché quand même — sauf s'il choisit explicitement
 *                de "remplacer l'existant", voir matchedId).
 * - "none"     : rien de comparable trouvé, import normal. */
export function detectDuplicateMatch(imported: ExportableEntry, existing: PlainVaultEntry[]): DuplicateMatch {
  const match = existing.find((e) => normalize(e.siteName) === normalize(imported.siteName) && sameIdentifier(e, imported));
  if (!match) return { status: "none", matchedId: null };
  return { status: match.password === imported.password ? "exact" : "conflict", matchedId: match.id };
}
