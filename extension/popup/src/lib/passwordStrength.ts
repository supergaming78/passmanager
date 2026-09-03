// Estimation de la force d'un mot de passe, pour l'indicateur affiché sur chaque entrée du coffre
// (voir App.tsx::renderEntryRow).
//
// Sous-ensemble STRICT de frontend(app)/src/lib/passwordGenerator.ts : uniquement l'estimation
// d'entropie et son classement. Le reste de ce fichier côté app (génération de mots de passe,
// liste de mots, scénarios de temps de cassage, formatage des durées) ne sert qu'à des écrans que
// la popup n'a pas — l'y copier alourdirait le paquet chargé à CHAQUE ouverture (voir
// App.tsx::LazyView) pour du code jamais atteint.
//
// Les seuils et les libellés sont IDENTIQUES à ceux de l'app : un même mot de passe doit être
// qualifié pareil des deux côtés, sans quoi l'un contredirait l'autre sous les yeux de
// l'utilisateur.

const ASCII_SYMBOLS_PATTERN = /[!-/:-@[-`{-~]/;

/** Taille de l'alphabet dont le mot de passe SEMBLE tiré, déduite des classes de caractères
 * présentes. Approximation volontairement grossière : on ne connaît que le résultat final, jamais
 * les réglages qui l'ont produit. */
function classifyPasswordPoolSize(password: string): number {
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (ASCII_SYMBOLS_PATTERN.test(password)) pool += 33;
  if (/[^\x20-\x7e]/.test(password)) pool += 1000;
  return pool;
}

/** Entropie estimée, en bits. `0` quand il n'y a rien d'exploitable (chaîne vide, ou un seul
 * caractère répété dont l'alphabet déduit se réduit à lui-même). */
export function estimatePasswordEntropyBits(password: string): number {
  if (!password) return 0;
  const poolSize = classifyPasswordPoolSize(password);
  if (poolSize <= 1) return 0;
  return password.length * Math.log2(poolSize);
}

export interface EntropyRating {
  label: string;
  textClass: string;
  barClass: string;
}

/** Classement affiché — mêmes seuils et mêmes libellés que côté app (voir en tête de fichier). */
export function rateEntropy(bits: number): EntropyRating {
  if (bits < 28) return { label: "Très faible", textClass: "text-red-600 dark:text-red-400", barClass: "bg-red-600 dark:bg-red-400" };
  if (bits < 36) return { label: "Faible", textClass: "text-orange-600 dark:text-orange-400", barClass: "bg-orange-600 dark:bg-orange-400" };
  if (bits < 60) return { label: "Raisonnable", textClass: "text-yellow-600 dark:text-yellow-400", barClass: "bg-yellow-600 dark:bg-yellow-400" };
  if (bits < 128) return { label: "Forte", textClass: "text-emerald-600 dark:text-emerald-400", barClass: "bg-emerald-600 dark:bg-emerald-400" };
  return { label: "Excellente", textClass: "text-emerald-700 dark:text-emerald-300", barClass: "bg-emerald-700 dark:bg-emerald-300" };
}
