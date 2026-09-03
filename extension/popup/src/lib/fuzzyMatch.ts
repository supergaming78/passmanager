// Tolérance aux fautes de frappe pour la recherche du coffre (voir App.tsx::filtered) —
// UNIQUEMENT un repli quand la correspondance exacte de sous-chaîne ne trouve rien, jamais à la
// place : garde le comportement rapide/précis habituel intact quand il n'y a pas de faute de frappe.
//
// Copie CONFORME de frontend(app)/src/lib/fuzzyMatch.ts (aucune adaptation nécessaire : logique
// pure, sans dépendance à Tauri ni au navigateur). La recherche compte encore plus ici que dans
// l'app : dans une popup de 380px, elle EST la navigation principale — pas de menu latéral, pas de
// filtres rapides, pas de dispositions alternatives.

const DIACRITICS_PATTERN = /[̀-ͯ]/g;

/** Même normalisation que vaultFile.ts::normalizeKey en esprit (accents/casse en moins), mais SANS
 * retirer les espaces — ici on doit encore pouvoir découper en mots. */
function normalize(value: string): string {
  return value.normalize("NFD").replace(DIACRITICS_PATTERN, "").toLowerCase();
}

/** Distance d'édition (Levenshtein) classique — nombre minimal d'insertions/suppressions/
 * substitutions pour transformer `a` en `b`. Programmation dynamique O(longueur(a) × longueur(b)),
 * largement suffisant pour des mots courts (noms de site, identifiants). */
export function levenshteinDistance(a: string, b: string): number {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  let previousRow = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const currentRow = [i];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      currentRow.push(Math.min(currentRow[j - 1] + 1, previousRow[j] + 1, previousRow[j - 1] + cost));
    }
    previousRow = currentRow;
  }
  return previousRow[b.length];
}

/** Seuil de tolérance selon la longueur de la requête — une requête très courte (≤4 caractères)
 * tolère 1 faute, au-delà 2 : évite qu'une requête courte finisse par matcher presque n'importe
 * quel mot (heuristique standard de recherche floue). */
function thresholdFor(query: string): number {
  return query.length <= 4 ? 1 : 2;
}

/** Vrai si `query` est une faute de frappe plausible d'un des MOTS de `text` (découpé sur
 * espaces/ponctuation) — pas juste de `text` entier, pour qu'un nom de site à plusieurs mots
 * ("Ma Banque Pro") reste trouvable en tapant une faute sur un seul de ses mots. */
export function fuzzyIncludes(text: string, query: string): boolean {
  const normalizedQuery = normalize(query).trim();
  if (!normalizedQuery) return false;

  const words = normalize(text).split(/[^\p{L}\p{N}]+/u).filter(Boolean);
  const threshold = thresholdFor(normalizedQuery);
  return words.some((word) => levenshteinDistance(word, normalizedQuery) <= threshold);
}
