// Disposition d'affichage des listes (coffre, comptes dans Administration...) — retour utilisateur
// (2026-09-02), suite directe du choix de disposition du menu principal (voir lib/menuLayout.ts),
// mais PAS réservé au desktop cette fois : une disposition plus dense a du sens aussi sur mobile
// (voir Réglages, où les deux réglages vivent l'un sous l'autre). "list" (actuelle, DÉFAUT) /
// "cards" (grille de cartes, avatars/logos plus visibles) / "compact" (lignes plus serrées, plus
// d'éléments visibles à l'écran sans faire défiler).
export type ListLayout = "list" | "cards" | "compact";

const STORAGE_KEY = "passmanager.listLayout";
const VALID_LAYOUTS: readonly ListLayout[] = ["list", "cards", "compact"];

// CORRECTIF PERF (retour utilisateur, 2026-09-02) : getListLayout() est maintenant lu au montage
// par 6 écrans (Coffre, Administration, Partagé avec moi, partage à usage limité, coffres
// partagés, entrées d'un coffre partagé) — même raisonnement/même petit cache mémoire que
// lib/theme.ts::cachedTheme, pour éviter de retaper `localStorage` (E/S synchrone) à chaque
// montage. Aucune implication sécurité : préférence d'affichage, pas une donnée sensible.
let cachedListLayout: ListLayout | null = null;

export function getListLayout(): ListLayout {
  if (cachedListLayout) return cachedListLayout;
  const stored = localStorage.getItem(STORAGE_KEY);
  cachedListLayout = (VALID_LAYOUTS as readonly string[]).includes(stored ?? "") ? (stored as ListLayout) : "list";
  return cachedListLayout;
}

export function setListLayout(layout: ListLayout): void {
  cachedListLayout = layout;
  localStorage.setItem(STORAGE_KEY, layout);
}

/** Classe de conteneur à utiliser pour une liste d'éléments — un seul endroit pour cette règle
 * (grille pour "cards", liste empilée pour "list"/"compact"), réutilisé par toutes les listes de
 * l'app (Administration, Partagé avec moi, Coffres partagés...) plutôt que de la redupliquer à
 * chaque écran. Toujours un `<ul>` (voir appelants) : `display: grid` fonctionne aussi bien sur un
 * `<ul>` qu'un `<div>` — inutile de changer de balise juste pour "cards" et de risquer un `<li>`
 * mal imbriqué dans un `<div>` (HTML valide mais moins propre). `gridCols` : nombre de colonnes par
 * palier de largeur, ajustable par appelant — une liste avec peu de métadonnées par élément (ex:
 * partages reçus) tient plus de colonnes qu'une carte de coffre avec logo/avatar. */
export function listContainerClass(layout: ListLayout, gridCols = "grid-cols-2 sm:grid-cols-3 lg:grid-cols-4"): string {
  if (layout === "cards") return `grid gap-3 ${gridCols}`;
  return "flex flex-col gap-2";
}
