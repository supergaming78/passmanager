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
 * mal imbriqué dans un `<div>` (HTML valide mais moins propre).
 *
 * `gridCols` ("cards" uniquement) : CORRECTIF (retour utilisateur, 2026-09-02) — remplacé un
 * nombre de colonnes FIXE par palier de largeur (`grid-cols-2 @sm:grid-cols-3 @lg:grid-cols-4`...)
 * par `repeat(auto-fit, minmax(Npx, Mpx))` : la TAILLE d'une carte ne change plus BRUSQUEMENT
 * (repéré par l'utilisateur : passer de 4 à 5 colonnes à un palier de largeur changeait visiblement
 * le format des cartes) — c'est le NOMBRE de colonnes qui s'adapte à l'espace disponible, en
 * calculant combien de cartes tiennent sur une ligne à leur largeur MINIMALE (`N`), une carte
 * pouvant grandir un peu (jusqu'à `M`) pour combler le reste plutôt que de laisser un grand vide à
 * droite (repéré par l'utilisateur, suite — une section avec peu d'entrées, ex. un dossier de 1-3
 * entrées, laissait un vide disproportionné). `auto-fit` (pas `auto-fill`) : indispensable pour ce
 * comblement — `auto-fill` réserverait quand même la largeur de TOUTES les colonnes possibles même
 * sans carte à y mettre (le vide resterait identique), `auto-fit` EFFONDRE les colonnes vides,
 * libérant leur place pour que les cartes réellement présentes grandissent jusqu'à `M`. Écart M-N
 * volontairement MODESTE (~50px, jamais `1fr`/illimité) : une carte grandit un peu, jamais au point
 * de ressembler à une disposition différente. LIMITE PHYSIQUE assumée : avec très peu de cartes
 * (1-2) dans une ligne très large, même à `M`, un vide reste inévitable — aucune disposition ne
 * peut à la fois garder un format quasi constant ET remplir une ligne bien plus large que son
 * contenu réel. Une liste avec peu de métadonnées par élément (ex: partages reçus) peut se
 * permettre une carte plus étroite qu'une carte de coffre avec logo/avatar — ajustable par
 * appelant.
 *
 * Fonctionne SANS `@container` (contrairement aux paliers `@sm:`/`@lg:` encore utilisés pour
 * "list"/"compact" juste en dessous) : `repeat(auto-fit, ...)` calcule directement combien de
 * colonnes de cette largeur tiennent dans l'espace RÉELLEMENT disponible pour la grille elle-même
 * (barre latérale déjà déduite, aucune requête de conteneur nécessaire) — le vrai motif CSS pour
 * "des cartes de taille quasi constante, le nombre qui s'adapte", plus robuste que des paliers de
 * largeur fixes qui font brusquement sauter le nombre de colonnes (et donc la taille des cartes
 * avec l'ancien `1fr`) à des seuils arbitraires. */
export function listContainerClass(layout: ListLayout, gridCols = "grid-cols-[repeat(auto-fit,minmax(200px,240px))]"): string {
  if (layout === "cards") return `grid gap-3 ${gridCols}`;
  // "list"/"compact" : CORRECTIF (retour utilisateur, 2026-09-02, captures d'écran plein écran
  // 1440p) — une seule colonne quelle que soit la largeur du conteneur laissait chaque ligne
  // s'étirer sur toute sa largeur une fois les pages élargies (voir Vault.tsx/pages.tsx, jusqu'à
  // 100-110rem désormais) : un grand vide entre le contenu (à gauche) et les boutons d'action
  // (poussés loin à droite par `justify-between`) au milieu de chaque ligne. Devient une grille à
  // plusieurs colonnes à partir d'un palier de largeur de CONTENEUR (pas de fenêtre — voir le
  // commentaire de fonction ci-dessus) : chaque ligne garde sa largeur naturelle, l'espace en trop
  // accueille des colonnes de lignes supplémentaires plutôt que de rester vide au milieu d'une
  // seule ligne démesurée.
  //
  // "compact" pousse plus loin que "list" (retour utilisateur, suite) : une ligne compacte (texte
  // réduit, une seule ligne de contenu) tient confortablement dans un espace bien plus étroit
  // qu'une ligne "list" (deux lignes de texte) — 3 colonnes dès @4xl au lieu d'attendre @6xl pour
  // seulement 2, pour vraiment exploiter l'esprit "compact" une fois l'espace disponible.
  if (layout === "compact") return "grid grid-cols-1 gap-1.5 @4xl:grid-cols-2 @6xl:grid-cols-3";
  return "grid grid-cols-1 gap-2 @6xl:grid-cols-2";
}
