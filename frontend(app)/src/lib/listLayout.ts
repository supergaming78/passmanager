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
 * partages reçus) tient plus de colonnes qu'une carte de coffre avec logo/avatar.
 *
 * CORRECTIF (retour utilisateur, 2026-09-02) : paliers `@sm:`/`@lg:` (container queries CSS,
 * réagissent à la largeur du PARENT le plus proche portant `@container`) plutôt que `sm:`/`lg:`
 * (réagissent à la largeur de la FENÊTRE entière) — avec la disposition de menu "Barre latérale"/
 * "Compacte" (voir lib/menuLayout.ts), l'espace réellement disponible pour cette liste est plus
 * étroit que la fenêtre (le menu en prend une partie), ce que `sm:`/`lg:` ignorait complètement :
 * une grille pouvait forcer 3-4 colonnes dans un espace en réalité bien plus restreint, comprimant
 * les cartes. Nécessite que l'APPELANT enveloppe le `<ul>` (celui qui reçoit cette classe) d'un
 * `<div className="@container">` — un élément ne peut pas réagir à sa PROPRE taille, seulement à
 * celle d'un ancêtre portant `@container` (voir les appelants : Vault.tsx, Admin.tsx,
 * SharedWithMeSettings.tsx, BlindSharesReceivedSettings.tsx, SharedVaultsPage.tsx,
 * SharedVaultDetailPage.tsx). Volontairement PAS posé plus haut dans l'arbre (ex: le conteneur de
 * contenu de AppShell.tsx, qui engloberait toute la page) : `container-type` fait de son élément un
 * point d'ancrage pour tout descendant en `position: fixed` (comme un `transform`) — posé au niveau
 * de toute la page, ÇA AURAIT CASSÉ toutes les fenêtres modales de l'app (ShareEntryModal,
 * VaultEntryForm, BugReportModal...), qui se seraient mises à défiler avec le contenu au lieu de
 * rester ancrées à l'écran. Scopé ICI, juste autour de la liste elle-même, aucun risque : les
 * modales ne sont jamais des descendantes de ce `<div>`. */
export function listContainerClass(layout: ListLayout, gridCols = "grid-cols-2 @sm:grid-cols-3 @lg:grid-cols-4"): string {
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
