// Disposition d'affichage des listes (coffre, comptes dans Administration...) — retour utilisateur
// (2026-09-02), suite directe du choix de disposition du menu principal (voir lib/menuLayout.ts).
// CORRECTIF (retour utilisateur, même jour, suite) : réservée au DESKTOP depuis ce correctif —
// "pas réservé au desktop, a du sens aussi sur mobile" était le choix D'ORIGINE, revenu dessus
// après coup ("sur téléphone il y a beaucoup moins d'espace") — voir getEffectiveListLayout()
// ci-dessous, même mécanisme que lib/menuLayout.ts::getEffectiveMenuLayout(). "list" (actuelle,
// DÉFAUT, la SEULE utilisée sur mobile désormais) / "cards" (grille de cartes, avatars/logos plus
// visibles) / "compact" (lignes plus serrées, plus d'éléments visibles à l'écran sans faire
// défiler).
import { isMobilePlatform } from "./platform";

export type ListLayout = "list" | "cards" | "compact";

const STORAGE_KEY = "passmanager.listLayout";
const VALID_LAYOUTS: readonly ListLayout[] = ["list", "cards", "compact"];

// CORRECTIF PERF (retour utilisateur, 2026-09-02) : getListLayout() est maintenant lu au montage
// par 6 écrans (Coffre, Administration, Partagé avec moi, partage à usage limité, coffres
// partagés, entrées d'un coffre partagé) — même raisonnement/même petit cache mémoire que
// lib/theme.ts::cachedTheme, pour éviter de retaper `localStorage` (E/S synchrone) à chaque
// montage. Aucune implication sécurité : préférence d'affichage, pas une donnée sensible.
let cachedListLayout: ListLayout | null = null;

/** Lit la préférence brute — utilisée par le sélecteur dans Réglages (voir
 * components/ListLayoutSettings.tsx, masqué sur mobile). Ne tient PAS compte de la plateforme :
 * voir getEffectiveListLayout() ci-dessous pour la valeur RÉELLEMENT appliquée au rendu. */
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

/** Valeur RÉELLEMENT appliquée au rendu (voir les 6 écrans concernés) — force "list" sur mobile
 * quelle que soit la valeur en localStorage (défensif : un ancien réglage resté en local après un
 * changement de plateforme, par exemple, ne doit jamais se retrouver appliqué sur téléphone), même
 * mécanisme que lib/menuLayout.ts::getEffectiveMenuLayout(). Le sélecteur lui-même reste de toute
 * façon masqué sur mobile (voir components/ListLayoutSettings.tsx et pages/Settings.tsx), cette
 * fonction est la seconde ligne de défense côté rendu. */
export function getEffectiveListLayout(): ListLayout {
  if (isMobilePlatform()) return "list";
  return getListLayout();
}

/** Classe de conteneur à utiliser pour une liste d'éléments — un seul endroit pour cette règle
 * (grille pour "cards", liste empilée pour "list"/"compact"), réutilisé par toutes les listes de
 * l'app (Administration, Partagé avec moi, Coffres partagés...) plutôt que de la redupliquer à
 * chaque écran. Toujours un `<ul>` (voir appelants) : `display: grid` fonctionne aussi bien sur un
 * `<ul>` qu'un `<div>` — inutile de changer de balise juste pour "cards" et de risquer un `<li>`
 * mal imbriqué dans un `<div>` (HTML valide mais moins propre).
 *
 * `gridCols` ("cards" uniquement) : CORRECTIF (retour utilisateur, 2026-09-02, plusieurs allers-
 * retours) — remplacé un nombre de colonnes FIXE par palier de largeur (`grid-cols-2 @sm:grid-
 * cols-3 @lg:grid-cols-4`...) par `repeat(auto-fit, minmax(Npx, 1fr))`. Historique des deux
 * défauts corrigés dans l'ordre : 1) des paliers fixes faisaient sauter BRUSQUEMENT le nombre de
 * colonnes (et donc la taille des cartes) à des seuils de largeur arbitraires ; 2) `minmax(Npx,
 * Npx)` (taille rigide) réglait ça mais laissait un grand vide à droite dès qu'une ligne ne
 * pouvait pas être remplie pile par des cartes de largeur fixe (fréquent : chaque section de
 * dossier est SA PROPRE grille, voir groupedSections dans Vault.tsx, donc souvent PEU d'entrées
 * par ligne) — même un écart modeste type `minmax(Npx, Npx+50)` ne comblait pas assez, la
 * disposition "Liste" d'à côté (qui utilise `grid-cols-N`, TOUJOURS pile ajusté à 100% de la
 * largeur) faisait paraître "Cartes" plus étroite en comparaison directe. `1fr` (comme "list") :
 * les cartes présentes sur une ligne comblent maintenant TOUJOURS tout l'espace, comme "list" —
 * plus de vide à droite. `auto-fit` (pas `auto-fill`) reste indispensable : `auto-fill`
 * réserverait quand même la largeur de colonnes VIDES même sans carte à y mettre (le `1fr` se
 * répartirait alors sur des colonnes fantômes, pas sur les cartes visibles) ; `auto-fit` effondre
 * les colonnes vides, le `1fr` ne profite qu'aux cartes réellement présentes. COMPROMIS ASSUMÉ :
 * une ligne avec très peu d'entrées (ex. un dossier de 1 entrée) verra sa/ses carte(s) s'étirer
 * nettement plus large que `N` — contrairement au problème d'ORIGINE (un saut BRUSQUE à un seuil
 * de fenêtre arbitraire, sans lien avec le contenu), cet étirement reste CONTINU et dépend
 * uniquement du nombre RÉEL de cartes sur cette ligne précise, jamais de la largeur de la fenêtre
 * en elle-même. Une liste avec peu de métadonnées par élément (ex: partages reçus) peut se
 * permettre une carte plus étroite qu'une carte de coffre avec logo/avatar — ajustable par
 * appelant.
 *
 * Fonctionne SANS `@container` (contrairement aux paliers `@sm:`/`@lg:` encore utilisés pour
 * "list"/"compact" juste en dessous) : `repeat(auto-fit, ...)` calcule directement combien de
 * colonnes de cette largeur tiennent dans l'espace RÉELLEMENT disponible pour la grille elle-même
 * (barre latérale déjà déduite, aucune requête de conteneur nécessaire). */
export function listContainerClass(layout: ListLayout, gridCols = "grid-cols-[repeat(auto-fit,minmax(200px,1fr))]"): string {
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
