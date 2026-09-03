// PERSONNALISATION DE THÈME AVANCÉE — synchronisée par compte, en PROFILS nommés (retour
// utilisateur, 2026-09-03, affiné le même jour) : en plus des thèmes "presets" (voir
// theme.ts/App.css), un thème "custom" où l'utilisateur choisit LUI-MÊME chaque couleur — teinte
// (curseur 0-359°) ET luminosité (curseur 0-100%, "rendre une couleur plus sombre ou plus claire")
// pour l'accent (boutons/liens), le danger (Supprimer, erreurs), le succès (confirmations), les
// favoris (★), ET le fond lui-même (PAS une bascule clair/sombre séparée — voir applyBackground
// ci-dessous : le mode clair/sombre de l'interface se DÉDUIT de la luminosité de fond choisie).
//
// MÊME RECETTE que les thèmes presets pour l'accent/danger/succès/favoris (voir le long commentaire
// d'en-tête d'App.css) : la Chroma (C) de chaque palier Tailwind ne bouge JAMAIS — seules la
// Teinte (H, comme les presets) ET maintenant la Luminosité (L) sont personnalisables. La
// luminosité n'est PAS réglée palier par palier (11 curseurs par couleur serait ingérable) : un
// SEUL curseur positionne le palier "500" (le plus représentatif — boutons, badges...) à la
// luminosité choisie, et le MÊME décalage (delta = luminosité choisie − luminosité native du palier
// 500) est appliqué à TOUS les autres paliers de la famille, en gardant intact l'écart relatif
// entre paliers (donc toujours plus clair au fur et à mesure qu'on monte les paliers, jamais un
// dégradé aplati) — clampé à [0, 100] aux extrêmes.
//
// Valeurs L/C natives extraites du CSS Tailwind v4 réellement compilé (dist/assets/*.css), PAS
// approximées — même technique que pour les thèmes presets (voir App.css).

interface Step {
  l: number; // luminosité native Tailwind pour ce palier, en % (ex: 58.5)
  c: string; // chroma native, INCHANGÉE quelle que soit la personnalisation (ex: ".233")
}

/** Accent (boutons, liens, focus) — palette `indigo`. */
const INDIGO_STEPS: Record<string, Step> = {
  "50": { l: 96.2, c: ".018" },
  "100": { l: 93, c: ".034" },
  "200": { l: 87, c: ".065" },
  "300": { l: 78.5, c: ".115" },
  "400": { l: 67.3, c: ".182" },
  "500": { l: 58.5, c: ".233" },
  "600": { l: 51.1, c: ".262" },
  "700": { l: 45.7, c: ".24" },
  "800": { l: 39.8, c: ".195" },
  "900": { l: 35.9, c: ".144" },
  "950": { l: 25.7, c: ".09" },
};
const INDIGO_ANCHOR_L = INDIGO_STEPS["500"].l;

/** Danger (Supprimer, erreurs) — palette `red`, uniquement les paliers réellement utilisés dans
 * l'app (vérifié par grep sur src/). */
const RED_STEPS: Record<string, Step> = {
  "50": { l: 97.1, c: ".013" },
  "100": { l: 93.6, c: ".032" },
  "200": { l: 88.5, c: ".062" },
  "300": { l: 80.8, c: ".114" },
  "400": { l: 70.4, c: ".191" },
  "500": { l: 63.7, c: ".237" },
  "600": { l: 57.7, c: ".245" },
  "700": { l: 50.5, c: ".213" },
  "800": { l: 44.4, c: ".177" },
  "900": { l: 39.6, c: ".141" },
  "950": { l: 25.8, c: ".092" },
};
const RED_ANCHOR_L = RED_STEPS["500"].l;

/** Favoris (★) — palette `amber` (pas de palier 500 utilisé dans l'app — ancrage sur 400, le
 * palier le plus proche réellement présent). */
const AMBER_STEPS: Record<string, Step> = {
  "50": { l: 98.7, c: ".022" },
  "100": { l: 96.2, c: ".059" },
  "300": { l: 87.9, c: ".169" },
  "400": { l: 82.8, c: ".189" },
  "500": { l: 76.9, c: ".188" },
  "600": { l: 66.6, c: ".179" },
  "700": { l: 55.5, c: ".163" },
  "900": { l: 41.4, c: ".112" },
  "950": { l: 27.9, c: ".077" },
};
const AMBER_ANCHOR_L = AMBER_STEPS["500"].l;

/** Succès (confirmations) — DEUX familles utilisées côte à côte dans l'app pour ce sens
 * (`emerald` la plupart du temps, `green` à deux endroits — AutoBackupSettings.tsx,
 * PasswordStrengthMeter.tsx) : les deux tournent ET se déclarent ensemble, ancrées sur le 500
 * d'`emerald` (`green` n'a pas de palier 500 utilisé dans l'app). */
const EMERALD_STEPS: Record<string, Step> = {
  "100": { l: 95, c: ".052" },
  "300": { l: 84.5, c: ".143" },
  "400": { l: 76.5, c: ".177" },
  "500": { l: 69.6, c: ".17" },
  "600": { l: 59.6, c: ".145" },
  "700": { l: 50.8, c: ".118" },
  "950": { l: 26.2, c: ".051" },
};
const EMERALD_ANCHOR_L = EMERALD_STEPS["500"].l;
const GREEN_STEPS: Record<string, Step> = {
  "400": { l: 79.2, c: ".209" },
  "600": { l: 62.7, c: ".194" },
};

/** "neutral" (gris pur, `backgroundHue` ignoré) | "subtle" ("fondu", retour utilisateur : "par
 * exemple lorsqu'on choisit noir, le fondu permettrait d'avoir un noir avec une légère autre
 * couleur" — chroma faible et fixe, la recette de la toute première version de cette fonction-
 * nalité) | "vivid" (couleur pleinement perceptible, chroma nettement plus élevée) — voir
 * applyBackground() pour la chroma exacte associée à chacun. */
export type BackgroundStyle = "neutral" | "subtle" | "vivid";

export interface CustomThemeConfig {
  backgroundHue: number; // 0-359 — IGNORÉ si backgroundStyle vaut "neutral" (voir applyBackground).
  backgroundLightness: number; // 0-100 — luminosité du fond PRINCIPAL (page) ; < 50 = régime
  // sombre (fond très luminosité basse, texte clair), >= 50 = régime clair — voir applyBackground.
  backgroundStyle: BackgroundStyle;
  accentHue: number;
  accentLightness: number; // 0-100 — luminosité voulue pour le palier "500" de l'accent
  dangerHue: number;
  dangerLightness: number;
  successHue: number;
  successLightness: number;
  favoriteHue: number;
  favoriteLightness: number;
}

/** Reproduit EXACTEMENT le thème preset "Sombre" (aucune classe `.theme-X`, palette Tailwind
 * native) — c'est la cible du bouton "Réinitialiser" de l'éditeur de profil (retour utilisateur :
 * "ajoute un bouton pour réinitialiser les curseurs par défaut, les mêmes que le mode sombre") ET
 * la valeur de départ d'un tout nouveau profil. Luminosités = valeurs natives Tailwind (delta nul)
 * pour accent/danger/succès/favoris ; fond neutre (chroma nulle) à la luminosité native de
 * neutral-950 (14.5%, ARRONDIE à 15 — CORRECTIF, voir l'historique : le serveur stocke les
 * luminosités en entier (i64, voir models.rs::ThemeProfilePayload côté backend), un 14.5 envoyé
 * tel quel faisait échouer la désérialisation JSON avec une 422, pour CHAQUE nouveau profil créé
 * avec les valeurs par défaut — reproductible à coup sûr, pas un problème de build), IDENTIQUE au
 * thème "Sombre" à l'imperceptible près. */
export const DEFAULT_CUSTOM_THEME: CustomThemeConfig = {
  backgroundHue: 0,
  backgroundLightness: 15,
  backgroundStyle: "neutral",
  accentHue: 277, // teinte "native" de l'indigo Tailwind.
  accentLightness: Math.round(INDIGO_ANCHOR_L),
  dangerHue: 27,
  dangerLightness: Math.round(RED_ANCHOR_L),
  successHue: 163,
  successLightness: Math.round(EMERALD_ANCHOR_L),
  favoriteHue: 75,
  favoriteLightness: Math.round(AMBER_ANCHOR_L),
};

function clampL(l: number): number {
  return Math.min(100, Math.max(0, l));
}

function clampHue(h: number): number {
  return Math.min(359, Math.max(0, h));
}

/** CORRECTIF (retour utilisateur : "ça reste blank partout, le profil ne s'applique pas") : une
 * valeur non-numérique/hors-plage (localStorage corrompu, valeur laissée par une version antérieure
 * de ce schéma en cours de mise au point aujourd'hui même, un champ oublié...) se propage en NaN à
 * travers applyFamily()/applyBackground() ci-dessous (`NaN.toFixed(1)` renvoie la CHAÎNE "NaN", pas
 * une exception — l'app ne plante donc jamais, mais chaque `oklch(NaN% ...)` posé est une valeur
 * CSS invalide : la propriété qui l'utilise (ex: `background-color: var(--color-neutral-950)`)
 * retombe alors sur sa valeur INITIALE — `transparent` pour un fond — ce qui donne exactement une
 * interface "sans aucune couleur" alors que la mise en page reste normale). Cette fonction
 * garantit qu'AUCUNE valeur invalide ne peut jamais atteindre applyCustomTheme(), quelle que soit
 * la provenance de la config (cache local, réponse serveur) — retombe champ par champ sur
 * DEFAULT_CUSTOM_THEME plutôt que de faire échouer toute la config d'un coup pour UN SEUL champ
 * corrompu. */
export function sanitizeCustomThemeConfig(config: Partial<CustomThemeConfig> | null | undefined): CustomThemeConfig {
  function hue(value: unknown, fallback: number): number {
    return typeof value === "number" && Number.isFinite(value) ? clampHue(value) : fallback;
  }
  function lightness(value: unknown, fallback: number): number {
    return typeof value === "number" && Number.isFinite(value) ? clampL(value) : fallback;
  }
  const c = config ?? {};
  return {
    backgroundHue: hue(c.backgroundHue, DEFAULT_CUSTOM_THEME.backgroundHue),
    backgroundLightness: lightness(c.backgroundLightness, DEFAULT_CUSTOM_THEME.backgroundLightness),
    backgroundStyle: c.backgroundStyle === "neutral" || c.backgroundStyle === "subtle" || c.backgroundStyle === "vivid" ? c.backgroundStyle : DEFAULT_CUSTOM_THEME.backgroundStyle,
    accentHue: hue(c.accentHue, DEFAULT_CUSTOM_THEME.accentHue),
    accentLightness: lightness(c.accentLightness, DEFAULT_CUSTOM_THEME.accentLightness),
    dangerHue: hue(c.dangerHue, DEFAULT_CUSTOM_THEME.dangerHue),
    dangerLightness: lightness(c.dangerLightness, DEFAULT_CUSTOM_THEME.dangerLightness),
    successHue: hue(c.successHue, DEFAULT_CUSTOM_THEME.successHue),
    successLightness: lightness(c.successLightness, DEFAULT_CUSTOM_THEME.successLightness),
    favoriteHue: hue(c.favoriteHue, DEFAULT_CUSTOM_THEME.favoriteHue),
    favoriteLightness: lightness(c.favoriteLightness, DEFAULT_CUSTOM_THEME.favoriteLightness),
  };
}

/** Couleur d'UN palier d'une famille, à la teinte/luminosité choisies — même calcul (décalage
 * depuis le palier "500" natif) que applyFamily() ci-dessous, extrait en fonction pure pour être
 * réutilisable par l'aperçu visuel de l'éditeur (voir les fonctions preview*Color plus bas), sans
 * dupliquer la formule. */
function stepColor(steps: Record<string, Step>, anchorNativeL: number, step: string, hue: number, lightness: number): string {
  const { l, c } = steps[step];
  const offset = lightness - anchorNativeL;
  return `oklch(${clampL(l + offset).toFixed(1)}% ${c} ${hue})`;
}

function applyFamily(el: HTMLElement, family: string, steps: Record<string, Step>, hue: number, lightness: number, anchorNativeL: number): void {
  for (const step of Object.keys(steps)) {
    el.style.setProperty(`--color-${family}-${step}`, stepColor(steps, anchorNativeL, step, hue, lightness));
  }
}

/** Teintes toutes prêtes proposées en plus des curseurs (retour utilisateur : "améliore la
 * sélection de couleur") — un simple raccourci, pose `hue`, ne change jamais la luminosité déjà
 * choisie. Réparties sur tout le cercle chromatique (~30-40° d'écart) plutôt qu'une sélection
 * arbitraire, pour couvrir un large éventail de couleurs reconnaissables d'un coup d'œil. */
export const HUE_PRESETS: { hue: number; label: string }[] = [
  { hue: 0, label: "Rouge" },
  { hue: 25, label: "Orange" },
  { hue: 60, label: "Jaune" },
  { hue: 140, label: "Vert" },
  { hue: 180, label: "Turquoise" },
  { hue: 220, label: "Bleu" },
  { hue: 260, label: "Indigo" },
  { hue: 290, label: "Violet" },
  { hue: 330, label: "Rose" },
];

/** Dégradé arc-en-ciel posé en `style` inline sur chaque curseur de teinte (retour utilisateur :
 * "améliore [...] la sélection de couleur, rends-la plus complète") — voir `.hue-slider` dans
 * App.css pour la classe qui rend ce `background` réellement visible (un `<input type="range">`
 * natif l'ignore sinon). Luminosité/chroma FIXES (mêmes que les pastilles HUE_PRESETS) : ce
 * dégradé sert à repérer une teinte visuellement, pas à prévisualiser le rendu exact (déjà fait
 * par le curseur de luminosité et l'aperçu visuel, voir ThemePreviewMockup). Calculé UNE FOIS ici
 * (24 arrêts, tous les 15°) plutôt qu'à chaque rendu de curseur. */
export const HUE_GRADIENT = `linear-gradient(to right, ${Array.from({ length: 25 }, (_, i) => `oklch(65% .2 ${i * 15})`).join(", ")})`;

/** Couleurs pour l'aperçu visuel de l'éditeur (retour utilisateur : "aperçu visuel dans
 * l'éditeur") — reprennent EXACTEMENT le calcul réellement appliqué (voir stepColor ci-dessus),
 * au palier le plus représentatif de chaque usage (600 = couleur de bouton "plein", 500 = ★
 * favoris). Fonctions PURES (aucun accès au DOM) — utilisables aussi bien côté aperçu que, plus
 * tard, pour toute autre prévisualisation sans avoir à appliquer le thème pour de vrai. */
export function previewAccentColor(hue: number, lightness: number): string {
  return stepColor(INDIGO_STEPS, INDIGO_ANCHOR_L, "600", hue, lightness);
}
export function previewDangerColor(hue: number, lightness: number): string {
  return stepColor(RED_STEPS, RED_ANCHOR_L, "600", hue, lightness);
}
export function previewSuccessColor(hue: number, lightness: number): string {
  return stepColor(EMERALD_STEPS, EMERALD_ANCHOR_L, "600", hue, lightness);
}
export function previewFavoriteColor(hue: number, lightness: number): string {
  return stepColor(AMBER_STEPS, AMBER_ANCHOR_L, "500", hue, lightness);
}

/** Fond ENTIÈREMENT personnalisé (teinte + luminosité, retour utilisateur : "je ne veux pas que le
 * fond soit soit clair soit sombre je veux aussi pouvoir choisir la couleur pour le fond") — PAS
 * une bascule binaire : le régime clair/sombre se déduit simplement d'où se trouve la luminosité
 * choisie (< 50% = plutôt sombre, le fond `page` prend directement cette valeur et les 2 fonds
 * "secondaires" (cartes/bordures) sont dérivés avec les MÊMES écarts que la palette Tailwind native
 * neutral-950/900/800 ; >= 50% = plutôt clair, dérivés comme neutral-50/100/200).
 *
 * TROIS intensités de chroma (retour utilisateur, 2026-09-03, plusieurs allers-retours le même
 * jour) :
 * - "neutral" : chroma nulle, `hue` sans aucun effet visuel — un fond parfaitement gris, restauré
 *   après avoir disparu dans une version intermédiaire ("tu as enlevé une fonctionnalité").
 * - "subtle" ("fondu") : "par exemple lorsqu'on choisit noir, le fondu permettrait d'avoir un noir
 *   avec une légère autre couleur" — chroma faible et fixe (.006-.015), la recette de la toute
 *   première version de cette fonctionnalité (déjà utilisée par les thèmes preset "tintés").
 * - "vivid" : "j'ai le choix entre noir et blanc [...] mais je veux [choisir] entre toutes les
 *   couleurs" — la chroma "subtle" ne se voyait quasiment pas, le fond restait perçu comme un
 *   simple dégradé gris ; chroma nettement plus élevée (.05-.07) pour une VRAIE couleur, comme
 *   l'accent/danger/succès/favoris, tout en restant en-dessous de leur chroma (~.18-.26) — un fond
 *   de page ne doit pas être aussi saturé qu'un bouton, juste clairement teinté. */
const BACKGROUND_CHROMA_DARK: Record<BackgroundStyle, [string, string, string]> = {
  neutral: ["0", "0", "0"],
  subtle: [".006", ".008", ".01"],
  vivid: [".05", ".06", ".07"],
};
const BACKGROUND_CHROMA_LIGHT: Record<BackgroundStyle, [string, string, string]> = {
  neutral: ["0", "0", "0"],
  subtle: [".008", ".01", ".015"],
  vivid: [".02", ".025", ".03"],
};

/** Les 3 couleurs de fond (page/carte/bordure) pour la teinte/luminosité/style choisis — fonction
 * PURE partagée par applyBackground() (application réelle) et l'aperçu visuel de l'éditeur (voir
 * previewBackgroundColors ci-dessous), même raison que stepColor() plus haut. */
function backgroundColors(hue: number, lightness: number, style: BackgroundStyle): { page: string; card: string; border: string; isDark: boolean } {
  const isDark = lightness < 50;
  // CORRECTIF SÉCURITÉ (retour utilisateur : "une erreur est survenue" en ouvrant Réglages,
  // causé par un backend pas encore redémarré renvoyant une forme de profil antérieure au champ
  // `background_style`, actuel) : `style` n'est PAS forcément l'une des 3 valeurs valides ici — ni
  // applyBackground() ni previewBackgroundColors() (les deux seuls appelants) ne passent par
  // sanitizeCustomThemeConfig() avant d'arriver ici. Indexer BACKGROUND_CHROMA_DARK/LIGHT avec une
  // clé absente (`undefined`, une ancienne valeur...) renvoyait `undefined`, et la déstructuration
  // juste en dessous levait une exception NON RATTRAPÉE — faisait planter TOUTE la page Réglages
  // (voir ErrorBoundary.tsx), pas juste perdre la couleur comme pour les autres champs déjà
  // protégés (voir sanitizeCustomThemeConfig). `in` plutôt qu'un appel à sanitizeCustomThemeConfig
  // (qui reconstruit toute une config) : ne concerne qu'UN champ ici.
  const safeStyle: BackgroundStyle = style in BACKGROUND_CHROMA_DARK ? style : "neutral";
  const [c1, c2, c3] = isDark ? BACKGROUND_CHROMA_DARK[safeStyle] : BACKGROUND_CHROMA_LIGHT[safeStyle];
  if (isDark) {
    // Écarts natifs Tailwind neutral 950->900->800 : 14.5 -> 20.5 (+6) -> 26.9 (+12.4).
    return {
      page: `oklch(${clampL(lightness).toFixed(1)}% ${c1} ${hue})`,
      card: `oklch(${clampL(lightness + 6).toFixed(1)}% ${c2} ${hue})`,
      border: `oklch(${clampL(lightness + 12.4).toFixed(1)}% ${c3} ${hue})`,
      isDark: true,
    };
  }
  // Écarts natifs Tailwind neutral 50->100->200 : 98.5 -> 97 (-1.5) -> 92.2 (-6.3).
  return {
    page: `oklch(${clampL(lightness).toFixed(1)}% ${c1} ${hue})`,
    card: `oklch(${clampL(lightness - 1.5).toFixed(1)}% ${c2} ${hue})`,
    border: `oklch(${clampL(lightness - 6.3).toFixed(1)}% ${c3} ${hue})`,
    isDark: false,
  };
}

/** Voir backgroundColors() ci-dessus — exportée pour l'aperçu visuel de l'éditeur (retour
 * utilisateur : "aperçu visuel dans l'éditeur"). */
export function previewBackgroundColors(hue: number, lightness: number, style: BackgroundStyle): { page: string; card: string; border: string; isDark: boolean } {
  return backgroundColors(hue, lightness, style);
}

function applyBackground(el: HTMLElement, hue: number, lightness: number, style: BackgroundStyle): boolean {
  const { page, card, border, isDark } = backgroundColors(hue, lightness, style);
  if (isDark) {
    el.style.setProperty("--color-neutral-950", page);
    el.style.setProperty("--color-neutral-900", card);
    el.style.setProperty("--color-neutral-800", border);
  } else {
    el.style.setProperty("--color-neutral-50", page);
    el.style.setProperty("--color-neutral-100", card);
    el.style.setProperty("--color-neutral-200", border);
  }
  return isDark;
}

const TINT_PROPERTIES_DARK = ["--color-neutral-950", "--color-neutral-900", "--color-neutral-800"];
const TINT_PROPERTIES_LIGHT = ["--color-neutral-50", "--color-neutral-100", "--color-neutral-200"];
const ALL_FAMILY_PROPERTIES = [
  ...Object.keys(INDIGO_STEPS).map((s) => `--color-indigo-${s}`),
  ...Object.keys(RED_STEPS).map((s) => `--color-red-${s}`),
  ...Object.keys(AMBER_STEPS).map((s) => `--color-amber-${s}`),
  ...Object.keys(EMERALD_STEPS).map((s) => `--color-emerald-${s}`),
  ...Object.keys(GREEN_STEPS).map((s) => `--color-green-${s}`),
];

/** Applique la personnalisation sur `<html>` — appelée quand `getTheme() === "custom"` (voir
 * theme.ts::applyTheme). Renvoie `isDark` (déduit de la luminosité de fond, voir applyBackground
 * ci-dessus) — c'est applyTheme() qui pose la classe `dark`/`color-scheme`, PAS cette fonction :
 * elle ne touche qu'aux propriétés de couleur elles-mêmes. `sanitizeCustomThemeConfig()` en tout
 * premier : dernier filet de sécurité, même si l'appelant a déjà normalement sanitizé (voir
 * getCachedCustomTheme() dans theme.ts) — voir le commentaire de sanitizeCustomThemeConfig pour ce
 * que ça évite (interface qui perd toute couleur sans planter). */
export function applyCustomTheme(rawConfig: CustomThemeConfig): boolean {
  const config = sanitizeCustomThemeConfig(rawConfig);
  const el = document.documentElement;
  applyFamily(el, "indigo", INDIGO_STEPS, config.accentHue, config.accentLightness, INDIGO_ANCHOR_L);
  applyFamily(el, "red", RED_STEPS, config.dangerHue, config.dangerLightness, RED_ANCHOR_L);
  applyFamily(el, "amber", AMBER_STEPS, config.favoriteHue, config.favoriteLightness, AMBER_ANCHOR_L);
  applyFamily(el, "emerald", EMERALD_STEPS, config.successHue, config.successLightness, EMERALD_ANCHOR_L);
  applyFamily(el, "green", GREEN_STEPS, config.successHue, config.successLightness, EMERALD_ANCHOR_L);

  // Retire l'éventuel jeu de propriétés de fond de l'AUTRE régime (ex: on vient de passer d'un
  // fond sombre à un fond clair) avant d'appliquer celui du régime courant.
  for (const prop of [...TINT_PROPERTIES_DARK, ...TINT_PROPERTIES_LIGHT]) el.style.removeProperty(prop);
  return applyBackground(el, config.backgroundHue, config.backgroundLightness, config.backgroundStyle);
}

/** Retire toute personnalisation inline posée par applyCustomTheme() — appelée en quittant
 * "custom" pour un thème preset (voir theme.ts::applyTheme), pour laisser les classes `.theme-X`
 * (elles, statiques dans App.css) reprendre la main sans qu'une ancienne valeur inline ne les
 * masque (spécificité inline > classe, voir le commentaire d'en-tête). */
export function clearCustomTheme(): void {
  const el = document.documentElement;
  for (const prop of ALL_FAMILY_PROPERTIES) el.style.removeProperty(prop);
  for (const prop of [...TINT_PROPERTIES_DARK, ...TINT_PROPERTIES_LIGHT]) el.style.removeProperty(prop);
}
