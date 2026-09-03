// PERSONNALISATION DE THÈME AVANCÉE — synchronisée par compte, en PROFILS nommés (retour
// utilisateur, 2026-09-03, affiné plusieurs fois le même jour) : en plus des thèmes "presets" (voir
// theme.ts/App.css), un thème "custom" où l'utilisateur choisit LUI-MÊME chaque couleur — teinte
// (curseur 0-359°), luminosité (curseur 0-100%, "rendre une couleur plus sombre ou plus claire") ET
// saturation (curseur 0-100%, "contrôle de la saturation") pour l'accent (boutons/liens), le
// danger (Supprimer, erreurs), le succès (confirmations), les favoris (★), ET le fond lui-même
// (PAS une bascule clair/sombre séparée — voir applyBackground ci-dessous : le mode clair/sombre
// de l'interface se DÉDUIT de la luminosité de fond choisie).
//
// MÊME RECETTE que les thèmes presets pour l'accent/danger/succès/favoris (voir le long commentaire
// d'en-tête d'App.css) pour la teinte/luminosité : la Chroma (C) de chaque palier Tailwind reste la
// référence, mais est maintenant MULTIPLIÉE par la saturation choisie (100% = chroma native
// inchangée, valeur historique avant l'ajout de ce réglage ; 0% = entièrement grisé). La luminosité
// n'est PAS réglée palier par palier (11 curseurs par couleur serait ingérable) : un SEUL curseur
// positionne le palier "500" (le plus représentatif — boutons, badges...) à la luminosité choisie,
// et le MÊME décalage (delta = luminosité choisie − luminosité native du palier 500) est appliqué à
// TOUS les autres paliers de la famille, en gardant intact l'écart relatif entre paliers (donc
// toujours plus clair au fur et à mesure qu'on monte les paliers, jamais un dégradé aplati) —
// clampé à [0, 100] aux extrêmes.
//
// Valeurs L/C natives extraites du CSS Tailwind v4 réellement compilé (dist/assets/*.css), PAS
// approximées — même technique que pour les thèmes presets (voir App.css).

interface Step {
  l: number; // luminosité native Tailwind pour ce palier, en % (ex: 58.5)
  c: number; // chroma native Tailwind pour ce palier — MULTIPLIÉE par la saturation choisie, voir
  // stepColor() ci-dessous (ex: .233, valeur utilisée telle quelle à saturation 100%).
}

/** Accent (boutons, liens, focus) — palette `indigo`. */
const INDIGO_STEPS: Record<string, Step> = {
  "50": { l: 96.2, c: 0.018 },
  "100": { l: 93, c: 0.034 },
  "200": { l: 87, c: 0.065 },
  "300": { l: 78.5, c: 0.115 },
  "400": { l: 67.3, c: 0.182 },
  "500": { l: 58.5, c: 0.233 },
  "600": { l: 51.1, c: 0.262 },
  "700": { l: 45.7, c: 0.24 },
  "800": { l: 39.8, c: 0.195 },
  "900": { l: 35.9, c: 0.144 },
  "950": { l: 25.7, c: 0.09 },
};
const INDIGO_ANCHOR_L = INDIGO_STEPS["500"].l;

/** Danger (Supprimer, erreurs) — palette `red`, uniquement les paliers réellement utilisés dans
 * l'app (vérifié par grep sur src/). */
const RED_STEPS: Record<string, Step> = {
  "50": { l: 97.1, c: 0.013 },
  "100": { l: 93.6, c: 0.032 },
  "200": { l: 88.5, c: 0.062 },
  "300": { l: 80.8, c: 0.114 },
  "400": { l: 70.4, c: 0.191 },
  "500": { l: 63.7, c: 0.237 },
  "600": { l: 57.7, c: 0.245 },
  "700": { l: 50.5, c: 0.213 },
  "800": { l: 44.4, c: 0.177 },
  "900": { l: 39.6, c: 0.141 },
  "950": { l: 25.8, c: 0.092 },
};
const RED_ANCHOR_L = RED_STEPS["500"].l;

/** Favoris (★) — palette `amber` (pas de palier 500 utilisé dans l'app — ancrage sur 400, le
 * palier le plus proche réellement présent). */
const AMBER_STEPS: Record<string, Step> = {
  "50": { l: 98.7, c: 0.022 },
  "100": { l: 96.2, c: 0.059 },
  "300": { l: 87.9, c: 0.169 },
  "400": { l: 82.8, c: 0.189 },
  "500": { l: 76.9, c: 0.188 },
  "600": { l: 66.6, c: 0.179 },
  "700": { l: 55.5, c: 0.163 },
  "900": { l: 41.4, c: 0.112 },
  "950": { l: 27.9, c: 0.077 },
};
const AMBER_ANCHOR_L = AMBER_STEPS["500"].l;

/** Succès (confirmations) — DEUX familles utilisées côte à côte dans l'app pour ce sens
 * (`emerald` la plupart du temps, `green` à deux endroits — AutoBackupSettings.tsx,
 * PasswordStrengthMeter.tsx) : les deux tournent ET se déclarent ensemble, ancrées sur le 500
 * d'`emerald` (`green` n'a pas de palier 500 utilisé dans l'app). */
const EMERALD_STEPS: Record<string, Step> = {
  "100": { l: 95, c: 0.052 },
  "300": { l: 84.5, c: 0.143 },
  "400": { l: 76.5, c: 0.177 },
  "500": { l: 69.6, c: 0.17 },
  "600": { l: 59.6, c: 0.145 },
  "700": { l: 50.8, c: 0.118 },
  "950": { l: 26.2, c: 0.051 },
};
const EMERALD_ANCHOR_L = EMERALD_STEPS["500"].l;
const GREEN_STEPS: Record<string, Step> = {
  "400": { l: 79.2, c: 0.209 },
  "600": { l: 62.7, c: 0.194 },
};

export interface CustomThemeConfig {
  backgroundHue: number; // 0-359 — sans effet visuel si backgroundSaturation vaut 0 (gris pur).
  backgroundLightness: number; // 0-100 — luminosité du fond PRINCIPAL (page) ; < 50 = régime
  // sombre (fond très luminosité basse, texte clair), >= 50 = régime clair — voir applyBackground.
  /** Retour utilisateur : "contrôle de la saturation (pas que teinte+luminosité)" — 0 = gris pur
   * ("Neutre"), 100 = la couleur de fond la plus vive possible (voir applyBackground pour le
   * plafond exact, plus bas que l'accent/danger/succès/favoris : un fond de page ne doit pas être
   * aussi saturé qu'un bouton). Remplace l'ancien réglage à 3 choix discrets "Neutre"/"Fondu"/
   * "Couleur" par un curseur continu, cohérent avec les 4 couleurs ci-dessous. */
  backgroundSaturation: number;
  accentHue: number;
  accentLightness: number; // 0-100 — luminosité voulue pour le palier "500" de l'accent
  /** 0-100, multiplie la chroma native Tailwind de chaque palier — 100 = valeur historique
   * (chroma native inchangée, avant l'ajout de ce réglage), 0 = entièrement grisé. */
  accentSaturation: number;
  dangerHue: number;
  dangerLightness: number;
  dangerSaturation: number;
  successHue: number;
  successLightness: number;
  successSaturation: number;
  favoriteHue: number;
  favoriteLightness: number;
  favoriteSaturation: number;
}

/** Reproduit EXACTEMENT le thème preset "Sombre" (aucune classe `.theme-X`, palette Tailwind
 * native) — c'est la cible du bouton "Réinitialiser" de l'éditeur de profil (retour utilisateur :
 * "ajoute un bouton pour réinitialiser les curseurs par défaut, les mêmes que le mode sombre") ET
 * la valeur de départ d'un tout nouveau profil. Luminosités = valeurs natives Tailwind (delta nul),
 * saturations à 100% (chroma native inchangée) pour accent/danger/succès/favoris ; fond neutre
 * (saturation 0) à la luminosité native de neutral-950 (14.5%, ARRONDIE à 15 — CORRECTIF, voir
 * l'historique : le serveur stocke les luminosités en entier (i64, voir
 * models.rs::ThemeProfilePayload côté backend), un 14.5 envoyé tel quel faisait échouer la
 * désérialisation JSON avec une 422 — reproductible à coup sûr pour CHAQUE nouveau profil créé
 * avec les valeurs par défaut), IDENTIQUE au thème "Sombre" à l'imperceptible près. */
export const DEFAULT_CUSTOM_THEME: CustomThemeConfig = {
  backgroundHue: 0,
  backgroundLightness: 15,
  backgroundSaturation: 0,
  accentHue: 277, // teinte "native" de l'indigo Tailwind.
  accentLightness: Math.round(INDIGO_ANCHOR_L),
  accentSaturation: 100,
  dangerHue: 27,
  dangerLightness: Math.round(RED_ANCHOR_L),
  dangerSaturation: 100,
  successHue: 163,
  successLightness: Math.round(EMERALD_ANCHOR_L),
  successSaturation: 100,
  favoriteHue: 75,
  favoriteLightness: Math.round(AMBER_ANCHOR_L),
  favoriteSaturation: 100,
};

function clampL(l: number): number {
  return Math.min(100, Math.max(0, l));
}

function clampHue(h: number): number {
  return Math.min(359, Math.max(0, h));
}

function clampSaturation(s: number): number {
  return Math.min(100, Math.max(0, s));
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
  function saturation(value: unknown, fallback: number): number {
    return typeof value === "number" && Number.isFinite(value) ? clampSaturation(value) : fallback;
  }
  const c = config ?? {};
  return {
    backgroundHue: hue(c.backgroundHue, DEFAULT_CUSTOM_THEME.backgroundHue),
    backgroundLightness: lightness(c.backgroundLightness, DEFAULT_CUSTOM_THEME.backgroundLightness),
    backgroundSaturation: saturation(c.backgroundSaturation, DEFAULT_CUSTOM_THEME.backgroundSaturation),
    accentHue: hue(c.accentHue, DEFAULT_CUSTOM_THEME.accentHue),
    accentLightness: lightness(c.accentLightness, DEFAULT_CUSTOM_THEME.accentLightness),
    accentSaturation: saturation(c.accentSaturation, DEFAULT_CUSTOM_THEME.accentSaturation),
    dangerHue: hue(c.dangerHue, DEFAULT_CUSTOM_THEME.dangerHue),
    dangerLightness: lightness(c.dangerLightness, DEFAULT_CUSTOM_THEME.dangerLightness),
    dangerSaturation: saturation(c.dangerSaturation, DEFAULT_CUSTOM_THEME.dangerSaturation),
    successHue: hue(c.successHue, DEFAULT_CUSTOM_THEME.successHue),
    successLightness: lightness(c.successLightness, DEFAULT_CUSTOM_THEME.successLightness),
    successSaturation: saturation(c.successSaturation, DEFAULT_CUSTOM_THEME.successSaturation),
    favoriteHue: hue(c.favoriteHue, DEFAULT_CUSTOM_THEME.favoriteHue),
    favoriteLightness: lightness(c.favoriteLightness, DEFAULT_CUSTOM_THEME.favoriteLightness),
    favoriteSaturation: saturation(c.favoriteSaturation, DEFAULT_CUSTOM_THEME.favoriteSaturation),
  };
}

/** Couleur d'UN palier d'une famille, à la teinte/luminosité/saturation choisies — même calcul
 * (décalage depuis le palier "500" natif pour L, multiplication pour C) que applyFamily() ci-
 * dessous, extrait en fonction pure pour être réutilisable par l'aperçu visuel de l'éditeur (voir
 * les fonctions preview*Color plus bas), sans dupliquer la formule. */
function stepColor(steps: Record<string, Step>, anchorNativeL: number, step: string, hue: number, lightness: number, saturation: number): string {
  const { l, c } = steps[step];
  const offset = lightness - anchorNativeL;
  const chroma = (c * clampSaturation(saturation)) / 100;
  return `oklch(${clampL(l + offset).toFixed(1)}% ${chroma.toFixed(3)} ${hue})`;
}

function applyFamily(el: HTMLElement, family: string, steps: Record<string, Step>, hue: number, lightness: number, saturation: number, anchorNativeL: number): void {
  for (const step of Object.keys(steps)) {
    el.style.setProperty(`--color-${family}-${step}`, stepColor(steps, anchorNativeL, step, hue, lightness, saturation));
  }
}

/** Teintes toutes prêtes proposées en plus des curseurs (retour utilisateur : "améliore la
 * sélection de couleur") — un simple raccourci, pose `hue`, ne change jamais la luminosité/
 * saturation déjà choisies. Réparties sur tout le cercle chromatique (~30-40° d'écart) plutôt
 * qu'une sélection arbitraire, pour couvrir un large éventail de couleurs reconnaissables d'un
 * coup d'œil. */
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
export function previewAccentColor(hue: number, lightness: number, saturation: number): string {
  return stepColor(INDIGO_STEPS, INDIGO_ANCHOR_L, "600", hue, lightness, saturation);
}
export function previewDangerColor(hue: number, lightness: number, saturation: number): string {
  return stepColor(RED_STEPS, RED_ANCHOR_L, "600", hue, lightness, saturation);
}
export function previewSuccessColor(hue: number, lightness: number, saturation: number): string {
  return stepColor(EMERALD_STEPS, EMERALD_ANCHOR_L, "600", hue, lightness, saturation);
}
export function previewFavoriteColor(hue: number, lightness: number, saturation: number): string {
  return stepColor(AMBER_STEPS, AMBER_ANCHOR_L, "500", hue, lightness, saturation);
}

/** Chroma MAXIMALE (à saturation 100%) des 3 fonds page/carte/bordure — plus basse que l'accent/
 * danger/succès/favoris (~.18-.26) : un fond de page ne doit pas être aussi saturé qu'un bouton,
 * juste clairement teinté à son maximum. Écarts entre les 3 (page/carte/bordure) conservés
 * proportionnels à ceux de la recette "vivid" d'origine (retour utilisateur, 2026-09-03). */
const BACKGROUND_MAX_CHROMA_DARK: [number, number, number] = [0.05, 0.06, 0.07];
const BACKGROUND_MAX_CHROMA_LIGHT: [number, number, number] = [0.02, 0.025, 0.03];

/** Les 3 couleurs de fond (page/carte/bordure) pour la teinte/luminosité/saturation choisies —
 * fonction PURE partagée par applyBackground() (application réelle) et l'aperçu visuel de
 * l'éditeur (voir previewBackgroundColors ci-dessous), même raison que stepColor() plus haut.
 * Saturation 0 = chroma nulle sur les 3 fonds (gris pur, `hue` sans aucun effet visuel) —
 * remplace l'ancien réglage à 3 choix discrets "Neutre"/"Fondu"/"Couleur" par une interpolation
 * CONTINUE (retour utilisateur : "je veux [choisir] entre toutes les couleurs [...] contrôle de
 * la saturation") : plus besoin de valider `saturation` contre un jeu de valeurs fixes (l'ancien
 * bug de sécurité qui faisait planter la page Réglages avec une valeur invalide, voir l'historique,
 * ne peut plus se reproduire — `saturation` est un simple nombre, clampé par clampSaturation()). */
function backgroundColors(hue: number, lightness: number, saturation: number): { page: string; card: string; border: string; isDark: boolean } {
  const isDark = lightness < 50;
  const s = clampSaturation(saturation) / 100;
  const [m1, m2, m3] = isDark ? BACKGROUND_MAX_CHROMA_DARK : BACKGROUND_MAX_CHROMA_LIGHT;
  const c1 = (m1 * s).toFixed(3);
  const c2 = (m2 * s).toFixed(3);
  const c3 = (m3 * s).toFixed(3);
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
export function previewBackgroundColors(hue: number, lightness: number, saturation: number): { page: string; card: string; border: string; isDark: boolean } {
  return backgroundColors(hue, lightness, saturation);
}

function applyBackground(el: HTMLElement, hue: number, lightness: number, saturation: number): boolean {
  const { page, card, border, isDark } = backgroundColors(hue, lightness, saturation);
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

/** OPTIMISATION CPU (retour utilisateur : "optimise l'utilisation du processeur [...] pendant les
 * changements qu'on vient de faire") — applyCustomTheme() est appelée à CHAQUE tick d'un curseur
 * pendant qu'on le fait glisser (voir updateDraft() dans ThemeSettings.tsx, plusieurs fois par
 * seconde), mais un seul curseur à la fois change réellement — recalculer ET réécrire les 5
 * familles de couleurs (40 propriétés CSS au total) à chaque tick alors que 4 d'entre elles sont
 * IDENTIQUES à l'appel précédent est du travail perdu (recalcul OKLCH + écriture DOM, qui
 * déclenche un recalcul de style navigateur). Retient la dernière teinte/luminosité/saturation
 * RÉELLEMENT appliquée par famille ; applyFamily()/applyBackground() ne sont appelées que pour
 * les familles dont au moins une des 3 valeurs a changé depuis le dernier appel. RESET impératif
 * dans clearCustomTheme() ci-dessous : sans ça, ressortir de "custom" (qui EFFACE ces propriétés)
 * puis y revenir avec une config identique laisserait ce cache croire à tort que rien n'a besoin
 * d'être réécrit, alors que le DOM a été vidé entre-temps. */
type ColorTuple = readonly [hue: number, lightness: number, saturation: number];
let lastAppliedAccent: ColorTuple | null = null;
let lastAppliedDanger: ColorTuple | null = null;
let lastAppliedSuccess: ColorTuple | null = null;
let lastAppliedFavorite: ColorTuple | null = null;
let lastAppliedBackground: ColorTuple | null = null;

function tupleChanged(previous: ColorTuple | null, next: ColorTuple): boolean {
  return previous === null || previous[0] !== next[0] || previous[1] !== next[1] || previous[2] !== next[2];
}

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

  const accentTuple: ColorTuple = [config.accentHue, config.accentLightness, config.accentSaturation];
  if (tupleChanged(lastAppliedAccent, accentTuple)) {
    applyFamily(el, "indigo", INDIGO_STEPS, ...accentTuple, INDIGO_ANCHOR_L);
    lastAppliedAccent = accentTuple;
  }
  const dangerTuple: ColorTuple = [config.dangerHue, config.dangerLightness, config.dangerSaturation];
  if (tupleChanged(lastAppliedDanger, dangerTuple)) {
    applyFamily(el, "red", RED_STEPS, ...dangerTuple, RED_ANCHOR_L);
    lastAppliedDanger = dangerTuple;
  }
  const favoriteTuple: ColorTuple = [config.favoriteHue, config.favoriteLightness, config.favoriteSaturation];
  if (tupleChanged(lastAppliedFavorite, favoriteTuple)) {
    applyFamily(el, "amber", AMBER_STEPS, ...favoriteTuple, AMBER_ANCHOR_L);
    lastAppliedFavorite = favoriteTuple;
  }
  const successTuple: ColorTuple = [config.successHue, config.successLightness, config.successSaturation];
  if (tupleChanged(lastAppliedSuccess, successTuple)) {
    applyFamily(el, "emerald", EMERALD_STEPS, ...successTuple, EMERALD_ANCHOR_L);
    applyFamily(el, "green", GREEN_STEPS, ...successTuple, EMERALD_ANCHOR_L);
    lastAppliedSuccess = successTuple;
  }

  const backgroundTuple: ColorTuple = [config.backgroundHue, config.backgroundLightness, config.backgroundSaturation];
  if (tupleChanged(lastAppliedBackground, backgroundTuple)) {
    // Retire l'éventuel jeu de propriétés de fond de l'AUTRE régime (ex: on vient de passer d'un
    // fond sombre à un fond clair) avant d'appliquer celui du régime courant.
    for (const prop of [...TINT_PROPERTIES_DARK, ...TINT_PROPERTIES_LIGHT]) el.style.removeProperty(prop);
    const isDark = applyBackground(el, ...backgroundTuple);
    lastAppliedBackground = backgroundTuple;
    return isDark;
  }
  // Fond inchangé depuis le dernier appel : le régime clair/sombre ne peut pas avoir changé non
  // plus (il ne dépend QUE de backgroundLightness, déjà comparé ci-dessus) — recalculé ici sans
  // toucher le DOM plutôt que de mémoriser une 4e valeur.
  return config.backgroundLightness < 50;
}

/** Retire toute personnalisation inline posée par applyCustomTheme() — appelée en quittant
 * "custom" pour un thème preset (voir theme.ts::applyTheme), pour laisser les classes `.theme-X`
 * (elles, statiques dans App.css) reprendre la main sans qu'une ancienne valeur inline ne les
 * masque (spécificité inline > classe, voir le commentaire d'en-tête). Réinitialise aussi le cache
 * "dernière valeur appliquée" de applyCustomTheme() ci-dessus — voir son commentaire : sans ça, un
 * retour à "custom" avec une config identique à celle d'avant cette sortie croirait à tort n'avoir
 * rien à réécrire, alors que ces propriétés viennent d'être effacées juste en dessous. */
export function clearCustomTheme(): void {
  const el = document.documentElement;
  for (const prop of ALL_FAMILY_PROPERTIES) el.style.removeProperty(prop);
  for (const prop of [...TINT_PROPERTIES_DARK, ...TINT_PROPERTIES_LIGHT]) el.style.removeProperty(prop);
  lastAppliedAccent = null;
  lastAppliedDanger = null;
  lastAppliedSuccess = null;
  lastAppliedFavorite = null;
  lastAppliedBackground = null;
}

// -------------------------------------------------------------------------
// ALÉATOIRE — retour utilisateur : "bouton aléatoire (couleurs surprise)".
// -------------------------------------------------------------------------

function randRange(min: number, max: number): number {
  return Math.round(min + Math.random() * (max - min));
}

/** Décale une teinte "ancre" (ex: le rouge du danger) d'un peu de hasard, en restant dans une zone
 * reconnaissable — évite un "danger" verdâtre ou un "succès" violet, juste par hasard, qui
 * casserait la lecture immédiate de ces couleurs (retour utilisateur : couleurs "surprise", pas
 * méconnaissables). Boucle circulairement (0-359). */
function jitterHue(anchor: number, spread: number): number {
  return Math.round((((anchor + (Math.random() * 2 - 1) * spread) % 360) + 360) % 360);
}

/** Génère une combinaison de couleurs harmonieuse au hasard — retour utilisateur : "bouton
 * aléatoire (couleurs surprise), pour s'inspirer plutôt que tout régler curseur par curseur".
 * L'accent ET le fond partagent la MÊME teinte de base (cohérence visuelle, comme choisir un
 * "thème bleu" plutôt que des couleurs sans rapport) ; danger/succès/favoris restent dans leur
 * zone sémantique habituelle (rouge/vert/ambre) avec une légère variation, pour rester
 * reconnaissables même générés au hasard. Favorise un fond sombre (comme le reste de l'app,
 * volontairement pensée sombre par défaut) sans exclure un résultat clair de temps en temps. */
export function randomThemeConfig(): CustomThemeConfig {
  const baseHue = randRange(0, 359);
  const isDark = Math.random() < 0.85;
  return {
    backgroundHue: baseHue,
    backgroundLightness: isDark ? randRange(8, 20) : randRange(85, 97),
    backgroundSaturation: randRange(15, 70),
    accentHue: baseHue,
    accentLightness: randRange(45, 65),
    accentSaturation: randRange(70, 100),
    dangerHue: jitterHue(20, 25),
    dangerLightness: randRange(50, 65),
    dangerSaturation: randRange(80, 100),
    successHue: jitterHue(150, 25),
    successLightness: randRange(55, 72),
    successSaturation: randRange(70, 100),
    favoriteHue: jitterHue(70, 20),
    favoriteLightness: randRange(65, 80),
    favoriteSaturation: randRange(70, 100),
  };
}

// -------------------------------------------------------------------------
// EXPORT/IMPORT PAR CODE — retour utilisateur : "exporter/partager un profil avec un code".
// -------------------------------------------------------------------------

/** Ordre FIXE des 15 champs numériques dans le code — TENIR SYNCHRONISÉ entre encode/decode (un
 * seul et même tableau utilisé par les deux, pour ne jamais désynchroniser silencieusement). */
const THEME_CODE_FIELDS: (keyof CustomThemeConfig)[] = [
  "backgroundHue",
  "backgroundLightness",
  "backgroundSaturation",
  "accentHue",
  "accentLightness",
  "accentSaturation",
  "dangerHue",
  "dangerLightness",
  "dangerSaturation",
  "successHue",
  "successLightness",
  "successSaturation",
  "favoriteHue",
  "favoriteLightness",
  "favoriteSaturation",
];

/** Encode un profil en un court code copiable-collable (retour utilisateur : "exporter/partager un
 * profil avec un code") — juste les 15 nombres qui décrivent la personnalisation (jamais le nom,
 * ni aucune donnée de compte), séparés par des virgules puis encodés en base64 pour être copiable
 * d'un bloc sans caractères spéciaux à échapper. PAS un format sécurisé/signé : une préférence
 * d'affichage n'a rien à protéger, voir le même raisonnement que la migration côté backend. */
export function encodeThemeCode(config: CustomThemeConfig): string {
  const sanitized = sanitizeCustomThemeConfig(config);
  return btoa(THEME_CODE_FIELDS.map((field) => sanitized[field]).join(","));
}

/** Décode un code produit par encodeThemeCode() — `null` si le code est invalide/corrompu (mauvais
 * nombre de valeurs, caractères non-base64, valeurs non numériques...), plutôt qu'un profil à
 * moitié rempli : c'est à l'appelant de décider quoi afficher dans ce cas (voir ThemeSettings.tsx).
 * `sanitizeCustomThemeConfig()` en sortie : les valeurs décodées passent par le même filet de
 * sécurité que n'importe quelle autre source (cache local, réponse serveur) — voir son commentaire. */
export function decodeThemeCode(code: string): CustomThemeConfig | null {
  try {
    const values = atob(code.trim()).split(",").map(Number);
    if (values.length !== THEME_CODE_FIELDS.length || values.some((v) => !Number.isFinite(v))) return null;
    const partial: Partial<CustomThemeConfig> = {};
    THEME_CODE_FIELDS.forEach((field, i) => {
      partial[field] = values[i];
    });
    return sanitizeCustomThemeConfig(partial);
  } catch {
    return null;
  }
}
