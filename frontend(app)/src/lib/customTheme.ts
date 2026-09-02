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

export interface CustomThemeConfig {
  backgroundHue: number; // 0-359 — IGNORÉ si backgroundNeutral est vrai (voir applyBackground).
  backgroundLightness: number; // 0-100 — luminosité du fond PRINCIPAL (page) ; < 50 = régime
  // sombre (fond très luminosité basse, texte clair), >= 50 = régime clair — voir applyBackground.
  /** Fond parfaitement gris (chroma nulle), retour utilisateur : "je ne veux pas que le fond soit
   * soit clair soit sombre je veux aussi pouvoir choisir la couleur pour le fond" avait fait
   * disparaître l'option d'un fond NEUTRE (sans aucune teinte) qui existait dans la toute première
   * version de cette fonctionnalité (case "teinté ou pas") — restaurée ici comme un choix
   * indépendant plutôt qu'une bascule liée au clair/sombre. */
  backgroundNeutral: boolean;
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
 * neutral-950 (14.5%), IDENTIQUE au thème "Sombre". */
export const DEFAULT_CUSTOM_THEME: CustomThemeConfig = {
  backgroundHue: 0,
  backgroundLightness: 14.5,
  backgroundNeutral: true,
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

function applyFamily(el: HTMLElement, family: string, steps: Record<string, Step>, hue: number, lightness: number, anchorNativeL: number): void {
  const offset = lightness - anchorNativeL;
  for (const [step, { l, c }] of Object.entries(steps)) {
    el.style.setProperty(`--color-${family}-${step}`, `oklch(${clampL(l + offset).toFixed(1)}% ${c} ${hue})`);
  }
}

/** Fond ENTIÈREMENT personnalisé (teinte + luminosité, retour utilisateur : "je ne veux pas que le
 * fond soit soit clair soit sombre je veux aussi pouvoir choisir la couleur pour le fond") — PAS
 * une bascule binaire : le régime clair/sombre se déduit simplement d'où se trouve la luminosité
 * choisie (< 50% = plutôt sombre, le fond `page` prend directement cette valeur et les 2 fonds
 * "secondaires" (cartes/bordures) sont dérivés avec les MÊMES écarts que la palette Tailwind native
 * neutral-950/900/800 ; >= 50% = plutôt clair, dérivés comme neutral-50/100/200).
 *
 * `neutral` (retour utilisateur, 2026-09-03 : "tu as enlevé une fonctionnalité, le fondu" — un fond
 * parfaitement gris, sans AUCUNE teinte, existait dans la toute première version de cette
 * fonctionnalité et avait disparu) : force la chroma à 0 (donc `hue` sans aucun effet visuel) ;
 * sinon, chroma faible et fixe (indépendante du choix utilisateur, pour ne jamais nuire au
 * contraste du texte par-dessus), seule la teinte suit le choix. */
function applyBackground(el: HTMLElement, hue: number, lightness: number, neutral: boolean): boolean {
  const isDark = lightness < 50;
  const [c1, c2, c3] = neutral ? ["0", "0", "0"] : [".006", ".008", ".01"];
  const [lc1, lc2, lc3] = neutral ? ["0", "0", "0"] : [".008", ".01", ".015"];
  if (isDark) {
    // Écarts natifs Tailwind neutral 950->900->800 : 14.5 -> 20.5 (+6) -> 26.9 (+12.4).
    el.style.setProperty("--color-neutral-950", `oklch(${clampL(lightness).toFixed(1)}% ${c1} ${hue})`);
    el.style.setProperty("--color-neutral-900", `oklch(${clampL(lightness + 6).toFixed(1)}% ${c2} ${hue})`);
    el.style.setProperty("--color-neutral-800", `oklch(${clampL(lightness + 12.4).toFixed(1)}% ${c3} ${hue})`);
  } else {
    // Écarts natifs Tailwind neutral 50->100->200 : 98.5 -> 97 (-1.5) -> 92.2 (-6.3).
    el.style.setProperty("--color-neutral-50", `oklch(${clampL(lightness).toFixed(1)}% ${lc1} ${hue})`);
    el.style.setProperty("--color-neutral-100", `oklch(${clampL(lightness - 1.5).toFixed(1)}% ${lc2} ${hue})`);
    el.style.setProperty("--color-neutral-200", `oklch(${clampL(lightness - 6.3).toFixed(1)}% ${lc3} ${hue})`);
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
 * elle ne touche qu'aux propriétés de couleur elles-mêmes. */
export function applyCustomTheme(config: CustomThemeConfig): boolean {
  const el = document.documentElement;
  applyFamily(el, "indigo", INDIGO_STEPS, config.accentHue, config.accentLightness, INDIGO_ANCHOR_L);
  applyFamily(el, "red", RED_STEPS, config.dangerHue, config.dangerLightness, RED_ANCHOR_L);
  applyFamily(el, "amber", AMBER_STEPS, config.favoriteHue, config.favoriteLightness, AMBER_ANCHOR_L);
  applyFamily(el, "emerald", EMERALD_STEPS, config.successHue, config.successLightness, EMERALD_ANCHOR_L);
  applyFamily(el, "green", GREEN_STEPS, config.successHue, config.successLightness, EMERALD_ANCHOR_L);

  // Retire l'éventuel jeu de propriétés de fond de l'AUTRE régime (ex: on vient de passer d'un
  // fond sombre à un fond clair) avant d'appliquer celui du régime courant.
  for (const prop of [...TINT_PROPERTIES_DARK, ...TINT_PROPERTIES_LIGHT]) el.style.removeProperty(prop);
  return applyBackground(el, config.backgroundHue, config.backgroundLightness, config.backgroundNeutral);
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
