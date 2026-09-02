// PERSONNALISATION DE THÈME AVANCÉE — synchronisée par compte (retour utilisateur, 2026-09-03) :
// en plus des thèmes "presets" (voir theme.ts/App.css), un thème "custom" où l'utilisateur choisit
// LUI-MÊME chaque teinte (curseur de teinte 0-359°, PAS un vrai sélecteur RGB — voir la décision
// prise avec l'utilisateur) plutôt qu'un jeu de couleurs figé à l'avance. Contrairement aux presets
// (classes statiques dans App.css, un nombre fini de teintes possibles), une teinte choisie au
// curseur peut être N'IMPORTE quelle valeur entre 0 et 359 — impossible à précompiler en CSS statique
// à l'avance. On applique donc les variables directement en JS via `style.setProperty()` sur
// `<html>`, qui l'emporte en spécificité CSS sur n'importe quelle classe `.theme-X` (voir theme.ts).
//
// MÊME RECETTE que les thèmes presets (voir le long commentaire d'en-tête d'App.css) : la Lumino-
// sité (L) et la Chroma (C) de chaque palier Tailwind ne bougent JAMAIS — seule la Teinte (H) est
// remplacée par celle choisie par l'utilisateur, IDENTIQUE pour tous les paliers d'une même famille
// (c'est aussi ce que fait Tailwind par défaut à l'affichage : le "vrai" indigo a une teinte qui
// varie légèrement d'un palier à l'autre — 272° à 281° — les thèmes de ce projet l'aplatissent déjà
// tous à une seule valeur, donc rien de nouveau ici). Ça garantit que TOUS les contrastes déjà
// vérifiés (texte sur fond, anneaux de focus...) restent corrects sans re-tester quoi que ce soit :
// seule la teinte change, jamais ce qui fait la lisibilité.
//
// Valeurs L/C extraites du CSS Tailwind v4 réellement compilé (dist/assets/*.css), PAS
// approximées — même technique que pour les thèmes presets (voir App.css). Un seul palier
// manquant (ex: amber-200) n'a simplement jamais été utilisé nulle part dans l'app (vérifié par
// grep) — inutile de le fabriquer.

interface Step {
  l: string; // ex: "58.5%"
  c: string; // ex: ".233"
}

/** Accent (boutons, liens, focus) — palette `indigo`, remplace la teinte de TOUS les paliers déjà
 * utilisés par les thèmes presets ocean/forest/sunset/rose/violet/amber (voir App.css). */
const INDIGO_STEPS: Record<string, Step> = {
  "50": { l: "96.2%", c: ".018" },
  "100": { l: "93%", c: ".034" },
  "200": { l: "87%", c: ".065" },
  "300": { l: "78.5%", c: ".115" },
  "400": { l: "67.3%", c: ".182" },
  "500": { l: "58.5%", c: ".233" },
  "600": { l: "51.1%", c: ".262" },
  "700": { l: "45.7%", c: ".24" },
  "800": { l: "39.8%", c: ".195" },
  "900": { l: "35.9%", c: ".144" },
  "950": { l: "25.7%", c: ".09" },
};

/** Danger (Supprimer, erreurs) — palette `red`, uniquement les paliers réellement utilisés dans
 * l'app (vérifié par grep sur src/). */
const RED_STEPS: Record<string, Step> = {
  "50": { l: "97.1%", c: ".013" },
  "100": { l: "93.6%", c: ".032" },
  "200": { l: "88.5%", c: ".062" },
  "300": { l: "80.8%", c: ".114" },
  "400": { l: "70.4%", c: ".191" },
  "500": { l: "63.7%", c: ".237" },
  "600": { l: "57.7%", c: ".245" },
  "700": { l: "50.5%", c: ".213" },
  "800": { l: "44.4%", c: ".177" },
  "900": { l: "39.6%", c: ".141" },
  "950": { l: "25.8%", c: ".092" },
};

/** Favoris (★) — palette `amber`. */
const AMBER_STEPS: Record<string, Step> = {
  "50": { l: "98.7%", c: ".022" },
  "100": { l: "96.2%", c: ".059" },
  "300": { l: "87.9%", c: ".169" },
  "400": { l: "82.8%", c: ".189" },
  "500": { l: "76.9%", c: ".188" },
  "600": { l: "66.6%", c: ".179" },
  "700": { l: "55.5%", c: ".163" },
  "900": { l: "41.4%", c: ".112" },
  "950": { l: "27.9%", c: ".077" },
};

/** Succès (confirmations) — DEUX familles utilisées côte à côte dans l'app pour ce sens
 * (`emerald` la plupart du temps, `green` à deux endroits — AutoBackupSettings.tsx,
 * PasswordStrengthMeter.tsx) : les deux tournent ensemble sur la même teinte choisie. */
const EMERALD_STEPS: Record<string, Step> = {
  "100": { l: "95%", c: ".052" },
  "300": { l: "84.5%", c: ".143" },
  "400": { l: "76.5%", c: ".177" },
  "500": { l: "69.6%", c: ".17" },
  "600": { l: "59.6%", c: ".145" },
  "700": { l: "50.8%", c: ".118" },
  "950": { l: "26.2%", c: ".051" },
};
const GREEN_STEPS: Record<string, Step> = {
  "400": { l: "79.2%", c: ".209" },
  "600": { l: "62.7%", c: ".194" },
};

export interface CustomThemeConfig {
  mode: "dark" | "light";
  accentHue: number; // 0-359
  backgroundTinted: boolean;
  dangerHue: number;
  successHue: number;
  favoriteHue: number;
}

/** Repose exactement sur celle du serveur (voir models.rs::UpdateThemeCustomizationPayload côté
 * backend) — c'est aussi ce que renvoie `null` quand le compte n'a jamais rien configuré (voir
 * api/client.ts::getThemeCustomization). */
export const DEFAULT_CUSTOM_THEME: CustomThemeConfig = {
  mode: "dark",
  accentHue: 277, // teinte "native" de l'indigo Tailwind — un thème custom flambant neuf ressemble
  // donc au thème "dark" par défaut tant que l'utilisateur n'a rien bougé.
  backgroundTinted: false,
  dangerHue: 27,
  successHue: 163,
  favoriteHue: 75,
};

function applyFamily(el: HTMLElement, family: string, steps: Record<string, Step>, hue: number): void {
  for (const [step, { l, c }] of Object.entries(steps)) {
    el.style.setProperty(`--color-${family}-${step}`, `oklch(${l} ${c} ${hue})`);
  }
}

/** Fond légèrement teinté par l'accent (case à cocher "teinté") — MÊME recette que les thèmes
 * presets ocean/forest/... en mode sombre (voir App.css, section "fond teinté") : L et C décalés
 * (pas juste C) par rapport au neutral natif, valeur tranchée à l'œil sur captures d'écran lors de
 * l'ajout des thèmes presets, reprise ici telle quelle. En mode clair, pas de recette déjà vérifiée
 * du même genre à reprendre : on se contente d'une chroma faible SANS toucher la luminosité
 * (paliers 50/100/200 gardent leur L Tailwind natif) — un vrai "tint" sans en changer la clarté.
 */
function applyBackgroundTint(el: HTMLElement, mode: "dark" | "light", hue: number): void {
  if (mode === "dark") {
    el.style.setProperty("--color-neutral-950", `oklch(12% .006 ${hue})`);
    el.style.setProperty("--color-neutral-900", `oklch(19% .008 ${hue})`);
    el.style.setProperty("--color-neutral-800", `oklch(29% .01 ${hue})`);
  } else {
    el.style.setProperty("--color-neutral-50", `oklch(98.5% .008 ${hue})`);
    el.style.setProperty("--color-neutral-100", `oklch(97% .01 ${hue})`);
    el.style.setProperty("--color-neutral-200", `oklch(92.2% .015 ${hue})`);
  }
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
 * theme.ts::applyTheme). Écrase toute classe de palette preset éventuellement encore présente :
 * inutile ici, les propriétés inline ci-dessous l'emportent de toute façon en spécificité CSS, mais
 * clearCustomTheme() les retire proprement en sens inverse quand on QUITTE "custom" pour un preset. */
export function applyCustomTheme(config: CustomThemeConfig): void {
  const el = document.documentElement;
  applyFamily(el, "indigo", INDIGO_STEPS, config.accentHue);
  applyFamily(el, "red", RED_STEPS, config.dangerHue);
  applyFamily(el, "amber", AMBER_STEPS, config.favoriteHue);
  applyFamily(el, "emerald", EMERALD_STEPS, config.successHue);
  applyFamily(el, "green", GREEN_STEPS, config.successHue);

  // Retire l'éventuel tint de l'AUTRE mode (ex: on vient de basculer clair -> sombre) avant
  // d'appliquer celui du mode courant — sinon les deux jeux de propriétés inline coexisteraient
  // sans jamais se nettoyer (l'un des deux jeux ne serait de toute façon pas utilisé par les
  // utilitaires Tailwind du mode courant, mais autant ne rien laisser traîner en mémoire du DOM).
  for (const prop of [...TINT_PROPERTIES_DARK, ...TINT_PROPERTIES_LIGHT]) el.style.removeProperty(prop);
  if (config.backgroundTinted) applyBackgroundTint(el, config.mode, config.accentHue);
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
