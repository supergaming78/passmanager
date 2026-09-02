// Thème visuel de l'app — CORRECTIF (retour utilisateur, 2026-09-02) : jusqu'ici, aucun réglage
// n'existait, le thème suivait purement `prefers-color-scheme` (préférence système), sans aucun
// moyen de le forcer. Résultat signalé : sombre sur PC (Windows configuré en sombre) mais blanc
// sur mobile (Android/iOS souvent configurés en clair par défaut) — pas un bug, juste l'absence de
// contrôle. `getTheme()` défaut maintenant sur "dark" explicitement.
//
// ÉTENDU (retour utilisateur, 2026-09-02, suite) : "plusieurs thèmes au choix" — variantes sombres
// supplémentaires ("midnight"/"ocean" au départ, puis "forest"/"sunset"/"rose"/"violet"/"amber"/
// "slate" ajoutés ensuite, voir App.css), sans toucher un seul composant. Le truc : Tailwind v4
// génère ses utilitaires (`bg-neutral-950`, `text-indigo-600`...) sous forme de
// `background-color: var(--color-neutral-950)`, PAS une valeur codée en dur — voir App.css, qui
// redéfinit ces variables sous `.theme-X`. Toute la palette `neutral`/`indigo` déjà utilisée
// PARTOUT dans l'app suit donc automatiquement, sans rien modifier ailleurs — zéro risque de
// régression visuelle sur un écran qu'on aurait oublié de mettre à jour.
//
// Tailwind v4 : le variant `dark:` suit par défaut `prefers-color-scheme` seul (stratégie
// "media") — voir `@custom-variant dark (&:where(.dark, .dark *));` dans App.css, qui bascule sur
// une stratégie "class" (présence de `.dark` sur `<html>`, gérée ici) pour pouvoir le forcer.
export type Theme = "dark" | "light" | "system" | "midnight" | "ocean" | "forest" | "sunset" | "rose" | "violet" | "amber" | "slate";

const STORAGE_KEY = "passmanager.theme";
const VALID_THEMES: readonly Theme[] = ["dark", "light", "system", "midnight", "ocean", "forest", "sunset", "rose", "violet", "amber", "slate"];
const PALETTE_CLASSES = ["theme-midnight", "theme-ocean", "theme-forest", "theme-sunset", "theme-rose", "theme-violet", "theme-amber", "theme-slate"] as const;

/** Classe de palette supplémentaire (voir App.css) pour les thèmes qui vont plus loin qu'un
 * simple `dark`/pas `dark` — "midnight" (noir plus profond, pensé écrans OLED), "slate" (gris
 * ardoise plus doux, teinte froide plutôt que noir pur) recolorent le FOND ; "ocean" (bleu),
 * "forest" (vert), "sunset" (orange), "rose" (rose), "violet" recolorent l'ACCENT (même
 * contraste que l'indigo par défaut, seule la teinte tourne — voir le commentaire détaillé de
 * chaque bloc dans App.css) ; "amber" fait les deux à la fois (accent doré ET fond légèrement
 * réchauffé). `dark`/`light`/`system` n'en ont pas besoin : ils utilisent déjà la palette
 * Tailwind par défaut telle quelle. */
function paletteClassFor(theme: Theme): string | null {
  if (theme === "midnight" || theme === "ocean" || theme === "forest" || theme === "sunset" || theme === "rose" || theme === "violet" || theme === "amber" || theme === "slate") {
    return `theme-${theme}`;
  }
  return null;
}

// CORRECTIF PERF (retour utilisateur, 2026-09-02) : `getTheme()` est appelée plusieurs fois au
// démarrage (theme-init.js avant même React, puis initTheme(), puis l'état initial de
// ThemeSettings.tsx) — un petit cache mémoire évite de retaper `localStorage` (petite E/S
// synchrone, négligeable individuellement mais autant l'éviter quand c'est gratuit) à chaque
// appel. Aucune implication sécurité : c'est une préférence d'affichage, pas une donnée sensible.
let cachedTheme: Theme | null = null;

export function getTheme(): Theme {
  if (cachedTheme) return cachedTheme;
  const stored = localStorage.getItem(STORAGE_KEY);
  cachedTheme = (VALID_THEMES as readonly string[]).includes(stored ?? "") ? (stored as Theme) : "dark"; // nouveau défaut — voir le commentaire d'en-tête.
  return cachedTheme;
}

function systemPrefersDark(): boolean {
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

/** Applique un thème à la page (classe `dark` + classe de palette éventuelle sur `<html>`) sans le
 * persister — utilisé par setTheme() ci-dessous ET par le listener système (voir initTheme()), qui
 * ne doit jamais réécrire localStorage (le choix "system" doit rester "system", pas se figer sur
 * sa résolution du moment). Toutes les variantes de palette (midnight/ocean/forest/sunset/rose/
 * violet/amber/slate) sont volontairement des variantes SOMBRES uniquement (tout leur intérêt —
 * noir plus profond, accent différent — s'exprime sur fond sombre) : `theme !== "light"` suffit à
 * les forcer en sombre ci-dessous, quel que soit leur nombre. */
function applyTheme(theme: Theme): void {
  const isDark = theme !== "light" && (theme !== "system" || systemPrefersDark());
  document.documentElement.classList.toggle("dark", isDark);
  // `color-scheme` (PAS juste la classe `dark` ci-dessus) : contrôle le rendu des éléments natifs
  // du navigateur/webview (barres de défilement, cases à cocher non stylées...) — sans ça, ils
  // resteraient clairs même avec `dark` forcé sur le reste de la page.
  document.documentElement.style.colorScheme = isDark ? "dark" : "light";

  document.documentElement.classList.remove(...PALETTE_CLASSES);
  const paletteClass = paletteClassFor(theme);
  if (paletteClass) document.documentElement.classList.add(paletteClass);
}

/** Change le thème ET le persiste (voir components/ThemeSettings.tsx). */
export function setTheme(theme: Theme): void {
  cachedTheme = theme;
  localStorage.setItem(STORAGE_KEY, theme);
  applyTheme(theme);
}

let systemListenerAttached = false;

/** À appeler une seule fois, le plus tôt possible (voir index.html pour la toute première
 * application anti-flash, celle-ci vient en complément) : applique le thème actuel ET, si c'est
 * "system", se met à jour en direct si l'utilisateur change le thème de son OS sans rouvrir l'app. */
export function initTheme(): void {
  applyTheme(getTheme());
  if (!systemListenerAttached) {
    systemListenerAttached = true;
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
      if (getTheme() === "system") applyTheme("system");
    });
  }
}
