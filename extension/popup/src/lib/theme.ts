// Thème visuel de la popup — CORRECTIF (retour utilisateur, 2026-09-02) : même correctif que
// frontend(app)/src/lib/theme.ts (raisonnement identique, voir son commentaire d'en-tête) —
// jusqu'ici le thème suivait purement `prefers-color-scheme`, sans aucun moyen de le forcer.
// `getTheme()` défaut maintenant sur "dark" explicitement.
//
// ÉTENDU (retour utilisateur, 2026-09-02, suite ; nouveaux thèmes ajoutés le 2026-09-03) —
// "plusieurs thèmes au choix" (puis "plein de thèmes différents") — voir App.css, qui redéfinit
// les variables de couleur Tailwind (`--color-neutral-*`/`--color-indigo-*`) que les utilitaires
// déjà utilisés partout dans la popup (`bg-neutral-950`, `text-indigo-600`...) lisent au lieu
// d'une valeur codée en dur. Toute la palette suit donc automatiquement.
//
// Tailwind v4 : le variant `dark:` suit par défaut `prefers-color-scheme` seul (stratégie
// "media") — voir `@custom-variant dark (&:where(.dark, .dark *));` dans App.css, qui bascule sur
// une stratégie "class" (présence de `.dark` sur <html>, gérée ici) pour pouvoir le forcer.
//
// "custom" (retour utilisateur, 2026-09-03) : voir le commentaire équivalent dans
// frontend(app)/src/lib/theme.ts — même mécanique (lib/customTheme.ts), synchronisée par COMPTE
// (contrairement aux presets ci-dessus, purement locaux) — voir App.tsx pour le point de
// récupération (session active/juste après connexion, PAS un "établissement de session" dédié
// comme côté desktop : la popup n'en a pas, voir lib/session.ts).
import { applyCustomTheme, clearCustomTheme, sanitizeCustomThemeConfig, DEFAULT_CUSTOM_THEME, type CustomThemeConfig } from "./customTheme";
import type { ThemeProfileView } from "../api/types";

export type Theme = "dark" | "light" | "system" | "midnight" | "ocean" | "forest" | "sunset" | "rose" | "violet" | "amber" | "slate" | "custom";
export type { CustomThemeConfig };

const STORAGE_KEY = "passmanager.theme";
const VALID_THEMES: readonly Theme[] = ["dark", "light", "system", "midnight", "ocean", "forest", "sunset", "rose", "violet", "amber", "slate", "custom"];
const PALETTE_CLASSES = ["theme-midnight", "theme-ocean", "theme-forest", "theme-sunset", "theme-rose", "theme-violet", "theme-amber", "theme-slate"] as const;

/** Classe de palette supplémentaire (voir App.css) pour les thèmes qui vont plus loin qu'un
 * simple `dark`/pas `dark` — voir le même commentaire côté app desktop (frontend(app)/src/lib/theme.ts). */
function paletteClassFor(theme: Theme): string | null {
  if (theme === "midnight" || theme === "ocean" || theme === "forest" || theme === "sunset" || theme === "rose" || theme === "violet" || theme === "amber" || theme === "slate") {
    return `theme-${theme}`;
  }
  return null;
}

// CORRECTIF PERF (retour utilisateur, 2026-09-02) : `getTheme()` est appelée plusieurs fois au
// démarrage (theme-init.js avant même React, puis initTheme(), puis l'état initial de
// SettingsView.tsx) — un petit cache mémoire évite de retaper `localStorage` à chaque appel.
// Aucune implication sécurité : c'est une préférence d'affichage, pas une donnée sensible.
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

// -------------------------------------------------------------------------
// THÈME "CUSTOM" — cache local anti-FOUC, voir le commentaire équivalent côté desktop
// (frontend(app)/src/lib/theme.ts) pour le détail du raisonnement, identique ici.
const CUSTOM_THEME_STORAGE_KEY = "passmanager.customTheme";
let cachedCustomTheme: CustomThemeConfig | null = null;

export function getCachedCustomTheme(): CustomThemeConfig {
  if (cachedCustomTheme) return cachedCustomTheme;
  try {
    const stored = localStorage.getItem(CUSTOM_THEME_STORAGE_KEY);
    // sanitizeCustomThemeConfig() : voir son commentaire dans customTheme.ts — une valeur laissée
    // par un schéma antérieur ne doit jamais se propager en NaN (retour utilisateur : "ça reste
    // blank partout, le profil ne s'applique pas").
    cachedCustomTheme = sanitizeCustomThemeConfig(stored ? (JSON.parse(stored) as Partial<CustomThemeConfig>) : null);
  } catch {
    cachedCustomTheme = DEFAULT_CUSTOM_THEME;
  }
  return cachedCustomTheme;
}

export function setCachedCustomTheme(rawConfig: CustomThemeConfig): void {
  const config = sanitizeCustomThemeConfig(rawConfig);
  cachedCustomTheme = config;
  try {
    localStorage.setItem(CUSTOM_THEME_STORAGE_KEY, JSON.stringify(config));
  } catch {
    // best-effort.
  }
  if (getTheme() === "custom") applyTheme("custom");
}

// OPTIMISATION BANDE PASSANTE (retour utilisateur : "optimise [...] la bande passante") — voir le
// commentaire équivalent côté desktop (frontend(app)/src/lib/theme.ts) pour le raisonnement
// complet. Ici, réutilisé entre App.tsx::syncThemeCustomization (à l'ouverture de la popup) et
// SettingsView.tsx (ouverture de l'onglet "Personnalisé…") — utile SEULEMENT si les deux se
// produisent dans la MÊME ouverture de popup (le module JS entier redémarre à chaque réouverture,
// contrairement à l'app desktop où la session dure plus longtemps) : reste un cas fréquent (ouvrir
// la popup puis aller direct dans Réglages), pas la peine de reposer la question au serveur.
let cachedThemeProfiles: ThemeProfileView[] | null = null;

export function getCachedThemeProfiles(): ThemeProfileView[] | null {
  return cachedThemeProfiles;
}

export function setCachedThemeProfiles(profiles: ThemeProfileView[]): void {
  cachedThemeProfiles = profiles;
}

/** À appeler à la DÉCONNEXION (voir lib/session.ts::clearStored, appelée par logout() ET par
 * authorizedRequest() quand le rafraîchissement échoue) — voir ThemeSettings.tsx côté desktop pour
 * le raisonnement complet (identique ici) : CORRECTIF SÉCURITÉ/VIE PRIVÉE (retour utilisateur,
 * 2026-09-03 : "n'oublie pas la sécurité est le plus important") — cachedCustomTheme et
 * cachedThemeProfiles sont des variables de MODULE, qui ne redémarrent PAS à une simple
 * déconnexion (seulement à la fermeture complète de la popup) : sans ce nettoyage, un compte B qui
 * se connecte dans la MÊME ouverture de popup juste après la déconnexion du compte A pouvait voir
 * les couleurs/noms de profils de personnalisation de A. Aucune donnée sensible en jeu à
 * proprement parler (le serveur revérifie de toute façon la propriété de chaque profil par le
 * token de l'appelant, jamais par ce cache), mais un compte ne doit jamais voir ne serait-ce
 * qu'une couleur appartenant à un autre compte. */
export function clearAccountScopedThemeCache(): void {
  cachedCustomTheme = null;
  cachedThemeProfiles = null;
  try {
    localStorage.removeItem(CUSTOM_THEME_STORAGE_KEY);
  } catch {
    // best-effort — au pire la prochaine lecture tombe sur un JSON déjà géré par
    // sanitizeCustomThemeConfig (voir getCachedCustomTheme), jamais une fuite vers le compte B.
  }
  applyTheme(getTheme());
}

/** Applique un thème à la page (classe `dark` + classe de palette éventuelle sur `<html>`) sans le
 * persister — utilisé par setTheme() ci-dessous ET par le listener système (voir initTheme()), qui
 * ne doit jamais réécrire localStorage (le choix "system" doit rester "system", pas se figer sur
 * sa résolution du moment). Toutes les variantes de palette PRESET sont volontairement des
 * variantes SOMBRES uniquement (tout leur intérêt — noir plus profond, accent différent —
 * s'exprime sur fond sombre) : `theme !== "light"` suffit à les forcer en sombre ci-dessous.
 * "custom" fait exception — `isDark` y est DÉDUIT par applyCustomTheme() (voir son commentaire,
 * basé sur la luminosité de fond choisie), pas décidé ici. */
function applyTheme(theme: Theme): void {
  document.documentElement.classList.remove(...PALETTE_CLASSES);
  // Voir le commentaire équivalent côté desktop (frontend(app)/src/lib/theme.ts) pour le
  // raisonnement — App.css n'a rien à corriger avec pour la popup (voir theme-init.js), mais on
  // pose quand même la classe pour cohérence/simplicité de duplication entre les deux fichiers.
  document.documentElement.classList.toggle("theme-custom", theme === "custom");
  if (theme === "custom") {
    const isDark = applyCustomTheme(getCachedCustomTheme());
    document.documentElement.classList.toggle("dark", isDark);
    document.documentElement.style.colorScheme = isDark ? "dark" : "light";
    return;
  }

  const isDark = theme !== "light" && (theme !== "system" || systemPrefersDark());
  document.documentElement.classList.toggle("dark", isDark);
  document.documentElement.style.colorScheme = isDark ? "dark" : "light";

  clearCustomTheme();
  const paletteClass = paletteClassFor(theme);
  if (paletteClass) document.documentElement.classList.add(paletteClass);
}

/** Change le thème ET le persiste (voir components/SettingsView.tsx). */
export function setTheme(theme: Theme): void {
  cachedTheme = theme;
  localStorage.setItem(STORAGE_KEY, theme);
  applyTheme(theme);
}

let systemListenerAttached = false;

/** À appeler une seule fois, le plus tôt possible (voir index.html pour la toute première
 * application anti-flash, celle-ci vient en complément) : applique le thème actuel ET, si c'est
 * "system", se met à jour en direct si l'utilisateur change le thème de son OS sans rouvrir la
 * popup. */
export function initTheme(): void {
  applyTheme(getTheme());
  if (!systemListenerAttached) {
    systemListenerAttached = true;
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
      if (getTheme() === "system") applyTheme("system");
    });
  }
}
