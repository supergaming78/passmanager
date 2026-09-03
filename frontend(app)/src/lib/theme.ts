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
//
// "custom" (retour utilisateur, 2026-09-03, affiné le même jour) : un thème de PLUS, à côté des
// presets ci-dessus, où l'utilisateur choisit lui-même CHAQUE couleur — teinte ET luminosité
// indépendantes, fond compris (pas juste "teinté ou pas") — via des curseurs, voir
// lib/customTheme.ts pour la mécanique (propriétés CSS posées en inline, PAS une classe statique
// comme les presets, puisque la teinte/luminosité choisies peuvent être n'importe quelle valeur).
// Contrairement aux presets (volontairement sombres uniquement), "custom" peut être clair OU
// sombre — mais ce n'est PAS une bascule séparée : ça se déduit simplement de la luminosité de
// fond choisie (voir customTheme.ts::applyBackground). PLUSIEURS profils nommés, synchronisés par
// COMPTE (voir api/client.ts, state/AuthContext.tsx::establishSession) — pas juste en local comme
// le reste de ce fichier.
import { applyCustomTheme, clearCustomTheme, sanitizeCustomThemeConfig, DEFAULT_CUSTOM_THEME, type CustomThemeConfig } from "./customTheme";
import type { ThemeProfileView } from "../api/types";

export type Theme = "dark" | "light" | "system" | "midnight" | "ocean" | "forest" | "sunset" | "rose" | "violet" | "amber" | "slate" | "custom";
export type { CustomThemeConfig };

const STORAGE_KEY = "passmanager.theme";
const VALID_THEMES: readonly Theme[] = ["dark", "light", "system", "midnight", "ocean", "forest", "sunset", "rose", "violet", "amber", "slate", "custom"];
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

/** Valide qu'une chaîne quelconque (localStorage potentiellement périmé, ou valeur venue du
 * serveur — voir state/AuthContext.tsx::establishSession) correspond bien à un thème connu de
 * CETTE version du client, avec repli sur "dark" sinon (nouveau défaut, voir le commentaire
 * d'en-tête). Exportée pour être réutilisée là où une valeur de thème arrive de l'EXTÉRIEUR de ce
 * module (le champ `preferred_theme` de GET /me, par exemple un thème plus récent que cette
 * version de l'app ne connaît pas encore, ou une valeur corrompue). */
export function toValidTheme(value: string | null | undefined): Theme {
  return (VALID_THEMES as readonly string[]).includes(value ?? "") ? (value as Theme) : "dark";
}

export function getTheme(): Theme {
  if (cachedTheme) return cachedTheme;
  cachedTheme = toValidTheme(localStorage.getItem(STORAGE_KEY));
  return cachedTheme;
}

// -------------------------------------------------------------------------
// SYNCHRONISATION DU CHOIX DE THÈME — INTERRUPTEUR PAR APPAREIL (retour utilisateur : "pouvoir
// choisir si l'app (par périphérique) et l'extension ont le thème synchronisé pour chaque
// périphérique sur lequel l'app est (même compte), chaque extension pouvoir choisir si le thème
// est synchronisé") — CET interrupteur est volontairement JAMAIS envoyé au serveur (contrairement
// à `preferred_theme` lui-même) : c'est une préférence propre à CET appareil précis, pas au
// compte — deux appareils du même compte peuvent faire des choix différents (l'un synchronisé,
// l'autre gardant son propre thème local indépendant), exactement comme les thèmes presets
// (avant ce champ) sont restés purement locaux à chaque appareil.
//
// Activé PAR DÉFAUT (retour utilisateur initial : "je veux que ce soit appliqué partout") — un
// appareil qui veut un thème indépendant doit le désactiver explicitement, plutôt que l'inverse.
const SYNC_ENABLED_STORAGE_KEY = "passmanager.themeSyncEnabled";
let cachedSyncEnabled: boolean | null = null;

export function isThemeSyncEnabled(): boolean {
  if (cachedSyncEnabled !== null) return cachedSyncEnabled;
  const stored = localStorage.getItem(SYNC_ENABLED_STORAGE_KEY);
  cachedSyncEnabled = stored === null ? true : stored === "true"; // absent -> défaut activé.
  return cachedSyncEnabled;
}

export function setThemeSyncEnabled(enabled: boolean): void {
  cachedSyncEnabled = enabled;
  try {
    localStorage.setItem(SYNC_ENABLED_STORAGE_KEY, String(enabled));
  } catch {
    // best-effort — au pire, retombe sur le défaut (activé) au prochain démarrage.
  }
}

function systemPrefersDark(): boolean {
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

// -------------------------------------------------------------------------
// THÈME "CUSTOM" — cache local anti-FOUC (voir public/theme-init.js, qui lit la même clé en JS
// brut avant même que React ne soit chargé) + copie de la config synchronisée par compte (voir
// state/AuthContext.tsx::establishSession, seul point qui appelle setCachedCustomTheme() avec une
// valeur venue du serveur). Écrire ici ne synchronise RIEN côté serveur — voir
// api/client.ts::updateThemeCustomization pour ça, appelé séparément par components/ThemeSettings.tsx.
const CUSTOM_THEME_STORAGE_KEY = "passmanager.customTheme";
let cachedCustomTheme: CustomThemeConfig | null = null;

/** Dernière config connue (cache local, potentiellement en retard d'une modification faite sur un
 * autre appareil tant que establishSession() n'a pas encore tourné) — jamais `null` : retombe sur
 * DEFAULT_CUSTOM_THEME (identique visuellement à "dark") si rien n'a jamais été enregistré. */
export function getCachedCustomTheme(): CustomThemeConfig {
  if (cachedCustomTheme) return cachedCustomTheme;
  try {
    const stored = localStorage.getItem(CUSTOM_THEME_STORAGE_KEY);
    // sanitizeCustomThemeConfig() : voir son commentaire dans customTheme.ts — une valeur laissée
    // par un schéma antérieur (plusieurs versions de ce champ testées le même jour) ne doit jamais
    // se propager en NaN à travers la génération de palette (retour utilisateur : "ça reste blank
    // partout, le profil ne s'applique pas").
    cachedCustomTheme = sanitizeCustomThemeConfig(stored ? (JSON.parse(stored) as Partial<CustomThemeConfig>) : null);
  } catch {
    cachedCustomTheme = DEFAULT_CUSTOM_THEME;
  }
  return cachedCustomTheme;
}

/** Met à jour le cache local ET réapplique immédiatement si "custom" est le thème actif — appelée
 * à la fois par ThemeSettings.tsx (modification locale, avant même la confirmation du serveur —
 * réactivité immédiate) et par establishSession() (valeur fraîchement récupérée du serveur, voir
 * plus haut). Ne touche PAS `passmanager.theme` (voir setTheme() ci-dessous) : choisir "custom"
 * reste un choix séparé du contenu de la personnalisation elle-même. */
export function setCachedCustomTheme(rawConfig: CustomThemeConfig): void {
  // sanitizeCustomThemeConfig() : garantit que ce qui est PERSISTÉ (pas seulement ce qui est
  // appliqué à l'écran, déjà protégé dans applyCustomTheme lui-même) reste toujours valide — sinon
  // une valeur invalide écrite ici serait relue telle quelle par theme-init.js (anti-FOUC, en JS
  // brut) au prochain démarrage, avant même que ce fichier n'ait la moindre chance de la nettoyer.
  const config = sanitizeCustomThemeConfig(rawConfig);
  cachedCustomTheme = config;
  try {
    localStorage.setItem(CUSTOM_THEME_STORAGE_KEY, JSON.stringify(config));
  } catch {
    // best-effort — au pire, pas de cache anti-FOUC au prochain démarrage, rien de grave.
  }
  if (getTheme() === "custom") applyTheme("custom");
}

// -------------------------------------------------------------------------
// OPTIMISATION BANDE PASSANTE (retour utilisateur : "optimise [...] la bande passante [...] du
// côté app") — establishSession() (voir AuthContext.tsx) récupère déjà la liste COMPLÈTE des
// profils à CHAQUE connexion pour trouver le profil actif. ThemeSettings.tsx, en ouvrant l'onglet
// "Personnalisé…" peu après, refaisait le MÊME appel GET /theme-profiles pour la même donnée —
// un aller-retour réseau entièrement redondant dans l'immense majorité des cas (il faudrait qu'un
// AUTRE appareil modifie les profils dans l'intervalle pour que ça change quoi que ce soit). Ce
// cache mémoire (PAS localStorage : cette liste n'a pas besoin de survivre à un redémarrage,
// contrairement à passmanager.customTheme ci-dessus — un survol vite obsolète serait pire qu'un
// simple re-fetch) permet à ThemeSettings.tsx de réutiliser directement ce qu'establishSession()
// vient de récupérer, sans reposer la question au serveur. Écrit UNIQUEMENT par establishSession ;
// ThemeSettings.tsx écrit aussi dedans après ses propres mutations (créer/modifier/supprimer un
// profil), pour que le cache ne redevienne pas immédiatement obsolète après la première utilisation.
let cachedThemeProfiles: ThemeProfileView[] | null = null;

export function getCachedThemeProfiles(): ThemeProfileView[] | null {
  return cachedThemeProfiles;
}

export function setCachedThemeProfiles(profiles: ThemeProfileView[]): void {
  cachedThemeProfiles = profiles;
}

/** À appeler à la DÉCONNEXION (voir state/AuthContext.tsx::forceLocalLogout) — CORRECTIF
 * SÉCURITÉ/VIE PRIVÉE (retour utilisateur, 2026-09-03 : "n'oublie pas la sécurité est le plus
 * important") : cachedCustomTheme et cachedThemeProfiles ci-dessus sont des variables de MODULE —
 * contrairement à un site web classique, cette app tourne en continu dans le MÊME processus (la
 * déconnexion ne recharge jamais la page). Sans ce nettoyage, un compte B qui se connecte APRÈS
 * qu'un compte A se soit déconnecté sur le MÊME appareil (poste partagé en famille, par ex.)
 * pouvait voir — même brièvement, ou DURABLEMENT si son propre compte n'a lui-même aucun profil
 * actif — le NOM et les couleurs des profils de personnalisation de A, tant que sa propre session
 * (establishSession) n'avait pas encore eu la main. Aucune donnée SENSIBLE en jeu à proprement
 * parler (une couleur n'a rien à protéger, voir la migration SQL de
 * theme_customization_profiles ; toute MUTATION reste de toute façon rejetée côté serveur, qui
 * revérifie systématiquement la propriété du profil par le token de l'appelant, jamais par ce
 * cache) — mais un compte ne doit jamais voir, même une simple couleur ou un nom de profil,
 * appartenant à un AUTRE compte que le sien. Réinitialise les deux caches en mémoire ET, pour le
 * thème "custom", son entrée localStorage anti-FOUC (sinon relue telle quelle, stale, au prochain
 * accès avant même que la nouvelle session n'ait pu la remplacer) — puis réapplique immédiatement
 * le thème actif, qui retombe alors sur DEFAULT_CUSTOM_THEME tant qu'aucune nouvelle session n'a
 * rechargé son propre profil actif. */
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
 * sa résolution du moment). Toutes les variantes de palette PRESET (midnight/ocean/forest/sunset/
 * rose/violet/amber/slate) sont volontairement des variantes SOMBRES uniquement (tout leur
 * intérêt — noir plus profond, accent différent — s'exprime sur fond sombre) : `theme !== "light"`
 * suffit à les forcer en sombre ci-dessous, quel que soit leur nombre. "custom" fait exception —
 * pour lui, `isDark` est DÉDUIT par applyCustomTheme() (voir son commentaire, basé sur la
 * luminosité de fond choisie), pas décidé ici. */
function applyTheme(theme: Theme): void {
  document.documentElement.classList.remove(...PALETTE_CLASSES);
  // CORRECTIF (retour utilisateur : "au milieu du curseur luminosité tout est déjà blanc, alors
  // que ça doit arriver au bout") : de nombreux composants utilisent `bg-white` en dur pour leur
  // fond en mode clair (pas `bg-neutral-50`) — sans dark: gardant .dark actif, ces éléments basculent
  // vers ce blanc figé dès qu'on quitte le régime sombre du custom, quelle que soit la luminosité de
  // fond réellement choisie. `.theme-custom` (voir App.css) donne une prise CSS pour faire suivre
  // `bg-white` au fond personnalisé quand ce thème est en régime clair (`:not(.dark)`), sans toucher
  // `text-white`/`border-white` (boutons), qui doivent rester du vrai blanc — voir App.css.
  document.documentElement.classList.toggle("theme-custom", theme === "custom");
  if (theme === "custom") {
    const isDark = applyCustomTheme(getCachedCustomTheme());
    document.documentElement.classList.toggle("dark", isDark);
    document.documentElement.style.colorScheme = isDark ? "dark" : "light";
    return;
  }

  const isDark = theme !== "light" && (theme !== "system" || systemPrefersDark());
  document.documentElement.classList.toggle("dark", isDark);
  // `color-scheme` (PAS juste la classe `dark` ci-dessus) : contrôle le rendu des éléments natifs
  // du navigateur/webview (barres de défilement, cases à cocher non stylées...) — sans ça, ils
  // resteraient clairs même avec `dark` forcé sur le reste de la page.
  document.documentElement.style.colorScheme = isDark ? "dark" : "light";

  // Retire toute personnalisation inline qui pourrait rester d'un précédent "custom" — sinon elle
  // masquerait la classe de palette preset ci-dessous (spécificité inline > classe, voir
  // customTheme.ts). Sans effet si "custom" n'avait jamais été utilisé (rien à retirer).
  clearCustomTheme();
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
