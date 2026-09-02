// Thème visuel de la popup — CORRECTIF (retour utilisateur, 2026-09-02) : même correctif que
// frontend(app)/src/lib/theme.ts (raisonnement identique, voir son commentaire d'en-tête) —
// jusqu'ici le thème suivait purement `prefers-color-scheme`, sans aucun moyen de le forcer.
// `getTheme()` défaut maintenant sur "dark" explicitement.
//
// Tailwind v4 : le variant `dark:` suit par défaut `prefers-color-scheme` seul (stratégie
// "media") — voir `@custom-variant dark (&:where(.dark, .dark *));` dans App.css, qui bascule sur
// une stratégie "class" (présence de `.dark` sur <html>, gérée ici) pour pouvoir le forcer.
export type Theme = "dark" | "light" | "system";

const STORAGE_KEY = "passmanager.theme";

export function getTheme(): Theme {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored === "dark" || stored === "light" || stored === "system") return stored;
  return "dark"; // nouveau défaut — voir le commentaire d'en-tête.
}

function systemPrefersDark(): boolean {
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

/** Applique un thème à la page (classe `dark` sur `<html>`) sans le persister — utilisé par
 * setTheme() ci-dessous ET par le listener système (voir initTheme()), qui ne doit jamais
 * réécrire localStorage (le choix "system" doit rester "system", pas se figer sur sa résolution
 * du moment). */
function applyTheme(theme: Theme): void {
  const isDark = theme === "dark" || (theme === "system" && systemPrefersDark());
  document.documentElement.classList.toggle("dark", isDark);
  document.documentElement.style.colorScheme = isDark ? "dark" : "light";
}

/** Change le thème ET le persiste (voir components/SettingsView.tsx). */
export function setTheme(theme: Theme): void {
  localStorage.setItem(STORAGE_KEY, theme);
  applyTheme(theme);
}

let systemListenerAttached = false;

/** À appeler une seule fois, le plus tôt possible (voir index.html pour la toute première
 * application anti-flash, celle-ci vient en complément) : applique le thème actuel ET, si c'est
 * "system", se met à jour en direct si l'utilisateur change le thème de son OS sans rouvrir la
 * popup (rare pour une popup — elle se ferme/rouvre souvent — mais coûte rien à couvrir). */
export function initTheme(): void {
  applyTheme(getTheme());
  if (!systemListenerAttached) {
    systemListenerAttached = true;
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
      if (getTheme() === "system") applyTheme("system");
    });
  }
}
