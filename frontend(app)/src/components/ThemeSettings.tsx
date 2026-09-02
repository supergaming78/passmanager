import { useState } from "react";
import { getTheme, setTheme, type Theme } from "../lib/theme";

const THEME_OPTIONS: { value: Theme; label: string }[] = [
  { value: "dark", label: "Sombre" },
  { value: "light", label: "Clair" },
  { value: "system", label: "Suivre l'appareil" },
  { value: "midnight", label: "Minuit (noir OLED)" },
  { value: "slate", label: "Ardoise (gris froid)" },
  { value: "ocean", label: "Océan (accent bleu)" },
  { value: "forest", label: "Forêt (accent vert)" },
  { value: "sunset", label: "Coucher de soleil (accent orange)" },
  { value: "rose", label: "Rose (accent rose)" },
  { value: "violet", label: "Violet (accent pourpre)" },
  { value: "amber", label: "Ambre (accent doré, fond réchauffé)" },
];

/** Réglage du thème visuel — CORRECTIF (retour utilisateur, 2026-09-02) : jusqu'ici, aucun réglage
 * n'existait, le thème suivait purement la préférence système (sombre sur un PC configuré en
 * sombre, mais clair sur un mobile configuré en clair par défaut — pas un bug, juste l'absence de
 * contrôle). Purement local à cet appareil (localStorage, voir lib/theme.ts) — pas partagé entre
 * appareils, comme les autres réglages de cette page (AutoLockSettings...). */
export default function ThemeSettings() {
  const [theme, setThemeState] = useState<Theme>(() => getTheme());

  function handleChange(value: Theme) {
    setThemeState(value);
    setTheme(value);
  }

  return (
    <div>
      <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">Thème</label>
      <select
        value={theme}
        onChange={(e) => handleChange(e.target.value as Theme)}
        className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
      >
        {THEME_OPTIONS.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
      <p className="mt-1 text-xs text-neutral-500">
        "Suivre l'appareil" utilise le thème clair/sombre configuré dans les réglages de ton
        système d'exploitation. Toutes les autres variantes (Minuit, Ardoise, Océan, Forêt,
        Coucher de soleil, Rose, Violet, Ambre) sont des versions sombres — seuls le fond et/ou
        la couleur d'accent changent.
      </p>
    </div>
  );
}
