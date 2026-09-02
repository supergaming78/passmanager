import { useState } from "react";
import { getTheme, setTheme, getCachedCustomTheme, setCachedCustomTheme, type Theme, type CustomThemeConfig } from "../lib/theme";
import { useAuth } from "../state/AuthContext";
import * as api from "../api/client";

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
  { value: "custom", label: "Personnalisé…" },
];

/** Aperçu de teinte — palier "500" d'indigo (voir lib/customTheme.ts), assez saturé pour bien
 * distinguer les teintes au survol du curseur sans avoir à dupliquer toute une table L/C ici. */
function swatchStyle(hue: number): React.CSSProperties {
  return { backgroundColor: `oklch(58.5% .233 ${hue})` };
}

function HueSlider({ label, value, onChange }: { label: string; value: number; onChange: (hue: number) => void }) {
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-xs text-neutral-600 dark:text-neutral-400">
        <span>{label}</span>
        <span
          className="h-4 w-4 rounded-full border border-neutral-300 dark:border-neutral-700"
          style={swatchStyle(value)}
          aria-hidden="true"
        />
      </div>
      <input
        type="range"
        min={0}
        max={359}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full accent-indigo-600"
        aria-label={label}
      />
    </div>
  );
}

/** Réglage du thème visuel — CORRECTIF (retour utilisateur, 2026-09-02) : jusqu'ici, aucun réglage
 * n'existait, le thème suivait purement la préférence système (sombre sur un PC configuré en
 * sombre, mais clair sur un mobile configuré en clair par défaut — pas un bug, juste l'absence de
 * contrôle). Les thèmes "presets" (Sombre/Minuit/Océan/...) restent purement locaux à cet appareil
 * (localStorage, voir lib/theme.ts) — pas partagés entre appareils, comme les autres réglages de
 * cette page (AutoLockSettings...).
 *
 * "Personnalisé…" (retour utilisateur, 2026-09-03) fait EXCEPTION à ça : SEUL réglage de cette
 * page synchronisé par compte (voir api/client.ts::getThemeCustomization/updateThemeCustomization
 * et state/AuthContext.tsx::establishSession) — le choisir sur un appareil l'active sur tous les
 * autres au prochain démarrage de chacun. */
export default function ThemeSettings() {
  const { authorizedRequest } = useAuth();
  const [theme, setThemeState] = useState<Theme>(() => getTheme());
  const [custom, setCustom] = useState<CustomThemeConfig>(() => getCachedCustomTheme());
  const [saveState, setSaveState] = useState<"idle" | "saving" | "saved" | "error">("idle");

  async function handleThemeChange(value: Theme) {
    setThemeState(value);
    setTheme(value);
    if (value !== "custom") {
      // On quitte "custom" pour un preset classique : supprime la personnalisation côté serveur
      // (best-effort) — sinon elle reviendrait forcer "custom" sur CET appareil (et tous les
      // autres) au prochain lancement, voir establishSession(). Aucun effet si le compte n'avait
      // de toute façon jamais rien enregistré (DELETE idempotent, voir handlers backend).
      try {
        await authorizedRequest((token) => api.deleteThemeCustomization(token));
      } catch {
        // best-effort — le pire cas est de revoir "custom" réapparaître au prochain démarrage,
        // rien de destructif ; l'utilisateur peut relancer l'action.
      }
    }
  }

  function updateCustom(patch: Partial<CustomThemeConfig>) {
    const next = { ...custom, ...patch };
    setCustom(next);
    // Aperçu immédiat, purement local — la synchro serveur se fait explicitement via le bouton
    // "Enregistrer" ci-dessous (évite un appel réseau à chaque tick du curseur pendant le glissé).
    setCachedCustomTheme(next);
    setSaveState("idle");
  }

  async function handleSave() {
    setSaveState("saving");
    try {
      await authorizedRequest((token) =>
        api.updateThemeCustomization(token, {
          mode: custom.mode,
          accent_hue: custom.accentHue,
          background_tinted: custom.backgroundTinted,
          danger_hue: custom.dangerHue,
          success_hue: custom.successHue,
          favorite_hue: custom.favoriteHue,
        }),
      );
      setSaveState("saved");
    } catch {
      setSaveState("error");
    }
  }

  return (
    <div>
      <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">Thème</label>
      <select
        value={theme}
        onChange={(e) => void handleThemeChange(e.target.value as Theme)}
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
        système d'exploitation. Minuit, Ardoise, Océan, Forêt, Coucher de soleil, Rose, Violet et
        Ambre sont des versions sombres toutes prêtes — seuls le fond et/ou la couleur d'accent
        changent. "Personnalisé…" te laisse choisir chaque teinte toi-même, et se synchronise sur
        tous tes appareils connectés à ce compte.
      </p>

      {theme === "custom" && (
        <div className="mt-4 space-y-4 rounded-lg border border-neutral-200 p-4 dark:border-neutral-800">
          <div className="flex gap-2">
            {(["dark", "light"] as const).map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => updateCustom({ mode: m })}
                className={`flex-1 rounded-lg border px-3 py-1.5 text-sm ${
                  custom.mode === m
                    ? "border-indigo-500 bg-indigo-50 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300"
                    : "border-neutral-300 text-neutral-700 dark:border-neutral-700 dark:text-neutral-300"
                }`}
              >
                {m === "dark" ? "Sombre" : "Clair"}
              </button>
            ))}
          </div>

          <HueSlider label="Accent (boutons, liens)" value={custom.accentHue} onChange={(h) => updateCustom({ accentHue: h })} />
          <HueSlider label="Danger (supprimer, erreurs)" value={custom.dangerHue} onChange={(h) => updateCustom({ dangerHue: h })} />
          <HueSlider label="Succès (confirmations)" value={custom.successHue} onChange={(h) => updateCustom({ successHue: h })} />
          <HueSlider label="Favoris (★)" value={custom.favoriteHue} onChange={(h) => updateCustom({ favoriteHue: h })} />

          <label className="flex items-center gap-2 text-sm text-neutral-700 dark:text-neutral-300">
            <input
              type="checkbox"
              checked={custom.backgroundTinted}
              onChange={(e) => updateCustom({ backgroundTinted: e.target.checked })}
              className="h-4 w-4 rounded border-neutral-300 text-indigo-600 dark:border-neutral-700"
            />
            Teinter aussi le fond avec la couleur d'accent
          </label>

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => void handleSave()}
              disabled={saveState === "saving"}
              className="rounded-lg bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-60"
            >
              {saveState === "saving" ? "Enregistrement…" : "Enregistrer sur ce compte"}
            </button>
            {saveState === "saved" && <span className="text-xs text-emerald-600 dark:text-emerald-400">Enregistré — synchronisé sur tous tes appareils.</span>}
            {saveState === "error" && <span className="text-xs text-red-600 dark:text-red-400">Échec de l'enregistrement — réessaie.</span>}
          </div>
        </div>
      )}
    </div>
  );
}
