import { useEffect, useState } from "react";
import { getTheme, setTheme, getCachedCustomTheme, setCachedCustomTheme, type Theme, type CustomThemeConfig } from "../lib/theme";
import { DEFAULT_CUSTOM_THEME } from "../lib/customTheme";
import { useAuth } from "../state/AuthContext";
import * as api from "../api/client";
import type { ThemeProfileView } from "../api/types";
import { getErrorMessage } from "../lib/errors";

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

const MAX_PROFILES = 3;

/** Aperçu teinte+luminosité — chroma fixe assez saturée pour bien distinguer les réglages
 * (`neutral` : aperçu gris pur, chroma 0, pour le fond quand "Fond neutre" est coché). */
function swatchStyle(hue: number, lightness: number, neutral?: boolean): React.CSSProperties {
  return { backgroundColor: `oklch(${lightness}% ${neutral ? 0 : ".18"} ${hue})` };
}

function ColorRow({
  label,
  hue,
  lightness,
  onChange,
  hueDisabled,
}: {
  label: string;
  hue: number;
  lightness: number;
  onChange: (patch: { hue?: number; lightness?: number }) => void;
  /** Fond "neutre" (voir la case à cocher juste en dessous) : la teinte n'a alors aucun effet
   * visuel (chroma forcée à 0, voir lib/customTheme.ts) — le curseur reste visible mais grisé
   * plutôt que caché, pour ne pas perdre la valeur choisie si l'utilisateur redécoche ensuite. */
  hueDisabled?: boolean;
}) {
  return (
    <div>
      <div className="mb-1 flex items-center justify-between text-xs text-neutral-600 dark:text-neutral-400">
        <span>{label}</span>
        <span className="h-4 w-4 rounded-full border border-neutral-300 dark:border-neutral-700" style={swatchStyle(hueDisabled ? 0 : hue, lightness, hueDisabled)} aria-hidden="true" />
      </div>
      <div className="flex items-center gap-2">
        <span className="w-16 shrink-0 text-[11px] text-neutral-500">Teinte</span>
        <input
          type="range"
          min={0}
          max={359}
          value={hue}
          disabled={hueDisabled}
          onChange={(e) => onChange({ hue: Number(e.target.value) })}
          className="w-full accent-indigo-600 disabled:opacity-40"
          aria-label={`${label} — teinte`}
        />
      </div>
      <div className="mt-0.5 flex items-center gap-2">
        <span className="w-16 shrink-0 text-[11px] text-neutral-500">Luminosité</span>
        <input
          type="range"
          min={0}
          max={100}
          value={lightness}
          onChange={(e) => onChange({ lightness: Number(e.target.value) })}
          className="w-full accent-indigo-600"
          aria-label={`${label} — luminosité (plus sombre/plus clair)`}
        />
      </div>
    </div>
  );
}

function profileToConfig(p: ThemeProfileView): CustomThemeConfig {
  return {
    backgroundHue: p.background_hue,
    backgroundLightness: p.background_lightness,
    backgroundNeutral: p.background_neutral,
    accentHue: p.accent_hue,
    accentLightness: p.accent_lightness,
    dangerHue: p.danger_hue,
    dangerLightness: p.danger_lightness,
    successHue: p.success_hue,
    successLightness: p.success_lightness,
    favoriteHue: p.favorite_hue,
    favoriteLightness: p.favorite_lightness,
  };
}

function configToPayload(name: string, c: CustomThemeConfig) {
  // Math.round() défensif : le serveur stocke teintes/luminosités en entier (i64, voir
  // models.rs::ThemeProfilePayload) — un flottant échoue la désérialisation JSON avec une 422 (voir
  // le CORRECTIF sur DEFAULT_CUSTOM_THEME.backgroundLightness, la cause déjà rencontrée une fois).
  // Les curseurs eux-mêmes ne peuvent produire que des entiers (step=1), donc en théorie inutile —
  // filet de sécurité si une future valeur par défaut/calculée oubliait à nouveau d'arrondir.
  return {
    name,
    background_hue: Math.round(c.backgroundHue),
    background_lightness: Math.round(c.backgroundLightness),
    background_neutral: c.backgroundNeutral,
    accent_hue: Math.round(c.accentHue),
    accent_lightness: Math.round(c.accentLightness),
    danger_hue: Math.round(c.dangerHue),
    danger_lightness: Math.round(c.dangerLightness),
    success_hue: Math.round(c.successHue),
    success_lightness: Math.round(c.successLightness),
    favorite_hue: Math.round(c.favoriteHue),
    favorite_lightness: Math.round(c.favoriteLightness),
  };
}

/** Réglage du thème visuel — CORRECTIF (retour utilisateur, 2026-09-02) : jusqu'ici, aucun réglage
 * n'existait, le thème suivait purement la préférence système. Les thèmes "presets"
 * (Sombre/Minuit/Océan/...) restent purement locaux à cet appareil (localStorage, voir
 * lib/theme.ts) — pas partagés entre appareils, comme les autres réglages de cette page
 * (AutoLockSettings...).
 *
 * "Personnalisé…" (retour utilisateur, 2026-09-03, affiné le même jour) fait EXCEPTION : PLUSIEURS
 * profils nommés, synchronisés par COMPTE (voir api/client.ts, state/AuthContext.tsx::
 * establishSession) — les créer/activer/modifier ici prend effet sur tous les appareils connectés
 * à ce compte. Plafonnés à 3 profils par compte, ILLIMITÉ pour l'Admin. */
export default function ThemeSettings() {
  const { authorizedRequest, isAdmin } = useAuth();
  const [theme, setThemeState] = useState<Theme>(() => getTheme());

  const [profiles, setProfiles] = useState<ThemeProfileView[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | "new" | null>(null);
  const [draftName, setDraftName] = useState("");
  const [draft, setDraft] = useState<CustomThemeConfig>(() => getCachedCustomTheme());
  const [actionError, setActionError] = useState<string | null>(null);
  const [saveState, setSaveState] = useState<"idle" | "saving" | "saved">("idle");

  useEffect(() => {
    if (theme !== "custom" || profiles !== null) return;
    authorizedRequest((token) => api.listThemeProfiles(token))
      .then((list) => {
        setProfiles(list);
        const active = list.find((p) => p.is_active);
        if (active) {
          setEditingId(active.id);
          setDraftName(active.name);
          setDraft(profileToConfig(active));
        }
      })
      .catch((err) => setLoadError(getErrorMessage(err)));
  }, [theme, profiles, authorizedRequest]);

  async function handleThemeChange(value: Theme) {
    setThemeState(value);
    setTheme(value);
  }

  // CORRECTIF (retour utilisateur : "je ne peux pas appliquer, ça reste tout le temps comme ça") :
  // startNewProfile/startEditProfile/updateDraft appliquent maintenant TOUJOURS un aperçu immédiat
  // (setCachedCustomTheme), pas seulement quand le profil édité est déjà celui actif côté serveur.
  // Éditer un profil est une action WYSIWYG — bouger un curseur doit se voir tout de suite, même
  // pour le tout premier profil d'un compte (jamais actif avant sa création, donc l'ancienne
  // condition ne prévisualisait JAMAIS rien pour ce cas, le plus courant). Le seul coût : quitter
  // l'écran sans enregistrer laisse l'aperçu du brouillon dans le cache local jusqu'au prochain
  // establishSession()/activation, qui le remplace par la vraie valeur active côté serveur — sans
  // gravité, ce cache n'a jamais été une source de vérité (voir lib/theme.ts).
  function startNewProfile() {
    setEditingId("new");
    setDraftName(`Profil ${(profiles?.length ?? 0) + 1}`);
    const config = getCachedCustomTheme();
    setDraft(config);
    setCachedCustomTheme(config);
    setActionError(null);
    setSaveState("idle");
  }

  function startEditProfile(p: ThemeProfileView) {
    setEditingId(p.id);
    setDraftName(p.name);
    const config = profileToConfig(p);
    setDraft(config);
    setCachedCustomTheme(config);
    setActionError(null);
    setSaveState("idle");
  }

  function updateDraft(patch: Partial<CustomThemeConfig>) {
    const next = { ...draft, ...patch };
    setDraft(next);
    setSaveState("idle");
    setCachedCustomTheme(next);
  }

  /** Réinitialise les curseurs du profil en cours d'édition sur les valeurs par défaut — IDENTIQUES
   * au thème preset "Sombre" (voir customTheme.ts::DEFAULT_CUSTOM_THEME), retour utilisateur :
   * "ajoute un bouton pour réinitialiser les curseurs par défaut, les mêmes que le mode sombre". Ne
   * touche pas au nom du profil. */
  function handleResetDraft() {
    updateDraft(DEFAULT_CUSTOM_THEME);
  }

  async function handleSaveProfile() {
    setSaveState("saving");
    setActionError(null);
    try {
      const payload = configToPayload(draftName.trim() || "Sans nom", draft);
      if (editingId === "new") {
        const created = await authorizedRequest((token) => api.createThemeProfile(token, payload));
        // Un compte qui crée son PREMIER profil s'attend à ce qu'il s'applique tout de suite —
        // demander un second clic "Activer" séparé n'était pas clair (retour utilisateur : "je ne
        // peux pas activer le profil"). On l'active automatiquement à la création, plutôt que de
        // ne réserver "activer" qu'aux profils EXISTANTS déjà écartés (voir handleActivate).
        await authorizedRequest((token) => api.activateThemeProfile(token, created.id));
        const createdActive = { ...created, is_active: true };
        setProfiles((prev) => [...(prev ?? []).map((p) => ({ ...p, is_active: false })), createdActive]);
        setEditingId(created.id);
        setCachedCustomTheme(draft);
        setTheme("custom");
      } else if (editingId) {
        await authorizedRequest((token) => api.updateThemeProfile(token, editingId, payload));
        setProfiles((prev) => (prev ?? []).map((p) => (p.id === editingId ? { ...p, ...payload } : p)));
      }
      setSaveState("saved");
    } catch (err) {
      setActionError(getErrorMessage(err));
      setSaveState("idle");
    }
  }

  async function handleActivate(p: ThemeProfileView) {
    setActionError(null);
    try {
      await authorizedRequest((token) => api.activateThemeProfile(token, p.id));
      setProfiles((prev) => (prev ?? []).map((item) => ({ ...item, is_active: item.id === p.id })));
      setCachedCustomTheme(profileToConfig(p));
      setTheme("custom");
      setThemeState("custom");
    } catch (err) {
      setActionError(getErrorMessage(err));
    }
  }

  async function handleDelete(p: ThemeProfileView) {
    if (!confirm(`Supprimer le profil "${p.name}" ? Cette action est irréversible.`)) return;
    setActionError(null);
    try {
      await authorizedRequest((token) => api.deleteThemeProfile(token, p.id));
      setProfiles((prev) => (prev ?? []).filter((item) => item.id !== p.id));
      if (editingId === p.id) setEditingId(null);
      // Le profil supprimé était actif : revient à un thème preset plutôt que de laisser un
      // aperçu figé sur des couleurs qui n'existent plus côté serveur (voir DELETE côté backend).
      if (p.is_active) {
        setTheme("dark");
        setThemeState("dark");
      }
    } catch (err) {
      setActionError(getErrorMessage(err));
    }
  }

  const atLimit = !isAdmin && (profiles?.length ?? 0) >= MAX_PROFILES;

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
        Ambre sont des versions sombres toutes prêtes. "Personnalisé…" te laisse enregistrer
        jusqu'à {MAX_PROFILES} profils où chaque couleur (fond compris) a sa propre teinte et sa
        propre luminosité — synchronisés sur tous tes appareils connectés à ce compte.
      </p>

      {theme === "custom" && (
        <div className="mt-4 space-y-4 rounded-lg border border-neutral-200 p-4 dark:border-neutral-800">
          {loadError && <p className="text-xs text-red-600 dark:text-red-400">{loadError}</p>}
          {actionError && <p className="text-xs text-red-600 dark:text-red-400">{actionError}</p>}

          {profiles && (
            <div className="flex flex-wrap gap-2">
              {profiles.map((p) => (
                <div
                  key={p.id}
                  className={`flex items-center gap-1 rounded-lg border px-2 py-1 text-xs ${
                    p.is_active ? "border-indigo-500 bg-indigo-50 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300" : "border-neutral-300 dark:border-neutral-700"
                  }`}
                >
                  <button type="button" onClick={() => startEditProfile(p)} className="font-medium hover:underline">
                    {p.name}
                    {p.is_active ? " ✓" : ""}
                  </button>
                  {!p.is_active && (
                    <button type="button" onClick={() => void handleActivate(p)} className="text-neutral-500 hover:text-indigo-600 dark:hover:text-indigo-400" title="Activer">
                      Activer
                    </button>
                  )}
                  <button type="button" onClick={() => void handleDelete(p)} className="text-neutral-500 hover:text-red-600 dark:hover:text-red-400" title="Supprimer">
                    ✕
                  </button>
                </div>
              ))}
              <button
                type="button"
                onClick={startNewProfile}
                disabled={atLimit}
                className="rounded-lg border border-dashed border-neutral-300 px-2 py-1 text-xs text-neutral-600 hover:border-indigo-400 disabled:cursor-not-allowed disabled:opacity-50 dark:border-neutral-700 dark:text-neutral-400"
                title={atLimit ? `Limite de ${MAX_PROFILES} profils atteinte` : "Nouveau profil"}
              >
                + Nouveau profil
              </button>
            </div>
          )}
          {atLimit && <p className="text-xs text-neutral-500">Limite de {MAX_PROFILES} profils atteinte — supprime-en un pour en créer un nouveau.</p>}

          {editingId && (
            <div className="space-y-3 border-t border-neutral-200 pt-3 dark:border-neutral-800">
              <input
                type="text"
                value={draftName}
                onChange={(e) => setDraftName(e.target.value)}
                placeholder="Nom du profil"
                maxLength={60}
                className="w-full rounded-lg border border-neutral-300 px-3 py-1.5 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
              />

              <ColorRow
                label="Fond de l'app"
                hue={draft.backgroundHue}
                lightness={draft.backgroundLightness}
                hueDisabled={draft.backgroundNeutral}
                onChange={(p) => updateDraft({ backgroundHue: p.hue ?? draft.backgroundHue, backgroundLightness: p.lightness ?? draft.backgroundLightness })}
              />
              <label className="-mt-2 flex items-center gap-2 text-xs text-neutral-700 dark:text-neutral-300">
                <input
                  type="checkbox"
                  checked={draft.backgroundNeutral}
                  onChange={(e) => updateDraft({ backgroundNeutral: e.target.checked })}
                  className="h-3.5 w-3.5 rounded border-neutral-300 text-indigo-600 dark:border-neutral-700"
                />
                Fond neutre (gris pur, sans aucune teinte)
              </label>

              <ColorRow label="Accent (boutons, liens)" hue={draft.accentHue} lightness={draft.accentLightness} onChange={(p) => updateDraft({ accentHue: p.hue ?? draft.accentHue, accentLightness: p.lightness ?? draft.accentLightness })} />
              <ColorRow label="Danger (supprimer, erreurs)" hue={draft.dangerHue} lightness={draft.dangerLightness} onChange={(p) => updateDraft({ dangerHue: p.hue ?? draft.dangerHue, dangerLightness: p.lightness ?? draft.dangerLightness })} />
              <ColorRow label="Succès (confirmations)" hue={draft.successHue} lightness={draft.successLightness} onChange={(p) => updateDraft({ successHue: p.hue ?? draft.successHue, successLightness: p.lightness ?? draft.successLightness })} />
              <ColorRow label="Favoris (★)" hue={draft.favoriteHue} lightness={draft.favoriteLightness} onChange={(p) => updateDraft({ favoriteHue: p.hue ?? draft.favoriteHue, favoriteLightness: p.lightness ?? draft.favoriteLightness })} />

              <p className="text-xs text-neutral-500">Une luminosité de fond inférieure à 50% donne une interface sombre, au-delà une interface claire.</p>

              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => void handleSaveProfile()}
                  disabled={saveState === "saving"}
                  className="rounded-lg bg-indigo-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-60"
                >
                  {saveState === "saving" ? "Enregistrement…" : editingId === "new" ? "Créer le profil" : "Enregistrer"}
                </button>
                <button type="button" onClick={handleResetDraft} className="rounded-lg border border-neutral-300 px-3 py-1.5 text-sm text-neutral-700 hover:border-neutral-400 dark:border-neutral-700 dark:text-neutral-300">
                  Réinitialiser
                </button>
                {saveState === "saved" && <span className="text-xs text-emerald-600 dark:text-emerald-400">Enregistré — synchronisé sur tous tes appareils.</span>}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
