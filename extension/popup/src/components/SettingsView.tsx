// Réglages — port réduit de frontend(app)/src/pages/Settings.tsx : URL du backend, délai de
// verrouillage popup, délai d'effacement du presse-papiers, changement d'email, appareils de
// confiance. PAS de changement de mot de passe maître (voir le plan — reste une opération desktop).

import { useEffect, useState, type FormEvent } from "react";
import * as api from "../api/client";
import * as session from "../lib/session";
import * as wasmCrypto from "../lib/wasmCrypto";
import { changeEmail } from "../lib/emailChange";
import { getDeviceId } from "../lib/deviceId";
import {
  getBackendUrl,
  setBackendUrl,
  getPopupLockMinutes,
  setPopupLockMinutes,
  getClipboardClearSeconds,
  setClipboardClearSeconds,
  getWindowMode,
  setWindowMode,
  type WindowMode,
} from "../lib/settings";
import { getTheme, setTheme, getCachedCustomTheme, setCachedCustomTheme, getCachedThemeProfiles, setCachedThemeProfiles, type Theme, type CustomThemeConfig } from "../lib/theme";
import {
  DEFAULT_CUSTOM_THEME,
  HUE_PRESETS,
  HUE_GRADIENT,
  previewAccentColor,
  previewDangerColor,
  previewSuccessColor,
  previewFavoriteColor,
  previewBackgroundColors,
  randomThemeConfig,
  encodeThemeCode,
  decodeThemeCode,
} from "../lib/customTheme";
import type { TrustedDevice, ThemeProfileView, SharedThemeProfileView } from "../api/types";
import { getErrorMessage } from "../lib/errors";

const LOCK_MINUTES_OPTIONS = [1, 5, 15, 30];
const CLIPBOARD_SECONDS_OPTIONS = [0, 10, 20, 60];

/** Retour utilisateur : "tu as aussi enlevé les options de fondu et autre" — raccourcis
 * Neutre/Fondu/Couleur restaurés pour le fond, voir ThemeSettings.tsx côté desktop. */
const SATURATION_PRESETS: { value: number; label: string }[] = [
  { value: 0, label: "Neutre" },
  { value: 30, label: "Fondu" },
  { value: 80, label: "Couleur" },
];

function inputClass() {
  return "w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900";
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="border-b border-neutral-200 px-4 py-3 dark:border-neutral-800">
      <h2 className="mb-2 text-sm font-medium text-neutral-900 dark:text-neutral-100">{title}</h2>
      {children}
    </div>
  );
}

/** Voir ThemeSettings.tsx côté desktop pour le raisonnement complet (retour utilisateur : "aperçu
 * visuel dans l'éditeur") — version compacte pour la popup (380×580px). */
function ThemePreviewMockup({ draft }: { draft: CustomThemeConfig }) {
  const bg = previewBackgroundColors(draft.backgroundHue, draft.backgroundLightness, draft.backgroundSaturation);
  const accent = previewAccentColor(draft.accentHue, draft.accentLightness, draft.accentSaturation);
  const danger = previewDangerColor(draft.dangerHue, draft.dangerLightness, draft.dangerSaturation);
  const success = previewSuccessColor(draft.successHue, draft.successLightness, draft.successSaturation);
  const favorite = previewFavoriteColor(draft.favoriteHue, draft.favoriteLightness, draft.favoriteSaturation);
  const textColor = bg.isDark ? "oklch(92% 0 0)" : "oklch(20% 0 0)";

  return (
    <div className="overflow-hidden rounded-lg border border-neutral-200 dark:border-neutral-800" style={{ backgroundColor: bg.page }}>
      <div className="m-2 rounded-lg p-2" style={{ backgroundColor: bg.card, border: `1px solid ${bg.border}` }}>
        <div className="mb-1.5 flex items-center justify-between">
          <p className="text-xs font-medium" style={{ color: textColor }}>
            Aperçu
          </p>
          <span style={{ color: favorite }} aria-hidden="true">
            ★
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="rounded-lg px-2 py-0.5 text-[10px] font-medium text-white" style={{ backgroundColor: accent }}>
            Copier
          </span>
          <span className="rounded-lg px-2 py-0.5 text-[10px] font-medium text-white" style={{ backgroundColor: danger }}>
            Supprimer
          </span>
          <span className="rounded-lg px-2 py-0.5 text-[10px] font-medium text-white" style={{ backgroundColor: success }}>
            Enregistré ✓
          </span>
        </div>
      </div>
    </div>
  );
}

export default function SettingsView({
  email,
  onBack,
  onLoggedOut,
}: {
  email: string;
  onBack: () => void;
  onLoggedOut: () => void;
}) {
  const [backendUrl, setBackendUrlState] = useState(getBackendUrl());
  const [lockMinutes, setLockMinutes] = useState(getPopupLockMinutes());
  const [clipboardSeconds, setClipboardSeconds] = useState(getClipboardClearSeconds());
  const [windowMode, setWindowModeState] = useState(getWindowMode());
  const [theme, setThemeState] = useState<Theme>(() => getTheme());
  const MAX_PROFILES = 3;
  const [profiles, setProfiles] = useState<ThemeProfileView[] | null>(null);
  const [profilesLoadError, setProfilesLoadError] = useState<string | null>(null);
  const [editingProfileId, setEditingProfileId] = useState<string | "new" | null>(null);
  const [draftProfileName, setDraftProfileName] = useState("");
  const [draftProfile, setDraftProfile] = useState<CustomThemeConfig>(() => getCachedCustomTheme());
  const [profileActionError, setProfileActionError] = useState<string | null>(null);
  const [profileSaveState, setProfileSaveState] = useState<"idle" | "saving" | "saved">("idle");
  const [themeCodeInput, setThemeCodeInput] = useState("");
  const [themeCodeMessage, setThemeCodeMessage] = useState<{ ok: boolean; text: string } | null>(null);
  // Retour utilisateur : "au lieu de uniquement copier le code, il faudrait plutôt savoir le
  // partager avec d'autres utilisateurs" — voir handleShareProfile/handleAcceptShare plus bas.
  const [sharingProfileId, setSharingProfileId] = useState<string | null>(null);
  const [shareEmailInput, setShareEmailInput] = useState("");
  const [shareMessage, setShareMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [receivedShares, setReceivedShares] = useState<SharedThemeProfileView[] | null>(null);

  const [newEmail, setNewEmail] = useState("");
  const [emailPassword, setEmailPassword] = useState("");
  const [emailError, setEmailError] = useState<string | null>(null);
  const [isChangingEmail, setIsChangingEmail] = useState(false);

  const [devices, setDevices] = useState<TrustedDevice[] | null>(null);
  const [deviceError, setDeviceError] = useState<string | null>(null);
  const [busyDeviceId, setBusyDeviceId] = useState<string | null>(null);
  const [showLimitForm, setShowLimitForm] = useState(false);
  const [newLimit, setNewLimit] = useState(5);
  const [limitPassword, setLimitPassword] = useState("");
  const currentDeviceId = getDeviceId();

  // isModerator/canChangeEmailViaExtension : récupérés via le même appel GET /me que ci-dessous
  // (pas de requête réseau supplémentaire) — voir la restriction correspondante côté serveur
  // (backend/src/handlers/auth/account.rs::update_email + common::is_extension_origin). `null` tant
  // que non chargé : les sections concernées restent masquées par défaut plutôt que de s'afficher
  // un instant avant de disparaître.
  const [isModerator, setIsModerator] = useState<boolean | null>(null);
  const [canChangeEmailViaExtension, setCanChangeEmailViaExtension] = useState(false);
  // Vrai UNIQUEMENT pour le compte ADMIN_EMAIL — voir le même champ côté desktop
  // (state/AuthContext.tsx). Utilisé ici pour la limite de 3 profils de personnalisation de thème
  // (illimité pour l'Admin, voir handlers/theme_customization.rs côté serveur).
  const [isAdmin, setIsAdmin] = useState(false);

  async function loadDevices() {
    try {
      const [deviceList, me] = await Promise.all([
        session.authorizedRequest((token) => api.listDevices(token)),
        session.authorizedRequest((token) => api.getMe(token)),
      ]);
      setDevices(deviceList);
      setNewLimit(me.max_trusted_devices);
      setIsModerator(me.is_moderator);
      setCanChangeEmailViaExtension(me.can_change_email_via_extension);
      setIsAdmin(me.is_admin);
    } catch (err) {
      setDeviceError(getErrorMessage(err));
    }
  }

  useEffect(() => {
    void loadDevices();
  }, []);

  function handleSaveBackendUrl() {
    setBackendUrl(backendUrl);
  }

  function handleSaveLockMinutes(minutes: number) {
    setLockMinutes(minutes);
    setPopupLockMinutes(minutes);
  }

  function handleSaveClipboardSeconds(seconds: number) {
    setClipboardSeconds(seconds);
    setClipboardClearSeconds(seconds);
  }

  function handleSaveWindowMode(mode: WindowMode) {
    setWindowModeState(mode);
    setWindowMode(mode);
  }

  function handleSaveTheme(value: Theme) {
    setThemeState(value);
    setTheme(value);
    if (value === "custom" && profiles === null) {
      // OPTIMISATION BANDE PASSANTE (retour utilisateur) : App.tsx a déjà récupéré cette même
      // liste à l'ouverture de la popup — la réutiliser directement si elle est encore là plutôt
      // que de reposer la même question au serveur, voir lib/theme.ts.
      const cached = getCachedThemeProfiles();
      if (cached) {
        setProfiles(cached);
        const active = cached.find((p) => p.is_active);
        if (active) {
          setEditingProfileId(active.id);
          setDraftProfileName(active.name);
          setDraftProfile(profileToConfig(active));
        }
      } else {
        session.authorizedRequest((token) => api.listThemeProfiles(token))
          .then((list) => {
            setProfilesAndCache(list);
            const active = list.find((p) => p.is_active);
            if (active) {
              setEditingProfileId(active.id);
              setDraftProfileName(active.name);
              setDraftProfile(profileToConfig(active));
            }
          })
          .catch((err) => setProfilesLoadError(getErrorMessage(err)));
      }
      session.authorizedRequest((token) => api.listSharedThemeProfiles(token))
        .then(setReceivedShares)
        .catch(() => {
          // best-effort — les profils reçus sont une commodité, pas la fonctionnalité principale.
        });
    }
  }

  /** Voir ThemeSettings.tsx côté desktop pour le même raisonnement — garde le cache mémoire de
   * lib/theme.ts synchronisé avec l'état local à chaque mutation. */
  function setProfilesAndCache(update: ThemeProfileView[] | ((prev: ThemeProfileView[]) => ThemeProfileView[])) {
    setProfiles((prev) => {
      const next = typeof update === "function" ? update(prev ?? []) : update;
      setCachedThemeProfiles(next);
      return next;
    });
  }

  function profileToConfig(p: ThemeProfileView): CustomThemeConfig {
    return {
      backgroundHue: p.background_hue,
      backgroundLightness: p.background_lightness,
      backgroundSaturation: p.background_saturation,
      accentHue: p.accent_hue,
      accentLightness: p.accent_lightness,
      accentSaturation: p.accent_saturation,
      dangerHue: p.danger_hue,
      dangerLightness: p.danger_lightness,
      dangerSaturation: p.danger_saturation,
      successHue: p.success_hue,
      successLightness: p.success_lightness,
      successSaturation: p.success_saturation,
      favoriteHue: p.favorite_hue,
      favoriteLightness: p.favorite_lightness,
      favoriteSaturation: p.favorite_saturation,
    };
  }

  function configToProfilePayload(name: string, c: CustomThemeConfig) {
    // Math.round() défensif : le serveur stocke teintes/luminosités/saturations en entier (i64,
    // voir models.rs::ThemeProfilePayload) — un flottant échoue la désérialisation JSON avec une
    // 422 (voir le CORRECTIF sur customTheme.ts::DEFAULT_CUSTOM_THEME.backgroundLightness, la
    // cause déjà rencontrée une fois). Les curseurs eux-mêmes ne peuvent produire que des entiers
    // (step=1), donc en théorie inutile — filet de sécurité si une future valeur oubliait d'arrondir.
    return {
      name,
      background_hue: Math.round(c.backgroundHue),
      background_lightness: Math.round(c.backgroundLightness),
      background_saturation: Math.round(c.backgroundSaturation),
      accent_hue: Math.round(c.accentHue),
      accent_lightness: Math.round(c.accentLightness),
      accent_saturation: Math.round(c.accentSaturation),
      danger_hue: Math.round(c.dangerHue),
      danger_lightness: Math.round(c.dangerLightness),
      danger_saturation: Math.round(c.dangerSaturation),
      success_hue: Math.round(c.successHue),
      success_lightness: Math.round(c.successLightness),
      success_saturation: Math.round(c.successSaturation),
      favorite_hue: Math.round(c.favoriteHue),
      favorite_lightness: Math.round(c.favoriteLightness),
      favorite_saturation: Math.round(c.favoriteSaturation),
    };
  }

  // CORRECTIF (retour utilisateur : "je ne peux pas appliquer, ça reste tout le temps comme ça") :
  // voir ThemeSettings.tsx côté desktop pour le raisonnement complet — aperçu TOUJOURS appliqué en
  // éditant, pas seulement pour le profil déjà actif (qui ne concernait jamais le tout premier
  // profil d'un compte, le cas le plus courant).
  function startNewThemeProfile() {
    setEditingProfileId("new");
    setDraftProfileName(`Profil ${(profiles?.length ?? 0) + 1}`);
    const config = getCachedCustomTheme();
    setDraftProfile(config);
    setCachedCustomTheme(config);
    setProfileActionError(null);
    setProfileSaveState("idle");
  }

  function startEditThemeProfile(p: ThemeProfileView) {
    setEditingProfileId(p.id);
    setDraftProfileName(p.name);
    const config = profileToConfig(p);
    setDraftProfile(config);
    setCachedCustomTheme(config);
    setProfileActionError(null);
    setProfileSaveState("idle");
  }

  /** Voir ThemeSettings.tsx côté desktop pour le raisonnement (retour utilisateur : "améliore [...]
   * la personnalisation") — `editingProfileId = "new"` : "Créer" enregistrera un NOUVEAU profil. */
  function duplicateThemeProfile(p: ThemeProfileView) {
    setEditingProfileId("new");
    setDraftProfileName(`${p.name} (copie)`);
    const config = profileToConfig(p);
    setDraftProfile(config);
    setCachedCustomTheme(config);
    setProfileActionError(null);
    setProfileSaveState("idle");
  }

  function updateDraftProfile(patch: Partial<CustomThemeConfig>) {
    const next = { ...draftProfile, ...patch };
    setDraftProfile(next);
    setProfileSaveState("idle");
    setCachedCustomTheme(next);
  }

  /** Voir ThemeSettings.tsx côté desktop pour le même raisonnement : identique au thème preset
   * "Sombre" (retour utilisateur : "ajoute un bouton pour réinitialiser les curseurs par défaut,
   * les mêmes que le mode sombre"). Ne touche pas au nom du profil. */
  function handleResetThemeDraft() {
    updateDraftProfile(DEFAULT_CUSTOM_THEME);
  }

  /** Retour utilisateur : "bouton aléatoire (couleurs surprise)". */
  function handleRandomizeTheme() {
    updateDraftProfile(randomThemeConfig());
  }

  /** Retour utilisateur : "exporter/partager un profil avec un code". */
  async function handleCopyThemeCode() {
    try {
      await navigator.clipboard.writeText(encodeThemeCode(draftProfile));
      setThemeCodeMessage({ ok: true, text: "Code copié." });
    } catch {
      setThemeCodeMessage({ ok: false, text: "Impossible de copier." });
    }
  }

  function handleImportThemeCode() {
    const decoded = decodeThemeCode(themeCodeInput);
    if (!decoded) {
      setThemeCodeMessage({ ok: false, text: "Code invalide." });
      return;
    }
    updateDraftProfile(decoded);
    setThemeCodeInput("");
    setThemeCodeMessage({ ok: true, text: "Importé — pense à l'enregistrer." });
  }

  async function handleSaveThemeProfile() {
    setProfileSaveState("saving");
    setProfileActionError(null);
    try {
      const payload = configToProfilePayload(draftProfileName.trim() || "Sans nom", draftProfile);
      if (editingProfileId === "new") {
        const created = await session.authorizedRequest((token) => api.createThemeProfile(token, payload));
        // Voir ThemeSettings.tsx côté desktop pour le même raisonnement : activer automatiquement
        // le premier profil créé (retour utilisateur : "je ne peux pas activer le profil").
        await session.authorizedRequest((token) => api.activateThemeProfile(token, created.id));
        const createdActive = { ...created, is_active: true };
        setProfilesAndCache((prev) => [...prev.map((p) => ({ ...p, is_active: false })), createdActive]);
        setEditingProfileId(created.id);
        setCachedCustomTheme(draftProfile);
        setTheme("custom");
      } else if (editingProfileId) {
        await session.authorizedRequest((token) => api.updateThemeProfile(token, editingProfileId, payload));
        setProfilesAndCache((prev) => prev.map((p) => (p.id === editingProfileId ? { ...p, ...payload } : p)));
      }
      setProfileSaveState("saved");
    } catch (err) {
      setProfileActionError(getErrorMessage(err));
      setProfileSaveState("idle");
    }
  }

  async function handleActivateThemeProfile(p: ThemeProfileView) {
    setProfileActionError(null);
    try {
      await session.authorizedRequest((token) => api.activateThemeProfile(token, p.id));
      setProfilesAndCache((prev) => prev.map((item) => ({ ...item, is_active: item.id === p.id })));
      setCachedCustomTheme(profileToConfig(p));
      setTheme("custom");
      setThemeState("custom");
    } catch (err) {
      setProfileActionError(getErrorMessage(err));
    }
  }

  async function handleDeleteThemeProfile(p: ThemeProfileView) {
    if (!confirm(`Supprimer le profil "${p.name}" ?`)) return;
    setProfileActionError(null);
    try {
      await session.authorizedRequest((token) => api.deleteThemeProfile(token, p.id));
      setProfilesAndCache((prev) => prev.filter((item) => item.id !== p.id));
      if (editingProfileId === p.id) setEditingProfileId(null);
      if (p.is_active) {
        setTheme("dark");
        setThemeState("dark");
      }
    } catch (err) {
      setProfileActionError(getErrorMessage(err));
    }
  }

  function startShareThemeProfile(p: ThemeProfileView) {
    setSharingProfileId((current) => (current === p.id ? null : p.id));
    setShareEmailInput("");
    setShareMessage(null);
  }

  async function handleShareThemeProfile(profileId: string) {
    const emailTo = shareEmailInput.trim();
    if (!emailTo) return;
    try {
      await session.authorizedRequest((token) => api.shareThemeProfile(token, profileId, { shared_with_email: emailTo }));
      setShareMessage({ ok: true, text: `Partagé avec ${emailTo}.` });
      setShareEmailInput("");
    } catch (err) {
      setShareMessage({ ok: false, text: getErrorMessage(err) });
    }
  }

  async function handleAcceptThemeShare(share: SharedThemeProfileView) {
    setProfileActionError(null);
    try {
      const created = await session.authorizedRequest((token) => api.acceptSharedThemeProfile(token, share.id));
      setProfilesAndCache((prev) => [...prev, created]);
      setReceivedShares((prev) => (prev ?? []).filter((s) => s.id !== share.id));
    } catch (err) {
      setProfileActionError(getErrorMessage(err));
    }
  }

  async function handleDeclineThemeShare(share: SharedThemeProfileView) {
    try {
      await session.authorizedRequest((token) => api.declineSharedThemeProfile(token, share.id));
      setReceivedShares((prev) => (prev ?? []).filter((s) => s.id !== share.id));
    } catch (err) {
      setProfileActionError(getErrorMessage(err));
    }
  }

  async function handleChangeEmail(e: FormEvent) {
    e.preventDefault();
    setEmailError(null);
    setIsChangingEmail(true);
    try {
      await changeEmail(email, newEmail, emailPassword, session.authorizedRequest);
      await session.logout();
      onLoggedOut();
    } catch (err) {
      setEmailError(getErrorMessage(err));
    } finally {
      setIsChangingEmail(false);
    }
  }

  async function handleRevokeDevice(deviceId: string) {
    if (!confirm("Révoquer cet appareil ?")) return;
    setBusyDeviceId(deviceId);
    setDeviceError(null);
    try {
      await session.authorizedRequest((token) => api.revokeDevice(token, deviceId));
      setDevices((prev) => (prev ? prev.filter((d) => d.device_id !== deviceId) : prev));
    } catch (err) {
      setDeviceError(getErrorMessage(err));
    } finally {
      setBusyDeviceId(null);
    }
  }

  async function handleLogoutAll() {
    if (!confirm("Déconnecter TOUS les appareils, y compris celui-ci ?")) return;
    try {
      await session.authorizedRequest((token) => api.logoutAllDevices(token));
      await session.logout();
      onLoggedOut();
    } catch (err) {
      setDeviceError(getErrorMessage(err));
    }
  }

  async function handleSaveLimit(e: FormEvent) {
    e.preventDefault();
    setDeviceError(null);
    try {
      const { authHashHex } = await wasmCrypto.deriveKeys(email, limitPassword);
      await session.authorizedRequest((token) => api.updateDeviceLimit(token, { new_limit: newLimit, master_password_hash: authHashHex }));
      setLimitPassword("");
      setShowLimitForm(false);
    } catch (err) {
      setDeviceError(getErrorMessage(err));
    }
  }

  return (
    <div className="flex flex-col">
      <div className="flex items-center gap-2 border-b border-neutral-200 px-4 py-3 dark:border-neutral-800">
        <button onClick={onBack} className="text-sm text-neutral-500 hover:underline">
          ← Retour
        </button>
        <h1 className="text-sm font-medium text-neutral-900 dark:text-neutral-100">Réglages</h1>
      </div>

      {isModerator === true && (
        <Section title="Serveur">
          <div className="flex gap-2">
            <input type="text" value={backendUrl} onChange={(e) => setBackendUrlState(e.target.value)} className={inputClass()} />
            <button onClick={handleSaveBackendUrl} className="shrink-0 rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-700">
              Enregistrer
            </button>
          </div>
        </Section>
      )}

      <Section title="Apparence">
        <label className="mb-1 block text-xs text-neutral-500">Thème</label>
        <select value={theme} onChange={(e) => handleSaveTheme(e.target.value as Theme)} className={inputClass()}>
          <option value="dark">Sombre</option>
          <option value="light">Clair</option>
          <option value="system">Suivre l'appareil</option>
          <option value="midnight">Minuit (noir OLED)</option>
          <option value="slate">Ardoise (gris froid)</option>
          <option value="ocean">Océan (accent bleu)</option>
          <option value="forest">Forêt (accent vert)</option>
          <option value="sunset">Coucher de soleil (accent orange)</option>
          <option value="rose">Rose (accent rose)</option>
          <option value="violet">Violet (accent pourpre)</option>
          <option value="amber">Ambre (accent doré, fond réchauffé)</option>
          <option value="custom">Personnalisé…</option>
        </select>

        {theme === "custom" && (
          <div className="mt-3 space-y-3 rounded-lg border border-neutral-200 p-3 dark:border-neutral-800">
            {profilesLoadError && <p className="text-xs text-red-600 dark:text-red-400">{profilesLoadError}</p>}
            {profileActionError && <p className="text-xs text-red-600 dark:text-red-400">{profileActionError}</p>}

            {/* Retour utilisateur : "savoir le partager avec d'autres utilisateurs". */}
            {receivedShares && receivedShares.length > 0 && (
              <div className="space-y-1 rounded-lg border border-indigo-200 bg-indigo-50/50 p-1.5 dark:border-indigo-900 dark:bg-indigo-950/30">
                <p className="text-[11px] font-medium text-neutral-700 dark:text-neutral-300">Profils reçus</p>
                {receivedShares.map((s) => (
                  <div key={s.id} className="flex items-center justify-between gap-2 text-[11px]">
                    <span className="truncate text-neutral-600 dark:text-neutral-400">
                      <span className="font-medium text-neutral-900 dark:text-neutral-100">{s.name}</span> — {s.from_email}
                    </span>
                    <div className="flex shrink-0 gap-1.5">
                      <button type="button" onClick={() => void handleAcceptThemeShare(s)} className="text-indigo-600 hover:underline dark:text-indigo-400">
                        Accepter
                      </button>
                      <button type="button" onClick={() => void handleDeclineThemeShare(s)} className="text-neutral-500 hover:underline">
                        Refuser
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {profiles && (
              <div className="flex flex-wrap gap-1.5">
                {profiles.map((p) => (
                  <div key={p.id} className="flex flex-col gap-1">
                    <div
                      className={`flex items-center gap-1 rounded-lg border px-1.5 py-0.5 text-[11px] ${
                        p.is_active ? "border-indigo-500 bg-indigo-50 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300" : "border-neutral-300 dark:border-neutral-700"
                      }`}
                    >
                      <button type="button" onClick={() => startEditThemeProfile(p)} className="font-medium hover:underline">
                        {p.name}
                        {p.is_active ? " ✓" : ""}
                      </button>
                      {!p.is_active && (
                        <button type="button" onClick={() => void handleActivateThemeProfile(p)} className="text-neutral-500 hover:text-indigo-600 dark:hover:text-indigo-400">
                          Activer
                        </button>
                      )}
                      {/* CORRECTIF (retour utilisateur : "je vois toujours pas comment partager") :
                          remplace les symboles "↗"/"⧉" (repérés uniquement au survol, voir
                          ThemeSettings.tsx côté desktop pour le même correctif) par du texte,
                          comme "Activer" juste au-dessus. */}
                      <button type="button" onClick={() => startShareThemeProfile(p)} className="text-neutral-500 hover:text-indigo-600 dark:hover:text-indigo-400">
                        Partager
                      </button>
                      <button
                        type="button"
                        onClick={() => duplicateThemeProfile(p)}
                        disabled={!isAdmin && (profiles?.length ?? 0) >= MAX_PROFILES}
                        className="text-neutral-500 hover:text-indigo-600 disabled:cursor-not-allowed disabled:opacity-40 dark:hover:text-indigo-400"
                      >
                        Dupliquer
                      </button>
                      <button type="button" onClick={() => void handleDeleteThemeProfile(p)} className="text-neutral-500 hover:text-red-600 dark:hover:text-red-400">
                        ✕
                      </button>
                    </div>
                    {sharingProfileId === p.id && (
                      <div className="flex items-center gap-1 rounded-lg border border-neutral-200 p-1 dark:border-neutral-800">
                        <input
                          type="email"
                          value={shareEmailInput}
                          onChange={(e) => setShareEmailInput(e.target.value)}
                          placeholder="Email du destinataire"
                          className="w-full rounded border border-neutral-300 px-1.5 py-0.5 text-[10px] outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
                        />
                        <button
                          type="button"
                          onClick={() => void handleShareThemeProfile(p.id)}
                          disabled={!shareEmailInput.trim()}
                          className="shrink-0 rounded bg-indigo-600 px-1.5 py-0.5 text-[10px] font-medium text-white hover:bg-indigo-700 disabled:opacity-60"
                        >
                          Envoyer
                        </button>
                      </div>
                    )}
                    {sharingProfileId === p.id && shareMessage && (
                      <p className={`text-[10px] ${shareMessage.ok ? "text-emerald-600 dark:text-emerald-400" : "text-red-600 dark:text-red-400"}`}>{shareMessage.text}</p>
                    )}
                  </div>
                ))}
                <button
                  type="button"
                  onClick={startNewThemeProfile}
                  disabled={!isAdmin && (profiles?.length ?? 0) >= MAX_PROFILES}
                  className="self-start rounded-lg border border-dashed border-neutral-300 px-1.5 py-0.5 text-[11px] text-neutral-600 disabled:cursor-not-allowed disabled:opacity-50 dark:border-neutral-700 dark:text-neutral-400"
                >
                  + Nouveau
                </button>
              </div>
            )}
            {!isAdmin && (profiles?.length ?? 0) >= MAX_PROFILES && <p className="text-[11px] text-neutral-500">Limite de {MAX_PROFILES} profils atteinte.</p>}

            {editingProfileId && (
              <div className="space-y-2 border-t border-neutral-200 pt-2 dark:border-neutral-800">
                <input
                  type="text"
                  value={draftProfileName}
                  onChange={(e) => setDraftProfileName(e.target.value)}
                  placeholder="Nom du profil"
                  maxLength={60}
                  className={inputClass()}
                />

                <ThemePreviewMockup draft={draftProfile} />

                {(
                  [
                    ["Fond de l'app", "backgroundHue", "backgroundLightness", "backgroundSaturation"],
                    ["Accent (boutons, liens)", "accentHue", "accentLightness", "accentSaturation"],
                    ["Danger (supprimer, erreurs)", "dangerHue", "dangerLightness", "dangerSaturation"],
                    ["Succès (confirmations)", "successHue", "successLightness", "successSaturation"],
                    ["Favoris (★)", "favoriteHue", "favoriteLightness", "favoriteSaturation"],
                  ] as const
                ).map(([label, hueKey, lightnessKey, saturationKey]) => {
                  const hue = draftProfile[hueKey];
                  const lightness = draftProfile[lightnessKey];
                  const saturation = draftProfile[saturationKey];
                  return (
                    <div key={hueKey}>
                      <div className="mb-0.5 flex items-center justify-between text-[11px] text-neutral-600 dark:text-neutral-400">
                        <span>{label}</span>
                        <span
                          className="h-3.5 w-3.5 rounded-full border border-neutral-300 dark:border-neutral-700"
                          style={{ backgroundColor: `oklch(${lightness}% ${(0.18 * saturation) / 100} ${hue})` }}
                          aria-hidden="true"
                        />
                      </div>
                      {/* Retour utilisateur : "je veux aussi que la suggestion de couleur soit
                          au-dessus du curseur de teinte" — voir ThemeSettings.tsx côté desktop. */}
                      <div className="mb-0.5 flex flex-wrap gap-1">
                        {HUE_PRESETS.map((preset) => (
                          <button
                            key={preset.hue}
                            type="button"
                            onClick={() => updateDraftProfile({ [hueKey]: preset.hue } as Partial<CustomThemeConfig>)}
                            title={preset.label}
                            aria-label={`${label} — ${preset.label}`}
                            className={`h-3 w-3 rounded-full border ${hue === preset.hue ? "border-neutral-900 dark:border-white" : "border-neutral-300 dark:border-neutral-700"}`}
                            style={{ backgroundColor: `oklch(65% .2 ${preset.hue})` }}
                          />
                        ))}
                      </div>
                      {/* Retour utilisateur : "améliore [...] la sélection de couleur, rends-la
                          plus complète" — dégradé arc-en-ciel + valeur numérique, voir
                          ThemeSettings.tsx côté desktop pour le même raisonnement. */}
                      <div className="flex items-center gap-1.5">
                        <input
                          type="range"
                          min={0}
                          max={359}
                          value={hue}
                          onChange={(e) => updateDraftProfile({ [hueKey]: Number(e.target.value) } as Partial<CustomThemeConfig>)}
                          className="hue-slider w-full"
                          style={{ background: HUE_GRADIENT }}
                          aria-label={`${label} — teinte`}
                        />
                        <span className="w-7 shrink-0 text-right text-[10px] tabular-nums text-neutral-500">{Math.round(hue)}°</span>
                      </div>
                      <div className="mt-0.5 flex items-center gap-1.5">
                        <input
                          type="range"
                          min={0}
                          max={100}
                          value={lightness}
                          onChange={(e) => updateDraftProfile({ [lightnessKey]: Number(e.target.value) } as Partial<CustomThemeConfig>)}
                          className="w-full"
                          style={{ accentColor: `oklch(${lightness}% ${(0.15 * saturation) / 100} ${hue})` }}
                          aria-label={`${label} — luminosité`}
                        />
                        <span className="w-7 shrink-0 text-right text-[10px] tabular-nums text-neutral-500">{Math.round(lightness)}%</span>
                      </div>
                      {/* Retour utilisateur : "contrôle de la saturation (pas que
                          teinte+luminosité)". */}
                      <div className="flex items-center gap-1.5">
                        <input
                          type="range"
                          min={0}
                          max={100}
                          value={saturation}
                          onChange={(e) => updateDraftProfile({ [saturationKey]: Number(e.target.value) } as Partial<CustomThemeConfig>)}
                          className="w-full"
                          style={{ accentColor: `oklch(${lightness}% ${(0.18 * saturation) / 100} ${hue})` }}
                          aria-label={`${label} — saturation`}
                        />
                        <span className="w-7 shrink-0 text-right text-[10px] tabular-nums text-neutral-500">{Math.round(saturation)}%</span>
                      </div>
                      {/* Retour utilisateur : "tu as aussi enlevé les options de fondu et autre" —
                          raccourcis restaurés pour le fond, en plus du curseur continu. */}
                      {hueKey === "backgroundHue" && (
                        <div className="mt-1 flex gap-1">
                          {SATURATION_PRESETS.map((preset) => (
                            <button
                              key={preset.label}
                              type="button"
                              onClick={() => updateDraftProfile({ backgroundSaturation: preset.value })}
                              className={`flex-1 rounded-lg border px-1.5 py-0.5 text-[10px] ${
                                saturation === preset.value
                                  ? "border-indigo-500 bg-indigo-50 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300"
                                  : "border-neutral-300 text-neutral-700 dark:border-neutral-700 dark:text-neutral-300"
                              }`}
                            >
                              {preset.label}
                            </button>
                          ))}
                        </div>
                      )}
                      {hueKey === "backgroundHue" && (
                        <p className="mt-1 text-[10px] text-neutral-500">
                          Luminosité &lt; 50% = interface sombre, au-delà = claire — bascule aussi les boutons/textes, pas que le fond.
                        </p>
                      )}
                    </div>
                  );
                })}

                <div className="flex flex-wrap items-center gap-2">
                  <button
                    type="button"
                    onClick={() => void handleSaveThemeProfile()}
                    disabled={profileSaveState === "saving"}
                    className="rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-700 disabled:opacity-60"
                  >
                    {profileSaveState === "saving" ? "Enregistrement…" : editingProfileId === "new" ? "Créer" : "Enregistrer"}
                  </button>
                  <button type="button" onClick={handleRandomizeTheme} className="rounded-lg border border-neutral-300 px-2 py-1 text-[11px] text-neutral-700 dark:border-neutral-700 dark:text-neutral-300">
                    🎲
                  </button>
                  <button type="button" onClick={handleResetThemeDraft} className="rounded-lg border border-neutral-300 px-2 py-1 text-[11px] text-neutral-700 dark:border-neutral-700 dark:text-neutral-300">
                    Réinitialiser
                  </button>
                  {profileSaveState === "saved" && <span className="text-[11px] text-emerald-600 dark:text-emerald-400">Synchronisé.</span>}
                </div>

                {/* Retour utilisateur : "exporter/partager un profil avec un code" — pour partager
                    HORS de l'app. Le bouton "↗" sur chaque profil, plus haut, envoie directement
                    le profil à un autre compte de ce serveur. */}
                <div className="space-y-1.5 border-t border-neutral-200 pt-2 dark:border-neutral-800">
                  <p className="text-[10px] text-neutral-500">Ou par un autre moyen (SMS, email…) :</p>
                  <button type="button" onClick={() => void handleCopyThemeCode()} className="rounded-lg border border-neutral-300 px-2 py-1 text-[10px] text-neutral-700 dark:border-neutral-700 dark:text-neutral-300">
                    Copier le code de ce profil
                  </button>
                  <div className="flex items-center gap-1.5">
                    <input
                      type="text"
                      value={themeCodeInput}
                      onChange={(e) => setThemeCodeInput(e.target.value)}
                      placeholder="Coller un code…"
                      className="w-full rounded-lg border border-neutral-300 px-2 py-1 text-[10px] outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
                    />
                    <button
                      type="button"
                      onClick={handleImportThemeCode}
                      disabled={!themeCodeInput.trim()}
                      className="shrink-0 rounded-lg border border-neutral-300 px-2 py-1 text-[10px] text-neutral-700 disabled:cursor-not-allowed disabled:opacity-50 dark:border-neutral-700 dark:text-neutral-300"
                    >
                      Importer
                    </button>
                  </div>
                  {themeCodeMessage && <p className={`text-[10px] ${themeCodeMessage.ok ? "text-emerald-600 dark:text-emerald-400" : "text-red-600 dark:text-red-400"}`}>{themeCodeMessage.text}</p>}
                </div>
              </div>
            )}
          </div>
        )}
      </Section>

      <Section title="Sécurité">
        <label className="mb-1 block text-xs text-neutral-500">Verrouiller après une popup fermée depuis plus de…</label>
        <select value={lockMinutes} onChange={(e) => handleSaveLockMinutes(Number(e.target.value))} className={inputClass()}>
          {LOCK_MINUTES_OPTIONS.map((m) => (
            <option key={m} value={m}>
              {m} minute{m > 1 ? "s" : ""}
            </option>
          ))}
        </select>
        <label className="mb-1 mt-3 block text-xs text-neutral-500">Effacer le presse-papiers après…</label>
        <select value={clipboardSeconds} onChange={(e) => handleSaveClipboardSeconds(Number(e.target.value))} className={inputClass()}>
          {CLIPBOARD_SECONDS_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {s === 0 ? "Jamais" : `${s} secondes`}
            </option>
          ))}
        </select>
        <label className="mb-1 mt-3 block text-xs text-neutral-500">Fenêtre séparée (ne se ferme pas si tu cliques ailleurs)</label>
        <select value={windowMode} onChange={(e) => handleSaveWindowMode(e.target.value as WindowMode)} className={inputClass()}>
          <option value="always">Toujours</option>
          <option value="tfa">Seulement pour saisir le code de vérification</option>
          <option value="never">Jamais (rester en popup classique)</option>
        </select>
        <p className="mt-1 text-xs text-neutral-500">
          {windowMode === "always" &&
            "L'extension s'ouvre toujours dans une vraie fenêtre — pratique à garder ouverte à côté, ne se ferme jamais en cliquant ailleurs."}
          {windowMode === "tfa" &&
            "Une petite fenêtre s'ouvre uniquement le temps de saisir le code — elle ne se ferme pas si tu vas consulter tes emails ailleurs, puis se referme une fois le code validé."}
          {windowMode === "never" &&
            "Reste toujours en popup classique — se ferme dès qu'on clique ailleurs, y compris pour aller lire le code reçu par email."}
        </p>
      </Section>

      <Section title="Compte">
        <p className="mb-2 text-xs text-neutral-500">Email actuel : {email}</p>
        {(isModerator === true || canChangeEmailViaExtension) && (
          <form onSubmit={handleChangeEmail} className="flex flex-col gap-2">
            <input
              type="email"
              required
              placeholder="Nouvel email"
              value={newEmail}
              onChange={(e) => setNewEmail(e.target.value)}
              className={inputClass()}
            />
            <input
              type="password"
              required
              placeholder="Mot de passe maître actuel"
              value={emailPassword}
              onChange={(e) => setEmailPassword(e.target.value)}
              className={inputClass()}
            />
            {emailError && <p className="text-sm text-red-600 dark:text-red-400">{emailError}</p>}
            <button
              type="submit"
              disabled={isChangingEmail}
              className="self-start rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-60"
            >
              {isChangingEmail ? "Changement…" : "Changer l'email"}
            </button>
          </form>
        )}
      </Section>

      <Section title="Appareils de confiance">
        {deviceError && <p className="mb-2 text-sm text-red-600 dark:text-red-400">{deviceError}</p>}
        {devices === null && !deviceError && <p className="text-sm text-neutral-500">Chargement…</p>}
        <ul className="flex flex-col gap-2">
          {(devices ?? []).map((d) => (
            <li key={d.device_id} className="rounded-lg border border-neutral-200 p-2 dark:border-neutral-800">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate text-sm text-neutral-900 dark:text-neutral-100">
                  {d.device_name || "Appareil sans nom"} {d.device_id === currentDeviceId && "(cet appareil)"}
                </span>
                <button
                  disabled={busyDeviceId === d.device_id}
                  onClick={() => void handleRevokeDevice(d.device_id)}
                  className="shrink-0 rounded-md border border-red-300 px-2 py-1 text-xs text-red-600 hover:bg-red-50 disabled:opacity-60 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
                >
                  Révoquer
                </button>
              </div>
              <p className="mt-1 text-xs text-neutral-500">
                Dernière utilisation : {new Date(d.last_used_at).toLocaleString()}
                {d.last_ip && <> · IP : {d.last_ip}</>}
              </p>
            </li>
          ))}
        </ul>

        <div className="mt-3 flex flex-col gap-2">
          <button onClick={() => setShowLimitForm((v) => !v)} className="self-start text-xs text-indigo-600 hover:underline dark:text-indigo-400">
            {showLimitForm ? "Masquer" : "Modifier la limite d'appareils"}
          </button>
          {showLimitForm && (
            <form onSubmit={handleSaveLimit} className="flex flex-col gap-2">
              <input
                type="number"
                min={1}
                value={newLimit}
                onChange={(e) => setNewLimit(Number(e.target.value))}
                className={inputClass()}
              />
              <input
                type="password"
                required
                placeholder="Mot de passe maître"
                value={limitPassword}
                onChange={(e) => setLimitPassword(e.target.value)}
                className={inputClass()}
              />
              <button type="submit" className="self-start rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-700">
                Enregistrer la limite
              </button>
            </form>
          )}
          <button onClick={() => void handleLogoutAll()} className="self-start text-xs text-red-600 hover:underline dark:text-red-400">
            Déconnecter tous les appareils
          </button>
        </div>
      </Section>
    </div>
  );
}
