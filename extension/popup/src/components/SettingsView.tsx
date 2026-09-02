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
import { getTheme, setTheme, getCachedCustomTheme, setCachedCustomTheme, type Theme, type CustomThemeConfig } from "../lib/theme";
import type { TrustedDevice } from "../api/types";
import { getErrorMessage } from "../lib/errors";

const LOCK_MINUTES_OPTIONS = [1, 5, 15, 30];
const CLIPBOARD_SECONDS_OPTIONS = [0, 10, 20, 60];

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
  const [customTheme, setCustomThemeState] = useState<CustomThemeConfig>(() => getCachedCustomTheme());
  const [customThemeSaveState, setCustomThemeSaveState] = useState<"idle" | "saving" | "saved" | "error">("idle");

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
    if (value !== "custom") {
      // Voir ThemeSettings.tsx côté desktop pour le même raisonnement : sans ce DELETE, une
      // personnalisation encore enregistrée côté serveur reviendrait forcer "custom" ici (et sur
      // tous les autres appareils) au prochain lancement (voir App.tsx::syncThemeCustomization).
      void session.authorizedRequest((token) => api.deleteThemeCustomization(token)).catch(() => {});
    }
  }

  function updateCustomTheme(patch: Partial<CustomThemeConfig>) {
    const next = { ...customTheme, ...patch };
    setCustomThemeState(next);
    setCachedCustomTheme(next);
    setCustomThemeSaveState("idle");
  }

  async function handleSaveCustomTheme() {
    setCustomThemeSaveState("saving");
    try {
      await session.authorizedRequest((token) =>
        api.updateThemeCustomization(token, {
          mode: customTheme.mode,
          accent_hue: customTheme.accentHue,
          background_tinted: customTheme.backgroundTinted,
          danger_hue: customTheme.dangerHue,
          success_hue: customTheme.successHue,
          favorite_hue: customTheme.favoriteHue,
        }),
      );
      setCustomThemeSaveState("saved");
    } catch {
      setCustomThemeSaveState("error");
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
            <div className="flex gap-2">
              {(["dark", "light"] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => updateCustomTheme({ mode: m })}
                  className={`flex-1 rounded-lg border px-2 py-1 text-xs ${
                    customTheme.mode === m
                      ? "border-indigo-500 bg-indigo-50 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300"
                      : "border-neutral-300 text-neutral-700 dark:border-neutral-700 dark:text-neutral-300"
                  }`}
                >
                  {m === "dark" ? "Sombre" : "Clair"}
                </button>
              ))}
            </div>

            {(
              [
                ["Accent (boutons, liens)", "accentHue"],
                ["Danger (supprimer, erreurs)", "dangerHue"],
                ["Succès (confirmations)", "successHue"],
                ["Favoris (★)", "favoriteHue"],
              ] as const
            ).map(([label, key]) => (
              <div key={key}>
                <div className="mb-0.5 flex items-center justify-between text-xs text-neutral-600 dark:text-neutral-400">
                  <span>{label}</span>
                  <span
                    className="h-3.5 w-3.5 rounded-full border border-neutral-300 dark:border-neutral-700"
                    style={{ backgroundColor: `oklch(58.5% .233 ${customTheme[key]})` }}
                    aria-hidden="true"
                  />
                </div>
                <input
                  type="range"
                  min={0}
                  max={359}
                  value={customTheme[key]}
                  onChange={(e) => updateCustomTheme({ [key]: Number(e.target.value) } as Partial<CustomThemeConfig>)}
                  className="w-full accent-indigo-600"
                  aria-label={label}
                />
              </div>
            ))}

            <label className="flex items-center gap-2 text-xs text-neutral-700 dark:text-neutral-300">
              <input
                type="checkbox"
                checked={customTheme.backgroundTinted}
                onChange={(e) => updateCustomTheme({ backgroundTinted: e.target.checked })}
                className="h-3.5 w-3.5 rounded border-neutral-300 text-indigo-600 dark:border-neutral-700"
              />
              Teinter aussi le fond avec la couleur d'accent
            </label>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => void handleSaveCustomTheme()}
                disabled={customThemeSaveState === "saving"}
                className="rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-indigo-700 disabled:opacity-60"
              >
                {customThemeSaveState === "saving" ? "Enregistrement…" : "Enregistrer sur ce compte"}
              </button>
              {customThemeSaveState === "saved" && <span className="text-xs text-emerald-600 dark:text-emerald-400">Synchronisé.</span>}
              {customThemeSaveState === "error" && <span className="text-xs text-red-600 dark:text-red-400">Échec — réessaie.</span>}
            </div>
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
