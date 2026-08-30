import { useEffect, useState } from "react";
import { useAuth } from "../state/AuthContext";
import * as tauri from "../api/tauri";
import { getErrorMessage } from "../lib/errors";
import {
  getAutoLockMinutes,
  getClipboardClearSeconds,
  getLockOnFocusLossDelaySeconds,
  setAutoLockMinutes,
  setClipboardClearSeconds,
  setLockOnFocusLossDelaySeconds,
} from "../lib/settings";

const LOCK_OPTIONS = [
  { value: 1, label: "1 minute" },
  { value: 5, label: "5 minutes" },
  { value: 15, label: "15 minutes" },
  { value: 30, label: "30 minutes" },
  { value: 0, label: "Jamais" },
];

const CLIPBOARD_OPTIONS = [
  { value: 10, label: "10 secondes" },
  { value: 20, label: "20 secondes" },
  { value: 60, label: "1 minute" },
  { value: 0, label: "Jamais" },
];

const FOCUS_LOSS_OPTIONS = [
  { value: 5, label: "5 secondes" },
  { value: 15, label: "15 secondes" },
  { value: 30, label: "30 secondes" },
  { value: 60, label: "1 minute" },
  { value: 0, label: "Désactivé" },
];

/** Réglages des deux minuteurs de sécurité de l'app — verrouillage auto du coffre par inactivité
 * (voir state/AuthContext.tsx::isVaultLocked) et effacement auto du presse-papiers après copie
 * d'un mot de passe (voir pages/Vault.tsx::handleCopyPassword) — plus un bouton pour verrouiller
 * immédiatement. Purement local à cet appareil (localStorage) — pas partagé entre appareils. */
export default function AutoLockSettings() {
  const { lockVaultNow } = useAuth();
  const [lockMinutes, setLockMinutes] = useState(() => getAutoLockMinutes());
  const [clipboardSeconds, setClipboardSeconds] = useState(() => getClipboardClearSeconds());
  const [focusLossDelay, setFocusLossDelay] = useState(() => getLockOnFocusLossDelaySeconds());
  const [quickUnlockEnabled, setQuickUnlockEnabled] = useState(false);
  const [quickUnlockError, setQuickUnlockError] = useState<string | null>(null);
  const [isTogglingQuickUnlock, setIsTogglingQuickUnlock] = useState(false);

  useEffect(() => {
    tauri
      .isQuickUnlockAvailable()
      .then(setQuickUnlockEnabled)
      .catch(() => setQuickUnlockEnabled(false));
  }, []);

  async function handleQuickUnlockToggle(checked: boolean) {
    setQuickUnlockError(null);
    setIsTogglingQuickUnlock(true);
    try {
      if (checked) {
        await tauri.enableQuickUnlock();
      } else {
        await tauri.disableQuickUnlock();
      }
      setQuickUnlockEnabled(checked);
    } catch (err) {
      setQuickUnlockError(getErrorMessage(err));
    } finally {
      setIsTogglingQuickUnlock(false);
    }
  }

  function handleLockChange(value: number) {
    setLockMinutes(value);
    setAutoLockMinutes(value);
  }

  function handleFocusLossDelayChange(value: number) {
    setFocusLossDelay(value);
    setLockOnFocusLossDelaySeconds(value);
  }

  function handleClipboardChange(value: number) {
    setClipboardSeconds(value);
    setClipboardClearSeconds(value);
  }

  return (
    <div className="flex flex-col gap-4">
      <div>
        <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
          Verrouiller le coffre automatiquement après
        </label>
        <select
          value={lockMinutes}
          onChange={(e) => handleLockChange(Number(e.target.value))}
          className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
        >
          {LOCK_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        <p className="mt-1 text-xs text-neutral-500">Après ce délai d'inactivité, le mot de passe maître sera redemandé.</p>
      </div>

      <div>
        <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
          Verrouiller si la fenêtre reste sans focus (ou réduite) plus de
        </label>
        <select
          value={focusLossDelay}
          onChange={(e) => handleFocusLossDelayChange(Number(e.target.value))}
          className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
        >
          {FOCUS_LOSS_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        <p className="mt-1 text-xs text-neutral-500">
          Un simple alt-tab ou l'ouverture d'une boîte de dialogue (export/import) ne compte pas —
          seule une absence prolongée déclenche le verrouillage.
        </p>
      </div>

      <div>
        <label className="flex items-center gap-2 text-sm text-neutral-700 dark:text-neutral-300">
          <input
            type="checkbox"
            checked={quickUnlockEnabled}
            disabled={isTogglingQuickUnlock}
            onChange={(e) => void handleQuickUnlockToggle(e.target.checked)}
            className="rounded border-neutral-300 text-indigo-600 focus:ring-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
          />
          Déverrouillage rapide (Windows Hello)
        </label>
        <p className="mt-1 text-xs text-neutral-500">
          Redéverrouiller le coffre par empreinte/visage/code PIN plutôt que ressaisir le mot de
          passe maître à chaque fois — celui-ci reste toujours utilisable en repli. Windows
          uniquement ; la clé protégée reste liée à ce compte Windows précis.
        </p>
        {quickUnlockError && <p className="mt-1 text-xs text-red-600 dark:text-red-400">{quickUnlockError}</p>}
      </div>

      <div>
        <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
          Vider le presse-papiers après
        </label>
        <select
          value={clipboardSeconds}
          onChange={(e) => handleClipboardChange(Number(e.target.value))}
          className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
        >
          {CLIPBOARD_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        <p className="mt-1 text-xs text-neutral-500">
          S'applique après avoir copié un mot de passe depuis le coffre. Réglages propres à cet appareil.
        </p>
      </div>

      <button
        type="button"
        onClick={() => void lockVaultNow()}
        className="self-start rounded-lg border border-neutral-300 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
      >
        🔒 Verrouiller maintenant
      </button>
    </div>
  );
}
