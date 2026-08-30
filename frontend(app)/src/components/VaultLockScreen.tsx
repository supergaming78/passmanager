import { useEffect, useState, type FormEvent } from "react";
import { useAuth } from "../state/AuthContext";
import { getErrorMessage } from "../lib/errors";
import * as tauri from "../api/tauri";

/** Écran plein cadre affiché par-dessus toute page protégée quand le coffre est verrouillé (voir
 * AuthContext.tsx::isVaultLocked) — la session reste active (tokens valides), seul le mot de
 * passe maître est redemandé pour re-dériver la clé côté Rust. "Se déconnecter" reste accessible
 * comme échappatoire (ex: mot de passe oublié — repasse alors par le flux normal de connexion).
 * Si le déverrouillage rapide (Windows Hello) a été activé au préalable (voir Réglages), un
 * bouton alternatif l'évite — le mot de passe maître reste toujours utilisable en repli. */
export default function VaultLockScreen() {
  const { email, unlockVault, quickUnlockVault, logout } = useAuth();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [quickUnlockAvailable, setQuickUnlockAvailable] = useState(false);
  const [isQuickUnlocking, setIsQuickUnlocking] = useState(false);

  useEffect(() => {
    tauri
      .isQuickUnlockAvailable()
      .then(setQuickUnlockAvailable)
      .catch(() => setQuickUnlockAvailable(false));
  }, []);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);
    try {
      await unlockVault(password);
      setPassword("");
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleQuickUnlock() {
    setError(null);
    setIsQuickUnlocking(true);
    try {
      await quickUnlockVault();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsQuickUnlocking(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-neutral-50 px-4 dark:bg-neutral-950">
      <div className="w-full max-w-sm rounded-2xl border border-neutral-200 bg-white p-6 shadow-xl dark:border-neutral-800 dark:bg-neutral-900">
        <div className="mb-1 text-3xl">🔒</div>
        <h1 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">Coffre verrouillé</h1>
        <p className="mt-1 text-sm text-neutral-500">{email}</p>

        {quickUnlockAvailable && (
          <>
            <button
              type="button"
              onClick={() => void handleQuickUnlock()}
              disabled={isQuickUnlocking}
              className="mt-4 w-full rounded-lg border border-neutral-300 px-4 py-2 text-sm font-medium text-neutral-700 transition hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-60 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              {isQuickUnlocking ? "…" : "🔓 Déverrouiller avec Windows Hello"}
            </button>
            <div className="my-3 flex items-center gap-2 text-xs text-neutral-400">
              <div className="h-px flex-1 bg-neutral-200 dark:bg-neutral-800" />
              ou
              <div className="h-px flex-1 bg-neutral-200 dark:bg-neutral-800" />
            </div>
          </>
        )}

        <form onSubmit={handleSubmit} className={quickUnlockAvailable ? "flex flex-col gap-3" : "mt-4 flex flex-col gap-3"}>
          <div>
            <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">Mot de passe maître</label>
            <input
              type="password"
              required
              autoFocus
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-lg border border-neutral-300 px-3 py-2 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
            />
          </div>

          {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}

          <button
            type="submit"
            disabled={isSubmitting}
            className="mt-1 w-full rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isSubmitting ? "…" : "Déverrouiller"}
          </button>
          <button
            type="button"
            onClick={() => void logout()}
            className="text-center text-xs text-neutral-500 hover:underline"
          >
            Se déconnecter
          </button>
        </form>
      </div>
    </div>
  );
}
