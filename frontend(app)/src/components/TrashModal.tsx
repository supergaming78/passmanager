import { useEffect, useState, useCallback } from "react";
import { useAuth } from "../state/AuthContext";
import * as api from "../api/client";
import { decryptTrashedEntry, type PlainTrashedEntry } from "../lib/vaultCrypto";
import { getErrorMessage } from "../lib/errors";

/** Liste les entrées supprimées (suppression douce, voir delete_vault_entry() côté backend) —
 * récupérables pendant 30 jours avant purge automatique. Pas de mot de passe affiché ici (le
 * backend ne le renvoie pas pour cet écran) : il faut restaurer l'entrée pour le revoir. */
export default function TrashModal({ onClose, onRestored }: { onClose: () => void; onRestored: () => void }) {
  const { authorizedRequest } = useAuth();
  const [entries, setEntries] = useState<PlainTrashedEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const trashed = await authorizedRequest((token) => api.getTrash(token));
      setEntries(await Promise.all(trashed.map(decryptTrashedEntry)));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
  }, [authorizedRequest]);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleRestore(id: string) {
    setBusyId(id);
    setError(null);
    try {
      await authorizedRequest((token) => api.restoreVaultEntry(token, id));
      setEntries((prev) => prev.filter((e) => e.id !== id));
      onRestored();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  async function handlePurge(id: string, siteName: string) {
    if (!confirm(`Supprimer définitivement "${siteName}" ? Aucun retour en arrière possible.`)) return;
    setBusyId(id);
    setError(null);
    try {
      await authorizedRequest((token) => api.permanentlyDeleteVaultEntry(token, id));
      setEntries((prev) => prev.filter((e) => e.id !== id));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="fixed inset-0 z-10 flex items-center justify-center bg-black/40 px-4 py-8">
      <div className="max-h-full w-full max-w-lg overflow-y-auto rounded-2xl border border-neutral-200 bg-white p-6 shadow-xl dark:border-neutral-800 dark:bg-neutral-900">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">Corbeille</h2>
          <button type="button" onClick={onClose} className="text-sm text-neutral-500 hover:underline">
            Fermer
          </button>
        </div>
        <p className="mb-3 text-xs text-neutral-500">
          Les entrées sont purgées automatiquement 30 jours après leur suppression.
        </p>

        {error && <p className="mb-3 text-sm text-red-600 dark:text-red-400">{error}</p>}

        {isLoading ? (
          <p className="text-sm text-neutral-500">Chargement…</p>
        ) : entries.length === 0 ? (
          <p className="text-sm text-neutral-500">La corbeille est vide.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {entries.map((entry) => (
              <li
                key={entry.id}
                className="flex items-center justify-between rounded-lg border border-neutral-200 px-3 py-2 text-sm dark:border-neutral-800"
              >
                <div className="min-w-0">
                  <p className="truncate font-medium text-neutral-800 dark:text-neutral-200">{entry.siteName}</p>
                  <p className="text-xs text-neutral-500">Supprimé le {new Date(entry.deletedAt).toLocaleDateString()}</p>
                </div>
                <div className="flex shrink-0 gap-1.5">
                  <button
                    type="button"
                    disabled={busyId === entry.id}
                    onClick={() => void handleRestore(entry.id)}
                    className="rounded-lg border border-neutral-300 px-2.5 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                  >
                    Restaurer
                  </button>
                  <button
                    type="button"
                    disabled={busyId === entry.id}
                    onClick={() => void handlePurge(entry.id, entry.siteName)}
                    className="rounded-lg border border-red-300 px-2.5 py-1 text-xs font-medium text-red-600 hover:bg-red-50 disabled:opacity-40 dark:border-red-900 dark:text-red-400 dark:hover:bg-red-950"
                  >
                    Purger
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
