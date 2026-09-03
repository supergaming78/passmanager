// Écran corbeille — port de frontend(app)/src/components/TrashModal.tsx (restauration/purge
// OPTIMISTES : retrait local dès le succès réseau, pas de rechargement complet de la liste).

import { useEffect, useState } from "react";
import * as api from "../api/client";
import * as session from "../lib/session";
import { decryptTrashedEntry, type PlainTrashedEntry } from "../lib/vaultCrypto";
import { getErrorMessage } from "../lib/errors";

export default function TrashView({
  vaultKey,
  onBack,
  onRestored,
}: {
  vaultKey: Uint8Array;
  onBack: () => void;
  onRestored: () => void;
}) {
  const [entries, setEntries] = useState<PlainTrashedEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const raw = await session.authorizedRequest((token) => api.getTrash(token));
        const decrypted = await Promise.all(raw.map((entry) => decryptTrashedEntry(entry, vaultKey)));
        if (!cancelled) setEntries(decrypted);
      } catch (err) {
        if (!cancelled) setError(getErrorMessage(err));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [vaultKey]);

  async function handleRestore(entry: PlainTrashedEntry) {
    setBusyId(entry.id);
    setError(null);
    try {
      await session.authorizedRequest((token) => api.restoreVaultEntry(token, entry.id));
      setEntries((prev) => (prev ? prev.filter((e) => e.id !== entry.id) : prev));
      onRestored();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  async function handlePurge(entry: PlainTrashedEntry) {
    if (!confirm(`Purger définitivement "${entry.siteName}" ? Cette action est irréversible.`)) return;
    setBusyId(entry.id);
    setError(null);
    try {
      await session.authorizedRequest((token) => api.permanentlyDeleteVaultEntry(token, entry.id));
      setEntries((prev) => (prev ? prev.filter((e) => e.id !== entry.id) : prev));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="flex flex-col">
      <div className="flex items-center gap-2 border-b border-neutral-200 px-4 py-3 dark:border-neutral-800">
        <button onClick={onBack} className="text-sm text-neutral-500 hover:underline">
          ← Retour
        </button>
        <h1 className="text-sm font-medium text-neutral-900 dark:text-neutral-100">Corbeille</h1>
      </div>

      <p className="px-4 pt-2 text-xs text-neutral-500">Les entrées sont purgées automatiquement 30 jours après leur suppression.</p>

      {error && <p className="px-4 pt-2 text-sm text-red-600 dark:text-red-400">{error}</p>}

      {entries === null && !error && <p className="p-4 text-sm text-neutral-500">Chargement…</p>}
      {entries !== null && entries.length === 0 && <p className="p-4 text-sm text-neutral-500">La corbeille est vide.</p>}

      <ul className="flex flex-col divide-y divide-neutral-200 pb-2 dark:divide-neutral-800">
        {(entries ?? []).map((entry) => (
          <li key={entry.id} className="vault-row-cv flex items-center justify-between gap-2 px-4 py-2">
            <div className="min-w-0">
              <p className="truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">{entry.siteName}</p>
              <p className="truncate text-xs text-neutral-500">Supprimée le {new Date(entry.deletedAt).toLocaleDateString()}</p>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <button
                disabled={busyId === entry.id}
                onClick={() => void handleRestore(entry)}
                className="rounded-md bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-700 disabled:opacity-60"
              >
                Restaurer
              </button>
              <button
                disabled={busyId === entry.id}
                onClick={() => void handlePurge(entry)}
                className="rounded-md border border-red-300 px-2 py-1 text-xs text-red-600 hover:bg-red-50 disabled:opacity-60 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
              >
                Purger
              </button>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
