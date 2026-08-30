import { useEffect, useState } from "react";
import * as api from "../api/client";
import * as tauri from "../api/tauri";
import { getErrorMessage } from "../lib/errors";
import type { PlainVaultEntry } from "../lib/vaultCrypto";

interface PlainHistoryRow {
  id: string;
  password: string;
  changedAt: string;
}

interface Props {
  entry: PlainVaultEntry;
  authorizedRequest: <T,>(fn: (accessToken: string) => Promise<T>) => Promise<T>;
  onClose: () => void;
  /** Remet le mot de passe COURANT de l'entrée à cette ancienne valeur (voir
   * pages/Vault.tsx::handleRestoreHistoricalPassword). */
  onRestore: (oldPassword: string) => void;
}

/** Historique des mots de passe d'UNE entrée (voir GET /vault/{id}/history côté backend) — chaque
 * ligne est déchiffrée individuellement, comme le reste du coffre (jamais de crypto en JS, voir
 * api/tauri.ts). Plafonné à 20 versions par entrée côté serveur (les plus anciennes sont purgées
 * automatiquement). */
export default function VaultHistoryModal({ entry, authorizedRequest, onClose, onRestore }: Props) {
  const [rows, setRows] = useState<PlainHistoryRow[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [revealedId, setRevealedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      setIsLoading(true);
      setError(null);
      try {
        const encrypted = await authorizedRequest((token) => api.getVaultEntryHistory(token, entry.id));
        const decrypted = await Promise.all(
          encrypted.map(async (row) => ({
            id: row.id,
            password: await tauri.decryptField(row.encrypted_password),
            changedAt: row.changed_at,
          })),
        );
        setRows(decrypted);
      } catch (err) {
        setError(getErrorMessage(err));
      } finally {
        setIsLoading(false);
      }
    })();
  }, [entry.id, authorizedRequest]);

  async function handleCopy(row: PlainHistoryRow) {
    await navigator.clipboard.writeText(row.password);
    setCopiedId(row.id);
    setTimeout(() => setCopiedId((current) => (current === row.id ? null : current)), 1500);
  }

  return (
    <div className="fixed inset-0 z-10 flex items-center justify-center bg-black/40 px-4 py-8">
      <div className="max-h-full w-full max-w-md overflow-y-auto rounded-2xl bg-white p-6 shadow-xl dark:bg-neutral-900">
        <div className="mb-1 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">Historique — {entry.siteName}</h2>
          <button type="button" onClick={onClose} className="text-sm text-neutral-500 hover:underline">
            Fermer
          </button>
        </div>
        <p className="mb-4 text-xs text-neutral-500">Anciens mots de passe, du plus récent au plus ancien (20 maximum conservés).</p>

        {isLoading ? (
          <p className="text-sm text-neutral-500">Chargement…</p>
        ) : error ? (
          <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
        ) : rows.length === 0 ? (
          <p className="text-sm text-neutral-500">
            Aucun historique pour cette entrée — il se remplit à chaque changement réel du mot de passe.
          </p>
        ) : (
          <ul className="flex flex-col gap-2">
            {rows.map((row) => (
              <li key={row.id} className="rounded-lg border border-neutral-200 p-3 dark:border-neutral-800">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs text-neutral-500">{new Date(row.changedAt).toLocaleString()}</span>
                  <div className="flex shrink-0 gap-1.5">
                    <button
                      type="button"
                      onClick={() => setRevealedId((current) => (current === row.id ? null : row.id))}
                      className="rounded-lg border border-neutral-300 px-2 py-0.5 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                    >
                      {revealedId === row.id ? "Cacher" : "Voir"}
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleCopy(row)}
                      className="rounded-lg border border-neutral-300 px-2 py-0.5 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                    >
                      {copiedId === row.id ? "Copié !" : "Copier"}
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        if (confirm("Remettre ce mot de passe comme mot de passe actuel de cette entrée ?")) {
                          onRestore(row.password);
                        }
                      }}
                      className="rounded-lg border border-indigo-300 px-2 py-0.5 text-xs font-medium text-indigo-700 hover:bg-indigo-50 dark:border-indigo-800 dark:text-indigo-300 dark:hover:bg-indigo-950"
                    >
                      Restaurer
                    </button>
                  </div>
                </div>
                {revealedId === row.id && (
                  <p className="mt-1.5 select-all break-all font-mono text-sm text-neutral-700 dark:text-neutral-300">{row.password}</p>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
