import { useEffect, useState, type FormEvent } from "react";
import { getErrorMessage } from "../lib/errors";
import { listMyShares, revokeShare, shareEntry } from "../lib/entrySharing";
import type { VaultShare } from "../api/types";
import type { PlainVaultEntry } from "../lib/vaultCrypto";

interface Props {
  entry: PlainVaultEntry;
  authorizedRequest: <T,>(fn: (accessToken: string) => Promise<T>) => Promise<T>;
  onClose: () => void;
}

/** Partage sécurisé d'UNE entrée (voir POST/GET/DELETE /vault/{id}/shares et /shares/{id} côté
 * backend, lib/entrySharing.ts côté client) — INSTANTANÉ, pas de délai d'attente ni d'acceptation
 * requise contrairement à l'accès d'urgence (voir EmergencyAccessSettings.tsx) : le destinataire
 * voit le partage dès l'appel. Nécessite que le destinataire ait déjà configuré ses propres clés
 * (visité au moins une fois ses réglages) — sinon le partage échoue avec un message explicite. */
export default function ShareEntryModal({ entry, authorizedRequest, onClose }: Props) {
  const [shares, setShares] = useState<VaultShare[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const [newEmail, setNewEmail] = useState("");
  const [isSharing, setIsSharing] = useState(false);

  async function loadShares() {
    setIsLoading(true);
    setError(null);
    try {
      setShares(await listMyShares(authorizedRequest, entry.id));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    void loadShares();
    // eslint pas configuré dans ce projet ; authorizedRequest est stable (voir AuthContext.tsx).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entry.id]);

  async function handleShare(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setIsSharing(true);
    try {
      await shareEntry(authorizedRequest, entry, newEmail.trim().toLowerCase());
      setNewEmail("");
      await loadShares();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsSharing(false);
    }
  }

  async function handleRevoke(share: VaultShare) {
    if (!confirm(`Retirer l'accès de "${share.shared_with_email}" à cette entrée ?`)) return;
    setError(null);
    setBusyId(share.id);
    try {
      await revokeShare(authorizedRequest, share.id);
      setShares((prev) => prev.filter((s) => s.id !== share.id));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="fixed inset-0 z-10 flex items-center justify-center bg-black/40 px-4 py-8">
      <div className="max-h-full w-full max-w-md overflow-y-auto rounded-2xl bg-white p-6 shadow-xl dark:bg-neutral-900">
        <div className="mb-1 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">Partager — {entry.siteName}</h2>
          <button type="button" onClick={onClose} className="text-sm text-neutral-500 hover:underline">
            Fermer
          </button>
        </div>
        <p className="mb-4 text-xs text-neutral-500">
          Chiffré de bout en bout pour le destinataire (lui seul peut le déchiffrer) — accès immédiat, pas de délai
          d'attente. Le destinataire doit avoir déjà visité ses propres réglages une fois.
        </p>

        {isLoading ? (
          <p className="text-sm text-neutral-500">Chargement…</p>
        ) : shares.length === 0 ? (
          <p className="mb-4 text-sm text-neutral-500">Cette entrée n'est partagée avec personne.</p>
        ) : (
          <ul className="mb-4 flex flex-col gap-2">
            {shares.map((share) => (
              <li
                key={share.id}
                className="flex items-center justify-between gap-2 rounded-lg border border-neutral-200 px-3 py-2 dark:border-neutral-800"
              >
                <p className="min-w-0 truncate text-sm text-neutral-800 dark:text-neutral-200">{share.shared_with_email}</p>
                <button
                  type="button"
                  onClick={() => void handleRevoke(share)}
                  disabled={busyId === share.id}
                  className="shrink-0 rounded-lg border border-red-300 px-2 py-1 text-xs font-medium text-red-600 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-900 dark:text-red-400 dark:hover:bg-red-950"
                >
                  Retirer
                </button>
              </li>
            ))}
          </ul>
        )}

        {error && <p className="mb-3 text-sm text-red-600 dark:text-red-400">{error}</p>}

        <form onSubmit={handleShare} className="flex items-end gap-2">
          <div className="min-w-0 flex-1">
            <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">Email du destinataire</label>
            <input
              type="email"
              required
              value={newEmail}
              onChange={(e) => setNewEmail(e.target.value)}
              placeholder="quelqu'un@example.com"
              className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
            />
          </div>
          <button
            type="submit"
            disabled={isSharing}
            className="shrink-0 rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isSharing ? "…" : "Partager"}
          </button>
        </form>
      </div>
    </div>
  );
}
