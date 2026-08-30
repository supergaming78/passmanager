import { useEffect, useState, type FormEvent } from "react";
import { getErrorMessage } from "../lib/errors";
import { listMyBlindShares, revokeBlindShare, sendBlindShare } from "../lib/blindShare";
import type { VaultBlindShare } from "../api/types";
import type { PlainVaultEntry } from "../lib/vaultCrypto";

interface Props {
  entry: PlainVaultEntry;
  authorizedRequest: <T,>(fn: (accessToken: string) => Promise<T>) => Promise<T>;
  onClose: () => void;
}

/** Partage à USAGE LIMITÉ ("aveugle") d'UNE entrée — voir POST/GET/DELETE /vault/{id}/blind-shares
 * et /blind-shares/{id} côté backend, lib/blindShare.ts côté client. Différence avec
 * ShareEntryModal.tsx (partage classique) : le destinataire ne verra JAMAIS l'identifiant ni le
 * mot de passe, seulement le nom du site — et ne pourra "utiliser" ce partage qu'un nombre de fois
 * limité (choisi ici, 1 par défaut). Nécessite que le destinataire ait déjà configuré ses propres
 * clés (visité au moins une fois ses réglages) — sinon le partage échoue avec un message explicite. */
export default function BlindShareModal({ entry, authorizedRequest, onClose }: Props) {
  const [shares, setShares] = useState<VaultBlindShare[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const [newEmail, setNewEmail] = useState("");
  const [maxUses, setMaxUses] = useState(1);
  const [isSharing, setIsSharing] = useState(false);

  async function loadShares() {
    setIsLoading(true);
    setError(null);
    try {
      setShares(await listMyBlindShares(authorizedRequest, entry.id));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    void loadShares();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entry.id]);

  async function handleShare(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setIsSharing(true);
    try {
      await sendBlindShare(authorizedRequest, entry, newEmail.trim().toLowerCase(), maxUses);
      setNewEmail("");
      setMaxUses(1);
      await loadShares();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsSharing(false);
    }
  }

  async function handleRevoke(share: VaultBlindShare) {
    if (!confirm(`Retirer l'accès de "${share.shared_with_email}" à ce partage à usage limité ?`)) return;
    setError(null);
    setBusyId(share.id);
    try {
      await revokeBlindShare(authorizedRequest, share.id);
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
          <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">Partage à usage limité — {entry.siteName}</h2>
          <button type="button" onClick={onClose} className="text-sm text-neutral-500 hover:underline">
            Fermer
          </button>
        </div>
        <p className="mb-4 text-xs text-neutral-500">
          Le destinataire ne verra JAMAIS l'identifiant ni le mot de passe — seulement le nom du
          site — et ne pourra l'utiliser (remplissage automatique côté extension, copie sans
          affichage côté desktop) que le nombre de fois choisi ci-dessous. Le destinataire doit
          avoir déjà visité ses propres réglages une fois.
        </p>

        {isLoading ? (
          <p className="text-sm text-neutral-500">Chargement…</p>
        ) : shares.length === 0 ? (
          <p className="mb-4 text-sm text-neutral-500">Aucun partage à usage limité actif pour cette entrée.</p>
        ) : (
          <ul className="mb-4 flex flex-col gap-2">
            {shares.map((share) => (
              <li
                key={share.id}
                className="flex items-center justify-between gap-2 rounded-lg border border-neutral-200 px-3 py-2 dark:border-neutral-800"
              >
                <div className="min-w-0">
                  <p className="truncate text-sm text-neutral-800 dark:text-neutral-200">{share.shared_with_email}</p>
                  <p className="text-xs text-neutral-500">{share.remaining_uses} / {share.max_uses} usage(s) restant(s)</p>
                </div>
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

        <form onSubmit={handleShare} className="flex flex-col gap-2">
          <div className="flex items-end gap-2">
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
            <div className="w-20 shrink-0">
              <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">Usages</label>
              <input
                type="number"
                min={1}
                max={1000}
                value={maxUses}
                onChange={(e) => setMaxUses(Math.max(1, Math.min(1000, Number(e.target.value) || 1)))}
                className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
              />
            </div>
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
