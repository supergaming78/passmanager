import { useEffect, useState } from "react";
import { useAuth } from "../state/AuthContext";
import { listReceivedBlindShares, revokeBlindShare, unlockForOneTimeUse } from "../lib/blindShare";
import type { ReceivedBlindShare } from "../lib/blindShare";
import { getErrorMessage } from "../lib/errors";
import { getListLayout, listContainerClass } from "../lib/listLayout";

/** Copie déjà disponible pour un partage à usage limité DÉJÀ déverrouillé (un "Utiliser" a déjà
 * consommé l'usage) — voir lib/blindShare.ts::unlockForOneTimeUse pour pourquoi ce sont des
 * FONCTIONS de copie, jamais les valeurs elles-mêmes, qui sont gardées en état ici : ce composant
 * ne peut donc jamais afficher, logger, ni exposer l'identifiant/le mot de passe lui-même. */
interface UnlockedHandle {
  copyUsername: () => Promise<void>;
  copyPassword: () => Promise<void>;
}

/** Ce qui a été partagé EN USAGE LIMITÉ avec l'utilisateur courant (voir lib/blindShare.ts, GET
 * /blind-shares/shared-with-me) — voir SharedWithMeSettings.tsx pour l'équivalent du partage
 * classique. Différence : jamais de "Voir", seulement "Utiliser" (consomme un usage) puis des
 * boutons de copie qui n'affichent jamais la valeur copiée. */
export default function BlindSharesReceivedSettings() {
  const { authorizedRequest } = useAuth();

  const [shares, setShares] = useState<ReceivedBlindShare[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [unlocked, setUnlocked] = useState<Record<string, UnlockedHandle>>({});
  const [copiedLabel, setCopiedLabel] = useState<string | null>(null);
  // Réglé dans Réglages (voir components/ListLayoutSettings.tsx) — même préférence que le Coffre.
  const [listLayout] = useState(() => getListLayout());

  async function loadAll() {
    setIsLoading(true);
    setError(null);
    try {
      setShares(await listReceivedBlindShares(authorizedRequest));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    void loadAll();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleUse(share: ReceivedBlindShare) {
    if (!confirm(`Utiliser ce partage pour "${share.siteName}" ? Ceci consomme un usage (${share.remainingUses} restant(s)).`)) return;
    setError(null);
    setBusyId(share.id);
    try {
      const handle = await unlockForOneTimeUse(authorizedRequest, share.id);
      setUnlocked((prev) => ({ ...prev, [share.id]: handle }));
      setShares((prev) => prev.map((s) => (s.id === share.id ? { ...s, remainingUses: handle.remainingUses } : s)));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  async function handleCopyUsername(share: ReceivedBlindShare) {
    await unlocked[share.id]?.copyUsername();
    setCopiedLabel(`${share.id}-username`);
    setTimeout(() => setCopiedLabel((cur) => (cur === `${share.id}-username` ? null : cur)), 1500);
  }

  async function handleCopyPassword(share: ReceivedBlindShare) {
    await unlocked[share.id]?.copyPassword();
    setCopiedLabel(`${share.id}-password`);
    setTimeout(() => setCopiedLabel((cur) => (cur === `${share.id}-password` ? null : cur)), 1500);
  }

  async function handleRevoke(share: ReceivedBlindShare) {
    if (!confirm(`Renoncer à ce partage à usage limité pour "${share.siteName}" ?`)) return;
    setError(null);
    setBusyId(share.id);
    try {
      await revokeBlindShare(authorizedRequest, share.id);
      setShares((prev) => prev.filter((s) => s.id !== share.id));
      setUnlocked((prev) => {
        const next = { ...prev };
        delete next[share.id];
        return next;
      });
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  if (isLoading) return <p className="text-sm text-neutral-500">Chargement…</p>;

  return (
    <div className="flex flex-col gap-3">
      {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
      {shares.length === 0 ? (
        <p className="text-sm text-neutral-500">Aucun partage à usage limité en attente.</p>
      ) : (
        <ul className={listContainerClass(listLayout, "grid-cols-1 sm:grid-cols-2")}>
          {shares.map((share) => (
            <li
              key={share.id}
              className={`flex flex-col gap-2 rounded-lg border border-neutral-200 dark:border-neutral-800 ${
                listLayout === "compact" ? "px-3 py-2" : "p-3"
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <div className="min-w-0">
                  <p className="truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">{share.siteName}</p>
                  <p className="text-xs text-neutral-500">Partagé par {share.ownerEmail} — {share.remainingUses} / {share.maxUses} usage(s) restant(s)</p>
                </div>
                <div className="flex shrink-0 gap-1.5">
                  <button
                    type="button"
                    onClick={() => void handleUse(share)}
                    disabled={busyId === share.id || share.remainingUses <= 0}
                    className="rounded-lg bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    Utiliser
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleRevoke(share)}
                    disabled={busyId === share.id}
                    className="rounded-lg border border-red-300 px-2 py-1 text-xs font-medium text-red-600 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-900 dark:text-red-400 dark:hover:bg-red-950"
                  >
                    Retirer
                  </button>
                </div>
              </div>
              {unlocked[share.id] && (
                <div className="flex gap-1.5 border-t border-neutral-100 pt-2 dark:border-neutral-800">
                  <button
                    type="button"
                    onClick={() => void handleCopyUsername(share)}
                    className="rounded-lg border border-neutral-300 px-2 py-1 text-xs text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                  >
                    {copiedLabel === `${share.id}-username` ? "Copié !" : "Copier l'identifiant"}
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleCopyPassword(share)}
                    className="rounded-lg border border-neutral-300 px-2 py-1 text-xs text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                  >
                    {copiedLabel === `${share.id}-password` ? "Copié !" : "Copier le mot de passe"}
                  </button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
