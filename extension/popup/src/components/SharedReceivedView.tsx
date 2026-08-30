// Tout ce qui a été partagé AVEC moi — les DEUX mécanismes de partage "reçus" réunis sur un même
// écran, accessible directement depuis la barre du coffre (PAS deux boutons séparés comme
// auparavant). Le coffre partagé familial reste sur son propre écran dédié
// (SharedVaultsListView.tsx) : c'est une ressource commune à plusieurs membres, pas quelque chose
// qu'on "reçoit" ponctuellement de la même façon que ces deux-là.

import { useEffect, useState } from "react";
import * as session from "../lib/session";
import * as entrySharing from "../lib/entrySharing";
import * as blindShare from "../lib/blindShare";
import type { SharedWithMeEntry } from "../api/types";
import type { ReceivedBlindShare } from "../lib/blindShare";
import { getErrorMessage } from "../lib/errors";

export default function SharedReceivedView({
  vaultKey,
  onBack,
  onViewClassic,
}: {
  vaultKey: Uint8Array;
  onBack: () => void;
  onViewClassic: (shareId: string) => void;
}) {
  const [classicShares, setClassicShares] = useState<SharedWithMeEntry[] | null>(null);
  const [blindShares, setBlindShares] = useState<ReceivedBlindShare[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [filledId, setFilledId] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      try {
        setClassicShares(await entrySharing.listSharedWithMe(session.authorizedRequest));
      } catch (err) {
        setError(getErrorMessage(err));
      }
      try {
        setBlindShares(await blindShare.listReceivedBlindShares(vaultKey, session.authorizedRequest));
      } catch (err) {
        setError(getErrorMessage(err));
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vaultKey]);

  async function handleRevokeClassic(shareId: string) {
    setBusyId(shareId);
    setError(null);
    try {
      await entrySharing.revokeShare(shareId, session.authorizedRequest);
      setClassicShares((prev) => (prev ? prev.filter((s) => s.id !== shareId) : prev));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  async function handleUseBlind(share: ReceivedBlindShare) {
    if (!confirm(`Utiliser ce partage pour "${share.siteName}" sur l'onglet actif ? Ceci consomme un usage (${share.remainingUses} restant(s)).`)) return;
    setError(null);
    setBusyId(share.id);
    try {
      const { result, remainingUses } = await blindShare.useBlindShareAndFill(share.id, vaultKey, session.authorizedRequest);
      if (!result.passwordFilled) {
        setError("Aucun champ mot de passe trouvé sur cette page — l'usage a quand même été consommé.");
      } else {
        setFilledId(share.id);
        setTimeout(() => setFilledId((cur) => (cur === share.id ? null : cur)), 1500);
      }
      setBlindShares((prev) => (prev ? prev.map((s) => (s.id === share.id ? { ...s, remainingUses } : s)) : prev));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  async function handleRevokeBlind(shareId: string) {
    setBusyId(shareId);
    setError(null);
    try {
      await blindShare.revokeBlindShare(shareId, session.authorizedRequest);
      setBlindShares((prev) => (prev ? prev.filter((s) => s.id !== shareId) : prev));
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
        <h1 className="text-sm font-medium text-neutral-900 dark:text-neutral-100">Partagé avec moi</h1>
      </div>

      {error && <p className="px-4 pt-2 text-sm text-red-600 dark:text-red-400">{error}</p>}

      <div className="px-4 pt-3">
        <h2 className="text-xs font-semibold text-neutral-500">Partage classique</h2>
      </div>
      {classicShares === null ? (
        <p className="px-4 py-2 text-sm text-neutral-500">Chargement…</p>
      ) : classicShares.length === 0 ? (
        <p className="px-4 py-2 text-sm text-neutral-500">Rien n'a été partagé avec toi.</p>
      ) : (
        <ul className="flex flex-col divide-y divide-neutral-200 pb-2 dark:divide-neutral-800">
          {classicShares.map((share) => (
            <li key={share.id} className="flex items-center justify-between gap-2 px-4 py-2">
              <span className="truncate text-sm text-neutral-900 dark:text-neutral-100">Partagé par {share.owner_email}</span>
              <div className="flex shrink-0 items-center gap-2">
                <button
                  onClick={() => onViewClassic(share.id)}
                  className="rounded-md bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-700"
                >
                  Voir
                </button>
                <button
                  disabled={busyId === share.id}
                  onClick={() => void handleRevokeClassic(share.id)}
                  className="rounded-md border border-red-300 px-2 py-1 text-xs text-red-600 hover:bg-red-50 disabled:opacity-60 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
                >
                  Quitter
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}

      <div className="border-t border-neutral-200 px-4 pt-3 dark:border-neutral-800">
        <h2 className="text-xs font-semibold text-neutral-500">Partage à usage limité</h2>
        <p className="pt-1 text-xs text-neutral-500">
          Assure-toi d'être sur le bon site avant de cliquer "Utiliser" — chaque clic consomme un usage.
        </p>
      </div>
      {blindShares === null ? (
        <p className="px-4 py-2 text-sm text-neutral-500">Chargement…</p>
      ) : blindShares.length === 0 ? (
        <p className="px-4 py-2 text-sm text-neutral-500">Rien n'a été partagé avec toi en usage limité.</p>
      ) : (
        <ul className="flex flex-col divide-y divide-neutral-200 pb-2 dark:divide-neutral-800">
          {blindShares.map((share) => (
            <li key={share.id} className="flex items-center justify-between gap-2 px-4 py-2">
              <div className="min-w-0">
                <p className="truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">{share.siteName}</p>
                <p className="truncate text-xs text-neutral-500">Partagé par {share.ownerEmail} — {share.remainingUses} / {share.maxUses} usage(s)</p>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                <button
                  disabled={busyId === share.id || share.remainingUses <= 0}
                  onClick={() => void handleUseBlind(share)}
                  className="rounded-md bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {filledId === share.id ? "Rempli !" : "Utiliser"}
                </button>
                <button
                  disabled={busyId === share.id}
                  onClick={() => void handleRevokeBlind(share.id)}
                  className="rounded-md border border-red-300 px-2 py-1 text-xs text-red-600 hover:bg-red-50 disabled:opacity-60 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
                >
                  Retirer
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
