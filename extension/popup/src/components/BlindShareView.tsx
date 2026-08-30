// Partage à USAGE LIMITÉ ("aveugle") d'une entrée — liste les partages actifs + formulaire
// d'ajout (email + nombre d'usages). Port réduit de frontend(app)/src/components/BlindShareModal.tsx.
// Différence avec ShareEntryView.tsx (partage classique) : le destinataire ne verra JAMAIS
// l'identifiant ni le mot de passe, seulement le nom du site.

import { useEffect, useState, type FormEvent } from "react";
import * as session from "../lib/session";
import * as blindShare from "../lib/blindShare";
import type { PlainVaultEntry } from "../lib/vaultCrypto";
import type { VaultBlindShare } from "../api/types";
import { getErrorMessage } from "../lib/errors";

export default function BlindShareView({ entry, onBack }: { entry: PlainVaultEntry; onBack: () => void }) {
  const [shares, setShares] = useState<VaultBlindShare[] | null>(null);
  const [email, setEmail] = useState("");
  const [maxUses, setMaxUses] = useState(1);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [isBusy, setIsBusy] = useState(false);

  async function load() {
    try {
      const list = await blindShare.listMyBlindShares(entry.id, session.authorizedRequest);
      setShares(list);
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entry.id]);

  async function handleShare(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setStatus(null);
    setIsBusy(true);
    try {
      await blindShare.sendBlindShare(entry, email, maxUses, session.authorizedRequest);
      setEmail("");
      setMaxUses(1);
      setStatus("Partage créé.");
      await load();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsBusy(false);
    }
  }

  async function handleRevoke(shareId: string) {
    setIsBusy(true);
    setError(null);
    try {
      await blindShare.revokeBlindShare(shareId, session.authorizedRequest);
      setShares((prev) => (prev ? prev.filter((s) => s.id !== shareId) : prev));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsBusy(false);
    }
  }

  return (
    <div className="flex flex-col">
      <div className="flex items-center gap-2 border-b border-neutral-200 px-4 py-3 dark:border-neutral-800">
        <button onClick={onBack} className="text-sm text-neutral-500 hover:underline">
          ← Retour
        </button>
        <h1 className="truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">Partage limité « {entry.siteName} »</h1>
      </div>

      <p className="px-4 pt-2 text-xs text-neutral-500">
        Le destinataire ne verra jamais l'identifiant ni le mot de passe — seulement le nom du
        site — et pourra remplir un formulaire avec (pas copier) le nombre de fois choisi
        ci-dessous. Il doit avoir déjà ouvert son propre écran "Réglages" au moins une fois.
      </p>

      <form onSubmit={handleShare} className="flex flex-col gap-2 px-4 py-3">
        <div className="flex gap-2">
          <input
            type="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="destinataire@example.com"
            className="min-w-0 flex-1 rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
          />
          <input
            type="number"
            min={1}
            max={1000}
            value={maxUses}
            onChange={(e) => setMaxUses(Math.max(1, Math.min(1000, Number(e.target.value) || 1)))}
            title="Nombre d'usages"
            className="w-16 shrink-0 rounded-lg border border-neutral-300 px-2 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
          />
        </div>
        <button
          type="submit"
          disabled={isBusy}
          className="shrink-0 rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-60"
        >
          Partager
        </button>
      </form>

      {status && <p className="px-4 pb-2 text-sm text-green-600 dark:text-green-400">{status}</p>}
      {error && <p className="px-4 pb-2 text-sm text-red-600 dark:text-red-400">{error}</p>}

      {shares === null && !error && <p className="p-4 text-sm text-neutral-500">Chargement…</p>}
      {shares !== null && shares.length === 0 && <p className="px-4 pb-4 text-sm text-neutral-500">Pas encore partagée en usage limité.</p>}

      <ul className="flex flex-col divide-y divide-neutral-200 pb-2 dark:divide-neutral-800">
        {(shares ?? []).map((share) => (
          <li key={share.id} className="flex items-center justify-between gap-2 px-4 py-2">
            <div className="min-w-0">
              <p className="truncate text-sm text-neutral-900 dark:text-neutral-100">{share.shared_with_email}</p>
              <p className="text-xs text-neutral-500">{share.remaining_uses} / {share.max_uses} usage(s) restant(s)</p>
            </div>
            <button
              disabled={isBusy}
              onClick={() => void handleRevoke(share.id)}
              className="shrink-0 rounded-md border border-red-300 px-2 py-1 text-xs text-red-600 hover:bg-red-50 disabled:opacity-60 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
            >
              Retirer
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
