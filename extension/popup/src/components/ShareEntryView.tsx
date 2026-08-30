// Partage d'une entrée — liste les destinataires actuels + formulaire d'ajout par email. Port
// réduit de frontend(app)/src/components/ShareEntryModal.tsx.

import { useEffect, useState, type FormEvent } from "react";
import * as session from "../lib/session";
import * as entrySharing from "../lib/entrySharing";
import type { PlainVaultEntry } from "../lib/vaultCrypto";
import type { VaultShare } from "../api/types";
import { getErrorMessage } from "../lib/errors";

export default function ShareEntryView({ entry, onBack }: { entry: PlainVaultEntry; onBack: () => void }) {
  const [shares, setShares] = useState<VaultShare[] | null>(null);
  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [isBusy, setIsBusy] = useState(false);

  async function load() {
    try {
      const list = await entrySharing.listMyShares(entry.id, session.authorizedRequest);
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
      await entrySharing.shareEntry(entry, email, session.authorizedRequest);
      setEmail("");
      setStatus("Entrée partagée.");
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
      await entrySharing.revokeShare(shareId, session.authorizedRequest);
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
        <h1 className="truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">Partager « {entry.siteName} »</h1>
      </div>

      <p className="px-4 pt-2 text-xs text-neutral-500">
        Le destinataire doit avoir déjà ouvert son propre écran "Réglages" au moins une fois (pour publier ses clés).
      </p>

      <form onSubmit={handleShare} className="flex gap-2 px-4 py-3">
        <input
          type="email"
          required
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="destinataire@example.com"
          className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
        />
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
      {shares !== null && shares.length === 0 && <p className="px-4 pb-4 text-sm text-neutral-500">Pas encore partagée.</p>}

      <ul className="flex flex-col divide-y divide-neutral-200 pb-2 dark:divide-neutral-800">
        {(shares ?? []).map((share) => (
          <li key={share.id} className="flex items-center justify-between gap-2 px-4 py-2">
            <span className="truncate text-sm text-neutral-900 dark:text-neutral-100">{share.shared_with_email}</span>
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
