// Affichage en lecture seule d'une entrée partagée avec moi — port réduit de
// frontend(app)/src/pages/SharedEntryPage.tsx. Jamais modifiable ni renvoyée en PUT.

import { useEffect, useState } from "react";
import * as session from "../lib/session";
import * as entrySharing from "../lib/entrySharing";
import type { PlainVaultEntry } from "../lib/vaultCrypto";
import { getErrorMessage } from "../lib/errors";
import { copyPasswordWithAutoClear } from "../lib/clipboard";

export default function SharedEntryView({ shareId, vaultKey, onBack }: { shareId: string; vaultKey: Uint8Array; onBack: () => void }) {
  const [entry, setEntry] = useState<PlainVaultEntry | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const opened = await entrySharing.openSharedEntry(vaultKey, shareId, session.authorizedRequest);
        if (!cancelled) setEntry(opened);
      } catch (err) {
        if (!cancelled) setError(getErrorMessage(err));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [shareId, vaultKey]);

  async function handleCopy() {
    if (!entry) return;
    await copyPasswordWithAutoClear(entry.password);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="flex flex-col">
      <div className="flex items-center gap-2 border-b border-neutral-200 px-4 py-3 dark:border-neutral-800">
        <button onClick={onBack} className="text-sm text-neutral-500 hover:underline">
          ← Retour
        </button>
        <h1 className="text-sm font-medium text-neutral-900 dark:text-neutral-100">Entrée partagée</h1>
      </div>

      {error && <p className="px-4 pt-2 text-sm text-red-600 dark:text-red-400">{error}</p>}
      {!entry && !error && <p className="p-4 text-sm text-neutral-500">Déchiffrement…</p>}

      {entry && (
        <div className="flex flex-col gap-3 p-4">
          <div>
            <p className="text-xs text-neutral-500">{entry.entryType === "login" ? "Site / application" : "Nom"}</p>
            <p className="text-sm font-medium text-neutral-900 dark:text-neutral-100">{entry.siteName}</p>
          </div>
          {(entry.username || entry.loginEmail) && (
            <div>
              <p className="text-xs text-neutral-500">Identifiant</p>
              <p className="text-sm text-neutral-900 dark:text-neutral-100">
                {entry.preferredLoginType === "email" ? entry.loginEmail : entry.username || entry.loginEmail}
              </p>
            </div>
          )}
          <div>
            <p className="text-xs text-neutral-500">Mot de passe</p>
            <div className="flex items-center gap-2">
              <p className="text-sm text-neutral-900 dark:text-neutral-100">{showPassword ? entry.password : "••••••••"}</p>
              <button onClick={() => setShowPassword((s) => !s)} className="text-xs text-indigo-600 hover:underline dark:text-indigo-400">
                {showPassword ? "Cacher" : "Voir"}
              </button>
              <button onClick={() => void handleCopy()} className="text-xs text-indigo-600 hover:underline dark:text-indigo-400">
                {copied ? "Copié !" : "Copier"}
              </button>
            </div>
          </div>
          {entry.url && (
            <button
              onClick={() => window.open(entry.url, "_blank", "noopener,noreferrer")}
              className="self-start rounded-md border border-neutral-300 px-2 py-1 text-xs text-neutral-600 hover:bg-neutral-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              Ouvrir le site
            </button>
          )}
          {entry.notes && (
            <div>
              <p className="text-xs text-neutral-500">Notes</p>
              <p className="whitespace-pre-wrap text-sm text-neutral-900 dark:text-neutral-100">{entry.notes}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
