// Coffre d'urgence en lecture seule — port réduit de frontend(app)/src/pages/EmergencyVaultPage.tsx.
// La clé du propriétaire est déverrouillée UNE FOIS à l'ouverture (voir
// emergencyAccess.openEmergencyVault) et reste en mémoire JS locale à ce composant — jamais dans
// chrome.storage.session, voir le plan (accès occasionnel/lecture seule, pas besoin de survivre à
// une fermeture de popup).

import { useEffect, useState } from "react";
import * as session from "../lib/session";
import * as emergencyAccess from "../lib/emergencyAccess";
import type { PlainVaultEntry } from "../lib/vaultCrypto";
import { getErrorMessage } from "../lib/errors";
import { copyPasswordWithAutoClear } from "../lib/clipboard";
import { getPreferredIdentifier } from "../lib/entryIdentifier";
import { openEntryUrl } from "../lib/openExternalUrl";

export default function EmergencyVaultView({
  vaultKey,
  contactId,
  ownerEmail,
  onBack,
}: {
  vaultKey: Uint8Array;
  contactId: string;
  ownerEmail: string;
  onBack: () => void;
}) {
  const [entries, setEntries] = useState<PlainVaultEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revealedId, setRevealedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const opened = await emergencyAccess.openEmergencyVault(vaultKey, contactId, session.authorizedRequest);
        if (!cancelled) setEntries(opened);
      } catch (err) {
        if (!cancelled) setError(getErrorMessage(err));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [vaultKey, contactId]);

  async function handleCopy(entry: PlainVaultEntry) {
    await copyPasswordWithAutoClear(entry.password);
    setCopiedId(entry.id);
    setTimeout(() => setCopiedId((id) => (id === entry.id ? null : id)), 1500);
  }

  return (
    <div className="flex flex-col">
      <div className="flex items-center gap-2 border-b border-neutral-200 px-4 py-3 dark:border-neutral-800">
        <button onClick={onBack} className="text-sm text-neutral-500 hover:underline">
          ← Retour
        </button>
        <h1 className="truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">Coffre de {ownerEmail}</h1>
      </div>

      {error && <p className="px-4 pt-2 text-sm text-red-600 dark:text-red-400">{error}</p>}
      {entries === null && !error && <p className="p-4 text-sm text-neutral-500">Déchiffrement…</p>}
      {entries !== null && entries.length === 0 && <p className="p-4 text-sm text-neutral-500">Ce coffre est vide.</p>}

      <ul className="flex flex-col divide-y divide-neutral-200 pb-2 dark:divide-neutral-800">
        {(entries ?? []).map((entry) => (
          <li key={entry.id} className="flex flex-col gap-1 px-4 py-2">
            <div className="flex items-center justify-between gap-2">
              <div className="min-w-0">
                <p className="truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">{entry.siteName}</p>
                <p className="truncate text-xs text-neutral-500">
                  {getPreferredIdentifier(entry)}
                </p>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                {entry.url && (
                  <button
                    onClick={() => openEntryUrl(entry.url)}
                    className="rounded-md border border-neutral-300 px-2 py-1 text-xs text-neutral-600 hover:bg-neutral-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                  >
                    Ouvrir
                  </button>
                )}
                <button
                  onClick={() => setRevealedId((id) => (id === entry.id ? null : entry.id))}
                  className="rounded-md border border-neutral-300 px-2 py-1 text-xs text-neutral-600 hover:bg-neutral-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                >
                  {revealedId === entry.id ? "Cacher" : "Voir"}
                </button>
                <button
                  onClick={() => void handleCopy(entry)}
                  className="rounded-md bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-700"
                >
                  {copiedId === entry.id ? "Copié !" : "Copier"}
                </button>
              </div>
            </div>
            {revealedId === entry.id && (
              <p className="rounded-md bg-neutral-100 px-2 py-1 text-xs text-neutral-800 dark:bg-neutral-800 dark:text-neutral-200">
                {entry.password}
              </p>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
