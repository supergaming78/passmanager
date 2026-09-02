import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { useAuth } from "../state/AuthContext";
import { openEmergencyVault, closeEmergencyVault } from "../lib/emergencyAccess";
import { openEntryUrl } from "../lib/openExternalUrl";
import { copyPasswordWithAutoClear } from "../lib/clipboard";
import { getErrorMessage } from "../lib/errors";
import type { PlainVaultEntry } from "../lib/vaultCrypto";
import { getPreferredIdentifier } from "../lib/entryIdentifier";

/** Consultation d'urgence d'un coffre distant, en LECTURE SEULE — voir lib/emergencyAccess.ts
 * pour le déchiffrement (Zero-Knowledge de bout en bout, la clé du coffre distant ne quitte
 * jamais le processus Rust). Referme systématiquement l'accès en quittant l'écran (voir le
 * nettoyage de l'effet ci-dessous), qu'on parte volontairement ou par navigation ailleurs. */
export default function EmergencyVaultPage() {
  const { id } = useParams<{ id: string }>();
  const { authorizedRequest } = useAuth();

  const [entries, setEntries] = useState<PlainVaultEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [revealedId, setRevealedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;

    (async () => {
      setIsLoading(true);
      setError(null);
      try {
        const decrypted = await openEmergencyVault(authorizedRequest, id);
        if (cancelled) {
          // CORRECTIF SÉCURITÉ : le composant a été démonté PENDANT que openEmergencyVault()
          // était encore en vol (ses propres appels réseau, avant même d'atteindre
          // tauri.unlockEmergencyVault) — l'appel à closeEmergencyVault() du nettoyage ci-dessous
          // s'est donc exécuté trop tôt, sur un coffre pas encore déverrouillé (no-op). Sans ce
          // second appel, la clé du coffre D'URGENCE resterait déverrouillée indéfiniment côté
          // Rust, sans qu'aucun composant ne soit plus là pour jamais la reverrouiller.
          void closeEmergencyVault();
          return;
        }
        setEntries(decrypted);
      } catch (err) {
        if (!cancelled) setError(getErrorMessage(err));
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    })();

    return () => {
      cancelled = true;
      void closeEmergencyVault();
    };
  }, [id, authorizedRequest]);

  async function handleCopyPassword(entry: PlainVaultEntry) {
    await copyPasswordWithAutoClear(entry.password);
    setCopiedId(entry.id);
    setTimeout(() => setCopiedId((current) => (current === entry.id ? null : current)), 1500);
  }

  if (!id) return null;

  return (
    <main className="min-h-screen bg-neutral-50 px-4 py-8 dark:bg-neutral-950">
      {/* Largeur progressive tablette/desktop — voir le commentaire équivalent dans Vault.tsx. */}
      <div className="mx-auto max-w-2xl md:max-w-3xl lg:max-w-4xl xl:max-w-6xl 2xl:max-w-[100rem]">
        {/* Plus de lien "← Retour" ici (retour utilisateur, 2026-09-02) : redondant maintenant
         * que la navigation vit dans components/AppShell.tsx ("Réglages" y est toujours
         * accessible d'un clic). */}
        <header className="mb-6">
          <h1 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">Coffre d'urgence (lecture seule)</h1>
          <p className="text-sm text-neutral-500">Consultation via l'accès d'urgence — aucune modification possible.</p>
        </header>

        {isLoading ? (
          <p className="text-sm text-neutral-500">Déchiffrement en cours…</p>
        ) : error ? (
          <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
        ) : entries.length === 0 ? (
          <p className="text-sm text-neutral-500">Ce coffre ne contient aucune entrée.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {entries.map((entry) => (
              <li
                key={entry.id}
                className="flex items-start justify-between gap-3 rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900"
              >
                <div className="min-w-0 flex-1">
                  <p className="truncate font-medium text-neutral-900 dark:text-neutral-100">{entry.siteName}</p>
                  <p className="truncate text-sm text-neutral-500">
                    {getPreferredIdentifier(entry) || "—"}
                  </p>
                  {revealedId === entry.id && (
                    <p className="mt-1 select-all font-mono text-sm text-neutral-700 dark:text-neutral-300">{entry.password}</p>
                  )}
                  {entry.notes && <p className="mt-1 whitespace-pre-wrap text-xs text-neutral-500">{entry.notes}</p>}
                </div>
                <div className="ml-3 flex shrink-0 flex-wrap justify-end gap-1.5">
                  {entry.url && (
                    <button
                      type="button"
                      onClick={() => void openEntryUrl(entry.url)}
                      className="rounded-lg border border-neutral-300 px-2.5 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                    >
                      Ouvrir le site
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => setRevealedId((current) => (current === entry.id ? null : entry.id))}
                    className="rounded-lg border border-neutral-300 px-2.5 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                  >
                    {revealedId === entry.id ? "Cacher" : "Voir"}
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleCopyPassword(entry)}
                    className="rounded-lg border border-neutral-300 px-2.5 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                  >
                    {copiedId === entry.id ? "Copié !" : "Copier"}
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </main>
  );
}
