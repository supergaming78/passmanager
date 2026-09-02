import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { useAuth } from "../state/AuthContext";
import { openSharedEntry } from "../lib/entrySharing";
import { openEntryUrl } from "../lib/openExternalUrl";
import { copyPasswordWithAutoClear } from "../lib/clipboard";
import { getErrorMessage } from "../lib/errors";
import type { PlainVaultEntry } from "../lib/vaultCrypto";
import { getPreferredIdentifier } from "../lib/entryIdentifier";

/** Consultation d'une entrée partagée avec l'utilisateur courant, en LECTURE SEULE — voir
 * lib/entrySharing.ts::openSharedEntry pour le descellement (Zero-Knowledge de bout en bout, la
 * clé privée ne quitte jamais le processus Rust). Contrairement à EmergencyVaultPage.tsx, aucun
 * état à "refermer" en quittant l'écran : openSharedEntry() est une opération ponctuelle, pas une
 * session qui reste ouverte côté Rust. */
export default function SharedEntryPage() {
  const { id } = useParams<{ id: string }>();
  const { authorizedRequest } = useAuth();

  const [entry, setEntry] = useState<PlainVaultEntry | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isRevealed, setIsRevealed] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!id) return;
    let cancelled = false;

    (async () => {
      setIsLoading(true);
      setError(null);
      try {
        const decrypted = await openSharedEntry(authorizedRequest, id);
        if (!cancelled) setEntry(decrypted);
      } catch (err) {
        if (!cancelled) setError(getErrorMessage(err));
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [id, authorizedRequest]);

  async function handleCopyPassword() {
    if (!entry) return;
    await copyPasswordWithAutoClear(entry.password);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  if (!id) return null;

  return (
    <main className="min-h-screen bg-neutral-50 px-4 py-8 dark:bg-neutral-950">
      {/* Largeur progressive tablette/desktop — voir le commentaire équivalent dans Vault.tsx. */}
      <div className="mx-auto max-w-2xl md:max-w-3xl lg:max-w-4xl">
        {/* Plus de lien "← Retour" ici (retour utilisateur, 2026-09-02) : redondant maintenant
         * que la navigation vit dans components/AppShell.tsx. */}
        <header className="mb-6">
          <h1 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">Entrée partagée (lecture seule)</h1>
          <p className="text-sm text-neutral-500">Partagée avec vous — aucune modification possible.</p>
        </header>

        {isLoading ? (
          <p className="text-sm text-neutral-500">Déchiffrement en cours…</p>
        ) : error ? (
          <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
        ) : entry ? (
          <div className="rounded-xl border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-neutral-900">
            <p className="text-lg font-medium text-neutral-900 dark:text-neutral-100">{entry.siteName}</p>
            <p className="mt-1 text-sm text-neutral-500">
              {getPreferredIdentifier(entry) || "—"}
            </p>

            <div className="mt-3 flex items-center gap-2">
              <p className="select-all font-mono text-sm text-neutral-700 dark:text-neutral-300">
                {isRevealed ? entry.password : "••••••••••••"}
              </p>
              <button
                type="button"
                onClick={() => setIsRevealed((v) => !v)}
                className="rounded-lg border border-neutral-300 px-2.5 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                {isRevealed ? "Cacher" : "Voir"}
              </button>
              <button
                type="button"
                onClick={() => void handleCopyPassword()}
                className="rounded-lg border border-neutral-300 px-2.5 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                {copied ? "Copié !" : "Copier"}
              </button>
            </div>

            {entry.url && (
              <button
                type="button"
                onClick={() => void openEntryUrl(entry.url)}
                className="mt-3 rounded-lg border border-neutral-300 px-2.5 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                Ouvrir le site
              </button>
            )}

            {entry.notes && <p className="mt-4 whitespace-pre-wrap text-xs text-neutral-500">{entry.notes}</p>}
          </div>
        ) : null}
      </div>
    </main>
  );
}
