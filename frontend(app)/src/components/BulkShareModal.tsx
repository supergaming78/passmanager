import { useState, type FormEvent } from "react";
import { getErrorMessage } from "../lib/errors";
import { shareEntry } from "../lib/entrySharing";
import type { PlainVaultEntry } from "../lib/vaultCrypto";

interface Props {
  entries: PlainVaultEntry[];
  authorizedRequest: <T,>(fn: (accessToken: string) => Promise<T>) => Promise<T>;
  onClose: () => void;
}

/** Partage classique (voir ShareEntryModal.tsx) mais pour PLUSIEURS entrées à la fois, avec UN
 * seul destinataire — retour utilisateur (2026-09-02), accessible depuis le mode "Sélectionner" du
 * Coffre (voir Vault.tsx). Volontairement plus simple que ShareEntryModal.tsx : pas de liste des
 * partages déjà actifs par entrée (n'aurait aucun sens agrégée sur plusieurs entrées à la fois),
 * juste "partager cette sélection avec cette personne" en une action — pour gérer/révoquer un
 * partage précis ensuite, ShareEntryModal.tsx (accessible depuis chaque entrée individuellement)
 * reste l'écran de référence, inchangé. Chaque entrée est partagée par un appel séparé
 * (lib/entrySharing.ts::shareEntry n'a pas de variante "en lot" côté backend — voir son
 * commentaire, une clé de contenu scellée différente par destinataire ET par entrée), en parallèle
 * via Promise.allSettled — même motif que Vault.tsx::handleBulkDelete/handleBulkSetFavorite : un
 * échec partiel (ex: cette personne n'a pas encore configuré ses propres clés) ne doit jamais faire
 * échouer les autres partages de la sélection. */
export default function BulkShareModal({ entries, authorizedRequest, onClose }: Props) {
  const [email, setEmail] = useState("");
  const [isSharing, setIsSharing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ succeeded: number; failed: number } | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const recipient = email.trim().toLowerCase();
    if (!recipient) return;
    setIsSharing(true);
    setError(null);
    try {
      const results = await Promise.allSettled(entries.map((entry) => shareEntry(authorizedRequest, entry, recipient)));
      const failed = results.filter((r) => r.status === "rejected").length;
      setResult({ succeeded: entries.length - failed, failed });
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsSharing(false);
    }
  }

  return (
    <div className="fixed inset-0 z-10 flex items-center justify-center bg-black/40 px-4 py-8">
      <div className="max-h-full w-full max-w-md overflow-y-auto rounded-2xl border border-neutral-200 bg-white p-6 shadow-xl dark:border-neutral-800 dark:bg-neutral-900">
        <div className="mb-1 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">
            Partager {entries.length} entrée{entries.length > 1 ? "s" : ""}
          </h2>
          <button type="button" onClick={onClose} className="text-sm text-neutral-500 hover:underline">
            Fermer
          </button>
        </div>
        <p className="mb-4 text-xs text-neutral-500">
          Chiffré de bout en bout pour le destinataire, accès immédiat — même mécanisme que partager
          une entrée seule. Le destinataire doit avoir déjà visité ses propres réglages une fois.
        </p>

        {result ? (
          <div className="flex flex-col gap-3">
            <p className="text-sm text-emerald-600 dark:text-emerald-400">
              {result.succeeded} entrée{result.succeeded > 1 ? "s" : ""} partagée{result.succeeded > 1 ? "s" : ""} avec succès.
            </p>
            {result.failed > 0 && (
              <p className="text-sm text-red-600 dark:text-red-400">
                {result.failed} échec{result.failed > 1 ? "s" : ""} — le destinataire n'a peut-être pas encore configuré ses clés
                (voir Réglages de son côté), ou une entrée a déjà été partagée avec lui.
              </p>
            )}
            <button
              type="button"
              onClick={onClose}
              className="self-start rounded-lg border border-neutral-300 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              Fermer
            </button>
          </div>
        ) : (
          <form onSubmit={(e) => void handleSubmit(e)} className="flex items-end gap-2">
            <div className="min-w-0 flex-1">
              <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">Email du destinataire</label>
              <input
                type="email"
                required
                autoFocus
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="quelqu'un@example.com"
                className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
              />
            </div>
            <button
              type="submit"
              disabled={isSharing || !email.trim()}
              className="shrink-0 rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {isSharing ? "…" : "Partager"}
            </button>
          </form>
        )}

        {error && <p className="mt-3 text-sm text-red-600 dark:text-red-400">{error}</p>}
      </div>
    </div>
  );
}
