import { useState, type FormEvent } from "react";
import { useAuth } from "../state/AuthContext";
import { createFeatureSuggestion } from "../api/client";
import { getErrorMessage } from "../lib/errors";

// Doit rester cohérent avec la limite serveur (4000, voir models.rs::CreateFeatureSuggestionPayload).
const MAX_DESCRIPTION_LENGTH = 4000;

interface Props {
  onClose: () => void;
}

/** Suggestion de fonctionnalité — retour utilisateur (2026-09-02), "un peu comme le signalement de
 * bug" (voir BugReportModal.tsx) mais bien plus simple : app DESKTOP uniquement, un compte connecté
 * est requis (voir components/AppNav.tsx, qui ne propose ce point de menu que sur desktop — voir
 * lib/platform.ts::isMobilePlatform), donc pas besoin de collecter email/version/plateforme/journal
 * technique comme pour un bug — juste une idée en texte libre, l'auteur vient du compte connecté. */
export default function FeatureSuggestionModal({ onClose }: Props) {
  const { authorizedRequest } = useAuth();
  const [description, setDescription] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!description.trim()) return;
    setIsSubmitting(true);
    setError(null);
    try {
      await authorizedRequest((token) => createFeatureSuggestion(token, { description: description.trim() }));
      setSent(true);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-20 flex items-center justify-center bg-black/40 px-4 py-8">
      <div className="w-full max-w-md rounded-2xl border border-neutral-200 bg-white p-6 shadow-xl dark:border-neutral-800 dark:bg-neutral-900">
        <div className="mb-1 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">Suggérer une fonctionnalité</h2>
          <button type="button" onClick={onClose} className="text-sm text-neutral-500 hover:underline">
            Fermer
          </button>
        </div>

        {sent ? (
          <div className="flex flex-col gap-3">
            <p className="text-sm text-emerald-600 dark:text-emerald-400">
              Merci, ta suggestion a bien été envoyée.
            </p>
            <button
              type="button"
              onClick={onClose}
              className="self-start rounded-lg border border-neutral-300 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              Fermer
            </button>
          </div>
        ) : (
          <form onSubmit={(e) => void handleSubmit(e)} className="flex flex-col gap-3">
            <p className="text-xs text-neutral-500">
              Une idée de fonctionnalité à ajouter, une amélioration à apporter — décris-la
              simplement, elle sera lue directement par l'administrateur.
            </p>

            <textarea
              required
              autoFocus
              rows={5}
              maxLength={MAX_DESCRIPTION_LENGTH}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Ce que tu aimerais voir ajouté, et pourquoi..."
              className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
            />

            {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}

            <button
              type="submit"
              disabled={isSubmitting || !description.trim()}
              className="self-start rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {isSubmitting ? "Envoi…" : "Envoyer"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
