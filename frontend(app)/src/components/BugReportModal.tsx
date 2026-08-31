import { useEffect, useState, type FormEvent } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { createBugReport } from "../api/client";
import { getDetailedPlatformInfo } from "../lib/platform";
import { getBackendUrl } from "../lib/settings";
import { getRecentDiagnosticLog } from "../lib/diagnosticLog";
import { getErrorMessage } from "../lib/errors";
import type { BugReportCategory } from "../api/types";

// Doit rester cohérent avec la limite serveur (4000, voir models.rs::CreateBugReportPayload) —
// une marge est gardée (pas pile 4000) pour ne jamais dépendre d'un décompte de caractères
// identique au caractère près des deux côtés.
const MAX_DESCRIPTION_LENGTH = 3900;

/** Compose la description finale envoyée : le texte de l'utilisateur D'ABORD (jamais tronqué,
 * c'est lui qui compte le plus), puis l'écran actuel + l'état du backend + le journal de
 * diagnostic (voir lib/diagnosticLog.ts) — TRONQUÉS si besoin pour respecter la limite serveur,
 * plutôt que de faire échouer tout l'envoi sur un dépassement causé par le contexte technique
 * auto-collecté, pas par ce que la personne a réellement écrit. */
function composeFinalDescription(userText: string, screen: string, backendStatus: string): string {
  const technicalBlock = `\n\n[Écran : ${screen}]\n[Backend : ${backendStatus}]\n[Journal récent :\n${getRecentDiagnosticLog()}]`;
  const budget = MAX_DESCRIPTION_LENGTH - userText.length;
  if (budget <= 0) return userText.slice(0, MAX_DESCRIPTION_LENGTH);
  return userText + technicalBlock.slice(0, budget);
}

const CATEGORIES: BugReportCategory[] = ["Plantage", "Affichage", "Synchronisation", "Autre"];

interface Props {
  onClose: () => void;
  /** Email pré-rempli si un compte est déjà connecté (voir Vault.tsx) — laissé vide sinon (voir
   * Login.tsx, accessible AVANT toute connexion). Toujours éditable, jamais vérifié côté serveur
   * (voir models.rs::CreateBugReportPayload). */
  defaultEmail?: string;
  /** Pré-remplit la description ET force la catégorie sur "Plantage" — utilisé par
   * ErrorBoundary.tsx quand ce formulaire s'ouvre suite à un crash React (message d'erreur + pile
   * d'appels déjà collectés, jamais de contenu du coffre). */
  initialDescription?: string;
}

/** Vérification RAPIDE (timeout court, jamais bloquante) que le backend actuellement configuré
 * répond — souvent LA vraie cause d'un problème signalé ("l'app ne fait rien"), et bien plus utile
 * à savoir que juste la plateforme. Résultat inclus tel quel dans la description envoyée, jamais
 * affiché comme un diagnostic fiable à 100% (un simple GET /health qui échoue peut avoir plein de
 * causes différentes) — juste un indice de plus pour qui va lire le signalement. */
async function checkBackendReachable(): Promise<string> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    const response = await fetch(`${getBackendUrl()}/health`, { signal: controller.signal });
    clearTimeout(timeout);
    return response.ok ? "joignable" : `répond mais avec une erreur (${response.status})`;
  } catch {
    return "injoignable";
  }
}

/** Signalement de bug — PUBLIC (voir api/client.ts::createBugReport, aucun jeton requis) :
 * accessible depuis l'écran de connexion, depuis le coffre, et depuis ErrorBoundary.tsx après un
 * crash — exactement le même formulaire dans les trois cas. `app_version`/`platform`/l'état du
 * backend sont collectés automatiquement, jamais demandés à l'utilisateur. */
export default function BugReportModal({ onClose, defaultEmail, initialDescription }: Props) {
  const [description, setDescription] = useState(initialDescription ?? "");
  const [category, setCategory] = useState<BugReportCategory>(initialDescription ? "Plantage" : "Autre");
  const [email, setEmail] = useState(defaultEmail ?? "");
  const [appVersion, setAppVersion] = useState("inconnue");
  const [backendStatus, setBackendStatus] = useState("vérification…");
  // Capturé UNE FOIS au montage (pas recalculé à l'envoi) : reflète l'écran depuis lequel la
  // personne a cliqué "Signaler un bug", pas un écran vers lequel elle aurait navigué entre-temps
  // en rédigeant sa description.
  const [currentScreen] = useState(() => window.location.hash || "/");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState(false);

  useEffect(() => {
    getVersion()
      .then(setAppVersion)
      .catch(() => setAppVersion("inconnue"));
    void checkBackendReachable().then(setBackendStatus);
  }, []);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!description.trim()) return;
    setIsSubmitting(true);
    setError(null);
    try {
      // window.location.hash : HashRouter (voir main.tsx) — reflète l'écran affiché AU MOMENT DE
      // L'OUVERTURE de ce formulaire (capturé une fois au montage, pas ici, au cas où la personne
      // aurait navigué pendant qu'elle rédigeait — voir le useEffect ci-dessus).
      await createBugReport({
        description: composeFinalDescription(description.trim(), currentScreen, backendStatus),
        reporter_email: email.trim() || undefined,
        app_version: appVersion,
        platform: getDetailedPlatformInfo(),
        category,
      });
      setSent(true);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-20 flex items-center justify-center bg-black/40 px-4 py-8">
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-xl dark:bg-neutral-900">
        <div className="mb-1 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">Signaler un bug</h2>
          <button type="button" onClick={onClose} className="text-sm text-neutral-500 hover:underline">
            Fermer
          </button>
        </div>

        {sent ? (
          <div className="flex flex-col gap-3">
            <p className="text-sm text-emerald-600 dark:text-emerald-400">
              Merci, ton signalement a bien été envoyé.
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
              Décris ce qui s'est passé — la version de l'app ({appVersion}), la plateforme, l'écran
              actuel, si le backend répond ({backendStatus}) et un journal technique récent sont
              joints automatiquement. Rien de ton coffre n'est jamais inclus.
            </p>

            <div>
              <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                Catégorie
              </label>
              <select
                value={category}
                onChange={(e) => setCategory(e.target.value as BugReportCategory)}
                className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
              >
                {CATEGORIES.map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </div>

            <textarea
              required
              autoFocus={!initialDescription}
              rows={5}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Ce qui s'est passé, ce que tu attendais à la place..."
              className="w-full rounded-lg border border-neutral-300 px-3 py-2 font-mono text-xs outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
            />

            {/* Transparence : le bloc technique est composé silencieusement à l'envoi (voir
                composeFinalDescription) — sans cet aperçu, la personne n'aurait aucun moyen de voir
                ce qui est réellement joint avant que ce soit parti. Repliable par défaut : utile à
                vérifier, pas la peine de l'imposer visuellement à chaque fois. */}
            <details className="rounded-lg border border-neutral-200 dark:border-neutral-800">
              <summary className="cursor-pointer px-3 py-1.5 text-xs font-medium text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300">
                Voir les informations techniques jointes automatiquement
              </summary>
              <pre className="whitespace-pre-wrap break-words border-t border-neutral-200 px-3 py-2 text-[11px] text-neutral-500 dark:border-neutral-800 dark:text-neutral-400">
                {`Écran : ${currentScreen}\nBackend : ${backendStatus}\nJournal récent :\n${getRecentDiagnosticLog()}`}
              </pre>
            </details>
            <div>
              <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                Email de contact (facultatif)
              </label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="pour te répondre si besoin, et te prévenir une fois traité"
                className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
              />
            </div>

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
