import { useEffect, useState } from "react";
import { getVersion } from "@tauri-apps/api/app";
import { checkForUpdate, downloadAndInstall } from "../lib/appUpdater";
import type { Update } from "@tauri-apps/plugin-updater";

type Status =
  | { kind: "idle" }
  | { kind: "checking" }
  | { kind: "upToDate" }
  | { kind: "available"; update: Update; version: string; notes?: string }
  | { kind: "installing"; percent: number }
  | { kind: "error"; message: string };

export default function AppUpdateSettings() {
  const [currentVersion, setCurrentVersion] = useState<string | null>(null);
  const [status, setStatus] = useState<Status>({ kind: "idle" });

  useEffect(() => {
    // Peut échouer/rester null sur une plateforme sans commande `app` exposée (aucune connue à ce
    // jour côté Tauri desktop) — purement informatif, jamais bloquant pour le reste de l'écran.
    getVersion()
      .then(setCurrentVersion)
      .catch(() => setCurrentVersion(null));
  }, []);

  async function handleCheck() {
    setStatus({ kind: "checking" });
    const result = await checkForUpdate();
    if (!result.available || !result.update) {
      setStatus({ kind: "upToDate" });
      return;
    }
    setStatus({ kind: "available", update: result.update, version: result.version!, notes: result.notes });
  }

  async function handleInstall(update: Update) {
    setStatus({ kind: "installing", percent: 0 });
    try {
      await downloadAndInstall(update, (percent) => setStatus({ kind: "installing", percent }));
      // downloadAndInstall relance l'app en cas de succès — ce code n'est normalement jamais
      // atteint (le processus se termine avant), gardé seulement par prudence.
    } catch (err) {
      setStatus({
        kind: "error",
        message: err instanceof Error ? err.message : "Échec de l'installation de la mise à jour.",
      });
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-neutral-500 dark:text-neutral-500">
        Les mises à jour sont installées automatiquement à l'ouverture de l'app, sans action de ta
        part. Ce bouton sert seulement à forcer une vérification immédiate.
      </p>
      <p className="text-sm text-neutral-600 dark:text-neutral-400">
        Version installée : {currentVersion ?? "inconnue"}
        {status.kind === "available" && ` — nouvelle version disponible : ${status.version}`}
      </p>

      {status.kind === "available" && status.notes && (
        <p className="whitespace-pre-wrap rounded-lg bg-neutral-100 p-3 text-xs text-neutral-600 dark:bg-neutral-800 dark:text-neutral-400">
          {status.notes}
        </p>
      )}

      {status.kind === "installing" && (
        <div className="flex flex-col gap-1">
          <div className="h-2 w-full overflow-hidden rounded-full bg-neutral-200 dark:bg-neutral-800">
            <div
              className="h-full rounded-full bg-indigo-600 transition-all dark:bg-indigo-500"
              style={{ width: `${status.percent}%` }}
            />
          </div>
          <p className="text-xs text-neutral-500 dark:text-neutral-500">
            Téléchargement et installation en cours — l'app va redémarrer automatiquement.
          </p>
        </div>
      )}

      {status.kind === "error" && (
        <p className="text-sm text-red-600 dark:text-red-400">{status.message}</p>
      )}

      {status.kind === "upToDate" && (
        <p className="text-sm text-emerald-600 dark:text-emerald-400">
          Aucune mise à jour trouvée (déjà à jour, ou vérification indisponible sur cette
          plateforme — Android se met à jour via un nouvel APK, pas via ce bouton).
        </p>
      )}

      <div className="flex gap-2">
        {status.kind === "available" ? (
          <button
            type="button"
            onClick={() => void handleInstall(status.update)}
            className="rounded-lg bg-indigo-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-indigo-700 dark:bg-indigo-500 dark:hover:bg-indigo-600"
          >
            Installer la mise à jour
          </button>
        ) : (
          <button
            type="button"
            onClick={() => void handleCheck()}
            disabled={status.kind === "checking" || status.kind === "installing"}
            className="rounded-lg border border-neutral-300 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-100 disabled:opacity-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            {status.kind === "checking" ? "Vérification…" : "Vérifier les mises à jour"}
          </button>
        )}
      </div>
    </div>
  );
}
