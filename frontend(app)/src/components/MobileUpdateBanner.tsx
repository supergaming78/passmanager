import { useEffect, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { isAndroid } from "../lib/platform";
import { checkForNewerVersionOnGitHub, GITHUB_RELEASES_URL } from "../lib/mobileUpdateCheck";

/**
 * Bandeau "nouvelle version disponible" — ANDROID UNIQUEMENT (voir isAndroid()). Contrairement au
 * desktop (mise à jour effectivement téléchargée+installée automatiquement, voir
 * lib/appUpdater.ts), Android ne peut PAS être mis à jour sans confirmation système — ce bandeau se
 * contente donc d'inviter et de renvoyer vers la page de téléchargement, à chaque ouverture de
 * l'app tant qu'une version plus récente existe (le "×" ne masque que pour cette session en cours,
 * pas de façon permanente — volontairement, pour ne pas laisser une installation oubliée sans
 * rappel indéfiniment).
 */
export default function MobileUpdateBanner() {
  const [dismissed, setDismissed] = useState(false);
  const [newVersion, setNewVersion] = useState<string | null>(null);

  useEffect(() => {
    if (!isAndroid()) return;
    checkForNewerVersionOnGitHub().then((result) => {
      if (result.available && result.version) setNewVersion(result.version);
    });
  }, []);

  if (!newVersion || dismissed) return null;

  return (
    <div className="flex items-center justify-between gap-3 bg-indigo-600 px-4 py-2 text-sm text-white dark:bg-indigo-700">
      <span>Nouvelle version disponible (v{newVersion}) — mets à jour pour les derniers correctifs.</span>
      <div className="flex shrink-0 items-center gap-2">
        <button
          type="button"
          onClick={() => void openUrl(GITHUB_RELEASES_URL)}
          className="rounded-lg bg-white px-2.5 py-1 text-xs font-medium text-indigo-700 hover:bg-indigo-50"
        >
          Télécharger
        </button>
        <button
          type="button"
          onClick={() => setDismissed(true)}
          aria-label="Fermer"
          className="rounded-lg px-2 py-1 text-white/80 hover:bg-white/10 hover:text-white"
        >
          ×
        </button>
      </div>
    </div>
  );
}
