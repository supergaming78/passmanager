import { useEffect, useState } from "react";
import { isAndroid } from "../lib/platform";
import { checkForUpdate, downloadAndInstall } from "../lib/appUpdater";

/**
 * Mise à jour AUTOMATIQUE au lancement — desktop uniquement, AUCUNE action requise de
 * l'utilisateur (pas de bouton "Vérifier"/"Installer" à cliquer, contrairement au flux manuel
 * toujours disponible dans Réglages > Mises à jour, voir components/AppUpdateSettings.tsx, qui
 * reste utile pour forcer une vérification à la demande). Vérifie une fois au montage de l'app ;
 * si une mise à jour est trouvée, la télécharge et l'installe SANS attendre de confirmation —
 * seul un bandeau informatif s'affiche pendant le téléchargement, pour ne pas surprendre par un
 * redémarrage sans prévenir (le coffre déverrouillé en mémoire serait sinon fermé sans un mot).
 * `downloadAndInstall` relance l'app à la fin — ce composant ne gère donc pas la suite, le
 * processus se termine avant que ce soit nécessaire.
 */
export default function DesktopAutoUpdater() {
  const [percent, setPercent] = useState<number | null>(null);

  useEffect(() => {
    if (isAndroid()) return;
    let cancelled = false;
    checkForUpdate().then((result) => {
      if (cancelled || !result.available || !result.update) return;
      setPercent(0);
      void downloadAndInstall(result.update, (p) => {
        if (!cancelled) setPercent(p);
      }).catch(() => {
        // Échec silencieux ici (réseau coupé en cours de route, etc.) — l'utilisateur garde la
        // main via le bouton manuel dans Réglages, pas la peine d'interrompre son usage courant
        // pour une mise à jour qui, de toute façon, réessaiera au prochain lancement.
        if (!cancelled) setPercent(null);
      });
    });
    return () => {
      cancelled = true;
    };
  }, []);

  if (percent === null) return null;

  return (
    <div className="flex items-center gap-3 bg-indigo-600 px-4 py-2 text-sm text-white dark:bg-indigo-700">
      <span>Mise à jour en cours — l'app va redémarrer automatiquement…</span>
      <div className="h-1.5 w-32 overflow-hidden rounded-full bg-white/30">
        <div className="h-full rounded-full bg-white transition-all" style={{ width: `${percent}%` }} />
      </div>
    </div>
  );
}
