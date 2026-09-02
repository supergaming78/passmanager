import { useEffect, useState } from "react";
import { checkForNewerVersion } from "../lib/updateCheck";

/**
 * Bandeau "nouvelle version disponible" — CHROME/EDGE UNIQUEMENT (voir lib/updateCheck.ts, qui ne
 * fait rien sur Firefox : mise à jour déjà automatique là-bas, voir manifest.json). Contrairement
 * à Firefox, rien ne peut être installé automatiquement ici — ce bandeau se contente d'inviter et
 * de renvoyer vers la page de release, à chaque ouverture du popup tant qu'une version plus
 * récente existe. Le "×" ne masque que pour cette ouverture du popup (pas de façon permanente,
 * volontairement — voir MobileUpdateBanner.tsx côté desktop pour le même raisonnement), le popup
 * se rouvrant à chaque clic sur l'icône de toute façon, un oubli ne reste jamais durablement caché.
 */
export default function UpdateBanner() {
  const [dismissed, setDismissed] = useState(false);
  const [update, setUpdate] = useState<{ version: string; releaseUrl: string } | null>(null);

  useEffect(() => {
    void checkForNewerVersion().then((result) => {
      if (result.available && result.version && result.releaseUrl) {
        setUpdate({ version: result.version, releaseUrl: result.releaseUrl });
      }
    });
  }, []);

  if (!update || dismissed) return null;

  return (
    <div className="flex items-center justify-between gap-2 bg-indigo-600 px-3 py-2 text-xs text-white">
      <span>Nouvelle version disponible (v{update.version}).</span>
      <div className="flex shrink-0 items-center gap-1.5">
        <a
          href={update.releaseUrl}
          target="_blank"
          rel="noreferrer"
          className="rounded-md bg-white px-2 py-1 font-medium text-indigo-700 hover:bg-indigo-50"
        >
          Télécharger
        </a>
        <button
          type="button"
          onClick={() => setDismissed(true)}
          aria-label="Fermer"
          className="rounded-md px-1.5 py-1 text-white/80 hover:bg-white/10 hover:text-white"
        >
          ×
        </button>
      </div>
    </div>
  );
}
