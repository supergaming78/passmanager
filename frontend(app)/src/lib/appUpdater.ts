// Mise à jour automatique de l'app desktop — DESKTOP UNIQUEMENT.
//
// Le plugin `@tauri-apps/plugin-updater` n'a de contrepartie Rust enregistrée que sur
// Windows/macOS/Linux (voir src-tauri/Cargo.toml et lib.rs, tous deux gardés par un cfg
// équivalent à `#[cfg(desktop)]` — le plugin n'existe même pas sur Android/iOS, une app mobile se
// met à jour via son store). Sur Android, `check()` échoue donc à l'exécution (commande Tauri
// inconnue) : toutes les fonctions ci-dessous avalent cette erreur et renvoient un résultat neutre
// plutôt que de la laisser remonter — l'appelant (voir components/AppUpdateSettings.tsx) n'a donc
// PAS besoin de savoir lui-même sur quelle plateforme il tourne, il reçoit juste "pas de mise à
// jour disponible ici".
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

export interface UpdateCheckResult {
  available: boolean;
  version?: string;
  notes?: string;
  /** Présent uniquement si `available` est vrai — à repasser tel quel à `downloadAndInstall`. */
  update?: Update;
}

/**
 * Interroge le manifeste `latest.json` publié sur les GitHub Releases (voir
 * src-tauri/tauri.conf.json::plugins.updater.endpoints) et compare à la version actuellement
 * installée. Ne télécharge rien : juste un aller-retour réseau léger pour savoir s'il y a du
 * nouveau. Renvoie `{ available: false }` aussi bien "vraiment à jour" que "impossible de
 * vérifier" (hors ligne, plateforme sans updater...) — voir le commentaire en tête de fichier.
 */
export async function checkForUpdate(): Promise<UpdateCheckResult> {
  try {
    const update = await check();
    if (!update?.available) {
      return { available: false };
    }
    return { available: true, version: update.version, notes: update.body, update };
  } catch {
    return { available: false };
  }
}

/**
 * Télécharge puis installe la mise à jour déjà détectée par `checkForUpdate`, et relance l'app
 * pour l'appliquer. `onProgress` reçoit une progression 0-100 approximative (basée sur les octets
 * déjà reçus quand le serveur annonce une taille totale, sinon reste à 0 jusqu'à la fin).
 */
export async function downloadAndInstall(
  update: Update,
  onProgress?: (percent: number) => void,
): Promise<void> {
  let received = 0;
  let total = 0;
  await update.downloadAndInstall((event) => {
    switch (event.event) {
      case "Started":
        total = event.data.contentLength ?? 0;
        break;
      case "Progress":
        received += event.data.chunkLength;
        if (total > 0) onProgress?.(Math.min(100, Math.round((received / total) * 100)));
        break;
      case "Finished":
        onProgress?.(100);
        break;
    }
  });
  await relaunch();
}
