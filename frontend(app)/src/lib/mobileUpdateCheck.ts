// Vérification de nouvelle version pour Android — PAS le plugin updater (desktop uniquement, voir
// lib/appUpdater.ts), un simple aller-retour réseau public vers le manifeste déjà publié pour le
// desktop (`latest.json`, généré par le même job CI, voir .github/workflows/release-app.yml). Android
// ne peut de toute façon PAS installer une mise à jour tout seul (confirmation système obligatoire à
// l'installation d'un APK, même signé) — ce module se contente donc de détecter qu'une version plus
// récente existe et de renvoyer un lien vers la page de release où la télécharger, voir
// components/MobileUpdateBanner.tsx pour l'affichage.
import { getVersion } from "@tauri-apps/api/app";

// ⚠️ À CORRIGER dès que le vrai dépôt GitHub est créé/nommé (voir tauri.conf.json::plugins.updater
// .endpoints, qui pointe vers le même nom deviné "supergaming78/passmanager" — un seul et même
// endroit à corriger suffirait normalement, mais JSON n'admet pas de référence à une constante JS,
// d'où la duplication entre ce fichier et tauri.conf.json).
const GITHUB_REPO = "supergaming78/passmanager";

export const GITHUB_RELEASES_URL = `https://github.com/${GITHUB_REPO}/releases/latest`;

/** Compare deux versions "X.Y.Z" — renvoie vrai si `remote` est strictement plus récente que `local`. */
function isNewer(remote: string, local: string): boolean {
  const toParts = (v: string) => v.split(".").map((n) => parseInt(n, 10) || 0);
  const [rMajor, rMinor, rPatch] = toParts(remote);
  const [lMajor, lMinor, lPatch] = toParts(local);
  if (rMajor !== lMajor) return rMajor > lMajor;
  if (rMinor !== lMinor) return rMinor > lMinor;
  return rPatch > lPatch;
}

export interface MobileUpdateCheckResult {
  available: boolean;
  version?: string;
}

/**
 * Interroge le `latest.json` déjà publié pour le desktop (même version applicative pour les deux,
 * voir le tag partagé `app-v*`) et compare au numéro de version de CETTE installation Android.
 * Échoue silencieusement (renvoie `{ available: false }`) hors ligne ou si le dépôt/la release
 * n'existe pas encore — jamais d'erreur qui remonterait à l'utilisateur pour une simple vérification
 * de fond.
 */
export async function checkForNewerVersionOnGitHub(): Promise<MobileUpdateCheckResult> {
  try {
    const [currentVersion, response] = await Promise.all([
      getVersion(),
      fetch(`https://github.com/${GITHUB_REPO}/releases/latest/download/latest.json`),
    ]);
    if (!response.ok) return { available: false };
    const manifest = (await response.json()) as { version?: string };
    if (!manifest.version || !isNewer(manifest.version, currentVersion)) {
      return { available: false };
    }
    return { available: true, version: manifest.version };
  } catch {
    return { available: false };
  }
}
