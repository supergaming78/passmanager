// Vérification de nouvelle version — équivalent réduit de
// frontend(app)/src/lib/mobileUpdateCheck.ts (même raisonnement : Chrome/Edge ne peuvent pas
// s'auto-mettre à jour ici, voir GUIDE_INSTALLATION.md — ce module se contente de détecter qu'une
// version plus récente existe et de renvoyer un lien vers la page de release où la télécharger).
// Firefox N'A PAS besoin de ça : il se met à jour tout seul (voir manifest.json::
// browser_specific_settings.gecko.update_url) — ce module et le bandeau qui l'utilise (voir
// components/UpdateBanner.tsx) sont donc mués côté Chromium uniquement.
//
// Réutilise le MÊME extension/updates.json que Firefox (committé dans le dépôt, lu ici en HTTP
// simple depuis raw.githubusercontent.com — accessible anonymement, le dépôt est PUBLIC) plutôt
// qu'un fichier séparé : une seule source de vérité pour "quelle est la dernière version publiée",
// peu importe qui la lit.
import { isFirefox } from "./platform";

const GITHUB_REPO = "supergaming78/passmanager";
const UPDATES_JSON_URL = `https://raw.githubusercontent.com/${GITHUB_REPO}/main/extension/updates.json`;
const GECKO_ID = "passmanager@supergaming78.dev";

/** Compare deux versions "X.Y.Z" — renvoie vrai si `remote` est strictement plus récente que `local`. */
function isNewer(remote: string, local: string): boolean {
  const toParts = (v: string) => v.split(".").map((n) => parseInt(n, 10) || 0);
  const [rMajor, rMinor, rPatch] = toParts(remote);
  const [lMajor, lMinor, lPatch] = toParts(local);
  if (rMajor !== lMajor) return rMajor > lMajor;
  if (rMinor !== lMinor) return rMinor > lMinor;
  return rPatch > lPatch;
}

export interface UpdateCheckResult {
  available: boolean;
  version?: string;
  releaseUrl?: string;
}

interface UpdatesManifest {
  addons?: Record<string, { updates?: { version: string }[] }>;
}

/**
 * Interroge extension/updates.json et compare à la version de CETTE installation (lue depuis le
 * manifest.json embarqué, jamais codée en dur ici — reste juste même si oubliée à une version).
 * Échoue silencieusement (renvoie `{ available: false }`) hors ligne ou si le fichier n'existe pas
 * encore — jamais d'erreur remontée à l'utilisateur pour une simple vérification de fond.
 * Ne fait RIEN sur Firefox (mise à jour déjà automatique, voir l'en-tête de ce fichier).
 */
export async function checkForNewerVersion(): Promise<UpdateCheckResult> {
  if (isFirefox()) return { available: false };
  try {
    const currentVersion = chrome.runtime.getManifest().version;
    const response = await fetch(UPDATES_JSON_URL);
    if (!response.ok) return { available: false };
    const manifest = (await response.json()) as UpdatesManifest;
    const updates = manifest.addons?.[GECKO_ID]?.updates ?? [];
    if (updates.length === 0) return { available: false };

    // La plus récente n'est pas forcément la DERNIÈRE de la liste (l'ordre n'est pas garanti) —
    // celle avec le plus grand numéro de version, tout simplement.
    const latest = updates.reduce((best, u) => (isNewer(u.version, best.version) ? u : best));
    if (!isNewer(latest.version, currentVersion)) return { available: false };

    return {
      available: true,
      version: latest.version,
      releaseUrl: `https://github.com/${GITHUB_REPO}/releases/tag/ext-v${latest.version}`,
    };
  } catch {
    return { available: false };
  }
}
