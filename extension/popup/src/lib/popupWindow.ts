// Bascule du popup ancré (se ferme dès qu'il perd le focus — comportement standard du navigateur,
// pas contournable directement) vers une VRAIE fenêtre détachée (`chrome.windows.create`, type
// "popup") : celle-ci reste ouverte quoi qu'on clique ailleurs. Utilisé spécifiquement pour l'écran
// 2FA (voir App.tsx) — voir lib/session.ts::savePendingTfa/readPendingTfa pour l'état qui survit
// à cette transition.
//
// `?standalone=1` distingue les deux contextes au chargement (voir App.tsx) : seul le popup ANCRÉ
// déclenche l'ouverture d'une fenêtre détachée en atteignant l'écran 2FA — la fenêtre détachée
// elle-même ne retente jamais cette bascule (déjà détachée, rien à faire de plus).
const STANDALONE_PARAM = "standalone";

export function isStandaloneWindow(): boolean {
  return new URLSearchParams(window.location.search).get(STANDALONE_PARAM) === "1";
}

/** Ouvre une fenêtre détachée avec la même popup, puis ferme la fenêtre/popup courante. À appeler
 * seulement APRÈS avoir persisté l'état à reprendre (voir savePendingTfa) — la nouvelle fenêtre le
 * relit à son montage. */
export async function openStandaloneAndClose(): Promise<void> {
  const url = chrome.runtime.getURL(`popup/dist/index.html?${STANDALONE_PARAM}=1`);
  await chrome.windows.create({ url, type: "popup", width: 400, height: 640 });
  window.close();
}
