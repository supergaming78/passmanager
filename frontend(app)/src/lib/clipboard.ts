// Copie un mot de passe dans le presse-papiers puis programme son effacement automatique (voir
// getClipboardClearSeconds()/AutoLockSettings.tsx pour le réglage) — extrait de Vault.tsx pour être
// réutilisé PARTOUT où un mot de passe peut être copié, y compris les vues en lecture seule
// d'entrées reçues (SharedEntryPage.tsx, EmergencyVaultPage.tsx). CORRECTIF : ces deux dernières
// copiaient auparavant sans jamais programmer d'effacement, ignorant silencieusement le réglage que
// l'utilisateur a choisi pour TOUT le reste de l'app.

import { getClipboardClearSeconds } from "./settings";

// Compteur de génération GLOBAL (pas par composant) : le presse-papiers est une ressource UNIQUE
// au niveau de tout l'OS, partagée entre toutes les pages de l'app — une copie depuis Vault.tsx
// puis une autre depuis SharedEntryPage.tsx doivent se coordonner sur le MÊME compteur, sinon le
// minuteur de la première copie pourrait effacer le mot de passe de la seconde après coup.
let copyGeneration = 0;

/** Copie `password` dans le presse-papiers, puis — sauf si l'utilisateur a désactivé l'effacement
 * automatique (délai <= 0, voir getClipboardClearSeconds) — l'efface après le délai configuré,
 * mais UNIQUEMENT si le presse-papiers contient encore CE mot de passe précis à ce moment-là (pas
 * un contenu plus récent copié entre-temps, par cette app ou une autre). */
export async function copyPasswordWithAutoClear(password: string): Promise<void> {
  await navigator.clipboard.writeText(password);

  const myGeneration = ++copyGeneration;
  const delaySeconds = getClipboardClearSeconds();
  if (delaySeconds <= 0) return;

  setTimeout(async () => {
    // Une copie plus récente a eu lieu entre-temps (ce mot de passe ou un autre, depuis n'importe
    // quelle page) : rien à faire, le minuteur de CETTE copie-ci n'a plus lieu d'être.
    if (copyGeneration !== myGeneration) return;
    try {
      // Vérifie qu'on efface bien CE mot de passe, pas quelque chose que l'utilisateur aurait
      // copié depuis une autre app entre-temps.
      const current = await navigator.clipboard.readText();
      if (current === password) await navigator.clipboard.writeText("");
    } catch {
      // Lecture refusée (permissions du système/webview) : on efface quand même par prudence — un
      // presse-papiers oublié avec un mot de passe dedans est pire qu'un effacement en trop.
      await navigator.clipboard.writeText("").catch(() => {});
    }
  }, delaySeconds * 1000);
}
