// Copie un mot de passe dans le presse-papiers puis programme son effacement automatique (voir
// getClipboardClearSeconds()/SettingsView.tsx pour le réglage) — extrait d'App.tsx pour être
// réutilisé PARTOUT où un mot de passe peut être copié, y compris les vues en lecture seule
// d'entrées reçues (SharedEntryView.tsx, EmergencyVaultView.tsx). CORRECTIF : ces trois call sites
// programmaient chacun un `setTimeout` d'effacement inconditionnel et indépendant — copier un mot
// de passe A puis, avant l'expiration de son délai, un mot de passe B faisait que le minuteur de A
// effaçait quand même le presse-papiers à l'heure prévue pour A, mais après que B y ait été copié,
// supprimant B en avance sur SON propre délai. Voir frontend(app)/src/lib/clipboard.ts pour le même
// correctif déjà appliqué côté client desktop.

import { getClipboardClearSeconds } from "./settings";

// Compteur de génération GLOBAL (pas par composant) : le presse-papiers est une ressource UNIQUE
// au niveau de tout l'OS, partagée entre toutes les vues de la popup — une copie depuis la liste
// principale puis une autre depuis une vue de partage doivent se coordonner sur le MÊME compteur.
let copyGeneration = 0;

/** Copie `password` dans le presse-papiers, puis — sauf si l'utilisateur a désactivé l'effacement
 * automatique (délai <= 0, voir getClipboardClearSeconds) — l'efface après le délai configuré,
 * mais UNIQUEMENT si le presse-papiers contient encore CE mot de passe précis à ce moment-là (pas
 * un contenu plus récent copié entre-temps, par cette extension ou une autre app). */
export async function copyPasswordWithAutoClear(password: string): Promise<void> {
  await navigator.clipboard.writeText(password);

  const myGeneration = ++copyGeneration;
  const delaySeconds = getClipboardClearSeconds();
  if (delaySeconds <= 0) return;

  setTimeout(async () => {
    // Une copie plus récente a eu lieu entre-temps (ce mot de passe ou un autre, depuis n'importe
    // quelle vue) : rien à faire, le minuteur de CETTE copie-ci n'a plus lieu d'être.
    if (copyGeneration !== myGeneration) return;
    try {
      // Vérifie qu'on efface bien CE mot de passe, pas quelque chose que l'utilisateur aurait
      // copié depuis une autre app entre-temps.
      const current = await navigator.clipboard.readText();
      if (current === password) await navigator.clipboard.writeText("");
    } catch {
      // Lecture refusée (permissions du système/navigateur) : on efface quand même par prudence —
      // un presse-papiers oublié avec un mot de passe dedans est pire qu'un effacement en trop.
      await navigator.clipboard.writeText("").catch(() => {});
    }
  }, delaySeconds * 1000);
}
