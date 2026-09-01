// Sélectionne l'identifiant à afficher/remplir/copier pour une entrée de type "login" — trouvé en
// double (revue de code du 2026-09-01) : `entry.preferredLoginType === "email" ? entry.loginEmail
// : entry.username || entry.loginEmail` était dupliqué à la main dans 5 fichiers, et TOUS
// souffraient du même bug asymétrique (corrigé ici une bonne fois) : le repli n'existait QUE côté
// "username" (repli vers loginEmail si username est vide), jamais côté "email" (aucun repli vers
// username si loginEmail est vide) — alors que les deux champs sont indépendamment optionnels (voir
// VaultEntryForm.tsx, aucune validation croisée ne garantit que le champ préféré soit réellement
// rempli). Un utilisateur avec preferredLoginType="email", loginEmail="" et username="alice" voyait
// donc un identifiant vide partout, malgré une valeur bien disponible.
//
// Type structurel minimal (pas PlainVaultEntry) : réutilisable tel quel pour les entrées
// personnelles (vaultCrypto.ts), partagées (sharedVault.ts/entrySharing.ts), d'urgence
// (emergencyAccess.ts) et à usage limité (blindShare.ts) sans dépendre du type exact de chacune.
export function getPreferredIdentifier(entry: {
  preferredLoginType: "username" | "email";
  username?: string | null;
  loginEmail?: string | null;
}): string {
  return entry.preferredLoginType === "email"
    ? entry.loginEmail || entry.username || ""
    : entry.username || entry.loginEmail || "";
}
