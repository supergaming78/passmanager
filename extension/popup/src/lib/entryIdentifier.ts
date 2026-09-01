// Sélectionne l'identifiant à afficher/remplir pour une entrée de type "login" — trouvé en double
// (revue de code du 2026-09-01, mirroir de frontend(app)/src/lib/entryIdentifier.ts) :
// `entry.preferredLoginType === "email" ? entry.loginEmail : entry.username || entry.loginEmail`
// était dupliqué à la main dans 7 endroits (App.tsx x2, SharedEntryView.tsx, EmergencyVaultView.tsx,
// SharedVaultDetailView.tsx x2, blindShare.ts), et TOUS souffraient du même bug asymétrique : le
// repli n'existait QUE côté "username" (repli vers loginEmail si username est vide), jamais côté
// "email" (aucun repli vers username si loginEmail est vide) — alors que les deux champs sont
// indépendamment optionnels (voir VaultEntryForm.tsx, aucune validation croisée ne garantit que le
// champ préféré soit réellement rempli). Un utilisateur avec preferredLoginType="email",
// loginEmail="" et username="alice" voyait donc un identifiant vide partout, malgré une valeur bien
// disponible — exactement le bug que le commit précédent avait corrigé pour l'autre branche.
//
// Type structurel minimal (pas un type d'entrée précis) : réutilisable tel quel pour les entrées
// personnelles, partagées, d'urgence et à usage limité sans dépendre du type exact de chacune.
export function getPreferredIdentifier(entry: {
  preferredLoginType: "username" | "email";
  username?: string | null;
  loginEmail?: string | null;
}): string {
  return entry.preferredLoginType === "email"
    ? entry.loginEmail || entry.username || ""
    : entry.username || entry.loginEmail || "";
}
