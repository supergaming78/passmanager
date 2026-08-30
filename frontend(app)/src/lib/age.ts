// Formatage de l'âge d'un mot de passe à partir de `updated_at` (métadonnée EN CLAIR côté
// serveur, jamais chiffrée — voir lib/vaultCrypto.ts) — utilisé à la fois dans la liste du coffre
// (pages/Vault.tsx) et dans le tableau de bord Santé du coffre (components/VaultHealthModal.tsx).

// Au-delà, un mot de passe est considéré "ancien" — repère purement indicatif, pas une alerte de
// sécurité en soi (rien ne dit qu'un mot de passe fort et jamais réutilisé doive être changé juste
// parce qu'il est vieux).
export const OLD_PASSWORD_DAYS = 365;

export function daysSince(isoDate: string): number {
  return Math.floor((Date.now() - new Date(isoDate).getTime()) / 86_400_000);
}

/** "il y a 3 jours", "il y a 2 ans"... */
export function formatRelativeAge(isoDate: string): { label: string; days: number } {
  const days = daysSince(isoDate);
  if (days <= 0) return { label: "aujourd'hui", days };
  if (days === 1) return { label: "hier", days };
  if (days < 30) return { label: `il y a ${days} jours`, days };
  if (days < 365) {
    const months = Math.floor(days / 30);
    return { label: `il y a ${months} mois`, days };
  }
  const years = Math.floor(days / 365);
  return { label: `il y a ${years} an${years > 1 ? "s" : ""}`, days };
}
