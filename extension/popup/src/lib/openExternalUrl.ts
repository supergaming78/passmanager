// Petit helper partagé entre App.tsx (bouton "Ouvrir" sur une ligne du coffre) et les vues en
// lecture seule d'entrées reçues par partage/coffre partagé/accès d'urgence (SharedEntryView.tsx,
// SharedVaultDetailView.tsx, EmergencyVaultView.tsx) — même raisonnement, même code que
// frontend(app)/src/lib/openExternalUrl.ts côté desktop (voir son commentaire pour l'historique
// complet du correctif), porté ici après avoir constaté qu'il manquait côté extension : les 4
// endroits qui appelaient `window.open(entry.url, ...)` directement, sans passer par un
// équivalent, avaient la même faille que celle déjà corrigée côté app.

/** Préfixe un schéma par défaut si l'utilisateur a tapé "exemple.com" sans "https://" — sinon la
 * validation ci-dessous rejetterait à tort une URL parfaitement légitime juste parce que le schéma
 * est sous-entendu (habitude de navigateur courante). */
function normalizeUrlForOpen(raw: string): string {
  const trimmed = raw.trim();
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed) ? trimmed : `https://${trimmed}`;
}

// CORRECTIF SÉCURITÉ (même correctif que côté app desktop, porté ici) : seuls http(s) sont
// légitimes pour "Ouvrir le site" — sans cette liste blanche, un schéma quelconque (`javascript:`,
// `file://`, l'URI custom d'une app installée avec sa propre faille connue...) passait tel quel
// jusqu'à `window.open()`. Risque concret ici : `url` peut provenir d'une entrée REÇUE (partage,
// coffre partagé, accès d'urgence) — donc du contenu choisi par un AUTRE utilisateur, pas
// seulement par soi-même. `noopener,noreferrer` (déjà en place sur chaque appel) protège contre la
// direction inverse (la page ouverte qui remonterait vers ce popup via `window.opener`), mais ne
// filtre jamais le SCHÉMA de l'URL cible elle-même — les deux protections sont complémentaires,
// aucune ne remplace l'autre.
const ALLOWED_SCHEMES = new Set(["http:", "https:"]);

/** Ouvre une URL de champ (potentiellement sans schéma) dans un nouvel onglet — rejette tout ce
 * qui n'est pas http(s), quelle que soit la provenance du champ `url`. */
export function openEntryUrl(raw: string): void {
  const normalized = normalizeUrlForOpen(raw);
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    return;
  }
  if (!ALLOWED_SCHEMES.has(parsed.protocol)) return;
  window.open(normalized, "_blank", "noopener,noreferrer");
}
