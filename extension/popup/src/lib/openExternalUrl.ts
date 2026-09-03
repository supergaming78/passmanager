// Petit helper partagé entre App.tsx (bouton "Ouvrir" sur une ligne du coffre) et les vues en
// lecture seule d'entrées reçues par partage/coffre partagé/accès d'urgence (SharedEntryView.tsx,
// SharedVaultDetailView.tsx, EmergencyVaultView.tsx) — même raisonnement, même code que
// frontend(app)/src/lib/openExternalUrl.ts côté desktop (voir son commentaire pour l'historique
// complet du correctif), porté ici après avoir constaté qu'il manquait côté extension : les 4
// endroits qui appelaient `window.open(entry.url, ...)` directement, sans passer par un
// équivalent, avaient la même faille que celle déjà corrigée côté app. Réutilisé aussi par
// lib/entryValidation.ts pour valider le champ URL À LA SAISIE (retour utilisateur : "s'assurer
// qu'une URL commence toujours par http, https").

/** Préfixe un schéma par défaut si l'utilisateur a tapé "exemple.com" sans "https://" — sinon la
 * validation ci-dessous rejetterait à tort une URL parfaitement légitime juste parce que le schéma
 * est sous-entendu (habitude de navigateur courante). */
function normalizeUrlScheme(raw: string): string {
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
export const ALLOWED_URL_SCHEMES = new Set(["http:", "https:"]);

/** Normalise (schéma par défaut ajouté si absent) PUIS valide qu'une URL de champ est bien
 * http(s) — un seul point de vérité utilisé à la fois pour "Ouvrir" (openEntryUrl ci-dessous) et
 * pour valider le champ URL du formulaire d'entrée AVANT enregistrement (voir
 * lib/entryValidation.ts). */
export function normalizeAndValidateUrl(raw: string): { ok: true; normalized: string } | { ok: false; error: string } {
  const normalized = normalizeUrlScheme(raw);
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    return { ok: false, error: "URL invalide." };
  }
  if (!ALLOWED_URL_SCHEMES.has(parsed.protocol)) {
    return { ok: false, error: `schéma non autorisé (${parsed.protocol}) — seuls http:// et https:// sont acceptés.` };
  }
  return { ok: true, normalized };
}

/** Ouvre une URL de champ (potentiellement sans schéma) dans un nouvel onglet — rejette tout ce
 * qui n'est pas http(s), quelle que soit la provenance du champ `url`. */
export function openEntryUrl(raw: string): void {
  const result = normalizeAndValidateUrl(raw);
  if (!result.ok) return;
  window.open(result.normalized, "_blank", "noopener,noreferrer");
}
