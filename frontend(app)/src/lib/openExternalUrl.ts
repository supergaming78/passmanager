// Petit helper partagé entre VaultEntryForm.tsx (bouton "Ouvrir le site" du formulaire), Vault.tsx
// (même bouton directement sur une ligne du coffre), et les vues en lecture seule d'entrées reçues
// par partage/accès d'urgence (SharedEntryPage.tsx, EmergencyVaultPage.tsx) — évite de dupliquer la
// même normalisation d'URL à plusieurs endroits.

import { openUrl } from "@tauri-apps/plugin-opener";

/** Préfixe un schéma par défaut si l'utilisateur a tapé "exemple.com" sans "https://" — sinon
 * openUrl() de plugin-opener refuse de l'ouvrir (schéma manquant), et beaucoup d'utilisateurs
 * omettent le "https://" par habitude de navigateur. */
function normalizeUrlForOpen(raw: string): string {
  const trimmed = raw.trim();
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed) ? trimmed : `https://${trimmed}`;
}

// CORRECTIF SÉCURITÉ : seuls http(s) sont légitimes pour "Ouvrir le site" — sans cette liste
// blanche, un schéma quelconque (`file://`, `javascript:`, ou l'URI custom d'une app installée
// avec sa propre faille connue) passait tel quel jusqu'à l'OS. Risque concret ici : `url` peut
// provenir d'une entrée REÇUE (partage, voir lib/entrySharing.ts, ou accès d'urgence) — donc du
// contenu choisi par un AUTRE utilisateur, pas seulement par soi-même.
const ALLOWED_SCHEMES = new Set(["http:", "https:"]);

/** Ouvre une URL de champ (potentiellement sans schéma) dans le navigateur par défaut — rejette
 * tout ce qui n'est pas http(s), quelle que soit la provenance du champ `url`. */
export function openEntryUrl(raw: string): Promise<void> {
  const normalized = normalizeUrlForOpen(raw);
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    return Promise.reject(new Error("URL invalide."));
  }
  if (!ALLOWED_SCHEMES.has(parsed.protocol)) {
    return Promise.reject(new Error(`Schéma d'URL non autorisé (${parsed.protocol}) — seuls http/https peuvent être ouverts.`));
  }
  return openUrl(normalized);
}
