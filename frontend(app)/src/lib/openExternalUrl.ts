// Petit helper partagé entre VaultEntryForm.tsx (bouton "Ouvrir le site" du formulaire), Vault.tsx
// (même bouton directement sur une ligne du coffre), et les vues en lecture seule d'entrées reçues
// par partage/accès d'urgence (SharedEntryPage.tsx, EmergencyVaultPage.tsx) — évite de dupliquer la
// même normalisation d'URL à plusieurs endroits. Réutilisé aussi par lib/entryValidation.ts pour
// valider le champ URL À LA SAISIE (retour utilisateur : "s'assurer qu'une URL commence toujours
// par http, https") — un seul point de vérité pour "qu'est-ce qu'une URL valide ici", que ce soit
// pour l'ouvrir ou pour accepter de l'enregistrer.

import { openUrl } from "@tauri-apps/plugin-opener";

/** Préfixe un schéma par défaut si l'utilisateur a tapé "exemple.com" sans "https://" — sinon
 * openUrl() de plugin-opener refuse de l'ouvrir (schéma manquant), et beaucoup d'utilisateurs
 * omettent le "https://" par habitude de navigateur. */
function normalizeUrlScheme(raw: string): string {
  const trimmed = raw.trim();
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed) ? trimmed : `https://${trimmed}`;
}

// CORRECTIF SÉCURITÉ : seuls http(s) sont légitimes ici — sans cette liste blanche, un schéma
// quelconque (`file://`, `javascript:`, ou l'URI custom d'une app installée avec sa propre faille
// connue) passait tel quel jusqu'à l'OS. Risque concret : `url` peut provenir d'une entrée REÇUE
// (partage, voir lib/entrySharing.ts, ou accès d'urgence) — donc du contenu choisi par un AUTRE
// utilisateur, pas seulement par soi-même.
export const ALLOWED_URL_SCHEMES = new Set(["http:", "https:"]);

/** Normalise (schéma par défaut ajouté si absent) PUIS valide qu'une URL de champ est bien
 * http(s) — un seul point de vérité utilisé à la fois pour "Ouvrir le site" (openEntryUrl
 * ci-dessous) et pour valider le champ URL du formulaire d'entrée AVANT enregistrement (voir
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

/** Ouvre une URL de champ (potentiellement sans schéma) dans le navigateur par défaut — rejette
 * tout ce qui n'est pas http(s), quelle que soit la provenance du champ `url`. */
export function openEntryUrl(raw: string): Promise<void> {
  const result = normalizeAndValidateUrl(raw);
  if (!result.ok) return Promise.reject(new Error(result.error));
  return openUrl(result.normalized);
}
