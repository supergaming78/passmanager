// Couleur/lettre d'avatar pour une entrée du coffre — calculées ENTIÈREMENT en local à partir du
// nom du site déjà déchiffré, SANS aucune requête réseau. Volontairement PAS de vraies icônes de
// site (favicon) récupérées via un service externe (type Google/DuckDuckGo favicons) : charger une
// image externe pour chaque entrée révélerait la liste de tous tes sites à ce service tiers, à
// chaque affichage du coffre — incohérent avec le reste de cette app (Zero-Knowledge, aucune
// requête sortante sauf action explicite comme la vérification de fuites, voir lib/breachCheck.ts).
//
// Pour ~3450 marques connues (voir knownLogos.ts), on affiche quand même leur VRAI logo — mais
// reconnu depuis une bibliothèque EMBARQUÉE dans l'app (CC0, aucun appel réseau), jamais
// téléchargée. Toute entrée hors de cette liste retombe sur le rond couleur/lettre ci-dessous.

import { lookupKnownLogo, type KnownLogo } from "./knownLogos";

// Classes Tailwind écrites en toutes lettres (pas construites/dérivées à l'exécution) : le
// scanner Tailwind repère les noms de classe littéralement présents dans le code source, il
// n'exécute rien — une classe assemblée via template au runtime ne serait jamais générée.
const AVATAR_COLORS = [
  "bg-red-500",
  "bg-orange-500",
  "bg-amber-500",
  "bg-lime-500",
  "bg-emerald-500",
  "bg-teal-500",
  "bg-cyan-500",
  "bg-blue-500",
  "bg-indigo-500",
  "bg-violet-500",
  "bg-fuchsia-500",
  "bg-pink-500",
] as const;

/** Hash simple et déterministe (même chaîne -> toujours le même résultat, sur n'importe quel
 * appareil) — pas besoin de propriétés cryptographiques ici, juste une répartition de couleurs
 * stable. */
function hashString(value: string): number {
  let hash = 0;
  for (let i = 0; i < value.length; i++) {
    hash = (hash * 31 + value.charCodeAt(i)) | 0;
  }
  return Math.abs(hash);
}

export function avatarColorClass(siteName: string): string {
  return AVATAR_COLORS[hashString(siteName) % AVATAR_COLORS.length];
}

export function avatarLetter(siteName: string): string {
  const trimmed = siteName.trim();
  return trimmed ? trimmed[0].toUpperCase() : "?";
}

const DIACRITICS_PATTERN = /[̀-ͯ]/g;

/** Même principe que normalizeKey() dans vaultFile.ts (minuscules, sans accents/ponctuation) —
 * dupliqué ici en petit plutôt qu'importé, pour garder ce module indépendant de vaultFile.ts. */
function normalizeForLogoMatch(value: string): string {
  return value
    .normalize("NFD")
    .replace(DIACRITICS_PATTERN, "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

/** Label de marque probable extrait d'un nom d'hôte, ex: "mail.google.com" -> "google",
 * "netflix.com" -> "netflix". Heuristique : le label juste avant le TLD — imparfaite pour les TLD à
 * deux segments (ex: "amazon.co.uk" -> "co" au lieu de "amazon"), mais sans conséquence ici : un
 * label qui ne correspond à aucune entrée connue retombe simplement sur l'avatar générique, jamais
 * une erreur. */
function brandLabelFromHostname(host: string): string {
  const parts = host.split(".").filter(Boolean);
  if (parts.length === 0) return "";
  return parts.length <= 2 ? parts[0] : parts[parts.length - 2];
}

function hostnameFromUrl(rawUrl: string): string {
  if (!rawUrl) return "";
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`;
    return new URL(withScheme).hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
}

/** Cherche un logo connu (voir knownLogos.ts) pour cette entrée — d'abord par nom de site, puis par
 * domaine de l'URL si fournie (plus fiable : "Mon Netflix" ne matcherait pas par nom, mais
 * "netflix.com" oui). `undefined` si aucune correspondance — l'appelant retombe alors sur
 * avatarColorClass()/avatarLetter() ci-dessus. */
export function matchKnownLogo(siteName: string, url?: string): KnownLogo | undefined {
  const bySiteName = lookupKnownLogo(normalizeForLogoMatch(siteName));
  if (bySiteName) return bySiteName;

  const host = url ? hostnameFromUrl(url) : "";
  if (!host) return undefined;
  return lookupKnownLogo(normalizeForLogoMatch(brandLabelFromHostname(host)));
}
