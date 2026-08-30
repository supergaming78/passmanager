// Bibliothèque LOCALE de logos de marques — la bibliothèque COMPLÈTE de Simple Icons
// (https://simpleicons.org, CC0-1.0, ~3450 marques) COMPLÉTÉE par des icônes venues de CoreUI
// Brands (https://coreui.io/icons/, CC0-1.0), de Wikimedia Commons (fichiers du domaine public,
// voir CAPCOM ci-dessous) et, pour une seule marque restée introuvable ailleurs (OpenAI), de Font
// Awesome Free (https://fontawesome.com, CC BY 4.0 — voir ATTRIBUTION ci-dessous). Objectif :
// reconnaître le plus grand nombre possible de sites/apps et afficher leur VRAI logo, SANS AUCUNE
// requête réseau (contrairement à un service de favicon externe). Toute entrée hors de ces
// bibliothèques retombe sur l'avatar lettre/couleur générique (voir siteAvatar.ts).
//
// Les données (`knownLogos.json`/`knownLogosMono.json`/`knownLogosMulti.json`, à côté de ce
// fichier) sont extraites des paquets/API `simple-icons`, `@coreui/icons` (via l'API
// iconify.design), Wikimedia Commons et `@fortawesome/fontawesome-free`, puis recopiées ici en dur
// — aucun de ces paquets n'est une dépendance de production (on ne veut que leurs données, pas
// tout leur outillage). Format compact volontaire (tuples plutôt qu'objets), pour économiser de la
// place sur un fichier déjà volumineux (~3450 entrées).
//
// TROIS FORMATS DIFFÉRENTS, RENDUS DIFFÉREMMENT (voir SiteAvatar.tsx) :
// - "color" (Simple Icons) : couleur officielle de la marque, UN SEUL tracé -> rond blanc, icône
//   couleur. Toujours viewBox 24x24 (format natif de Simple Icons, pas stocké par entrée).
// - "mono" (CoreUI Brands, Font Awesome) : silhouette monochrome SEULEMENT, PAS de couleur
//   officielle fournie par ces bibliothèques -> rendue en blanc sur un rond de couleur
//   déterministe (même logique que l'avatar lettre par défaut), plutôt que d'inventer une couleur
//   de marque non vérifiée.
// - "multicolor" (Wikimedia Commons) : PLUSIEURS tracés, chacun avec sa propre couleur -> rond
//   blanc, tracés superposés dans leurs couleurs respectives. Réservé aux rares logos dont la
//   version icône (pas juste le nom écrit en toutes lettres) reste simple à quelques couleurs —
//   voir CAPCOM, seul cas actuellement.
//
// CAPCOM (multicolor) : "File:Capcom logo icon.svg" sur Wikimedia Commons, catalogué domaine
// public (avec mention "trademarked" — même situation que n'importe quel logo de marque ici : la
// forme n'est pas protégeable par le droit d'auteur, mais le nom/la marque reste une marque
// déposée, ce qui n'empêche pas un usage d'identification comme celui-ci).
//
// ATTRIBUTION : CoreUI Brands, Simple Icons et les fichiers du domaine public de Wikimedia Commons
// ne requièrent aucune attribution. SEULE EXCEPTION : l'icône "openai" dans knownLogosMono.json
// vient de Font Awesome Free, sous licence CC BY 4.0
// (https://creativecommons.org/licenses/by/4.0/), qui EXIGE une attribution — voir la mention
// affichée dans Réglages.
//
// NOTE : de nombreuses marques restent malgré tout ABSENTES de ces bibliothèques — soit parce
// qu'aucune n'en propose de logo du tout (Visual Studio Code, Minecraft, Disney, Walmart, Hulu,
// Wargaming — vérifié y compris sur Wikimedia Commons), soit parce que la seule version trouvée est
// un texte de marque complet (wordmark), illisible une fois réduit à la taille d'un avatar rond, et
// délibérément écartée plutôt que d'afficher quelque chose d'illisible ou de mal coupé (Nexus Mods,
// Bandai Namco, Gearbox). Ces entrées retombent donc, elles aussi, sur l'avatar générique — pas un
// oubli.
//
// "crytek" est un ALIAS vers l'entrée "cryengine" (le moteur de jeu de Crytek, présent dans Simple
// Icons) — Crytek elle-même n'a pas de logo propre dans les bibliothèques utilisées ici, mais
// CryEngine reste un logo reconnaissable et directement associé à la marque.

import rawLogos from "./knownLogos.json";
import rawMonoLogos from "./knownLogosMono.json";
import rawMultiLogos from "./knownLogosMulti.json";

export type KnownLogo =
  | { kind: "color"; hex: string; path: string }
  | { kind: "mono"; viewBox: string; path: string }
  | { kind: "multicolor"; viewBox: string; layers: [string, string][] };

// Clé = forme normalisée (minuscules, sans accents/espaces/ponctuation, voir
// normalizeForLogoMatch() dans siteAvatar.ts) du nom de marque OU d'un alias courant (ex:
// "twitter" pour X) OU du domaine racine (ex: "netflix" pour netflix.com).
const RAW_LOGOS = rawLogos as unknown as Record<string, [string, string]>;
const RAW_MONO_LOGOS = rawMonoLogos as unknown as Record<string, [string, string]>;
const RAW_MULTI_LOGOS = rawMultiLogos as unknown as Record<string, [string, [string, string][]]>;

export function lookupKnownLogo(normalizedKey: string): KnownLogo | undefined {
  const color = RAW_LOGOS[normalizedKey];
  if (color) return { kind: "color", hex: color[0], path: color[1] };

  const mono = RAW_MONO_LOGOS[normalizedKey];
  if (mono) return { kind: "mono", viewBox: mono[0], path: mono[1] };

  const multi = RAW_MULTI_LOGOS[normalizedKey];
  if (multi) return { kind: "multicolor", viewBox: multi[0], layers: multi[1] };

  return undefined;
}
