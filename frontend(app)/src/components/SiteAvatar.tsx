import { useMemo, useSyncExternalStore } from "react";
import { avatarColorClass, avatarLetter, matchKnownLogo } from "../lib/siteAvatar";
import { areKnownLogosLoaded, subscribeToKnownLogos } from "../lib/knownLogos";

interface Props {
  siteName: string;
  /** Utilisée UNIQUEMENT pour reconnaître une marque connue par domaine (voir
   * lib/siteAvatar.ts::matchKnownLogo) — jamais envoyée nulle part, juste comparée localement. */
  url?: string;
  /** Taille en pixels (carrée) — 32 par défaut, adapté à une ligne de liste. */
  size?: number;
}

/** Petit avatar rond affiché devant chaque entrée du coffre. Pour de nombreuses marques connues
 * (voir lib/knownLogos.ts), affiche leur VRAI logo — reconnu depuis une bibliothèque embarquée
 * dans l'app, jamais téléchargée. Trois styles selon la source des données : "color"/"multicolor"
 * (couleur(s) officielle(s) connue(s)) sur fond blanc, "mono" (silhouette sans couleur officielle
 * fournie par la source) en blanc sur un rond de couleur déterministe — même logique que l'avatar
 * lettre par défaut, pour ne jamais inventer une couleur de marque non vérifiée. Pour tout le
 * reste, retombe sur le rond couleur + initiale ci-dessous. Dans tous les cas, aucune requête
 * réseau. */
export default function SiteAvatar({ siteName, url, size = 32 }: Props) {
  // CORRECTIF PERF (voir lib/knownLogos.ts) : la bibliothèque de logos (~4,87 Mo) charge
  // maintenant à la demande plutôt que d'être bundlée avec le reste de la page. Chaque instance de
  // SiteAvatar déclenche ce chargement (mémoïsé — un SEUL vrai chargement réseau/disque, même avec
  // des dizaines d'instances montées en même temps dans la liste du coffre) puis se re-rend une
  // fois prêt, pour passer de l'avatar générique (lettre/couleur) au vrai logo si reconnu.
  // OPTIMISATION : abonnement PARTAGÉ (voir lib/knownLogos.ts::subscribeToKnownLogos) plutôt qu'un
  // useState + useEffect + callback de promesse PAR instance. La liste du coffre peut afficher des
  // centaines d'avatars : c'était autant d'abonnements, de fermetures et de `setState` distincts
  // pour un seul et même signal booléen, identique pour tout le monde.
  const logosReady = useSyncExternalStore(subscribeToKnownLogos, areKnownLogosLoaded);

  // OPTIMISATION : mémoïsé. matchKnownLogo() normalise le nom du site et l'URL puis interroge
  // jusqu'à trois tables — auparavant refait à CHAQUE rendu de CHAQUE avatar, donc N fois à chaque
  // défilement, filtrage, copie de mot de passe ou changement d'état sans rapport dans la page.
  // Les entrées d'une liste ne changent quasiment jamais de nom : ce résultat est stable.
  const logo = useMemo(
    () => (logosReady ? matchKnownLogo(siteName, url) : undefined),
    [logosReady, siteName, url],
  );

  if (logo?.kind === "color") {
    return (
      <div
        aria-hidden="true"
        className="flex shrink-0 select-none items-center justify-center rounded-full bg-white p-1.5 ring-1 ring-neutral-200 dark:ring-neutral-800"
        style={{ width: size, height: size }}
      >
        <svg viewBox="0 0 24 24" fill={logo.hex} className="h-full w-full">
          <path d={logo.path} />
        </svg>
      </div>
    );
  }

  if (logo?.kind === "multicolor") {
    return (
      <div
        aria-hidden="true"
        className="flex shrink-0 select-none items-center justify-center rounded-full bg-white p-1.5 ring-1 ring-neutral-200 dark:ring-neutral-800"
        style={{ width: size, height: size }}
      >
        <svg viewBox={logo.viewBox} className="h-full w-full">
          {logo.layers.map(([hex, path], i) => (
            <path key={i} d={path} fill={hex} />
          ))}
        </svg>
      </div>
    );
  }

  if (logo?.kind === "mono") {
    return (
      <div
        aria-hidden="true"
        className={`flex shrink-0 select-none items-center justify-center rounded-full p-1.5 ${avatarColorClass(siteName)}`}
        style={{ width: size, height: size }}
      >
        <svg viewBox={logo.viewBox} fill="white" className="h-full w-full">
          <path d={logo.path} />
        </svg>
      </div>
    );
  }

  return (
    <div
      aria-hidden="true"
      className={`flex shrink-0 select-none items-center justify-center rounded-full font-semibold text-white ${avatarColorClass(siteName)}`}
      style={{ width: size, height: size, fontSize: Math.round(size * 0.45) }}
    >
      {avatarLetter(siteName)}
    </div>
  );
}
