import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../state/AuthContext";

/**
 * Garde d'accès à /server (voir pages/ServerSettings.tsx) — DEUX cas d'accès légitimes, PAS UN
 * SEUL :
 * 1. Pas encore connecté (build de dev OU production, `isDev` ou pas) — premier lancement, aucun
 *    compte/session n'existe encore, cet écran est justement ce qui permet de pointer l'app vers
 *    le bon backend AVANT de pouvoir s'inscrire/se connecter (voir le commentaire en tête de
 *    ServerSettings.tsx — un problème de l'œuf et de la poule, PAS quelque chose à restreindre).
 * 2. Déjà connecté ET modérateur (ou l'Admin) — repointer une app DÉJÀ configurée et utilisée vers
 *    un autre serveur reste réservé à un modérateur, pour qu'un compte familial normal ne puisse
 *    pas être amené (erreur, ingénierie sociale) à envoyer son mot de passe maître vers un serveur
 *    différent de celui prévu.
 * CORRECTIF : la version précédente bloquait aussi le cas 1 en production (seul `isDev` passait),
 * rendant impossible tout premier lancement pointé vers un backend auto-hébergé pour quiconque
 * n'est pas déjà modérateur — cassant exactement le scénario que ce fichier a été écrit pour
 * résoudre (voir ServerSettings.tsx), et bloquant purement et simplement l'installation de l'app
 * par la famille/les proches visés par ce projet.
 */
export default function ServerSettingsRoute({ children }: { children: ReactNode }) {
  const { isAuthenticated, isModerator } = useAuth();
  if (!isAuthenticated) return <>{children}</>;
  if (!isModerator) return <Navigate to="/vault" replace />;
  return <>{children}</>;
}
