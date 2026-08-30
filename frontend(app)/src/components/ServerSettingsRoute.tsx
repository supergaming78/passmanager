import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../state/AuthContext";
import { isDev } from "../lib/env";

/**
 * Garde d'accès à /server (voir pages/ServerSettings.tsx) : réservé aux développeurs (build de
 * dev, voir lib/env.ts) et aux modérateurs (ou l'Admin) déjà connectés — pas à un utilisateur
 * final en production, qui n'a aucune raison de changer à quel backend l'app se connecte. En
 * production ET pas encore connecté, impossible de vérifier isModerator (pas de session) : on
 * redirige vers /login plutôt que de laisser passer par défaut.
 */
export default function ServerSettingsRoute({ children }: { children: ReactNode }) {
  // useAuth() appelé inconditionnellement (règle des Hooks) même si isDev court-circuite le
  // résultat juste en dessous — isDev est une constante figée à la compilation, jamais un état
  // qui changerait entre deux rendus, donc aucun risque réel de bascule de branche en cours de
  // session, mais on respecte quand même l'ordre d'appel attendu par React.
  const { isAuthenticated, isModerator } = useAuth();
  if (isDev) return <>{children}</>;
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  if (!isModerator) return <Navigate to="/vault" replace />;
  return <>{children}</>;
}
