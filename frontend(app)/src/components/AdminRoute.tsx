import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../state/AuthContext";
import VaultLockScreen from "./VaultLockScreen";

/** Comme ProtectedRoute, mais exige EN PLUS isModerator (voir state/AuthContext.tsx, alimenté par
 * GET /me) — un modérateur doit pouvoir ouvrir ce panneau (pour gérer les comptes non-modérateur),
 * seuls certains boutons y restent ensuite réservés à l'Admin (voir Admin.tsx). Redirige vers
 * /login si pas connecté, vers /vault si connecté mais pas modérateur — le serveur revérifie de
 * toute façon is_moderator sur chaque route /admin/* lui-même (voir handlers/admin.rs côté
 * backend) : cette garde ne fait qu'éviter d'afficher un écran vide ou une cascade d'erreurs 403 à
 * un utilisateur qui n'a simplement pas les droits. */
export default function AdminRoute({ children }: { children: ReactNode }) {
  const { isAuthenticated, isModerator, isVaultLocked } = useAuth();
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  if (isVaultLocked) return <VaultLockScreen />;
  if (!isModerator) return <Navigate to="/vault" replace />;
  return <>{children}</>;
}
