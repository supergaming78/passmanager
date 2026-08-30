import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../state/AuthContext";
import VaultLockScreen from "./VaultLockScreen";

/** Redirige vers /login si aucun token n'est en mémoire (voir AuthContext) — utilisé pour
 * envelopper toutes les routes qui exigent une session active (le coffre, les réglages...).
 * Affiche l'écran de reverrouillage par-dessus si le coffre est verrouillé (isVaultLocked) — la
 * session reste valide, seule la clé de chiffrement a été effacée. */
export default function ProtectedRoute({ children }: { children: ReactNode }) {
  const { isAuthenticated, isVaultLocked } = useAuth();
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  if (isVaultLocked) return <VaultLockScreen />;
  return <>{children}</>;
}
