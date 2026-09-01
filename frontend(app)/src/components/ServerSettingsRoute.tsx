import type { ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../state/AuthContext";

/**
 * Garde d'accès à /server (voir pages/ServerSettings.tsx) — PURE PRÉ-CONNEXION désormais (voir la
 * conversation du 2026-09-01) : un compte déjà connecté qui veut changer l'adresse du backend
 * utilise pages/Settings.tsx (section "Serveur", visible pour l'Admin ou tout compte à qui il a
 * accordé l'accès — voir components/ServerUrlForm.tsx et handlers/admin.rs côté backend), plus
 * besoin de cette route dédiée dans ce cas. Redirige donc vers /vault si déjà connecté, plutôt que
 * d'afficher deux endroits différents pour le même réglage.
 *
 * PAS de vérification du réglage global server_choice_at_login_enabled ICI : cette page reste
 * accessible par URL directe même si le lien est masqué sur l'écran de connexion (voir
 * pages/Login.tsx) — ce réglage ne fait que masquer/afficher le LIEN, une simple "sensibilisation"
 * pour la famille/les proches visés par ce projet, pas une frontière de sécurité dure (rien
 * n'empêche techniquement de taper l'URL directement sur son propre appareil).
 */
export default function ServerSettingsRoute({ children }: { children: ReactNode }) {
  const { isAuthenticated } = useAuth();
  if (isAuthenticated) return <Navigate to="/vault" replace />;
  return <>{children}</>;
}
