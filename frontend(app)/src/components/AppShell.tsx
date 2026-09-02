import { useState } from "react";
import { Outlet } from "react-router-dom";
import { useAuth } from "../state/AuthContext";
import { getEffectiveMenuLayout, type MenuLayout } from "../lib/menuLayout";
import AppNav from "./AppNav";
import BugReportModal from "./BugReportModal";

/** Contexte passé aux pages enfants via `<Outlet context={...} />` — consommé par
 * components/MenuLayoutSettings.tsx (dans Réglages) pour appliquer un changement de disposition
 * IMMÉDIATEMENT, sans recharger la page. Nécessaire parce que AppShell (qui possède l'état de
 * disposition affichée) et MenuLayoutSettings (qui le modifie) sont dans des arbres de composants
 * différents, reliés seulement par le routage — le contexte d'Outlet de React Router est le moyen
 * le plus léger de les connecter sans ajouter un Context React dédié pour un seul usage. */
export interface AppShellContext {
  menuLayout: MenuLayout;
  onMenuLayoutChange: (layout: MenuLayout) => void;
}

/** Coquille persistante de l'app — retour utilisateur (2026-09-02) : navigation commune à TOUTES
 * les pages authentifiées (Coffre, Réglages, Administration, coffres/entrées partagés...), au lieu
 * de chaque page ayant jusqu'ici son propre en-tête dupliqué ("← Retour au coffre" répété partout,
 * bouton "Signaler un bug" disponible SEULEMENT depuis le Coffre). Voir App.tsx : englobe toutes
 * les routes protégées via une route de mise en page (`<Route element={<AppShell />}>`), chaque
 * page individuelle ne garde plus que son propre titre/contenu — la navigation, l'email du compte
 * et la déconnexion vivent ici, une seule fois. */
export default function AppShell() {
  const { email, isModerator, logout } = useAuth();
  const [menuLayout, setMenuLayout] = useState<MenuLayout>(() => getEffectiveMenuLayout());
  const [showBugReport, setShowBugReport] = useState(false);

  function handleMenuLayoutChange(layout: MenuLayout) {
    setMenuLayout(layout);
  }

  const context: AppShellContext = { menuLayout, onMenuLayoutChange: handleMenuLayoutChange };
  const isSideLayout = menuLayout === "sidebar" || menuLayout === "compact";

  return (
    <div className={isSideLayout ? "flex min-h-screen bg-neutral-50 dark:bg-neutral-950" : "min-h-screen bg-neutral-50 dark:bg-neutral-950"}>
      {isSideLayout && <AppNav layout={menuLayout} isModerator={isModerator} email={email} onLogout={() => void logout()} onReportBug={() => setShowBugReport(true)} />}
      <div className="min-w-0 flex-1">
        {!isSideLayout && <AppNav layout="top" isModerator={isModerator} email={email} onLogout={() => void logout()} onReportBug={() => setShowBugReport(true)} />}
        <Outlet context={context} />
      </div>
      {showBugReport && <BugReportModal onClose={() => setShowBugReport(false)} defaultEmail={email ?? undefined} />}
    </div>
  );
}
