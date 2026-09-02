import { useCallback, useMemo, useState } from "react";
import { Outlet } from "react-router-dom";
import { useAuth } from "../state/AuthContext";
import { getEffectiveMenuLayout, type MenuLayout } from "../lib/menuLayout";
import AppNav from "./AppNav";
import BugReportModal from "./BugReportModal";
import FeatureSuggestionModal from "./FeatureSuggestionModal";

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
 * et la déconnexion vivent ici, une seule fois.
 *
 * CORRECTIF (retour utilisateur, 2026-09-02) : le bandeau/la barre latérale défilaient AVEC le
 * contenu de la page — sur une longue liste (le Coffre, typiquement), le menu disparaissait en
 * scrollant, et pour la barre latérale, les icônes du haut/bas devenaient invisibles selon la
 * position de défilement (la barre entière s'étirait à la hauteur du CONTENU, pas de la fenêtre).
 * Cause : ni le conteneur racine ni le contenu n'avaient de hauteur/défilement propres — tout
 * grandissait ensemble dans le flux normal de la page, `<html>`/`<body>` faisant le défilement.
 * Fix : conteneur racine fixé à la hauteur de la fenêtre (`h-screen overflow-hidden`) — le menu
 * (`AppNav`, `shrink-0` en bandeau, hauteur pleine en barre latérale/compacte) reste FIXE, seule la
 * zone de contenu défile de façon INDÉPENDANTE (`flex-1 overflow-y-auto`) — le vrai motif "coquille
 * d'app" (menu fixe, contenu qui défile seul), plutôt que compter sur `position: sticky`. */
export default function AppShell() {
  const { email, isModerator, logout } = useAuth();
  const [menuLayout, setMenuLayout] = useState<MenuLayout>(() => getEffectiveMenuLayout());
  const [showBugReport, setShowBugReport] = useState(false);
  const [showFeatureSuggestion, setShowFeatureSuggestion] = useState(false);

  // CORRECTIF PERF (retour utilisateur, 2026-09-02) : tous ces callbacks + l'objet de contexte
  // ci-dessous étaient recréés à CHAQUE rendu de AppShell (ex: chaque frappe dans une recherche
  // ailleurs dans l'app ne le déclenche pas, mais un changement d'état ici — thème appliqué en
  // direct, etc. — si. Une nouvelle référence d'objet à chaque fois force React à re-rendre
  // TOUTE la sous-arborescence de l'Outlet consommant useOutletContext(), même quand menuLayout
  // n'a pas changé). `useCallback`/`useMemo` gardent la même référence tant que les dépendances
  // réelles ne changent pas — permet aussi à AppNav ci-dessous d'être enveloppé de `React.memo`
  // (voir AppNav.tsx) sans que ça perde son intérêt.
  const handleMenuLayoutChange = useCallback((layout: MenuLayout) => {
    setMenuLayout(layout);
  }, []);
  const handleLogout = useCallback(() => {
    void logout();
  }, [logout]);
  const handleReportBug = useCallback(() => setShowBugReport(true), []);
  const handleCloseBugReport = useCallback(() => setShowBugReport(false), []);
  const handleSuggestFeature = useCallback(() => setShowFeatureSuggestion(true), []);
  const handleCloseFeatureSuggestion = useCallback(() => setShowFeatureSuggestion(false), []);

  const context: AppShellContext = useMemo(
    () => ({ menuLayout, onMenuLayoutChange: handleMenuLayoutChange }),
    [menuLayout, handleMenuLayoutChange],
  );
  const isSideLayout = menuLayout === "sidebar" || menuLayout === "compact";

  return (
    <div className={`h-screen overflow-hidden bg-neutral-50 dark:bg-neutral-950 ${isSideLayout ? "flex" : "flex flex-col"}`}>
      <AppNav
        layout={menuLayout}
        isModerator={isModerator}
        email={email}
        onLogout={handleLogout}
        onReportBug={handleReportBug}
        onSuggestFeature={handleSuggestFeature}
      />
      <div className="min-w-0 flex-1 overflow-y-auto">
        <Outlet context={context} />
      </div>
      {showBugReport && <BugReportModal onClose={handleCloseBugReport} defaultEmail={email ?? undefined} />}
      {showFeatureSuggestion && <FeatureSuggestionModal onClose={handleCloseFeatureSuggestion} />}
    </div>
  );
}
