import { useOutletContext } from "react-router-dom";
import { setMenuLayout, type MenuLayout } from "../lib/menuLayout";
import type { AppShellContext } from "./AppShell";

const LAYOUT_OPTIONS: { value: MenuLayout; label: string }[] = [
  { value: "top", label: "Bandeau en haut (défaut)" },
  { value: "sidebar", label: "Barre latérale" },
  { value: "compact", label: "Compacte (icônes)" },
];

/** Réglage de la disposition du menu principal — retour utilisateur (2026-09-02), DESKTOP
 * UNIQUEMENT (voir Settings.tsx, qui ne rend ce composant que si !isMobilePlatform()). Lit/écrit
 * via `useOutletContext<AppShellContext>()` (voir components/AppShell.tsx) plutôt que directement
 * lib/menuLayout.ts::getMenuLayout() : AppShell (qui affiche la nav) et cette page (qui la modifie)
 * sont dans des arbres de composants différents, reliés seulement par le routage — le contexte
 * d'Outlet permet d'appliquer le changement IMMÉDIATEMENT (sans recharger la page) en notifiant
 * directement AppShell, qui possède l'état affiché. */
export default function MenuLayoutSettings() {
  const { menuLayout, onMenuLayoutChange } = useOutletContext<AppShellContext>();

  function handleChange(layout: MenuLayout) {
    setMenuLayout(layout); // persiste (localStorage, voir lib/menuLayout.ts)
    onMenuLayoutChange(layout); // applique immédiatement (voir AppShell.tsx)
  }

  return (
    <div>
      <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">Disposition du menu</label>
      <select
        value={menuLayout}
        onChange={(e) => handleChange(e.target.value as MenuLayout)}
        className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
      >
        {LAYOUT_OPTIONS.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
      <p className="mt-1 text-xs text-neutral-500">
        Comment la navigation (Coffre, Réglages, Administration...) s'affiche — purement une
        question de goût, aucune fonctionnalité ne change entre les trois.
      </p>
    </div>
  );
}
