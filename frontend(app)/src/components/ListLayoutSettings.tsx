import { useState } from "react";
import { getListLayout, setListLayout, type ListLayout } from "../lib/listLayout";

const LAYOUT_OPTIONS: { value: ListLayout; label: string }[] = [
  { value: "list", label: "Liste (défaut)" },
  { value: "cards", label: "Grille de cartes" },
  { value: "compact", label: "Compacte" },
];

/** Réglage de la disposition des listes (coffre, comptes dans Administration...) — retour
 * utilisateur (2026-09-02). Purement local à cet appareil (localStorage, voir lib/listLayout.ts),
 * comme le thème/la disposition du menu — pas de raison de suivre le compte, c'est un choix
 * d'affichage propre à l'écran utilisé. CORRECTIF (même jour, suite) : DESKTOP uniquement
 * désormais, comme MenuLayoutSettings.tsx (voir pages/Settings.tsx, qui ne rend ce composant que
 * si !isMobilePlatform()) — un téléphone a trop peu d'espace pour qu'une grille de cartes ou un
 * mode compact apportent un vrai gain ("disponible sur toutes les plateformes" était le choix
 * D'ORIGINE, revenu dessus après coup). */
export default function ListLayoutSettings() {
  const [layout, setLayoutState] = useState<ListLayout>(() => getListLayout());

  function handleChange(value: ListLayout) {
    setLayoutState(value);
    setListLayout(value);
  }

  return (
    <div>
      <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">Disposition des listes</label>
      <select
        value={layout}
        onChange={(e) => handleChange(e.target.value as ListLayout)}
        className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
      >
        {LAYOUT_OPTIONS.map((opt) => (
          <option key={opt.value} value={opt.value}>
            {opt.label}
          </option>
        ))}
      </select>
      <p className="mt-1 text-xs text-neutral-500">S'applique au Coffre et aux comptes utilisateurs (Administration).</p>
    </div>
  );
}
