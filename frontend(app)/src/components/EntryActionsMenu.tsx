import { useEffect, useRef } from "react";

interface MenuItem {
  label: string;
  onClick: () => void;
  danger?: boolean;
}

interface Props {
  isOpen: boolean;
  onToggle: () => void;
  onClose: () => void;
  items: MenuItem[];
}

/** Petit menu "⋯" pour les actions secondaires d'une entrée (voir pages/Vault.tsx::renderEntryRow) —
 * regrouper ici les actions les moins utilisées (dupliquer/historique/supprimer) plutôt que de
 * toutes les caser en boutons texte dans la ligne garde une rangée d'actions de largeur PRÉVISIBLE
 * d'une carte à l'autre, quel que soit le nombre de badges ou la longueur du nom de site — c'est ce
 * qui rendait les cartes visuellement incohérentes les unes par rapport aux autres (la rangée de
 * boutons passait à la ligne différemment selon les entrées). */
export default function EntryActionsMenu({ isOpen, onToggle, onClose, items }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isOpen) return;

    function handlePointerDown(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) onClose();
    }
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }

    window.addEventListener("mousedown", handlePointerDown);
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("mousedown", handlePointerDown);
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [isOpen, onClose]);

  return (
    <div ref={containerRef} className="relative">
      <button
        type="button"
        onClick={onToggle}
        aria-label="Plus d'actions"
        aria-expanded={isOpen}
        className={`rounded-lg border px-2.5 py-1 text-xs font-medium transition ${
          isOpen
            ? "border-indigo-300 bg-indigo-50 text-indigo-700 dark:border-indigo-800 dark:bg-indigo-950 dark:text-indigo-300"
            : "border-neutral-300 text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
        }`}
      >
        ⋯
      </button>
      {isOpen && (
        <div className="absolute right-0 top-full z-10 mt-1 w-44 overflow-hidden rounded-lg border border-neutral-200 bg-white py-1 shadow-lg dark:border-neutral-700 dark:bg-neutral-900">
          {items.map((item) => (
            <button
              key={item.label}
              type="button"
              onClick={() => {
                item.onClick();
                onClose();
              }}
              className={`block w-full px-3 py-1.5 text-left text-sm hover:bg-neutral-100 dark:hover:bg-neutral-800 ${
                item.danger ? "text-red-600 dark:text-red-400" : "text-neutral-700 dark:text-neutral-300"
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
