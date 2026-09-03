import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

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
 * boutons passait à la ligne différemment selon les entrées).
 *
 * CORRECTIF (retour utilisateur : "le menu déroulant [...] se fait de façon buguée, parfois on ne
 * voit même pas les options") — le panneau déroulant est désormais rendu via un PORTAL (dans
 * `document.body`), positionné en `fixed` à des coordonnées calculées, plutôt qu'en `absolute`
 * INLINE dans la ligne d'entrée. Cause réelle : les lignes du coffre portent depuis peu
 * `content-visibility: auto` (voir App.css, `.vault-row-cv`/`.vault-card-cv`/`.vault-compact-cv` —
 * optimisation perf pour un gros coffre) — cette propriété impose `contain: paint` en continu
 * (pas seulement quand la ligne est hors écran), qui empêche tout contenu de se peindre EN DEHORS
 * de la boîte de son élément. Un panneau positionné `absolute`/`top-full` (donc dépassant
 * systématiquement le bas de la ligne) se faisait alors rogner par cette ligne — c'était
 * invisible/coupé, pas aléatoire, mais dépendait de la carte concernée d'où l'impression "parfois".
 * Rendre le panneau hors de la ligne (portal) le sort entièrement de ce périmètre de rognage, sans
 * renoncer à l'optimisation de performance sur les lignes elles-mêmes. */
export default function EntryActionsMenu({ isOpen, onToggle, onClose, items }: Props) {
  const buttonRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const [position, setPosition] = useState<{ top: number; left: number } | null>(null);

  // Position calculée à l'OUVERTURE (coordonnées écran du bouton, voir getBoundingClientRect) —
  // volontairement pas re-suivie en direct pendant un défilement (menu à durée de vie courte,
  // fermé sur le prochain clic/Échap/défilement ci-dessous — pas la peine de la complexité d'un
  // recalcul continu pour un cas d'usage aussi bref).
  useEffect(() => {
    if (!isOpen || !buttonRef.current) {
      setPosition(null);
      return;
    }
    const rect = buttonRef.current.getBoundingClientRect();
    // `right: ...` par rapport au bord droit de la fenêtre (pas `left`) : réplique l'alignement
    // `right-0` d'origine (le panneau s'étend vers la GAUCHE depuis le bord droit du bouton),
    // pour un rendu identique à avant sur desktop comme sur un écran étroit.
    setPosition({ top: rect.bottom + 4, left: window.innerWidth - rect.right });
  }, [isOpen]);

  useEffect(() => {
    if (!isOpen) return;

    function handlePointerDown(e: MouseEvent) {
      const target = e.target as Node;
      if (buttonRef.current?.contains(target)) return;
      if (panelRef.current?.contains(target)) return;
      onClose();
    }
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    // Ferme plutôt que de laisser un panneau `fixed` (donc positionné en coordonnées ÉCRAN, pas
    // relatives au document) dériver visuellement loin de son bouton pendant un défilement — voir
    // le commentaire ci-dessus sur le choix de ne pas suivre la position en direct.
    function handleScroll() {
      onClose();
    }

    window.addEventListener("mousedown", handlePointerDown);
    window.addEventListener("keydown", handleKeyDown);
    window.addEventListener("scroll", handleScroll, { capture: true, passive: true });
    return () => {
      window.removeEventListener("mousedown", handlePointerDown);
      window.removeEventListener("keydown", handleKeyDown);
      window.removeEventListener("scroll", handleScroll, { capture: true });
    };
  }, [isOpen, onClose]);

  return (
    <div className="relative">
      <button
        ref={buttonRef}
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
      {isOpen && position &&
        createPortal(
          <div
            ref={panelRef}
            style={{ position: "fixed", top: position.top, right: position.left }}
            className="z-50 w-44 overflow-hidden rounded-lg border border-neutral-200 bg-white py-1 shadow-lg dark:border-neutral-700 dark:bg-neutral-900"
          >
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
          </div>,
          document.body,
        )}
    </div>
  );
}
