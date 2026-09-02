interface Props {
  onClose: () => void;
}

const SHORTCUTS: { keys: string; description: string }[] = [
  { keys: "Ctrl/Cmd + F", description: "Rechercher dans le coffre" },
  { keys: "Ctrl/Cmd + N", description: "Ajouter une nouvelle entrée" },
  { keys: "Échap", description: "Fermer la fenêtre ouverte, ou quitter le mode Sélection" },
  { keys: "?", description: "Afficher cette aide" },
];

/** Petit rappel des raccourcis clavier disponibles dans le coffre — voir pages/Vault.tsx pour
 * leur implémentation réelle (ce panneau ne fait que les documenter). */
export default function KeyboardShortcutsModal({ onClose }: Props) {
  return (
    <div className="fixed inset-0 z-10 flex items-center justify-center bg-black/40 px-4 py-8">
      <div className="w-full max-w-sm rounded-2xl border border-neutral-200 bg-white p-6 shadow-xl dark:border-neutral-800 dark:bg-neutral-900">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">Raccourcis clavier</h2>
          <button type="button" onClick={onClose} className="text-sm text-neutral-500 hover:underline">
            Fermer
          </button>
        </div>
        <ul className="flex flex-col gap-2">
          {SHORTCUTS.map((s) => (
            <li key={s.keys} className="flex items-center justify-between gap-3 text-sm">
              <span className="text-neutral-600 dark:text-neutral-400">{s.description}</span>
              <kbd className="shrink-0 rounded-md border border-neutral-300 bg-neutral-100 px-2 py-0.5 font-mono text-xs text-neutral-700 dark:border-neutral-700 dark:bg-neutral-800 dark:text-neutral-300">
                {s.keys}
              </kbd>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
