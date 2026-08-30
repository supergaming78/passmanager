// Liste des coffres partagés dont l'utilisateur est membre, + création d'un nouveau — équivalent
// de frontend(app)/src/pages/SharedVaultsPage.tsx. Voir lib/sharedVault.ts pour l'orchestration
// complète (déverrouillage de chaque coffre listé).

import { useEffect, useState } from "react";
import * as session from "../lib/session";
import * as sharedVault from "../lib/sharedVault";
import type { UnlockedSharedVault } from "../lib/sharedVault";
import { getErrorMessage } from "../lib/errors";

export default function SharedVaultsListView({
  vaultKey,
  onBack,
  onOpen,
}: {
  vaultKey: Uint8Array;
  onBack: () => void;
  onOpen: (vaultId: string) => void;
}) {
  const [vaults, setVaults] = useState<UnlockedSharedVault[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newName, setNewName] = useState("");
  const [isCreating, setIsCreating] = useState(false);

  async function load() {
    setError(null);
    try {
      const list = await sharedVault.listMySharedVaults(vaultKey, session.authorizedRequest);
      setVaults(list);
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vaultKey]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!newName.trim()) return;
    setIsCreating(true);
    setError(null);
    try {
      const id = await sharedVault.createSharedVault(vaultKey, newName.trim(), session.authorizedRequest);
      setNewName("");
      setShowCreateForm(false);
      onOpen(id);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsCreating(false);
    }
  }

  return (
    <div className="flex flex-col">
      <div className="flex items-center gap-2 border-b border-neutral-200 px-4 py-3 dark:border-neutral-800">
        <button onClick={onBack} className="text-sm text-neutral-500 hover:underline">
          ← Retour
        </button>
        <h1 className="text-sm font-medium text-neutral-900 dark:text-neutral-100">Coffres partagés</h1>
      </div>

      <p className="px-4 pt-2 text-xs text-neutral-500">
        Un ensemble d'identifiants partagé avec plusieurs personnes, mis à jour en direct pour tout
        le monde — différent du partage d'une entrée isolée.
      </p>

      {error && <p className="px-4 pt-2 text-sm text-red-600 dark:text-red-400">{error}</p>}

      <div className="px-4 py-2">
        {showCreateForm ? (
          <form onSubmit={(e) => void handleCreate(e)} className="flex gap-2">
            <input
              type="text"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="ex: Famille, Maison…"
              autoFocus
              className="flex-1 rounded-md border border-neutral-300 px-2 py-1 text-sm dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-100"
            />
            <button
              type="submit"
              disabled={isCreating || !newName.trim()}
              className="rounded-md bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-700 disabled:opacity-60"
            >
              {isCreating ? "…" : "Créer"}
            </button>
            <button
              type="button"
              onClick={() => { setShowCreateForm(false); setNewName(""); }}
              className="rounded-md border border-neutral-300 px-2 py-1 text-xs text-neutral-600 dark:border-neutral-700 dark:text-neutral-300"
            >
              Annuler
            </button>
          </form>
        ) : (
          <button
            onClick={() => setShowCreateForm(true)}
            className="rounded-md bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-700"
          >
            + Créer un coffre partagé
          </button>
        )}
      </div>

      {vaults === null && !error && <p className="p-4 text-sm text-neutral-500">Chargement…</p>}
      {vaults !== null && vaults.length === 0 && <p className="p-4 text-sm text-neutral-500">Aucun coffre partagé pour l'instant.</p>}

      <ul className="flex flex-col divide-y divide-neutral-200 pb-2 dark:divide-neutral-800">
        {(vaults ?? []).map((v) => (
          <li key={v.id}>
            <button
              onClick={() => onOpen(v.id)}
              className="flex w-full items-center justify-between gap-2 px-4 py-2 text-left hover:bg-neutral-50 dark:hover:bg-neutral-900"
            >
              <div className="min-w-0">
                <p className="truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">{v.name}</p>
                <p className="truncate text-xs text-neutral-500">{v.isOwner ? "Propriétaire" : `Créé par ${v.createdBy}`}</p>
              </div>
              <span className="shrink-0 text-neutral-400">→</span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
