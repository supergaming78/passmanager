import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../state/AuthContext";
import * as sharedVault from "../lib/sharedVault";
import type { UnlockedSharedVault } from "../lib/sharedVault";
import { getErrorMessage } from "../lib/errors";

/** Liste des coffres partagés dont l'utilisateur est membre, + création d'un nouveau. Voir
 * lib/sharedVault.ts pour l'orchestration complète (déverrouillage de chaque coffre listé). */
export default function SharedVaultsPage() {
  const { authorizedRequest, subscribeToVaultSync } = useAuth();
  const navigate = useNavigate();

  const [vaults, setVaults] = useState<UnlockedSharedVault[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newName, setNewName] = useState("");
  const [isCreating, setIsCreating] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      const list = await sharedVault.listMySharedVaults(authorizedRequest);
      setVaults(list);
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }, [authorizedRequest]);

  useEffect(() => {
    void load();
  }, [load]);

  // Recharge en direct si un coffre partagé apparaît/disparaît pendant que cette liste est
  // ouverte (voir le commentaire équivalent dans SharedVaultDetailPage.tsx).
  useEffect(() => {
    return subscribeToVaultSync(() => {
      void load();
    });
  }, [subscribeToVaultSync, load]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    if (!newName.trim()) return;
    setIsCreating(true);
    setError(null);
    try {
      const id = await sharedVault.createSharedVault(authorizedRequest, newName.trim());
      setNewName("");
      setShowCreateForm(false);
      navigate(`/shared-vaults/${id}`);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsCreating(false);
    }
  }

  return (
    <main className="min-h-screen bg-neutral-50 px-4 py-8 dark:bg-neutral-950">
      {/* Largeur progressive tablette/desktop — voir le commentaire équivalent dans Vault.tsx. */}
      <div className="mx-auto max-w-2xl md:max-w-3xl lg:max-w-4xl">
        <header className="mb-6 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">Coffres partagés</h1>
            <p className="text-sm text-neutral-500">
              Un ensemble d'identifiants partagé avec plusieurs personnes, mis à jour en direct pour
              tout le monde — différent du partage d'une entrée isolée (voir "Partager" dans le coffre).
            </p>
          </div>
          <Link
            to="/vault"
            className="rounded-lg border border-neutral-300 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-900"
          >
            ← Retour au coffre
          </Link>
        </header>

        {error && <p className="mb-4 text-sm text-red-600 dark:text-red-400">{error}</p>}

        {showCreateForm ? (
          <form onSubmit={(e) => void handleCreate(e)} className="mb-6 rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
            <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">Nom du coffre</label>
            <div className="flex gap-2">
              <input
                type="text"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="ex: Famille, Maison, Netflix..."
                autoFocus
                className="flex-1 rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-100"
              />
              <button
                type="submit"
                disabled={isCreating || !newName.trim()}
                className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isCreating ? "Création…" : "Créer"}
              </button>
              <button
                type="button"
                onClick={() => { setShowCreateForm(false); setNewName(""); }}
                className="rounded-lg border border-neutral-300 px-3 py-2 text-sm text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                Annuler
              </button>
            </div>
          </form>
        ) : (
          <button
            type="button"
            onClick={() => setShowCreateForm(true)}
            className="mb-6 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700"
          >
            + Créer un coffre partagé
          </button>
        )}

        {vaults === null ? (
          <p className="text-sm text-neutral-500">Chargement…</p>
        ) : vaults.length === 0 ? (
          <p className="text-sm text-neutral-500">Aucun coffre partagé pour l'instant.</p>
        ) : (
          <ul className="flex flex-col divide-y divide-neutral-200 overflow-hidden rounded-xl border border-neutral-200 bg-white dark:divide-neutral-800 dark:border-neutral-800 dark:bg-neutral-900">
            {vaults.map((v) => (
              <li key={v.id}>
                <Link
                  to={`/shared-vaults/${v.id}`}
                  className="flex items-center justify-between gap-3 px-4 py-3 hover:bg-neutral-50 dark:hover:bg-neutral-800"
                >
                  <div className="min-w-0">
                    <p className="truncate font-medium text-neutral-900 dark:text-neutral-100">{v.name}</p>
                    <p className="text-xs text-neutral-500">{v.isOwner ? "Propriétaire" : `Créé par ${v.createdBy}`}</p>
                  </div>
                  <span className="shrink-0 text-neutral-400">→</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </div>
    </main>
  );
}
