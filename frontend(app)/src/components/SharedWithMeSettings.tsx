import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../state/AuthContext";
import { ensureEmergencyKeys } from "../lib/emergencyAccess";
import { listSharedWithMe, revokeShare } from "../lib/entrySharing";
import { getErrorMessage } from "../lib/errors";
import { getListLayout, listContainerClass } from "../lib/listLayout";
import type { SharedWithMeEntry } from "../api/types";

/** Ce qui a été partagé avec l'utilisateur courant (voir lib/entrySharing.ts, GET
 * /shares/shared-with-me). Génère ses propres clés d'accès si besoin AU MONTAGE — c'est cette
 * étape (visiter cet écran une fois) qui rend l'utilisateur "partageable" pour les autres (voir le
 * commentaire de lib/entrySharing.ts::shareEntry). */
export default function SharedWithMeSettings() {
  const { authorizedRequest } = useAuth();
  const navigate = useNavigate();

  const [shares, setShares] = useState<SharedWithMeEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  // Réglé dans Réglages (voir components/ListLayoutSettings.tsx) — même préférence que le Coffre.
  const [listLayout] = useState(() => getListLayout());

  async function loadAll() {
    setIsLoading(true);
    setError(null);
    try {
      await ensureEmergencyKeys(authorizedRequest);
      setShares(await listSharedWithMe(authorizedRequest));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    void loadAll();
    // eslint pas configuré dans ce projet ; authorizedRequest est stable (voir AuthContext.tsx).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleLeave(share: SharedWithMeEntry) {
    if (!confirm(`Quitter ce partage de "${share.owner_email}" ?`)) return;
    setError(null);
    setBusyId(share.id);
    try {
      await revokeShare(authorizedRequest, share.id);
      setShares((prev) => prev.filter((s) => s.id !== share.id));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  if (isLoading) return <p className="text-sm text-neutral-500">Chargement…</p>;

  return (
    <div className="flex flex-col gap-3">
      {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}
      {shares.length === 0 ? (
        <p className="text-sm text-neutral-500">Aucune entrée n'a été partagée avec vous.</p>
      ) : (
        // @container (voir lib/listLayout.ts::listContainerClass) : réagit à la largeur réellement
        // disponible ici, pas à celle de la fenêtre entière — indispensable avec un menu latéral.
        <div className="@container">
        <ul className={listContainerClass(listLayout, "grid-cols-[repeat(auto-fit,minmax(190px,1fr))]")}>
          {shares.map((share) => {
            // CORRECTIF (retour utilisateur, 2026-09-02) : "compact" ne changeait auparavant QUE le
            // padding vertical du conteneur (p-3 -> px-3 py-1.5) — une différence trop fine pour être
            // perçue à côté de "list". Réduit maintenant aussi la taille du texte/des boutons, comme
            // le fait déjà pages/Vault.tsx::renderEntryCompact pour le Coffre, pour une densité
            // réellement visible.
            const isCompact = listLayout === "compact";
            return (
              <li
                key={share.id}
                className={`flex items-center justify-between gap-2 rounded-lg border border-neutral-200 dark:border-neutral-800 ${
                  isCompact ? "px-3 py-1" : "p-3"
                }`}
              >
                <p className={`min-w-0 truncate text-neutral-800 dark:text-neutral-200 ${isCompact ? "text-xs" : "text-sm"}`}>
                  Partagé par {share.owner_email}
                </p>
                <div className={`flex shrink-0 ${isCompact ? "gap-1" : "gap-1.5"}`}>
                  <button
                    type="button"
                    onClick={() => navigate(`/shared/${encodeURIComponent(share.id)}`)}
                    disabled={busyId === share.id}
                    className={`rounded-lg bg-indigo-600 font-medium text-white hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50 ${
                      isCompact ? "px-1.5 py-0.5 text-[11px]" : "px-2 py-1 text-xs"
                    }`}
                  >
                    Voir
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleLeave(share)}
                    disabled={busyId === share.id}
                    className={`rounded-lg border border-red-300 font-medium text-red-600 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-900 dark:text-red-400 dark:hover:bg-red-950 ${
                      isCompact ? "px-1.5 py-0.5 text-[11px]" : "px-2 py-1 text-xs"
                    }`}
                  >
                    Quitter
                  </button>
                </div>
              </li>
            );
          })}
        </ul>
        </div>
      )}
    </div>
  );
}
