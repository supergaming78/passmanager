import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../state/AuthContext";
import { getBackendUrl, setBackendUrl, resetBackendUrlToDefault } from "../lib/settings";

const DEFAULT_URL_HINT = "https://backend-passmanager.duckdns.org:3557";

/** Formulaire de changement d'URL du backend — RÉSERVÉ À L'ADMIN (voir pages/Admin.tsx, le seul
 * endroit où ce composant est monté, gardé derrière `isAdmin`), et UNIQUEMENT accessible après
 * connexion. L'adresse par défaut de l'app est désormais fixe pour tout le monde (voir
 * lib/settings.ts) — ce formulaire ne change qu'un OVERRIDE local à CET appareil, pas la valeur
 * que les autres comptes/appareils utilisent. */
export default function ServerUrlForm() {
  const { logout } = useAuth();
  const navigate = useNavigate();
  const [url, setUrl] = useState(getBackendUrl());
  const [savedUrl, setSavedUrl] = useState(getBackendUrl());

  async function handleSave(e: FormEvent) {
    e.preventDefault();
    setBackendUrl(url);
    setSavedUrl(getBackendUrl());
    // La session actuelle (tokens, ticket WebSocket...) est liée à L'ANCIEN serveur — la garder
    // vivante contre un nouveau backend n'a pas de sens (au mieux des 401 en boucle, au pire une
    // confusion totale si un autre backend répond différemment). On déconnecte proprement et on
    // laisse l'utilisateur se reconnecter explicitement contre le nouveau serveur.
    await logout();
    navigate("/login");
  }

  async function handleResetToDefault() {
    resetBackendUrlToDefault();
    setUrl(getBackendUrl());
    setSavedUrl(getBackendUrl());
    await logout();
    navigate("/login");
  }

  const isOverridden = savedUrl !== DEFAULT_URL_HINT;

  return (
    <form onSubmit={handleSave} className="flex flex-col gap-3">
      <p className="text-xs text-neutral-500">
        Adresse du backend auquel CET appareil se connecte. Réglage purement local à cet appareil —
        rien de partagé avec les autres comptes ni les autres appareils, et sans effet sur
        l'adresse par défaut de l'app. Changer cette valeur déconnecte la session en cours (les
        jetons actuels sont liés à l'ancien serveur).
      </p>
      <div>
        <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">URL du serveur</label>
        <input
          type="url"
          required
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder={DEFAULT_URL_HINT}
          className="w-full rounded-lg border border-neutral-300 px-3 py-2 font-mono text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
        />
      </div>
      <p className="text-xs text-neutral-500">
        Actuel : {savedUrl} {!isOverridden && "(adresse par défaut)"}
      </p>
      <div className="flex gap-2">
        <button
          type="submit"
          disabled={url === savedUrl}
          className="self-start rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
        >
          Enregistrer et se reconnecter
        </button>
        {isOverridden && (
          <button
            type="button"
            onClick={handleResetToDefault}
            className="self-start rounded-lg border border-neutral-300 px-4 py-2 text-sm font-medium text-neutral-700 transition hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            Revenir à l'adresse par défaut
          </button>
        )}
      </div>
    </form>
  );
}
