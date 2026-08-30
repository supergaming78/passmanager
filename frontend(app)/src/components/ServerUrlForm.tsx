import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../state/AuthContext";
import { getBackendUrl, setBackendUrl } from "../lib/settings";

/** Formulaire de changement d'URL du backend — voir components/ServerSettingsRoute.tsx et
 * pages/Admin.tsx pour qui peut y accéder (admin connecté, ou build de développement). */
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

  return (
    <form onSubmit={handleSave} className="flex flex-col gap-3">
      <p className="text-xs text-neutral-500">
        Adresse du backend auto-hébergé auquel CET appareil se connecte. Réglage purement local —
        rien de partagé avec les autres comptes ni les autres appareils. Changer cette valeur
        déconnecte la session en cours (les jetons actuels sont liés à l'ancien serveur).
      </p>
      <div>
        <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">URL du serveur</label>
        <input
          type="url"
          required
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://tonapp.duckdns.org"
          className="w-full rounded-lg border border-neutral-300 px-3 py-2 font-mono text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
        />
      </div>
      <p className="text-xs text-neutral-500">Actuel : {savedUrl}</p>
      <button
        type="submit"
        disabled={url === savedUrl}
        className="self-start rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
      >
        Enregistrer et se reconnecter
      </button>
    </form>
  );
}
