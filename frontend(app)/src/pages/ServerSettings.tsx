import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { getBackendUrl, setBackendUrl } from "../lib/settings";
import AuthCard from "../components/AuthCard";

/**
 * Route PUBLIQUE (pas de ProtectedRoute) — PURE PRÉ-CONNEXION (voir ServerSettingsRoute.tsx), pour
 * un premier lancement pointé vers un vrai backend auto-hébergé, avant même de pouvoir se
 * connecter. Le lien vers cette page (voir pages/Login.tsx) n'est visible que si l'Admin a activé
 * server_choice_at_login_enabled (réglage global, voir pages/Admin.tsx::ServerChoiceAtLoginSection)
 * — cette page reste néanmoins accessible par URL directe même sinon (voir ServerSettingsRoute.tsx).
 */
export default function ServerSettings() {
  const navigate = useNavigate();
  const [url, setUrl] = useState(getBackendUrl());

  function handleSave(e: FormEvent) {
    e.preventDefault();
    setBackendUrl(url);
    navigate("/login");
  }

  return (
    <AuthCard title="Serveur" subtitle="Adresse du backend auto-hébergé auquel se connecter.">
      <form onSubmit={handleSave} className="flex flex-col gap-4">
        <div>
          <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">URL du serveur</label>
          <input
            type="url"
            required
            autoFocus
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://tonapp.duckdns.org"
            className="w-full rounded-lg border border-neutral-300 px-3 py-2 font-mono text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
          />
        </div>
        <button
          type="submit"
          className="rounded-lg bg-indigo-600 px-4 py-2 font-medium text-white transition hover:bg-indigo-700"
        >
          Enregistrer
        </button>
      </form>
    </AuthCard>
  );
}
