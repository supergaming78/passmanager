import { useEffect, useState, type FormEvent } from "react";
import { useLocation, useNavigate, Link } from "react-router-dom";
import { useAuth } from "../state/AuthContext";
import { getErrorMessage } from "../lib/errors";
import { getPublicConfig } from "../api/client";
import AuthCard from "../components/AuthCard";
import BugReportModal from "../components/BugReportModal";

interface LocationState {
  email?: string;
  justVerified?: boolean;
}

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const locationState = location.state as LocationState | null;

  const [email, setEmail] = useState(locationState?.email ?? "");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [showBugReport, setShowBugReport] = useState(false);
  // Réglage GLOBAL côté Admin (voir pages/Admin.tsx::ServerChoiceAtLoginSection et
  // handlers/admin.rs::update_server_choice_at_login()) : le lien "Configurer le serveur" reste
  // masqué par défaut sur cet écran pré-connexion, sauf activation explicite. Best-effort (échec
  // silencieux) : une coupure réseau ne doit jamais bloquer l'écran de connexion lui-même, juste
  // laisser ce lien caché — cohérent avec le fait que /server reste de toute façon accessible par
  // URL directe (voir ServerSettingsRoute.tsx), ce n'est qu'un lien en moins, pas une vraie panne.
  const [showServerChoiceLink, setShowServerChoiceLink] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void getPublicConfig()
      .then((config) => {
        if (!cancelled) setShowServerChoiceLink(config.server_choice_at_login_enabled);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);
    try {
      const result = await login(email, password, rememberMe);
      if (result.status === "2FA_REQUIRED") {
        navigate("/verify-2fa", { state: { email, authHash: result.authHash, rememberMe } });
      } else {
        navigate("/vault");
      }
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <AuthCard
      title="Connexion"
      subtitle={locationState?.justVerified ? "Email confirmé — connecte-toi maintenant." : undefined}
    >
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <div>
          <label htmlFor="email" className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
            Adresse email
          </label>
          <input
            id="email"
            type="email"
            required
            autoFocus={!locationState?.email}
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded-lg border border-neutral-300 px-3 py-2 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
            placeholder="toi@example.com"
          />
        </div>

        <div>
          <label htmlFor="password" className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
            Mot de passe maître
          </label>
          <input
            id="password"
            type="password"
            required
            autoFocus={!!locationState?.email}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-lg border border-neutral-300 px-3 py-2 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
          />
        </div>

        <label className="flex items-center gap-2 text-sm text-neutral-700 dark:text-neutral-300">
          <input
            type="checkbox"
            checked={rememberMe}
            onChange={(e) => setRememberMe(e.target.checked)}
            className="rounded border-neutral-300 text-indigo-600 focus:ring-indigo-500"
          />
          Se souvenir de moi sur cet appareil
        </label>

        {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}

        <button
          type="submit"
          disabled={isSubmitting}
          className="mt-2 rounded-lg bg-indigo-600 px-4 py-2 font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {isSubmitting ? "Connexion…" : "Se connecter"}
        </button>
      </form>

      <div className="mt-6 flex justify-between text-sm">
        <Link to="/forgot-password" className="text-indigo-600 hover:underline dark:text-indigo-400">
          Mot de passe oublié ?
        </Link>
        <Link to="/register" className="text-indigo-600 hover:underline dark:text-indigo-400">
          Créer un compte
        </Link>
      </div>
      {/* "Configurer le serveur" : masqué par défaut (voir showServerChoiceLink plus haut) —
          l'Admin doit l'activer explicitement (réglage global, voir pages/Admin.tsx et
          handlers/admin.rs::update_server_choice_at_login()) pour qu'il apparaisse ici, avant
          toute connexion. */}
      <div className="mt-3 flex justify-center gap-3 text-center">
        {showServerChoiceLink && (
          <Link to="/server" className="text-xs text-neutral-400 hover:underline dark:text-neutral-500">
            Configurer le serveur
          </Link>
        )}
        {/* Accessible AVANT toute connexion — un bug qui empêche justement de se connecter doit
            pouvoir être signalé depuis l'app elle-même (voir components/BugReportModal.tsx). */}
        <button
          type="button"
          onClick={() => setShowBugReport(true)}
          className="text-xs text-neutral-400 hover:underline dark:text-neutral-500"
        >
          Signaler un bug
        </button>
      </div>
      {showBugReport && <BugReportModal onClose={() => setShowBugReport(false)} />}
    </AuthCard>
  );
}
