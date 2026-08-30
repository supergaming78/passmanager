import { useState, type FormEvent } from "react";
import { useLocation, useNavigate, Navigate } from "react-router-dom";
import { useAuth } from "../state/AuthContext";
import { getErrorMessage } from "../lib/errors";
import AuthCard from "../components/AuthCard";

interface LocationState {
  email: string;
  authHash: string;
  rememberMe: boolean;
}

export default function Verify2fa() {
  const { verifyDeviceAndLogin } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as LocationState | null;

  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Comme VerifyEmail : cet écran n'a de sens qu'en arrivant depuis Login avec le résultat
  // "2FA_REQUIRED" (voir Login.tsx) — sans ces informations, retour à la connexion.
  if (!state?.email || !state.authHash) {
    return <Navigate to="/login" replace />;
  }
  const { email, authHash, rememberMe } = state;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);
    try {
      await verifyDeviceAndLogin(email, code, authHash, rememberMe);
      navigate("/vault");
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <AuthCard title="Nouvel appareil détecté" subtitle={`Un code de sécurité a été envoyé à ${email}.`}>
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <div>
          <label htmlFor="code" className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
            Code de sécurité
          </label>
          <input
            id="code"
            type="text"
            inputMode="numeric"
            autoFocus
            required
            maxLength={6}
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-center text-lg tracking-[0.3em] outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
            placeholder="000000"
          />
        </div>

        {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}

        <button
          type="submit"
          disabled={isSubmitting || code.length !== 6}
          className="mt-2 rounded-lg bg-indigo-600 px-4 py-2 font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {isSubmitting ? "Vérification…" : "Valider cet appareil"}
        </button>
      </form>
    </AuthCard>
  );
}
