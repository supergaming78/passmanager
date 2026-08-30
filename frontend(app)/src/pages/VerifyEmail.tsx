import { useState, type FormEvent } from "react";
import { useLocation, useNavigate, Navigate } from "react-router-dom";
import { useAuth } from "../state/AuthContext";
import { getErrorMessage } from "../lib/errors";
import AuthCard from "../components/AuthCard";

interface LocationState {
  email: string;
}

export default function VerifyEmail() {
  const { verifyEmail, resendVerification } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as LocationState | null;

  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isResending, setIsResending] = useState(false);

  // Cet écran n'a de sens qu'arrivé depuis Register (voir navigate("/verify-email", {state})) —
  // sans email connu, impossible de savoir quel compte confirmer, donc retour à l'inscription.
  if (!state?.email) {
    return <Navigate to="/register" replace />;
  }
  const email = state.email;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);
    try {
      await verifyEmail(email, code);
      navigate("/login", { state: { email, justVerified: true } });
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handleResend() {
    setError(null);
    setInfo(null);
    setIsResending(true);
    try {
      await resendVerification(email);
      setInfo("Un nouveau code vient d'être envoyé.");
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsResending(false);
    }
  }

  return (
    <AuthCard title="Confirme ton email" subtitle={`Un code à 6 chiffres a été envoyé à ${email}.`}>
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <div>
          <label htmlFor="code" className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
            Code de confirmation
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
        {info && <p className="text-sm text-emerald-600 dark:text-emerald-400">{info}</p>}

        <button
          type="submit"
          disabled={isSubmitting || code.length !== 6}
          className="mt-2 rounded-lg bg-indigo-600 px-4 py-2 font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {isSubmitting ? "Vérification…" : "Confirmer"}
        </button>
      </form>

      <button
        type="button"
        onClick={handleResend}
        disabled={isResending}
        className="mt-4 w-full text-center text-sm text-indigo-600 hover:underline disabled:opacity-60 dark:text-indigo-400"
      >
        {isResending ? "Envoi…" : "Renvoyer le code"}
      </button>
    </AuthCard>
  );
}
