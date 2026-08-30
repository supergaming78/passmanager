import { useState, type FormEvent } from "react";
import { useNavigate, Link } from "react-router-dom";
import * as api from "../api/client";
import { getErrorMessage } from "../lib/errors";
import AuthCard from "../components/AuthCard";

export default function ForgotPassword() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);
    try {
      // Réponse volontairement identique côté serveur, que le compte existe ou non (voir
      // request_password_reset() côté backend) : on avance donc toujours à l'écran suivant,
      // jamais d'indice ici sur l'existence du compte.
      await api.forgotPassword(email);
      navigate("/reset-password", { state: { email } });
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <AuthCard title="Mot de passe oublié" subtitle="On t'envoie un code de réinitialisation par email.">
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <div>
          <label htmlFor="email" className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
            Adresse email
          </label>
          <input
            id="email"
            type="email"
            required
            autoFocus
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded-lg border border-neutral-300 px-3 py-2 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
            placeholder="toi@example.com"
          />
        </div>

        {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}

        <button
          type="submit"
          disabled={isSubmitting}
          className="mt-2 rounded-lg bg-indigo-600 px-4 py-2 font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {isSubmitting ? "Envoi…" : "Envoyer le code"}
        </button>
      </form>

      <p className="mt-6 text-center text-sm text-neutral-600 dark:text-neutral-400">
        <Link to="/login" className="font-medium text-indigo-600 hover:underline dark:text-indigo-400">
          Retour à la connexion
        </Link>
      </p>
    </AuthCard>
  );
}
