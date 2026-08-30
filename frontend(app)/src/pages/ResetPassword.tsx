import { useState, type FormEvent } from "react";
import { useLocation, useNavigate, Navigate } from "react-router-dom";
import * as api from "../api/client";
import * as tauri from "../api/tauri";
import { getErrorMessage } from "../lib/errors";
import AuthCard from "../components/AuthCard";
import PasswordStrengthMeter from "../components/PasswordStrengthMeter";

interface LocationState {
  email: string;
}

export default function ResetPassword() {
  const navigate = useNavigate();
  const location = useLocation();
  const state = location.state as LocationState | null;

  const [code, setCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  if (!state?.email) {
    return <Navigate to="/forgot-password" replace />;
  }
  const email = state.email;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);

    if (newPassword !== confirmPassword) {
      setError("Les deux mots de passe ne correspondent pas.");
      return;
    }
    if (newPassword.length < 8) {
      setError("Le mot de passe maître doit faire au moins 8 caractères.");
      return;
    }

    setIsSubmitting(true);
    try {
      const authHash = await tauri.deriveKeys(email, newPassword);
      await api.resetPassword({ email, code, new_master_password_hash: authHash });
      // La clé dérivée ci-dessus ne sert plus : une réinitialisation purge intégralement le
      // coffre côté serveur (Zero-Knowledge, voir confirm_password_reset() côté backend — aucune
      // clé de l'ancien mot de passe pour re-chiffrer quoi que ce soit). L'utilisateur devra se
      // reconnecter normalement, ce qui re-dérivera la clé de toute façon.
      await tauri.lockVault();
      navigate("/login", {
        state: { email, justVerified: false },
      });
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <AuthCard
      title="Réinitialiser le mot de passe"
      subtitle="⚠️ Le contenu actuel du coffre sera définitivement perdu (chiffré avec l'ancien mot de passe, impossible à récupérer)."
    >
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <div>
          <label htmlFor="code" className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
            Code reçu par email
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

        <div>
          <label htmlFor="newPassword" className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
            Nouveau mot de passe maître
          </label>
          <input
            id="newPassword"
            type="password"
            required
            minLength={8}
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            className="w-full rounded-lg border border-neutral-300 px-3 py-2 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
          />
          <PasswordStrengthMeter password={newPassword} />
        </div>

        <div>
          <label htmlFor="confirmPassword" className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
            Confirme le nouveau mot de passe
          </label>
          <input
            id="confirmPassword"
            type="password"
            required
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            className="w-full rounded-lg border border-neutral-300 px-3 py-2 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
          />
        </div>

        {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}

        <button
          type="submit"
          disabled={isSubmitting || code.length !== 6}
          className="mt-2 rounded-lg bg-red-600 px-4 py-2 font-medium text-white transition hover:bg-red-700 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {isSubmitting ? "Réinitialisation…" : "Réinitialiser (efface le coffre)"}
        </button>
      </form>
    </AuthCard>
  );
}
