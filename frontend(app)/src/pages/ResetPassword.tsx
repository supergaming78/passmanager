import { useState, type FormEvent } from "react";
import { useLocation, useNavigate, Navigate } from "react-router-dom";
import * as api from "../api/client";
import * as tauri from "../api/tauri";
import { getErrorMessage } from "../lib/errors";
import AuthCard from "../components/AuthCard";
import PasswordStrengthMeter from "../components/PasswordStrengthMeter";
import { flattenForReencryption, rebuildAttachments, rebuildEntries, rebuildHistory } from "../lib/passwordChangeCrypto";
import { getDeviceId } from "../lib/deviceId";

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
  // Deux issues très différentes derrière le même code reçu par email : repartir d'un coffre VIDE
  // (réinitialisation classique), ou le RETROUVER grâce au kit de récupération. Le choix reste
  // explicite — la première est irréversible.
  const [useRecoveryKit, setUseRecoveryKit] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState("");

  if (!state?.email) {
    return <Navigate to="/forgot-password" replace />;
  }
  const email = state.email;

  /** Récupération par le kit : le coffre est CONSERVÉ, contrairement à la réinitialisation.
   *
   * Le serveur renvoie le blob scellé ET le contenu chiffré du coffre en une fois — les routes
   * d'export exigeraient le hash du mot de passe maître, précisément ce qui a été oublié. Le
   * descellement puis le re-chiffrement ont lieu côté Rust : ni la clé retrouvée ni le contenu en
   * clair ne transitent par le JS (voir src-tauri/src/lib.rs). */
  async function recoverWithKit() {
    const data = await api.getRecoveryData({ email, code, device_id: getDeviceId() });

    // Dépose la clé retrouvée dans l'état Rust dédié. Échoue ici si le code est faux — avant
    // d'avoir touché quoi que ce soit côté serveur.
    await tauri.unsealRecoveryKit(data.sealed_vault_key, recoveryCode);
    try {
      const { ciphertexts, plans, historyPlans, attachmentPlans } = flattenForReencryption(
        data.entries,
        data.history,
        data.attachments,
      );
      const result = await tauri.prepareRecoveryReencryption(email, newPassword, ciphertexts);

      await api.completeRecovery({
        email,
        code,
        new_master_password_hash: result.new_auth_hash,
        reencrypted_entries: rebuildEntries(plans, result.reencrypted_ciphertexts),
        reencrypted_history: rebuildHistory(historyPlans, result.reencrypted_ciphertexts),
        reencrypted_attachments: rebuildAttachments(attachmentPlans, result.reencrypted_ciphertexts),
      });
    } finally {
      // Quoi qu'il arrive : cette clé ouvre le coffre, elle n'a aucune raison de survivre à
      // l'opération — succès comme échec.
      await tauri.clearRecoveryKey().catch(() => {});
    }

    // Le coffre local n'a jamais été déverrouillé ici (seul l'état de récupération l'était) ; on
    // repart d'une connexion normale, qui re-dérivera la clé du NOUVEAU mot de passe.
    await tauri.lockVault();
    navigate("/login", { state: { email, justVerified: false } });
  }

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
      if (useRecoveryKit) {
        await recoverWithKit();
        return;
      }
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
      title={useRecoveryKit ? "Récupérer le coffre" : "Réinitialiser le mot de passe"}
      subtitle={
        useRecoveryKit
          ? "Votre code de récupération va rouvrir le coffre, puis tout re-chiffrer avec le nouveau mot de passe. Rien n'est perdu."
          : "⚠️ Le contenu actuel du coffre sera définitivement perdu (chiffré avec l'ancien mot de passe, impossible à récupérer)."
      }
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

        {useRecoveryKit && (
          <div>
            <label htmlFor="recoveryCode" className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
              Code de récupération
            </label>
            <input
              id="recoveryCode"
              type="text"
              required
              value={recoveryCode}
              onChange={(e) => setRecoveryCode(e.target.value)}
              className="w-full rounded-lg border border-neutral-300 px-3 py-2 font-mono tracking-wider outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
              placeholder="ABCDE-FGHJK-MNPQR-STVWX-YZ234"
            />
            <p className="mt-1 text-xs text-neutral-500">
              Celui imprimé lors de la génération de votre kit. La casse, les tirets et les espaces
              n'ont pas d'importance.
            </p>
          </div>
        )}

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

        <button
          type="button"
          onClick={() => {
            setUseRecoveryKit((v) => !v);
            setError(null);
          }}
          className="self-start text-sm text-indigo-600 hover:underline dark:text-indigo-400"
        >
          {useRecoveryKit
            ? "Je n'ai pas de code de récupération"
            : "J'ai un code de récupération — conserver mon coffre"}
        </button>

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
