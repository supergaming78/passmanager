import { useState } from "react";
import { estimatePasswordEntropyBits, rateEntropy } from "../lib/passwordGenerator";
import { checkPasswordBreachCount } from "../lib/breachCheck";

/** Petite jauge de force EN DIRECT pour le mot de passe MAÎTRE — purement informative, jamais
 * bloquante (voir Register.tsx/ChangePasswordForm.tsx pour la seule vraie contrainte : 8
 * caractères minimum). Volontairement pas de règles de complexité forcées (majuscule/chiffre/
 * symbole obligatoires) : une longueur suffisante bat une complexité imposée, et forcer des règles
 * pousse souvent vers des mots de passe prévisibles ("Password1!"). Même style que le générateur
 * (voir PasswordGeneratorPanel.tsx) pour rester cohérent visuellement.
 *
 * Inclut aussi un bouton OPT-IN de vérification de fuite (voir lib/breachCheck.ts — API "Pwned
 * Passwords" de HaveIBeenPwned, k-anonymat, jamais automatique). Utilisée pour les mots de passe DU
 * COFFRE via VaultHealthModal.tsx ; ce composant couvre le seul cas qui manquait encore, le mot de
 * passe MAÎTRE lui-même, aux 3 seuls endroits où il est saisi (Register.tsx, ChangePasswordForm.tsx,
 * ResetPassword.tsx — tous les trois utilisent déjà ce composant, rien à changer de leur côté).
 *
 * Une deuxième source (XposedOrNot) a été envisagée puis écartée : son préfixe de recherche (10
 * caractères hex, ~40 bits) offre une bien moins bonne garantie d'anonymat que celui de HIBP (5
 * caractères hex, ~20 bits) — le service pourrait déduire avec bien plus de précision quel mot de
 * passe précis est vérifié — pour un corpus au final plus PETIT et moins récemment mis à jour que
 * HIBP. Le compromis ne rapportait donc rien : HIBP seul reste à la fois le plus anonyme et le plus
 * complet des deux. */
export default function PasswordStrengthMeter({ password }: { password: string }) {
  const [breachCount, setBreachCount] = useState<number | null>(null);
  const [isChecking, setIsChecking] = useState(false);
  const [checkError, setCheckError] = useState<string | null>(null);

  if (!password) return null;
  const bits = estimatePasswordEntropyBits(password);
  if (bits <= 0) return null;
  const rating = rateEntropy(bits);

  async function handleBreachCheck() {
    setIsChecking(true);
    setCheckError(null);
    setBreachCount(null);
    try {
      setBreachCount(await checkPasswordBreachCount(password));
    } catch (err) {
      setCheckError(err instanceof Error ? err.message : "Vérification impossible.");
    } finally {
      setIsChecking(false);
    }
  }

  return (
    <div className="mt-1.5">
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-neutral-200 dark:bg-neutral-800">
        <div
          className={`h-full rounded-full transition-all ${rating.barClass}`}
          style={{ width: `${Math.min(100, (bits / 128) * 100)}%` }}
        />
      </div>
      <p className={`mt-1 text-xs font-medium ${rating.textClass}`}>{rating.label}</p>

      <button
        type="button"
        onClick={() => void handleBreachCheck()}
        disabled={isChecking}
        className="mt-1 text-xs text-indigo-600 hover:underline disabled:cursor-not-allowed disabled:opacity-60 dark:text-indigo-400"
      >
        {isChecking ? "Vérification…" : "🔍 Vérifier les fuites (HIBP)"}
      </button>
      {breachCount !== null &&
        (breachCount > 0 ? (
          <p className="mt-1 text-xs font-medium text-red-600 dark:text-red-400">
            ⚠️ Trouvé dans {breachCount} fuite{breachCount > 1 ? "s" : ""} connue{breachCount > 1 ? "s" : ""} — choisis-en un autre.
          </p>
        ) : (
          <p className="mt-1 text-xs text-green-600 dark:text-green-400">✓ Aucune fuite connue.</p>
        ))}
      {checkError && <p className="mt-1 text-xs text-red-600 dark:text-red-400">{checkError}</p>}
    </div>
  );
}
