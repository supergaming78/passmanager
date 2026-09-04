import { useEffect, useState } from "react";
import { useAuth } from "../state/AuthContext";
import * as api from "../api/client";
import * as tauri from "../api/tauri";
import { getErrorMessage } from "../lib/errors";

/** Réglage du KIT DE RÉCUPÉRATION — la réponse au seul scénario où un coffre Zero-Knowledge est
 * autrement perdu sans recours : le mot de passe maître oublié.
 *
 * Sans kit, la seule issue est `POST /auth/reset-password`, qui VIDE le coffre — aucune clé
 * n'existe pour re-chiffrer quoi que ce soit. Avec un kit, la clé du coffre est scellée par un code
 * aléatoire que l'utilisateur imprime : le serveur n'en détient qu'un blob qu'il ne peut pas
 * ouvrir, et le Zero-Knowledge reste entier.
 *
 * Le code n'est affiché QU'UNE FOIS, au moment de la génération : il n'est stocké nulle part, ni
 * ici, ni sur le serveur. C'est précisément ce qui fait qu'il protège — et ce qui impose de le
 * dire clairement à l'écran. */
export default function RecoveryKitSettings() {
  const { authorizedRequest } = useAuth();
  const [hasKit, setHasKit] = useState<boolean | null>(null);
  const [generatedCode, setGeneratedCode] = useState<string | null>(null);
  const [isBusy, setIsBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void authorizedRequest((token) => api.getMe(token))
      .then((me) => {
        if (!cancelled) setHasKit(me.has_recovery_kit);
      })
      .catch(() => {
        if (!cancelled) setHasKit(false);
      });
    return () => {
      cancelled = true;
    };
  }, [authorizedRequest]);

  async function handleGenerate() {
    setError(null);
    setIsBusy(true);
    try {
      // Le scellement a lieu côté Rust, à partir de la clé déjà en mémoire : ni le code ni la clé
      // du coffre ne transitent par le serveur (voir src-tauri/src/lib.rs::generate_recovery_kit).
      const kit = await tauri.generateRecoveryKit();
      await authorizedRequest((token) => api.saveRecoveryKit(token, { sealed_vault_key: kit.sealed_vault_key }));
      // Affiché seulement APRÈS l'enregistrement réussi : montrer un code que le serveur n'a pas
      // accepté laisserait croire à une protection inexistante.
      setGeneratedCode(kit.recovery_code);
      setHasKit(true);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsBusy(false);
    }
  }

  async function handleDelete() {
    if (!window.confirm("Supprimer le kit ? Le code imprimé deviendra inutilisable, et un mot de passe maître oublié videra à nouveau le coffre.")) {
      return;
    }
    setError(null);
    setIsBusy(true);
    try {
      await authorizedRequest((token) => api.deleteRecoveryKit(token));
      setHasKit(false);
      setGeneratedCode(null);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsBusy(false);
    }
  }

  return (
    <section className="rounded-2xl border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-neutral-900">
      <h2 className="text-base font-semibold text-neutral-900 dark:text-neutral-100">Kit de récupération</h2>
      <p className="mt-1 text-sm text-neutral-600 dark:text-neutral-400">
        Un code à imprimer, qui permet de retrouver votre coffre si vous oubliez votre mot de passe
        maître. Sans lui, la seule issue serait de repartir d'un coffre vide.
      </p>

      {generatedCode ? (
        <div className="mt-4 rounded-xl border-2 border-amber-400 bg-amber-50 p-4 dark:border-amber-600 dark:bg-amber-950">
          <p className="text-sm font-semibold text-amber-900 dark:text-amber-200">
            Notez ce code maintenant — il ne sera plus jamais affiché.
          </p>
          <p className="my-3 select-all break-all text-center font-mono text-lg tracking-wider text-neutral-900 dark:text-neutral-100">
            {generatedCode}
          </p>
          <p className="text-xs text-amber-800 dark:text-amber-300">
            Imprimez-le ou recopiez-le, et rangez-le hors de votre ordinateur (avec vos papiers
            importants). Il n'est stocké nulle part : ni sur cet appareil, ni sur le serveur.
            Conservé au même endroit que votre mot de passe maître, il ne protégerait de rien.
          </p>
          <div className="mt-3 flex gap-2">
            <button
              type="button"
              onClick={() => window.print()}
              className="rounded-lg bg-amber-600 px-3 py-1.5 text-sm font-medium text-white transition hover:bg-amber-700"
            >
              Imprimer
            </button>
            <button
              type="button"
              onClick={() => setGeneratedCode(null)}
              className="rounded-lg border border-amber-400 px-3 py-1.5 text-sm font-medium text-amber-900 hover:bg-amber-100 dark:border-amber-700 dark:text-amber-200 dark:hover:bg-amber-900"
            >
              J'ai noté le code
            </button>
          </div>
        </div>
      ) : (
        <div className="mt-4 flex flex-wrap items-center gap-3">
          <button
            type="button"
            disabled={isBusy || hasKit === null}
            onClick={() => void handleGenerate()}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {hasKit ? "Générer un nouveau code" : "Générer mon kit"}
          </button>
          {hasKit && (
            <>
              <span className="text-sm text-emerald-600 dark:text-emerald-400">Kit actif</span>
              <button
                type="button"
                disabled={isBusy}
                onClick={() => void handleDelete()}
                className="text-sm text-red-600 hover:underline disabled:opacity-40 dark:text-red-400"
              >
                Supprimer
              </button>
            </>
          )}
        </div>
      )}

      {hasKit && !generatedCode && (
        <p className="mt-2 text-xs text-neutral-500">
          Générer un nouveau code remplace le précédent, qui cesse aussitôt de fonctionner.
        </p>
      )}

      {error && <p className="mt-3 text-sm text-red-600 dark:text-red-400">{error}</p>}
    </section>
  );
}
