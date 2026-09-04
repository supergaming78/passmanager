import { useEffect, useState } from "react";
import { generateTotp, parseTotpInput, secondsUntilRotation, type TotpConfig } from "../lib/totp";

interface Props {
  /** Contenu brut du champ `totpSecret` de l'entrée : soit un secret base32, soit une URI
   * otpauth:// complète (voir lib/totp.ts::parseTotpInput). */
  secret: string;
  onCopy?: (code: string) => void;
  /** Retour visuel après une copie — même convention que les autres boutons de copie du coffre. */
  copied?: boolean;
}

/** Code à usage unique d'une entrée, régénéré au fil du temps avec son compte à rebours.
 *
 * Même composant que côté app desktop, à une nuance de taille près (le code passe en `text-base` :
 * la popup ne fait que 380px de large).
 *
 * Le secret ne quitte jamais l'appareil : tout est calculé localement (voir lib/totp.ts), aucun
 * appel réseau. Un secret illisible affiche une erreur explicite plutôt que de disparaître en
 * silence — sans quoi l'utilisateur croirait le champ vide et perdrait son second facteur sans
 * comprendre pourquoi. */
export default function TotpCode({ secret, onCopy, copied }: Props) {
  const [config, setConfig] = useState<TotpConfig | null>(null);
  const [code, setCode] = useState("");
  const [remaining, setRemaining] = useState(0);

  useEffect(() => {
    setConfig(parseTotpInput(secret));
  }, [secret]);

  useEffect(() => {
    if (!config) return;
    let cancelled = false;

    // Recalcule chaque seconde : le code lui-même ne change qu'à chaque tranche (30 s en général),
    // mais le compte à rebours, lui, doit avancer visiblement. `generateTotp` est asynchrone
    // (Web Crypto) — le garde `cancelled` évite d'écrire dans un composant démonté entre-temps.
    async function tick() {
      const next = await generateTotp(config!);
      if (cancelled) return;
      setCode(next);
      setRemaining(secondsUntilRotation(config!));
    }

    void tick();
    const interval = setInterval(() => void tick(), 1000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [config]);

  if (!config) {
    return (
      <p className="text-xs text-red-600 dark:text-red-400">
        Code à usage unique illisible — vérifie le secret saisi (clé fournie par le site, ou lien otpauth://).
      </p>
    );
  }

  // Les 5 dernières secondes passent en ambre : signal qu'il vaut mieux attendre le code suivant
  // plutôt que de coller celui-ci dans un formulaire qui expirera avant validation.
  const isExpiring = remaining <= 5;

  return (
    <div className="flex items-center gap-2">
      <span className="font-mono text-base tracking-widest text-neutral-900 dark:text-neutral-100">
        {/* Groupé en deux moitiés : un code à 6 chiffres se recopie nettement mieux ainsi. */}
        {code ? `${code.slice(0, Math.ceil(code.length / 2))} ${code.slice(Math.ceil(code.length / 2))}` : "······"}
      </span>
      <span
        className={`text-xs tabular-nums ${isExpiring ? "text-amber-600 dark:text-amber-400" : "text-neutral-500"}`}
        title="Temps restant avant le prochain code"
      >
        {remaining}s
      </span>
      {onCopy && code && (
        <button
          type="button"
          onClick={() => onCopy(code)}
          className="rounded-lg border border-neutral-300 px-2 py-0.5 text-xs text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
        >
          {copied ? "Copié" : "Copier"}
        </button>
      )}
    </div>
  );
}
