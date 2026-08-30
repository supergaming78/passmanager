import { useMemo, useState } from "react";
import {
  AMBIGUOUS_CHARS,
  CATEGORY_LABELS,
  COMMONLY_REJECTED_CHARS,
  CRACK_SCENARIOS,
  DEFAULT_GENERATOR_OPTIONS,
  DEFAULT_PASSPHRASE_OPTIONS,
  estimateCrackTimeSeconds,
  estimateEntropyBits,
  estimatePassphraseEntropyBits,
  estimatePoolSize,
  formatCrackTime,
  generatePassphrase,
  generatePassword,
  rateEntropy,
  type CharCategory,
  type PassphraseOptions,
  type PasswordGeneratorOptions,
} from "../lib/passwordGenerator";
import {
  getStoredGeneratorMode,
  getStoredGeneratorOptions,
  getStoredPassphraseOptions,
  setStoredGeneratorMode,
  setStoredGeneratorOptions,
  setStoredPassphraseOptions,
} from "../lib/settings";

interface Props {
  onGenerate: (password: string) => void;
  onClose: () => void;
}

const CATEGORY_ORDER: CharCategory[] = ["lowercase", "uppercase", "numbers", "symbols"];

/** Panneau de configuration du générateur, avec deux modes au choix (voir les onglets en haut) :
 * par caractères (longueur totale, et pour CHAQUE catégorie un minimum ET un maximum indépendants,
 * plus des caractères explicitement interdits) ou par phrase de passe façon diceware (mots
 * aléatoires, voir lib/passwordGenerator.ts::generatePassphrase). Les préférences des DEUX modes
 * sont mémorisées séparément (voir lib/settings.ts) pour ne pas être à reconfigurer à chaque fois. */
export default function PasswordGeneratorPanel({ onGenerate, onClose }: Props) {
  const [mode, setMode] = useState<"characters" | "passphrase">(getStoredGeneratorMode);
  const [options, setOptions] = useState<PasswordGeneratorOptions>(() =>
    getStoredGeneratorOptions(DEFAULT_GENERATOR_OPTIONS),
  );
  const [passphraseOptions, setPassphraseOptions] = useState<PassphraseOptions>(() =>
    getStoredPassphraseOptions(DEFAULT_PASSPHRASE_OPTIONS),
  );
  const [error, setError] = useState<string | null>(null);

  function switchMode(next: "characters" | "passphrase") {
    setMode(next);
    setStoredGeneratorMode(next);
    setError(null);
  }

  function persist(next: PasswordGeneratorOptions) {
    setOptions(next);
    setStoredGeneratorOptions(next);
  }

  function persistPassphrase(next: PassphraseOptions) {
    setPassphraseOptions(next);
    setStoredPassphraseOptions(next);
  }

  function updateLength(length: number) {
    persist({ ...options, length });
  }

  function updateCategory(key: CharCategory, patch: Partial<PasswordGeneratorOptions["categories"][CharCategory]>) {
    persist({
      ...options,
      categories: { ...options.categories, [key]: { ...options.categories[key], ...patch } },
    });
  }

  function updateExcluded(excludedChars: string) {
    persist({ ...options, excludedChars });
  }

  /** Active/désactive un lot de caractères dans "Caractères interdits" en un clic — le champ
   * reste la seule source de vérité (visible et modifiable à la main), ce bouton n'est qu'un
   * raccourci qui l'édite. Réutilisé pour les deux boutons ci-dessous (ambigus, souvent refusés). */
  function isCharSetActive(charSet: string): boolean {
    return Array.from(charSet).every((c) => options.excludedChars.includes(c));
  }

  function toggleCharSet(charSet: string) {
    if (isCharSetActive(charSet)) {
      const without = Array.from(options.excludedChars)
        .filter((c) => !charSet.includes(c))
        .join("");
      updateExcluded(without);
    } else {
      const merged = new Set([...options.excludedChars, ...charSet]);
      updateExcluded(Array.from(merged).join(""));
    }
  }

  function handleGenerate() {
    setError(null);
    try {
      onGenerate(mode === "passphrase" ? generatePassphrase(passphraseOptions) : generatePassword(options));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Impossible de générer un mot de passe avec ces critères.");
    }
  }

  const isAmbiguousExcluded = isCharSetActive(AMBIGUOUS_CHARS);
  const isCommonlyRejectedExcluded = isCharSetActive(COMMONLY_REJECTED_CHARS);

  // Entropie affichée EN DIRECT pendant qu'on ajuste les critères — avant de générer quoi que ce
  // soit — pour voir l'effet de chaque réglage (longueur, catégories, exclusions) immédiatement.
  const poolSize = useMemo(() => estimatePoolSize(options), [options]);
  const characterEntropyBits = useMemo(() => estimateEntropyBits(options), [options]);
  const passphraseEntropyBits = useMemo(() => estimatePassphraseEntropyBits(passphraseOptions), [passphraseOptions]);
  const entropyBits = mode === "passphrase" ? passphraseEntropyBits : characterEntropyBits;
  const entropyRating = useMemo(() => rateEntropy(entropyBits), [entropyBits]);

  return (
    <div className="mt-2 rounded-xl border border-neutral-200 bg-neutral-50 p-4 dark:border-neutral-800 dark:bg-neutral-950">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-neutral-800 dark:text-neutral-200">Générateur de mot de passe</h3>
        <button type="button" onClick={onClose} className="text-xs text-neutral-500 hover:underline">
          Fermer
        </button>
      </div>

      <div className="mb-4 flex gap-1 rounded-lg bg-neutral-100 p-1 text-sm dark:bg-neutral-900">
        <button
          type="button"
          onClick={() => switchMode("characters")}
          className={`flex-1 rounded-md px-2 py-1 font-medium transition ${
            mode === "characters"
              ? "bg-white text-neutral-900 shadow-sm dark:bg-neutral-800 dark:text-neutral-100"
              : "text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-neutral-200"
          }`}
        >
          Caractères
        </button>
        <button
          type="button"
          onClick={() => switchMode("passphrase")}
          className={`flex-1 rounded-md px-2 py-1 font-medium transition ${
            mode === "passphrase"
              ? "bg-white text-neutral-900 shadow-sm dark:bg-neutral-800 dark:text-neutral-100"
              : "text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-neutral-200"
          }`}
        >
          Phrase de passe
        </button>
      </div>

      {mode === "passphrase" ? (
        <div>
          <div className="flex items-center justify-between text-sm font-medium text-neutral-700 dark:text-neutral-300">
            <label htmlFor="pp-wordcount">Nombre de mots</label>
            <span className="tabular-nums text-neutral-500">{passphraseOptions.wordCount}</span>
          </div>
          <input
            id="pp-wordcount"
            type="range"
            min={3}
            max={10}
            value={passphraseOptions.wordCount}
            onChange={(e) => persistPassphrase({ ...passphraseOptions, wordCount: Number(e.target.value) })}
            className="w-full accent-indigo-600"
          />

          <div className="mt-3">
            <label htmlFor="pp-separator" className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
              Séparateur
            </label>
            <input
              id="pp-separator"
              value={passphraseOptions.separator}
              onChange={(e) => persistPassphrase({ ...passphraseOptions, separator: e.target.value })}
              maxLength={4}
              className="w-full rounded-lg border border-neutral-300 px-2 py-1.5 font-mono text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
            />
          </div>

          <label className="mt-3 flex items-center gap-2 text-sm text-neutral-700 dark:text-neutral-300">
            <input
              type="checkbox"
              checked={passphraseOptions.capitalize}
              onChange={(e) => persistPassphrase({ ...passphraseOptions, capitalize: e.target.checked })}
              className="rounded border-neutral-300 text-indigo-600 focus:ring-indigo-500"
            />
            Mettre une majuscule à chaque mot
          </label>
          <label className="mt-1.5 flex items-center gap-2 text-sm text-neutral-700 dark:text-neutral-300">
            <input
              type="checkbox"
              checked={passphraseOptions.includeNumber}
              onChange={(e) => persistPassphrase({ ...passphraseOptions, includeNumber: e.target.checked })}
              className="rounded border-neutral-300 text-indigo-600 focus:ring-indigo-500"
            />
            Ajouter un numéro (4 chiffres) en fin de phrase
          </label>

          <p className="mt-3 text-[11px] text-neutral-400 dark:text-neutral-500">
            Mots tirés d'une liste fixe de 2048 (BIP-39 anglaise) — facile à retaper ou dicter à voix
            haute, notamment pour un mot de passe MAÎTRE.
          </p>
        </div>
      ) : (
        <>
      <div className="flex items-center justify-between text-sm font-medium text-neutral-700 dark:text-neutral-300">
        <label htmlFor="gen-length">Longueur</label>
        <span className="tabular-nums text-neutral-500">{options.length}</span>
      </div>
      <input
        id="gen-length"
        type="range"
        min={8}
        max={64}
        value={options.length}
        onChange={(e) => updateLength(Number(e.target.value))}
        className="w-full accent-indigo-600"
      />

      <div className="mt-4 overflow-hidden rounded-lg border border-neutral-200 dark:border-neutral-800">
        <div className="grid grid-cols-[1fr_4.5rem_4.5rem] items-center gap-x-2 bg-neutral-100 px-3 py-1.5 text-xs font-medium text-neutral-500 dark:bg-neutral-900">
          <span>Catégorie</span>
          <span className="text-center">Min</span>
          <span className="text-center">Max</span>
        </div>
        {CATEGORY_ORDER.map((key) => {
          const cat = options.categories[key];
          return (
            <div
              key={key}
              className="grid grid-cols-[1fr_4.5rem_4.5rem] items-center gap-x-2 border-t border-neutral-200 px-3 py-2 dark:border-neutral-800"
            >
              <label className="flex items-center gap-2 text-sm text-neutral-700 dark:text-neutral-300">
                <input
                  type="checkbox"
                  checked={cat.include}
                  onChange={(e) => updateCategory(key, { include: e.target.checked })}
                  className="rounded border-neutral-300 text-indigo-600 focus:ring-indigo-500"
                />
                {CATEGORY_LABELS[key]}
              </label>
              <input
                type="number"
                min={0}
                max={options.length}
                disabled={!cat.include}
                value={cat.min}
                onChange={(e) => updateCategory(key, { min: Number(e.target.value) })}
                className="w-full rounded-lg border border-neutral-300 px-2 py-1 text-center text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 disabled:opacity-40 dark:border-neutral-700 dark:bg-neutral-900"
              />
              <input
                type="number"
                min={0}
                max={options.length}
                disabled={!cat.include}
                value={cat.max}
                onChange={(e) => updateCategory(key, { max: Number(e.target.value) })}
                className="w-full rounded-lg border border-neutral-300 px-2 py-1 text-center text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 disabled:opacity-40 dark:border-neutral-700 dark:bg-neutral-900"
              />
            </div>
          );
        })}
      </div>

      <div className="mt-4">
        <div className="mb-1.5 flex items-center justify-between">
          <label htmlFor="gen-excluded" className="text-xs font-medium text-neutral-600 dark:text-neutral-400">
            Caractères interdits
          </label>
        </div>
        <div className="mb-1.5 flex flex-wrap gap-1.5">
          <button
            type="button"
            onClick={() => toggleCharSet(AMBIGUOUS_CHARS)}
            className={`rounded-full border px-2 py-0.5 text-xs transition ${
              isAmbiguousExcluded
                ? "border-indigo-300 bg-indigo-50 text-indigo-700 dark:border-indigo-800 dark:bg-indigo-950 dark:text-indigo-300"
                : "border-neutral-300 text-neutral-500 hover:bg-neutral-100 dark:border-neutral-700 dark:hover:bg-neutral-800"
            }`}
          >
            Exclure les ambigus (l 1 I O 0)
          </button>
          <button
            type="button"
            onClick={() => toggleCharSet(COMMONLY_REJECTED_CHARS)}
            title="Espace, guillemets, antislash, chevrons, point-virgule, barre verticale — souvent refusés par les formulaires d'inscription"
            className={`rounded-full border px-2 py-0.5 text-xs transition ${
              isCommonlyRejectedExcluded
                ? "border-indigo-300 bg-indigo-50 text-indigo-700 dark:border-indigo-800 dark:bg-indigo-950 dark:text-indigo-300"
                : "border-neutral-300 text-neutral-500 hover:bg-neutral-100 dark:border-neutral-700 dark:hover:bg-neutral-800"
            }`}
          >
            Exclure les caractères souvent refusés
          </button>
        </div>
        <input
          id="gen-excluded"
          value={options.excludedChars}
          onChange={(e) => updateExcluded(e.target.value)}
          placeholder="ex: des caractères refusés par un site en particulier"
          className="w-full rounded-lg border border-neutral-300 px-2 py-1.5 font-mono text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
        />
      </div>
        </>
      )}

      <div className="mt-4 rounded-lg border border-neutral-200 bg-white px-3 py-2 dark:border-neutral-800 dark:bg-neutral-900">
        <div className="flex items-center justify-between text-xs">
          <span className="font-medium text-neutral-600 dark:text-neutral-400">Entropie estimée</span>
          <span className={`font-semibold ${entropyRating.textClass}`}>
            {entropyBits > 0 ? `${Math.round(entropyBits)} bits — ${entropyRating.label}` : "—"}
          </span>
        </div>
        <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-neutral-200 dark:bg-neutral-800">
          <div
            className={`h-full rounded-full transition-all ${entropyRating.barClass}`}
            style={{ width: `${Math.min(100, (entropyBits / 128) * 100)}%` }}
          />
        </div>
        <p className="mt-1 text-[11px] text-neutral-400 dark:text-neutral-500">
          {mode === "passphrase"
            ? `${passphraseOptions.wordCount} mot${passphraseOptions.wordCount > 1 ? "s" : ""} tiré${passphraseOptions.wordCount > 1 ? "s" : ""} d'une liste de 2048${passphraseOptions.includeNumber ? ", plus un numéro à 4 chiffres" : ""}.`
            : `Pool de ${poolSize} caractère${poolSize > 1 ? "s" : ""} possible${poolSize > 1 ? "s" : ""}, longueur ${options.length} — min/max par catégorie pris en compte, pas juste la longueur.`}
        </p>

        <div className="mt-2 border-t border-neutral-100 pt-2 dark:border-neutral-800">
          <p className="mb-1 text-[11px] font-medium text-neutral-500 dark:text-neutral-400">
            Temps moyen pour le retrouver par force brute
          </p>
          <ul className="space-y-0.5">
            {CRACK_SCENARIOS.map((scenario) => (
              <li key={scenario.key} className="flex items-center justify-between gap-2 text-[11px]">
                <span className="text-neutral-500 dark:text-neutral-400">{scenario.label}</span>
                <span className="shrink-0 font-medium tabular-nums text-neutral-700 dark:text-neutral-300">
                  {entropyBits > 0 ? formatCrackTime(estimateCrackTimeSeconds(entropyBits, scenario.guessesPerSecond)) : "—"}
                </span>
              </li>
            ))}
          </ul>
          <p className="mt-1 text-[11px] text-neutral-400 dark:text-neutral-500">
            Le temps réel dépend surtout du site visé (comment IL stocke le mot de passe) — ces
            scénarios ne sont que des repères.
          </p>
        </div>
      </div>

      {error && <p className="mt-3 text-xs text-red-600 dark:text-red-400">{error}</p>}

      <button
        type="button"
        onClick={handleGenerate}
        className="mt-4 w-full rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-indigo-700"
      >
        {mode === "passphrase" ? "Générer une phrase de passe" : "Générer un mot de passe"}
      </button>
    </div>
  );
}
