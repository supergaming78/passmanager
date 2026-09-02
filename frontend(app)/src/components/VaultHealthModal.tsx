import { useMemo, useState } from "react";
import { WEAK_THRESHOLD_BITS, estimatePasswordEntropyBits, rateEntropy } from "../lib/passwordGenerator";
import { OLD_PASSWORD_DAYS, daysSince, formatRelativeAge } from "../lib/age";
import { checkEntriesForBreaches } from "../lib/breachCheck";
import { getErrorMessage } from "../lib/errors";
import type { PlainVaultEntry } from "../lib/vaultCrypto";

interface Props {
  entries: PlainVaultEntry[];
  onClose: () => void;
  /** Ouvre directement l'entrée en édition (ferme ce tableau de bord) — évite de devoir la
   * retrouver soi-même dans la liste après avoir repéré un problème ici. */
  onSelectEntry: (entry: PlainVaultEntry) => void;
}

type BreachCheckState = "idle" | "checking" | "done" | "error";

/** Vue d'ensemble de la santé du coffre : mots de passe faibles, réutilisés, compromis (fuites
 * connues), répartition par dossier — tout calculé en mémoire à partir des entrées déjà
 * déchiffrées, rien n'est envoyé nulle part (SAUF la vérification "compromis", explicitement
 * OPT-IN — voir lib/breachCheck.ts). Complète les indicateurs déjà présents sur chaque ligne de la
 * liste (StrengthDot, badge "Réutilisé") par une vue résumée plutôt que de devoir les repérer un
 * par un. */
export default function VaultHealthModal({ entries, onClose, onSelectEntry }: Props) {
  const [breachState, setBreachState] = useState<BreachCheckState>("idle");
  const [breachProgress, setBreachProgress] = useState({ done: 0, total: 0 });
  const [breachCounts, setBreachCounts] = useState<Map<string, number>>(new Map());
  const [breachError, setBreachError] = useState<string | null>(null);

  // Seules les entrées "login" ont un vrai mot de passe (voir lib/vaultCrypto.ts::EntryType) —
  // "card"/"identity" stockent un numéro de carte/document dans ce même champ (pas un mot de
  // passe au sens sécurité), et "note" y stocke un placeholder fixe non significatif. Toutes les
  // analyses ci-dessous (faible/réutilisé/ancien/fuite) ne portent donc QUE sur ces entrées-là —
  // même exclusion que les filtres rapides de Vault.tsx, pour rester cohérent.
  const loginEntries = useMemo(() => entries.filter((e) => e.entryType === "login"), [entries]);

  async function handleCheckBreaches() {
    setBreachState("checking");
    setBreachError(null);
    setBreachProgress({ done: 0, total: 0 });
    try {
      const results = await checkEntriesForBreaches(
        loginEntries.map((e) => ({ id: e.id, password: e.password })),
        (done, total) => setBreachProgress({ done, total }),
      );
      setBreachCounts(new Map(results.map((r) => [r.entryId, r.count])));
      setBreachState("done");
    } catch (err) {
      setBreachError(getErrorMessage(err));
      setBreachState("error");
    }
  }

  const breachedEntries = loginEntries
    .filter((e) => breachCounts.has(e.id))
    .map((entry) => ({ entry, count: breachCounts.get(entry.id)! }))
    .sort((a, b) => b.count - a.count);

  const weakEntries = loginEntries
    .map((entry) => ({ entry, bits: estimatePasswordEntropyBits(entry.password) }))
    .filter(({ bits }) => bits > 0 && bits < WEAK_THRESHOLD_BITS)
    .sort((a, b) => a.bits - b.bits);

  const groupsByPassword = new Map<string, PlainVaultEntry[]>();
  for (const entry of loginEntries) {
    if (!entry.password) continue;
    if (!groupsByPassword.has(entry.password)) groupsByPassword.set(entry.password, []);
    groupsByPassword.get(entry.password)!.push(entry);
  }
  const reusedGroups = Array.from(groupsByPassword.values()).filter((g) => g.length > 1);
  const reusedEntryCount = reusedGroups.reduce((sum, g) => sum + g.length, 0);

  const oldEntries = loginEntries
    .filter((entry) => entry.updatedAt && daysSince(entry.updatedAt) > OLD_PASSWORD_DAYS)
    .sort((a, b) => daysSince(b.updatedAt) - daysSince(a.updatedAt));

  // Volontairement TOUTES les entrées (comme averageAgeDays, pas comme healthScore) : une
  // répartition par dossier a du sens quel que soit le type d'entrée qu'il contient.
  const countByFolder = new Map<string, number>();
  for (const entry of entries) {
    const key = entry.folder || "Sans dossier";
    countByFolder.set(key, (countByFolder.get(key) ?? 0) + 1);
  }
  const folderRows = Array.from(countByFolder.entries()).sort((a, b) => b[1] - a[1]);

  // TABLEAU DE BORD — vue d'ensemble visuelle, complète les listes actionnables ci-dessus (qui
  // restent la partie principale : cliquer une entrée pour la corriger). Toujours calculé en
  // mémoire à partir des entrées déjà déchiffrées, comme le reste de ce composant.
  const strengthDistribution = useMemo(() => {
    // Même 5 paliers que rateEntropy() (voir lib/passwordGenerator.ts), dans l'ordre croissant de
    // force — réutilise ses classes de couleur (barClass) pour rester visuellement cohérent avec
    // l'indicateur de force affiché ailleurs (StrengthDot sur chaque ligne, générateur de mot de
    // passe...), plutôt que d'inventer une palette différente ici.
    const buckets = [
      rateEntropy(0), // "Très faible"
      rateEntropy(28), // "Faible"
      rateEntropy(36), // "Raisonnable"
      rateEntropy(60), // "Forte"
      rateEntropy(128), // "Excellente"
    ];
    const counts = new Map(buckets.map((b) => [b.label, 0]));
    for (const entry of loginEntries) {
      const label = rateEntropy(estimatePasswordEntropyBits(entry.password)).label;
      counts.set(label, (counts.get(label) ?? 0) + 1);
    }
    return buckets.map((b) => ({ ...b, count: counts.get(b.label) ?? 0 }));
  }, [loginEntries]);

  // Score de santé : proportion d'entrées qui ne sont NI faibles NI réutilisées (chaque entrée
  // n'est comptée qu'une fois même si elle cumule les deux problèmes). L'ancienneté n'est
  // volontairement PAS incluse ici : un mot de passe ancien mais fort et unique n'est pas un
  // problème de sécurité en soi, juste un rappel de bonne pratique — mélanger les deux aurait
  // rendu le score moins lisible ("pourquoi ce compte pourtant solide fait-il baisser le score ?").
  // Dénominateur = uniquement les entrées "login" (voir loginEntries plus haut) : mélanger des
  // notes/cartes qui ne peuvent jamais être "faibles" ou "réutilisées" gonflerait artificiellement
  // le score d'un coffre qui contient surtout des entrées d'autres types.
  const healthScore = useMemo(() => {
    if (loginEntries.length === 0) return null;
    const problematicIds = new Set<string>();
    for (const { entry } of weakEntries) problematicIds.add(entry.id);
    for (const group of reusedGroups) for (const entry of group) problematicIds.add(entry.id);
    return Math.round(((loginEntries.length - problematicIds.size) / loginEntries.length) * 100);
  }, [loginEntries.length, weakEntries, reusedGroups]);

  // Contrairement à healthScore ci-dessus (délibérément limité aux "login", voir son commentaire),
  // celui-ci porte sur TOUTES les entrées : "depuis combien de temps ce coffre n'a pas bougé" reste
  // une question sensée même pour une carte ou une identité, ce n'est pas une notion de force de
  // mot de passe — les deux stats sont volontairement scopées différemment, pas un oubli.
  const averageAgeDays = useMemo(() => {
    const withDate = entries.filter((e) => e.updatedAt);
    if (withDate.length === 0) return null;
    const totalDays = withDate.reduce((sum, e) => sum + daysSince(e.updatedAt), 0);
    return Math.round(totalDays / withDate.length);
  }, [entries]);

  function healthScoreClass(score: number): string {
    if (score >= 80) return "text-emerald-600 dark:text-emerald-400";
    if (score >= 50) return "text-amber-600 dark:text-amber-400";
    return "text-red-600 dark:text-red-400";
  }

  return (
    <div className="fixed inset-0 z-10 flex items-center justify-center bg-black/40 px-4 py-8">
      <div className="max-h-full w-full max-w-lg overflow-y-auto rounded-2xl border border-neutral-200 bg-white p-6 shadow-xl dark:border-neutral-800 dark:bg-neutral-900">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">Santé du coffre</h2>
          <button type="button" onClick={onClose} className="text-sm text-neutral-500 hover:underline">
            Fermer
          </button>
        </div>

        <div className="mb-5 grid grid-cols-4 gap-2 text-center">
          <div className="rounded-lg bg-neutral-100 p-3 dark:bg-neutral-800">
            <p className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">{entries.length}</p>
            <p className="text-xs text-neutral-500">entrée{entries.length > 1 ? "s" : ""}</p>
          </div>
          <div className="rounded-lg bg-red-50 p-3 dark:bg-red-950">
            <p className="text-xl font-semibold text-red-700 dark:text-red-400">{weakEntries.length}</p>
            <p className="text-xs text-red-600 dark:text-red-400">faible{weakEntries.length > 1 ? "s" : ""}</p>
          </div>
          <div className="rounded-lg bg-orange-50 p-3 dark:bg-orange-950">
            <p className="text-xl font-semibold text-orange-700 dark:text-orange-400">{reusedEntryCount}</p>
            <p className="text-xs text-orange-600 dark:text-orange-400">réutilisé{reusedEntryCount > 1 ? "s" : ""}</p>
          </div>
          <div className="rounded-lg bg-amber-50 p-3 dark:bg-amber-950">
            <p className="text-xl font-semibold text-amber-700 dark:text-amber-400">{oldEntries.length}</p>
            <p className="text-xs text-amber-600 dark:text-amber-400">ancien{oldEntries.length > 1 ? "s" : ""}</p>
          </div>
        </div>

        {entries.length > 0 && (
          <section className="mb-5 rounded-lg border border-neutral-200 p-3 dark:border-neutral-800">
            <div className="mb-3 flex items-center justify-between gap-3">
              <div>
                <p className="text-xs text-neutral-500">Score de santé</p>
                <p className={`text-2xl font-semibold ${healthScoreClass(healthScore ?? 0)}`}>
                  {healthScore === null ? "—" : `${healthScore}%`}
                </p>
              </div>
              {averageAgeDays !== null && (
                <div className="text-right">
                  <p className="text-xs text-neutral-500">Âge moyen</p>
                  <p className="text-2xl font-semibold text-neutral-800 dark:text-neutral-200">{averageAgeDays} j</p>
                </div>
              )}
            </div>
            <p className="mb-1 text-xs text-neutral-500">
              {loginEntries.length === 0
                ? "Aucune entrée de type « identifiant » — les autres types (carte, identité, note) n'ont pas de mot de passe à évaluer."
                : "Part des entrées « identifiant » ni faibles ni réutilisées — l'ancienneté n'est pas comptée (un mot de passe ancien mais fort reste sûr, juste à renouveler par bonne pratique)."}
            </p>

            {loginEntries.length > 0 && (
              <>
                <p className="mb-1 mt-3 text-xs font-medium text-neutral-600 dark:text-neutral-400">Répartition par force</p>
                <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-neutral-100 dark:bg-neutral-800">
                  {strengthDistribution
                    .filter((b) => b.count > 0)
                    .map((b) => (
                      <div
                        key={b.label}
                        title={`${b.label} : ${b.count}`}
                        className={b.barClass}
                        style={{ width: `${(b.count / loginEntries.length) * 100}%` }}
                      />
                    ))}
                </div>
              </>
            )}
            <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5">
              {strengthDistribution
                .filter((b) => b.count > 0)
                .map((b) => (
                  <span key={b.label} className={`text-xs ${b.textClass}`}>
                    {b.label} : {b.count}
                  </span>
                ))}
            </div>
          </section>
        )}

        <section className="mb-5">
          <div className="mb-1 flex items-center justify-between gap-2">
            <h3 className="text-sm font-semibold text-neutral-800 dark:text-neutral-200">Mots de passe compromis</h3>
            <button
              type="button"
              onClick={() => void handleCheckBreaches()}
              disabled={breachState === "checking"}
              className="shrink-0 rounded-lg border border-neutral-300 px-2.5 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              {breachState === "checking"
                ? breachProgress.total > 0
                  ? `Vérification… (${breachProgress.done}/${breachProgress.total})`
                  : "Vérification…"
                : breachState === "done"
                  ? "Revérifier"
                  : "Vérifier maintenant"}
            </button>
          </div>
          <p className="mb-2 text-xs text-neutral-500">
            Compare chaque mot de passe distinct aux fuites publiques connues (haveibeenpwned.com) — SANS jamais
            envoyer le mot de passe : seuls 5 caractères de son empreinte quittent l'appareil. Action manuelle
            uniquement, jamais automatique.
          </p>
          {breachState === "error" && <p className="text-sm text-red-600 dark:text-red-400">{breachError}</p>}
          {breachState === "done" &&
            (breachedEntries.length === 0 ? (
              <p className="text-sm text-neutral-500">Aucun — aucun de tes mots de passe n'apparaît dans les fuites connues.</p>
            ) : (
              <ul className="flex flex-col gap-1">
                {breachedEntries.map(({ entry, count }) => (
                  <li key={entry.id}>
                    <button
                      type="button"
                      onClick={() => onSelectEntry(entry)}
                      className="flex w-full items-center justify-between rounded-lg border border-red-200 bg-red-50 px-3 py-1.5 text-sm hover:bg-red-100 dark:border-red-900 dark:bg-red-950 dark:hover:bg-red-900"
                    >
                      <span className="min-w-0 truncate text-red-800 dark:text-red-300">{entry.siteName}</span>
                      <span className="shrink-0 text-xs font-medium text-red-700 dark:text-red-400">
                        vu {count.toLocaleString("fr-FR")} fois dans des fuites
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            ))}
        </section>

        <section className="mb-5">
          <h3 className="mb-2 text-sm font-semibold text-neutral-800 dark:text-neutral-200">Mots de passe faibles</h3>
          {weakEntries.length === 0 ? (
            <p className="text-sm text-neutral-500">Aucun — tous tes mots de passe ont une entropie raisonnable ou mieux.</p>
          ) : (
            <ul className="flex flex-col gap-1">
              {weakEntries.map(({ entry, bits }) => {
                const rating = rateEntropy(bits);
                return (
                  <li key={entry.id}>
                    <button
                      type="button"
                      onClick={() => onSelectEntry(entry)}
                      className="flex w-full items-center justify-between rounded-lg border border-neutral-200 px-3 py-1.5 text-sm hover:bg-neutral-50 dark:border-neutral-800 dark:hover:bg-neutral-800"
                    >
                      <span className="min-w-0 truncate text-neutral-800 dark:text-neutral-200">{entry.siteName}</span>
                      <span className={`shrink-0 text-xs font-medium ${rating.textClass}`}>
                        {Math.round(bits)} bits — {rating.label}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </section>

        <section className="mb-5">
          <h3 className="mb-2 text-sm font-semibold text-neutral-800 dark:text-neutral-200">Mots de passe réutilisés</h3>
          {reusedGroups.length === 0 ? (
            <p className="text-sm text-neutral-500">Aucun — chaque mot de passe n'est utilisé qu'une seule fois.</p>
          ) : (
            <ul className="flex flex-col gap-2">
              {reusedGroups.map((group, i) => (
                <li key={i} className="rounded-lg border border-orange-200 bg-orange-50 px-3 py-1.5 dark:border-orange-900 dark:bg-orange-950">
                  <p className="mb-1 text-xs font-medium text-orange-700 dark:text-orange-400">
                    Même mot de passe utilisé par {group.length} entrées :
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {group.map((entry) => (
                      <button
                        key={entry.id}
                        type="button"
                        onClick={() => onSelectEntry(entry)}
                        className="rounded-full bg-white px-2 py-0.5 text-xs text-orange-800 hover:bg-orange-100 dark:bg-neutral-900 dark:text-orange-300 dark:hover:bg-orange-900"
                      >
                        {entry.siteName}
                      </button>
                    ))}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="mb-5">
          <h3 className="mb-2 text-sm font-semibold text-neutral-800 dark:text-neutral-200">
            Mots de passe anciens (plus d'un an)
          </h3>
          {oldEntries.length === 0 ? (
            <p className="text-sm text-neutral-500">Aucun — toutes tes entrées ont été modifiées il y a moins d'un an.</p>
          ) : (
            <ul className="flex flex-col gap-1">
              {oldEntries.map((entry) => (
                <li key={entry.id}>
                  <button
                    type="button"
                    onClick={() => onSelectEntry(entry)}
                    className="flex w-full items-center justify-between rounded-lg border border-neutral-200 px-3 py-1.5 text-sm hover:bg-neutral-50 dark:border-neutral-800 dark:hover:bg-neutral-800"
                  >
                    <span className="min-w-0 truncate text-neutral-800 dark:text-neutral-200">{entry.siteName}</span>
                    <span className="shrink-0 text-xs font-medium text-amber-600 dark:text-amber-400">
                      modifié {formatRelativeAge(entry.updatedAt).label}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section>
          <h3 className="mb-2 text-sm font-semibold text-neutral-800 dark:text-neutral-200">Répartition par dossier</h3>
          <ul className="flex flex-col gap-1">
            {folderRows.map(([name, count]) => (
              <li key={name} className="flex items-center justify-between text-sm text-neutral-600 dark:text-neutral-400">
                <span>{name}</span>
                <span className="tabular-nums">{count}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  );
}
