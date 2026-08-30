import { useMemo, useState, type FormEvent, type ReactNode } from "react";
import { useAuth } from "../state/AuthContext";
import * as api from "../api/client";
import * as tauri from "../api/tauri";
import { decryptEntry, encryptEntry, type PlainVaultEntry } from "../lib/vaultCrypto";
import { decryptAndParseImportFile, exportEntriesToFile, pickImportFile, type ExportableEntry, type FileFormat } from "../lib/vaultFile";
import { detectDuplicateMatch, type DuplicateStatus } from "../lib/importDuplicates";
import { CRACK_SCENARIOS, estimateCrackTimeSeconds, estimatePasswordEntropyBits, formatCrackTime, rateEntropy } from "../lib/passwordGenerator";
import { getErrorMessage } from "../lib/errors";

// Étape "select" de l'export garde les `id` (PlainVaultEntry, pas ExportableEntry) le temps de
// faire correspondre `preselectedIds` (venu du mode sélection de Vault.tsx) aux bonnes entrées —
// retirés seulement à l'écriture du fichier, voir handleExportSelected.
type ExportModalState = { step: "password" } | { step: "select"; entries: PlainVaultEntry[] } | null;
// "decrypt" : le fichier choisi est un export chiffré (voir vaultFile.ts::PickedImportFile) —
// on demande le mot de passe d'export (SÉPARÉ du mot de passe maître) avant de pouvoir en tirer
// des entrées à afficher dans l'étape "select" habituelle.
type ImportModalState = { step: "select"; entries: ExportableEntry[] } | { step: "decrypt"; rawContent: string } | null;

/** Liste à cocher réutilisée pour la sélection d'entrées, aussi bien à l'export qu'à l'import —
 * même interaction dans les deux sens : décoche ce que tu ne veux pas. `annotate` permet d'ajouter
 * un badge sous une entrée (utilisé à l'import pour signaler les doublons). */
function EntryChecklist({
  entries,
  selected,
  onToggle,
  onToggleAll,
  annotate,
}: {
  entries: ExportableEntry[];
  selected: Set<number>;
  onToggle: (index: number) => void;
  onToggleAll: () => void;
  annotate?: (index: number) => ReactNode;
}) {
  const allSelected = selected.size === entries.length;
  return (
    <div className="max-h-64 overflow-y-auto rounded-lg border border-neutral-200 dark:border-neutral-800">
      <label className="flex items-center gap-2 border-b border-neutral-200 bg-neutral-50 px-3 py-2 text-sm font-medium text-neutral-700 dark:border-neutral-800 dark:bg-neutral-950 dark:text-neutral-300">
        <input
          type="checkbox"
          checked={allSelected}
          onChange={onToggleAll}
          className="rounded border-neutral-300 text-indigo-600 focus:ring-indigo-500"
        />
        Tout sélectionner ({selected.size}/{entries.length})
      </label>
      <ul>
        {entries.map((entry, index) => (
          <li key={index} className="border-b border-neutral-100 px-3 py-1.5 last:border-b-0 dark:border-neutral-900">
            <label className="flex items-center gap-2 text-sm text-neutral-700 dark:text-neutral-300">
              <input
                type="checkbox"
                checked={selected.has(index)}
                onChange={() => onToggle(index)}
                className="rounded border-neutral-300 text-indigo-600 focus:ring-indigo-500"
              />
              <span className="min-w-0 truncate">{entry.siteName}</span>
            </label>
            {annotate?.(index)}
          </li>
        ))}
      </ul>
    </div>
  );
}

function useSelection(count: number, isInitiallySelected: (index: number) => boolean = () => true) {
  const [selected, setSelected] = useState<Set<number>>(
    () => new Set(Array.from({ length: count }, (_, i) => i).filter(isInitiallySelected)),
  );
  function toggle(index: number) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  }
  function toggleAll() {
    setSelected((prev) => (prev.size === count ? new Set() : new Set(Array.from({ length: count }, (_, i) => i))));
  }
  /** Remplace la sélection entière par exactement ces indices — utilisé pour les sélections
   * rapides par critère (ex: "ce dossier" à l'export, voir ExportSelectStep), distinct de
   * toggle/toggleAll qui n'agissent que sur l'état courant. */
  function selectIndices(indices: number[]) {
    setSelected(new Set(indices));
  }
  return { selected, toggle, toggleAll, selectIndices };
}

function duplicateBadge(statusValue: DuplicateStatus) {
  if (statusValue === "exact") {
    return (
      <span className="inline-block rounded-full bg-neutral-200 px-1.5 py-0.5 text-[11px] text-neutral-600 dark:bg-neutral-800 dark:text-neutral-400">
        Déjà dans le coffre (identique)
      </span>
    );
  }
  if (statusValue === "conflict") {
    return (
      <span className="inline-block rounded-full bg-amber-100 px-1.5 py-0.5 text-[11px] text-amber-700 dark:bg-amber-950 dark:text-amber-400">
        Site + identifiant déjà présents, mot de passe différent
      </span>
    );
  }
  return null;
}

// Scénario affiché en tête du badge — le plus prudent des trois (GPU rapide hors ligne), pour ne
// pas donner une fausse impression de sécurité. Les deux autres scénarios restent visibles dans
// l'infobulle (survol du badge).
const HEADLINE_CRACK_SCENARIO = CRACK_SCENARIOS.find((s) => s.key === "offline-fast")!;

/** Entropie + temps de cassage estimés du mot de passe importé — voir estimatePasswordEntropyBits()
 * (approximation plus grossière que celle du générateur, puisqu'on ne connaît que le résultat
 * final, pas les réglages d'origine) — pour repérer d'un coup d'œil les mots de passe importés
 * visiblement faibles avant qu'ils n'atterrissent dans le coffre. */
function entropyBadge(password: string) {
  const bits = estimatePasswordEntropyBits(password);
  if (bits <= 0) return null;
  const rating = rateEntropy(bits);
  const crackTime = formatCrackTime(estimateCrackTimeSeconds(bits, HEADLINE_CRACK_SCENARIO.guessesPerSecond));
  const tooltip = CRACK_SCENARIOS.map(
    (s) => `${s.label} : ${formatCrackTime(estimateCrackTimeSeconds(bits, s.guessesPerSecond))}`,
  ).join("\n");
  return (
    <span
      title={tooltip}
      className={`inline-block rounded-full bg-neutral-100 px-1.5 py-0.5 text-[11px] font-medium dark:bg-neutral-800 ${rating.textClass}`}
    >
      {Math.round(bits)} bits — {rating.label} · {crackTime}
    </span>
  );
}

/** Boutons Importer/Exporter le coffre, avec leur logique complète. Les deux flux suivent la
 * même forme : récupérer les entrées (déchiffrement pour l'export, lecture de fichier pour
 * l'import) -> laisser choisir lesquelles garder -> agir seulement sur la sélection. */
export default function ImportExportBar({
  existingEntries,
  preselectedIds,
  onImported,
}: {
  existingEntries: PlainVaultEntry[];
  /** Ids déjà cochés dans le mode "Sélectionner" de Vault.tsx — si non vide, l'étape d'export ne
   * précoche QUE ces entrées-là au lieu de tout précocher (le reste du coffre reste visible et
   * sélectionnable, juste décoché par défaut). Vide ou omis -> comportement inchangé (tout coché). */
  preselectedIds?: Set<string>;
  onImported?: () => void;
}) {
  const { email, authorizedRequest } = useAuth();

  const [exportModal, setExportModal] = useState<ExportModalState>(null);
  const [exportPassword, setExportPassword] = useState("");
  const [exportFormat, setExportFormat] = useState<FileFormat>("json");
  const [isExporting, setIsExporting] = useState(false);
  // Chiffrement OPTIONNEL du fichier exporté, avec un mot de passe SÉPARÉ du mot de passe maître
  // (voir tauri.encryptExportContent) — pas de raison de réutiliser ce dernier pour un fichier
  // destiné à être partagé/stocké ailleurs.
  const [encryptExport, setEncryptExport] = useState(false);
  const [exportEncryptPassword, setExportEncryptPassword] = useState("");

  const [importModal, setImportModal] = useState<ImportModalState>(null);
  const [importDecryptPassword, setImportDecryptPassword] = useState("");
  const [isImporting, setIsImporting] = useState(false);

  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handlePasswordSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setIsExporting(true);
    try {
      const authHash = await tauri.deriveKeys(email!, exportPassword);
      const encrypted = await authorizedRequest((token) => api.exportVault(token, { master_password_hash: authHash }));
      const decrypted = await Promise.all(encrypted.map(decryptEntry));
      setExportPassword("");
      setExportModal({ step: "select", entries: decrypted });
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsExporting(false);
    }
  }

  async function handleExportSelected(entries: PlainVaultEntry[]) {
    setError(null);
    setIsExporting(true);
    try {
      const withoutIds: ExportableEntry[] = entries.map(({ id: _id, ...rest }) => rest);
      const saved = await exportEntriesToFile(withoutIds, exportFormat, encryptExport ? exportEncryptPassword : undefined);
      setStatus(saved ? `${entries.length} entrée(s) exportée(s) au format ${exportFormat.toUpperCase()}.` : "Export annulé.");
      if (saved) {
        setExportModal(null);
        setEncryptExport(false);
        setExportEncryptPassword("");
      }
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsExporting(false);
    }
  }

  async function handlePickImportFile() {
    setError(null);
    setStatus(null);
    setIsImporting(true);
    try {
      const picked = await pickImportFile();
      if (!picked) return;
      if (picked.kind === "encrypted") {
        setImportModal({ step: "decrypt", rawContent: picked.rawContent });
      } else {
        setImportModal({ step: "select", entries: picked.entries });
      }
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsImporting(false);
    }
  }

  async function handleImportDecryptSubmit(rawContent: string, password: string) {
    setError(null);
    setIsImporting(true);
    try {
      const entries = await decryptAndParseImportFile(rawContent, password);
      setImportDecryptPassword("");
      setImportModal({ step: "select", entries });
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsImporting(false);
    }
  }

  /** `toAdd` devient de nouvelles entrées (POST /vault/import, tout ou rien) ; `toReplace` écrase
   * le mot de passe (et le reste du contenu) d'une entrée EXISTANTE déjà repérée en doublon (voir
   * lib/importDuplicates.ts) — un appel PUT /vault/{id} par entrée, en parallèle, best-effort
   * (contrairement à l'import qui est tout-ou-rien, un remplacement raté n'a pas de raison
   * d'annuler les autres). */
  async function handleImportSelected(toAdd: ExportableEntry[], toReplace: { targetId: string; entry: ExportableEntry }[]) {
    setError(null);
    setIsImporting(true);
    try {
      let addedCount = 0;
      if (toAdd.length > 0) {
        // Un import ne peut connaître un "ancien" mot de passe à archiver (ce sont de nouvelles
        // entrées) : passwordChanged reste à sa valeur par défaut (false). `(e) => encryptEntry(e)`
        // plutôt que `encryptEntry` directement : .map() passe aussi l'index en 2e argument, qui
        // atterrirait sinon dans le paramètre passwordChanged (index tronqué en booléen).
        const encrypted = await Promise.all(toAdd.map((e) => encryptEntry(e)));
        const result = await authorizedRequest((token) => api.importVault(token, { entries: encrypted }));
        addedCount = result.imported;
      }

      let replacedCount = 0;
      if (toReplace.length > 0) {
        // Ici, passwordChanged: true — remplacer le contenu d'une entrée existante par une valeur
        // importée EST un changement réel de mot de passe, l'ancien doit être archivé (voir
        // handlers/vault.rs côté backend).
        const results = await Promise.allSettled(
          toReplace.map(async ({ targetId, entry }) => {
            const encrypted = await encryptEntry(entry, true);
            return authorizedRequest((token) => api.updateVaultEntry(token, targetId, encrypted));
          }),
        );
        replacedCount = results.filter((r) => r.status === "fulfilled").length;
        const failed = results.length - replacedCount;
        if (failed > 0) setError(`${failed} remplacement(s) ont échoué.`);
      }

      setStatus(`${addedCount} entrée(s) ajoutée(s), ${replacedCount} remplacée(s).`);
      setImportModal(null);
      onImported?.();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsImporting(false);
    }
  }

  return (
    <div>
      <div className="flex gap-2">
        <button
          type="button"
          onClick={() => void handlePickImportFile()}
          disabled={isImporting}
          title="JSON, CSV (Chrome/Edge, Firefox, LastPass, KeePass...), notre format TXT, ou un export chiffré — détecté automatiquement"
          className="rounded-lg border border-neutral-300 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-100 disabled:opacity-60 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-900"
        >
          {isImporting ? "…" : "Importer"}
        </button>
        <button
          type="button"
          onClick={() => setExportModal({ step: "password" })}
          className="rounded-lg border border-neutral-300 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-900"
        >
          Exporter
        </button>
      </div>

      {status && <p className="mt-2 text-sm text-emerald-600 dark:text-emerald-400">{status}</p>}
      {error && <p className="mt-2 text-sm text-red-600 dark:text-red-400">{error}</p>}

      {exportModal?.step === "password" && (
        <div className="fixed inset-0 z-10 flex items-center justify-center bg-black/40 px-4">
          <div className="w-full max-w-sm rounded-2xl bg-white p-6 shadow-xl dark:bg-neutral-900">
            <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">Exporter le coffre</h2>
            <p className="mt-2 text-xs text-red-600 dark:text-red-400">
              ⚠️ Par défaut, le fichier exporté n'est PAS chiffré — c'est un fichier en clair sur ton
              disque (une protection par mot de passe optionnelle sera proposée à l'étape suivante).
              Stocke-le en lieu sûr et supprime-le une fois utilisé.
            </p>

            <form onSubmit={handlePasswordSubmit} className="mt-4 flex flex-col gap-3">
              <div>
                <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
                  Mot de passe maître (confirmation)
                </label>
                <input
                  type="password"
                  required
                  autoFocus
                  value={exportPassword}
                  onChange={(e) => setExportPassword(e.target.value)}
                  className="w-full rounded-lg border border-neutral-300 px-3 py-2 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
                />
              </div>

              {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}

              <div className="mt-1 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setExportModal(null)}
                  className="rounded-lg border border-neutral-300 px-4 py-2 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                >
                  Annuler
                </button>
                <button
                  type="submit"
                  disabled={isExporting}
                  className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {isExporting ? "…" : "Continuer"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {exportModal?.step === "select" && (
        <ExportSelectStep
          entries={exportModal.entries}
          preselectedIds={preselectedIds ?? new Set()}
          format={exportFormat}
          onFormatChange={setExportFormat}
          encryptExport={encryptExport}
          onEncryptExportChange={setEncryptExport}
          exportEncryptPassword={exportEncryptPassword}
          onExportEncryptPasswordChange={setExportEncryptPassword}
          isExporting={isExporting}
          error={error}
          onCancel={() => setExportModal(null)}
          onConfirm={handleExportSelected}
        />
      )}

      {importModal?.step === "decrypt" && (
        <ImportDecryptStep
          password={importDecryptPassword}
          onPasswordChange={setImportDecryptPassword}
          isImporting={isImporting}
          error={error}
          onCancel={() => {
            setImportModal(null);
            setImportDecryptPassword("");
          }}
          onConfirm={() => void handleImportDecryptSubmit(importModal.rawContent, importDecryptPassword)}
        />
      )}

      {importModal?.step === "select" && (
        <ImportSelectStep
          entries={importModal.entries}
          existingEntries={existingEntries}
          isImporting={isImporting}
          error={error}
          onCancel={() => setImportModal(null)}
          onConfirm={handleImportSelected}
        />
      )}
    </div>
  );
}

function ImportDecryptStep({
  password,
  onPasswordChange,
  isImporting,
  error,
  onCancel,
  onConfirm,
}: {
  password: string;
  onPasswordChange: (value: string) => void;
  isImporting: boolean;
  error: string | null;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <div className="fixed inset-0 z-10 flex items-center justify-center bg-black/40 px-4">
      <div className="w-full max-w-sm rounded-2xl bg-white p-6 shadow-xl dark:bg-neutral-900">
        <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">Fichier chiffré</h2>
        <p className="mt-2 text-xs text-neutral-500">
          Ce fichier a été exporté avec un mot de passe de protection. Saisis-le pour continuer l'import.
        </p>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            onConfirm();
          }}
          className="mt-4 flex flex-col gap-3"
        >
          <div>
            <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">Mot de passe du fichier</label>
            <input
              type="password"
              required
              autoFocus
              value={password}
              onChange={(e) => onPasswordChange(e.target.value)}
              className="w-full rounded-lg border border-neutral-300 px-3 py-2 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
            />
          </div>

          {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}

          <div className="mt-1 flex justify-end gap-2">
            <button
              type="button"
              onClick={onCancel}
              className="rounded-lg border border-neutral-300 px-4 py-2 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              Annuler
            </button>
            <button
              type="submit"
              disabled={isImporting}
              className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {isImporting ? "…" : "Déchiffrer"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function ExportSelectStep({
  entries,
  preselectedIds,
  format,
  onFormatChange,
  encryptExport,
  onEncryptExportChange,
  exportEncryptPassword,
  onExportEncryptPasswordChange,
  isExporting,
  error,
  onCancel,
  onConfirm,
}: {
  entries: PlainVaultEntry[];
  preselectedIds: Set<string>;
  format: FileFormat;
  onFormatChange: (format: FileFormat) => void;
  encryptExport: boolean;
  onEncryptExportChange: (value: boolean) => void;
  exportEncryptPassword: string;
  onExportEncryptPasswordChange: (value: string) => void;
  isExporting: boolean;
  error: string | null;
  onCancel: () => void;
  onConfirm: (entries: PlainVaultEntry[]) => void;
}) {
  // Si une sélection a été faite dans le coffre (mode "Sélectionner" de Vault.tsx), ne précocher
  // que ces entrées-là — sinon (cas normal, bouton "Exporter" de la barre d'outils) tout précocher
  // comme avant.
  const { selected, toggle, toggleAll, selectIndices } = useSelection(
    entries.length,
    (i) => preselectedIds.size === 0 || preselectedIds.has(entries[i].id),
  );

  // Dossiers distincts présents dans le lot à exporter — permet de cocher d'un coup toutes les
  // entrées d'un même dossier ("exporter par dossier") sans avoir à les repérer une par une dans
  // la liste ci-dessous.
  const folders = useMemo(
    () => Array.from(new Set(entries.map((e) => e.folder).filter(Boolean))).sort((a, b) => a.localeCompare(b)),
    [entries],
  );

  // Contrôlé (pas un simple defaultValue remis à "" après coup) : le choix reste affiché tant
  // qu'on n'en fait pas un autre, plutôt que de revenir silencieusement au placeholder — plus
  // clair sur ce qui a effectivement été appliqué à la coche ci-dessous.
  const [quickFolderPick, setQuickFolderPick] = useState("");

  function selectByFolder(folderValue: string) {
    setQuickFolderPick(folderValue);
    const indices: number[] = [];
    entries.forEach((e, i) => {
      const matches = folderValue === "__all__" ? true : folderValue === "__none__" ? !e.folder : e.folder === folderValue;
      if (matches) indices.push(i);
    });
    selectIndices(indices);
  }

  return (
    <div className="fixed inset-0 z-10 flex items-center justify-center bg-black/40 px-4 py-8">
      <div className="max-h-full w-full max-w-md overflow-y-auto rounded-2xl bg-white p-6 shadow-xl dark:bg-neutral-900">
        <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">Choisir quoi exporter</h2>
        {preselectedIds.size > 0 && (
          <p className="mt-1 text-xs text-indigo-700 dark:text-indigo-400">
            {preselectedIds.size} entrée(s) déjà sélectionnée(s) dans le coffre — précochées ci-dessous.
          </p>
        )}

        {folders.length > 0 && (
          <div className="mt-3">
            <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
              Exporter par dossier (coche rapide)
            </label>
            <select
              value={quickFolderPick}
              onChange={(e) => selectByFolder(e.target.value)}
              className="w-full rounded-lg border border-neutral-300 px-2 py-1.5 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
            >
              <option value="" disabled>
                Choisir un dossier…
              </option>
              <option value="__all__">Tout cocher</option>
              <option value="__none__">Sans dossier</option>
              {folders.map((f) => (
                <option key={f} value={f}>
                  {f}
                </option>
              ))}
            </select>
          </div>
        )}

        <div className="mt-4">
          <EntryChecklist entries={entries} selected={selected} onToggle={toggle} onToggleAll={toggleAll} />
        </div>

        <div className="mt-4">
          <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">Format du fichier</label>
          <div className="flex gap-3 text-sm text-neutral-700 dark:text-neutral-300">
            <label className="flex items-center gap-1.5">
              <input type="radio" checked={format === "json"} onChange={() => onFormatChange("json")} className="text-indigo-600 focus:ring-indigo-500" />
              JSON
            </label>
            <label className="flex items-center gap-1.5">
              <input type="radio" checked={format === "txt"} onChange={() => onFormatChange("txt")} className="text-indigo-600 focus:ring-indigo-500" />
              Texte (.txt)
            </label>
            <label className="flex items-center gap-1.5">
              <input type="radio" checked={format === "csv"} onChange={() => onFormatChange("csv")} className="text-indigo-600 focus:ring-indigo-500" />
              CSV
            </label>
          </div>
        </div>

        <div className="mt-3">
          <label className="flex items-center gap-2 text-sm text-neutral-700 dark:text-neutral-300">
            <input
              type="checkbox"
              checked={encryptExport}
              onChange={(e) => onEncryptExportChange(e.target.checked)}
              className="rounded border-neutral-300 text-indigo-600 focus:ring-indigo-500"
            />
            Protéger le fichier avec un mot de passe
          </label>
          {encryptExport && (
            <div className="mt-2">
              <input
                type="password"
                required
                autoFocus
                value={exportEncryptPassword}
                onChange={(e) => onExportEncryptPasswordChange(e.target.value)}
                placeholder="Mot de passe du fichier (différent du mot de passe maître)"
                className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
              />
              <p className="mt-1 text-xs text-neutral-500">
                À conserver précieusement : sans lui, le fichier est illisible, y compris pour toi.
              </p>
            </div>
          )}
        </div>

        {error && <p className="mt-3 text-sm text-red-600 dark:text-red-400">{error}</p>}

        <div className="mt-4 flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="rounded-lg border border-neutral-300 px-4 py-2 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            Annuler
          </button>
          <button
            type="button"
            disabled={isExporting || selected.size === 0 || (encryptExport && !exportEncryptPassword)}
            onClick={() => onConfirm(entries.filter((_, i) => selected.has(i)))}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isExporting ? "Export…" : `Exporter (${selected.size})`}
          </button>
        </div>
      </div>
    </div>
  );
}

function ImportSelectStep({
  entries,
  existingEntries,
  isImporting,
  error,
  onCancel,
  onConfirm,
}: {
  entries: ExportableEntry[];
  existingEntries: PlainVaultEntry[];
  isImporting: boolean;
  error: string | null;
  onCancel: () => void;
  onConfirm: (toAdd: ExportableEntry[], toReplace: { targetId: string; entry: ExportableEntry }[]) => void;
}) {
  const matches = useMemo(
    () => entries.map((entry) => detectDuplicateMatch(entry, existingEntries)),
    [entries, existingEntries],
  );
  const statuses = useMemo(() => matches.map((m) => m.status), [matches]);
  // Les doublons (identiques ou en conflit) sont décochés par défaut : l'import n'écrase jamais
  // une entrée existante SAUF choix explicite "Remplacer" (voir replaceIndices ci-dessous), il en
  // ajoute une nouvelle si on coche la case normale quand même.
  const { selected, toggle, toggleAll } = useSelection(entries.length, (i) => statuses[i] === "none");
  // Indépendant de `selected` : une entrée marquée ici REMPLACE l'existante correspondante au lieu
  // d'en créer une nouvelle — uniquement proposé sur les conflits (même site/identifiant, mot de
  // passe différent), pas sur les doublons exacts (remplacer par une valeur identique est inutile).
  const [replaceIndices, setReplaceIndices] = useState<Set<number>>(new Set());

  function toggleReplace(index: number) {
    setReplaceIndices((prev) => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  }

  const exactCount = statuses.filter((s) => s === "exact").length;
  const conflictCount = statuses.filter((s) => s === "conflict").length;
  // Compte total réel de l'opération : union de la coche normale et des remplacements marqués
  // (une entrée dans les deux ne compte qu'une fois, voir la répartition juste en dessous).
  const totalCount = new Set([...selected, ...replaceIndices]).size;

  return (
    <div className="fixed inset-0 z-10 flex items-center justify-center bg-black/40 px-4 py-8">
      <div className="max-h-full w-full max-w-md overflow-y-auto rounded-2xl bg-white p-6 shadow-xl dark:bg-neutral-900">
        <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">Choisir quoi importer</h2>
        <p className="mt-1 text-xs text-neutral-500">{entries.length} entrée(s) trouvée(s) dans le fichier.</p>
        {(exactCount > 0 || conflictCount > 0) && (
          <p className="mt-1 text-xs text-amber-700 dark:text-amber-400">
            {exactCount > 0 && `${exactCount} déjà présente(s) à l'identique`}
            {exactCount > 0 && conflictCount > 0 && " · "}
            {conflictCount > 0 && `${conflictCount} avec un mot de passe différent`} — décochée(s) par défaut ; coche
            "Ajouter en double" pour les importer quand même, ou "Remplacer l'existant" pour écraser l'entrée déjà
            présente.
          </p>
        )}

        <div className="mt-4">
          <EntryChecklist
            entries={entries}
            selected={selected}
            onToggle={toggle}
            onToggleAll={toggleAll}
            annotate={(index) => {
              const badges = [entropyBadge(entries[index].password), duplicateBadge(statuses[index])].filter(Boolean);
              const canReplace = statuses[index] === "conflict";
              if (badges.length === 0 && !canReplace) return null;
              return (
                <div className="ml-6 mt-0.5 flex flex-wrap items-center gap-1">
                  {badges.map((badge, i) => (
                    <span key={i}>{badge}</span>
                  ))}
                  {canReplace && (
                    <button
                      type="button"
                      onClick={() => toggleReplace(index)}
                      className={`rounded-full border px-1.5 py-0.5 text-[11px] font-medium transition ${
                        replaceIndices.has(index)
                          ? "border-indigo-300 bg-indigo-50 text-indigo-700 dark:border-indigo-800 dark:bg-indigo-950 dark:text-indigo-300"
                          : "border-neutral-300 text-neutral-500 hover:bg-neutral-100 dark:border-neutral-700 dark:hover:bg-neutral-800"
                      }`}
                    >
                      {replaceIndices.has(index) ? "✓ Remplacera l'existant" : "Remplacer l'existant"}
                    </button>
                  )}
                </div>
              );
            }}
          />
        </div>

        {error && <p className="mt-3 text-sm text-red-600 dark:text-red-400">{error}</p>}

        <div className="mt-4 flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="rounded-lg border border-neutral-300 px-4 py-2 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            Annuler
          </button>
          <button
            type="button"
            disabled={isImporting || totalCount === 0}
            onClick={() => {
              const toAdd: ExportableEntry[] = [];
              const toReplace: { targetId: string; entry: ExportableEntry }[] = [];
              entries.forEach((entry, i) => {
                if (replaceIndices.has(i)) {
                  const targetId = matches[i].matchedId;
                  if (targetId) toReplace.push({ targetId, entry });
                } else if (selected.has(i)) {
                  toAdd.push(entry);
                }
              });
              onConfirm(toAdd, toReplace);
            }}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isImporting ? "Import…" : `Importer (${totalCount})`}
          </button>
        </div>
      </div>
    </div>
  );
}
