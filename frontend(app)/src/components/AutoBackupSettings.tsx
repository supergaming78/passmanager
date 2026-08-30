import { useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { useAuth } from "../state/AuthContext";
import * as api from "../api/client";
import { decryptEntry } from "../lib/vaultCrypto";
import { writeAutoBackup, pruneOldBackups, type ExportableEntry } from "../lib/vaultFile";
import { getAutoBackupEnabled, getAutoBackupFolder, setAutoBackupEnabled, setAutoBackupFolder, setLastAutoBackupAt } from "../lib/settings";
import { getErrorMessage } from "../lib/errors";

const AUTO_BACKUP_KEEP_COUNT = 5;

/** Réglage de la sauvegarde chiffrée automatique (voir lib/autoBackup.ts) — DÉSACTIVÉE PAR DÉFAUT :
 * n'a AUCUN effet tant que l'utilisateur n'a pas coché la case ET choisi un dossier ici même. Le
 * chiffrement réutilise la clé du coffre déjà déverrouillée (voir vaultFile.ts::BACKUP_MAGIC),
 * donc aucun mot de passe séparé à retenir pour ces fichiers. */
export default function AutoBackupSettings() {
  const { authorizedRequest } = useAuth();
  const [enabled, setEnabled] = useState(() => getAutoBackupEnabled());
  const [folder, setFolder] = useState(() => getAutoBackupFolder());
  const [error, setError] = useState<string | null>(null);
  const [isRunningNow, setIsRunningNow] = useState(false);
  const [lastRunMessage, setLastRunMessage] = useState<string | null>(null);

  async function handlePickFolder(): Promise<string | null> {
    let picked: string | string[] | null;
    try {
      picked = await open({ title: "Dossier de sauvegarde automatique", directory: true, multiple: false });
    } catch (err) {
      // Le sélecteur de DOSSIER n'existe pas sur mobile (Android/iOS) — voir la doc du plugin
      // dialog de Tauri : seul un sélecteur de FICHIER y est disponible. Plutôt qu'une exception
      // non gérée sans retour visible pour l'utilisateur, un message clair explique la limitation.
      setError(getErrorMessage(err) || "Le choix d'un dossier n'est pas disponible sur cette plateforme.");
      return null;
    }
    if (!picked || Array.isArray(picked)) return null;
    setFolder(picked);
    setAutoBackupFolder(picked);
    return picked;
  }

  async function handleToggle(checked: boolean) {
    setError(null);
    if (checked && !folder) {
      // Activer sans dossier choisi n'aurait aucun effet (voir maybeRunAutoBackup) — on demande
      // le dossier tout de suite plutôt que de laisser l'utilisateur croire que c'est déjà actif.
      const picked = await handlePickFolder();
      if (!picked) return; // annulé : on n'active pas la case pour rien.
    }
    setEnabled(checked);
    setAutoBackupEnabled(checked);
  }

  async function handleRunNow() {
    setError(null);
    setLastRunMessage(null);
    let targetFolder = folder;
    if (!targetFolder) {
      targetFolder = await handlePickFolder();
      if (!targetFolder) return;
    }
    setIsRunningNow(true);
    try {
      // getFullVault() (PAS getVault() seul) : le serveur plafonne toujours une page à 100
      // entrées — sans boucler sur `offset`, une sauvegarde "réussie" omettrait silencieusement
      // tout ce qui dépasse les 100 premières entrées.
      const encrypted = await authorizedRequest((token) => api.getFullVault(token));
      const decrypted = await Promise.all(encrypted.map(decryptEntry));
      const exportable: ExportableEntry[] = decrypted.map(
        ({ id: _id, updatedAt: _updatedAt, version: _version, hasAttachments: _hasAttachments, ...rest }) => rest,
      );
      await writeAutoBackup(exportable, targetFolder);
      await pruneOldBackups(targetFolder, AUTO_BACKUP_KEEP_COUNT);
      setLastAutoBackupAt(new Date().toISOString());
      setLastRunMessage(`Sauvegarde effectuée (${exportable.length} entrée${exportable.length > 1 ? "s" : ""}).`);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsRunningNow(false);
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <label className="flex items-center gap-2 text-sm text-neutral-700 dark:text-neutral-300">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => void handleToggle(e.target.checked)}
          className="rounded border-neutral-300 text-indigo-600 focus:ring-indigo-500"
        />
        Sauvegarde chiffrée automatique
      </label>
      <p className="text-xs text-neutral-500">
        Écrit périodiquement une copie chiffrée du coffre dans le dossier choisi (les {AUTO_BACKUP_KEEP_COUNT} plus
        récentes sont conservées, les plus anciennes sont supprimées automatiquement). Désactivée par défaut ; à
        activer explicitement ici.
      </p>

      <div>
        <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">Dossier de destination</label>
        <div className="flex items-center gap-2">
          <span className="min-w-0 flex-1 truncate rounded-lg border border-neutral-300 bg-neutral-50 px-3 py-2 text-sm text-neutral-600 dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-400">
            {folder ?? "Aucun dossier choisi"}
          </span>
          <button
            type="button"
            onClick={() => void handlePickFolder()}
            className="shrink-0 rounded-lg border border-neutral-300 px-3 py-2 text-sm text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            Choisir…
          </button>
        </div>
      </div>

      <button
        type="button"
        disabled={isRunningNow}
        onClick={() => void handleRunNow()}
        className="self-start rounded-lg border border-neutral-300 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-60 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
      >
        {isRunningNow ? "Sauvegarde en cours…" : "💾 Sauvegarder maintenant"}
      </button>

      {lastRunMessage && <p className="text-xs text-green-600 dark:text-green-400">{lastRunMessage}</p>}
      {error && <p className="text-xs text-red-600 dark:text-red-400">{error}</p>}
    </div>
  );
}
