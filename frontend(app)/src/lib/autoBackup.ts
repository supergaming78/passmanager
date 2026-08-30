// Sauvegarde chiffrée automatique — DÉSACTIVÉE PAR DÉFAUT (voir settings.ts::getAutoBackupEnabled),
// l'utilisateur doit l'activer explicitement dans Réglages ET choisir un dossier de destination
// avant qu'elle ne produise le moindre effet (voir components/AutoBackupSettings.tsx pour l'UI).
//
// Déclenchée en best-effort (jamais bloquant, jamais d'erreur remontée à l'utilisateur — un échec
// d'écriture disque ne doit jamais empêcher l'utilisateur de consulter son coffre) à chaque
// chargement du coffre (voir pages/Vault.tsx::loadEntries) plutôt que sur une minuterie séparée :
// le coffre est déjà rechargé à chaque connexion et à chaque événement de synchronisation, ce qui
// suffit largement à respecter l'intervalle choisi ci-dessous pour un usage personnel.

import { getAutoBackupEnabled, getAutoBackupFolder, getLastAutoBackupAt, setLastAutoBackupAt } from "./settings";
import { writeAutoBackup, pruneOldBackups, type ExportableEntry } from "./vaultFile";
import type { PlainVaultEntry } from "./vaultCrypto";

/** Intervalle minimal (en jours) entre deux sauvegardes automatiques — inutile d'en écrire une à
 * chaque ouverture de l'app, un coffre personnel change rarement plusieurs fois par jour. */
const AUTO_BACKUP_INTERVAL_DAYS = 7;

/** Nombre de sauvegardes conservées dans le dossier de destination — voir vaultFile.ts::pruneOldBackups. */
const AUTO_BACKUP_KEEP_COUNT = 5;

function isDue(lastRunIso: string | null): boolean {
  if (!lastRunIso) return true;
  const last = new Date(lastRunIso).getTime();
  if (!Number.isFinite(last)) return true; // valeur corrompue en stockage local -> due par prudence
  const elapsedDays = (Date.now() - last) / (1000 * 60 * 60 * 24);
  return elapsedDays >= AUTO_BACKUP_INTERVAL_DAYS;
}

/** À appeler en best-effort (jamais attendu ni propagé — voir l'appel dans Vault.tsx::loadEntries,
 * toujours suivi d'un `.catch(() => {})`) après chaque chargement du coffre. Ne fait STRICTEMENT
 * rien tant que l'utilisateur n'a pas explicitement activé la fonctionnalité ET choisi un dossier
 * de destination dans Réglages — voir settings.ts pour le détail des valeurs par défaut. */
export async function maybeRunAutoBackup(entries: PlainVaultEntry[]): Promise<void> {
  if (!getAutoBackupEnabled()) return;
  const folder = getAutoBackupFolder();
  if (!folder) return;
  if (!isDue(getLastAutoBackupAt())) return;
  if (entries.length === 0) return; // rien à sauvegarder, inutile d'écrire un fichier vide

  const exportable: ExportableEntry[] = entries.map(
    ({ id: _id, updatedAt: _updatedAt, version: _version, hasAttachments: _hasAttachments, ...rest }) => rest,
  );
  await writeAutoBackup(exportable, folder);
  await pruneOldBackups(folder, AUTO_BACKUP_KEEP_COUNT);
  setLastAutoBackupAt(new Date().toISOString());
}
