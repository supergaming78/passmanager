// Paramètres NON sensibles de l'app, persistés dans le stockage local du webview (contrairement
// à la clé du coffre ou aux tokens, qui ne doivent jamais y transiter — voir state/session.ts).

import { isDev } from "./env";

const BACKEND_URL_OVERRIDE_KEY = "passmanager.backendUrl";

/**
 * URL de base du backend — DÉFAUT fixé en dur (voir la conversation du 2026-09-01) : l'app
 * pointait auparavant vers une URL configurable par n'importe qui via l'écran pré-connexion
 * "Configurer le serveur" (retiré), le temps de vérifier que le déploiement auto-hébergé définitif
 * (NPM + DuckDNS + certificat Let's Encrypt via DNS Challenge, redirection de port 3557→443 chez
 * le fournisseur d'accès) fonctionnait vraiment, en local ET à distance. C'est confirmé.
 *
 * CORRECTIF (toujours le 2026-09-01, demande explicite formulée plus tôt dans le projet) : cette
 * adresse par défaut reste modifiable, mais UNIQUEMENT par l'Admin (voir AuthUser::is_admin, pas
 * un simple modérateur), et UNIQUEMENT depuis les Réglages une fois connecté — jamais avant
 * connexion (voir pages/Admin.tsx::ServerUrlForm, gardé derrière `isAdmin`). Un override local
 * (ce stockage), PAS partagé avec les autres comptes/appareils — sert par exemple à basculer CET
 * appareil vers un second backend (test, secours...) sans changer ce que tout le monde utilise par
 * défaut.
 *
 * En dev (`npm run tauri dev`) : reste TOUJOURS sur le backend local (`cargo run` dans backend/),
 * même override ignoré — évite de tester par erreur contre les vraies données de production.
 */
const PRODUCTION_BACKEND_URL = "https://backend-passmanager.duckdns.org:3557";
const DEV_BACKEND_URL = "http://localhost:3000";

export function getBackendUrl(): string {
  if (isDev) return DEV_BACKEND_URL;
  return localStorage.getItem(BACKEND_URL_OVERRIDE_KEY) ?? PRODUCTION_BACKEND_URL;
}

/** Réservé à l'Admin (voir pages/Admin.tsx::ServerUrlForm) — voir le commentaire de
 * getBackendUrl() ci-dessus pour la portée (local à cet appareil, jamais avant connexion). */
export function setBackendUrl(url: string): void {
  // Retire un slash final éventuel pour éviter les doubles "//" lors de la concaténation des routes.
  localStorage.setItem(BACKEND_URL_OVERRIDE_KEY, url.replace(/\/+$/, ""));
}

/** Revient à l'adresse définitive par défaut, en effaçant l'override local — voir ServerUrlForm. */
export function resetBackendUrlToDefault(): void {
  localStorage.removeItem(BACKEND_URL_OVERRIDE_KEY);
}

const GENERATOR_OPTIONS_KEY = "passmanager.generatorOptions";

/**
 * Dernières préférences du générateur de mot de passe (longueur, catégories, minimums,
 * exclusions) — PAS sensible : ce ne sont que des réglages, jamais un mot de passe généré
 * lui-même. Persister ça évite à l'utilisateur de reconfigurer ses critères à chaque entrée.
 */
export function getStoredGeneratorOptions<T>(fallback: T): T {
  const raw = localStorage.getItem(GENERATOR_OPTIONS_KEY);
  if (!raw) return fallback;
  try {
    return { ...fallback, ...JSON.parse(raw) };
  } catch {
    return fallback;
  }
}

export function setStoredGeneratorOptions(options: unknown): void {
  localStorage.setItem(GENERATOR_OPTIONS_KEY, JSON.stringify(options));
}

const PASSPHRASE_OPTIONS_KEY = "passmanager.passphraseOptions";

/** Pendant de getStoredGeneratorOptions()/setStoredGeneratorOptions() pour le mode phrase de
 * passe (voir lib/passwordGenerator.ts::PassphraseOptions) — clé de stockage distincte, les deux
 * modes gardent leurs réglages indépendamment l'un de l'autre. */
export function getStoredPassphraseOptions<T>(fallback: T): T {
  const raw = localStorage.getItem(PASSPHRASE_OPTIONS_KEY);
  if (!raw) return fallback;
  try {
    return { ...fallback, ...JSON.parse(raw) };
  } catch {
    return fallback;
  }
}

export function setStoredPassphraseOptions(options: unknown): void {
  localStorage.setItem(PASSPHRASE_OPTIONS_KEY, JSON.stringify(options));
}

const GENERATOR_MODE_KEY = "passmanager.generatorMode";

/** Dernier mode de générateur utilisé ("caractères" ou "phrase de passe") — mémorisé pour que le
 * panneau se rouvre là où l'utilisateur l'a laissé plutôt que de toujours revenir au mode par
 * défaut. */
export function getStoredGeneratorMode(): "characters" | "passphrase" {
  return localStorage.getItem(GENERATOR_MODE_KEY) === "passphrase" ? "passphrase" : "characters";
}

export function setStoredGeneratorMode(mode: "characters" | "passphrase"): void {
  localStorage.setItem(GENERATOR_MODE_KEY, mode);
}

const AUTO_LOCK_MINUTES_KEY = "passmanager.autoLockMinutes";
const DEFAULT_AUTO_LOCK_MINUTES = 5;

/** Délai d'inactivité (en minutes) avant verrouillage automatique du coffre — voir
 * state/AuthContext.tsx. 0 (ou toute valeur <= 0) désactive le verrouillage automatique. PAS
 * sensible : ce n'est qu'un réglage, comme le reste de ce fichier. */
export function getAutoLockMinutes(): number {
  const raw = localStorage.getItem(AUTO_LOCK_MINUTES_KEY);
  if (raw === null) return DEFAULT_AUTO_LOCK_MINUTES;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : DEFAULT_AUTO_LOCK_MINUTES;
}

export function setAutoLockMinutes(minutes: number): void {
  localStorage.setItem(AUTO_LOCK_MINUTES_KEY, String(minutes));
}

const CLIPBOARD_CLEAR_SECONDS_KEY = "passmanager.clipboardClearSeconds";
const DEFAULT_CLIPBOARD_CLEAR_SECONDS = 20;

/** Délai (en secondes) avant effacement automatique du presse-papiers après copie d'un mot de
 * passe (voir pages/Vault.tsx::handleCopyPassword). 0 (ou toute valeur <= 0) désactive
 * l'effacement automatique. */
export function getClipboardClearSeconds(): number {
  const raw = localStorage.getItem(CLIPBOARD_CLEAR_SECONDS_KEY);
  if (raw === null) return DEFAULT_CLIPBOARD_CLEAR_SECONDS;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : DEFAULT_CLIPBOARD_CLEAR_SECONDS;
}

export function setClipboardClearSeconds(seconds: number): void {
  localStorage.setItem(CLIPBOARD_CLEAR_SECONDS_KEY, String(seconds));
}

const LOCK_ON_FOCUS_LOSS_DELAY_KEY = "passmanager.lockOnFocusLossDelaySeconds";
const DEFAULT_LOCK_ON_FOCUS_LOSS_DELAY_SECONDS = 15;

/**
 * Délai de grâce (en secondes) avant verrouillage quand la fenêtre perd le focus (alt-tab, clic
 * ailleurs, réduction) — voir state/AuthContext.tsx. 0 désactive complètement ce verrouillage.
 * Un DÉLAI plutôt qu'un verrouillage instantané (comportement d'origine, jugé trop agressif à
 * l'usage) : un simple alt-tab bref pour vérifier quelque chose, ou une boîte de dialogue native
 * (export/import de fichier) qui vole momentanément le focus, ne doit pas redemander le mot de
 * passe maître à chaque fois — voir aussi lib/focusLossLockSuppression.ts, qui suspend carrément
 * ce verrouillage pendant qu'un dialogue ouvert par l'app elle-même est affiché.
 */
export function getLockOnFocusLossDelaySeconds(): number {
  const raw = localStorage.getItem(LOCK_ON_FOCUS_LOSS_DELAY_KEY);
  if (raw === null) return DEFAULT_LOCK_ON_FOCUS_LOSS_DELAY_SECONDS;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : DEFAULT_LOCK_ON_FOCUS_LOSS_DELAY_SECONDS;
}

export function setLockOnFocusLossDelaySeconds(seconds: number): void {
  localStorage.setItem(LOCK_ON_FOCUS_LOSS_DELAY_KEY, String(seconds));
}

const AUTO_BACKUP_ENABLED_KEY = "passmanager.autoBackupEnabled";
const AUTO_BACKUP_FOLDER_KEY = "passmanager.autoBackupFolder";
const LAST_AUTO_BACKUP_AT_KEY = "passmanager.lastAutoBackupAt";

/** Sauvegarde chiffrée automatique (voir lib/autoBackup.ts) — DÉSACTIVÉE PAR DÉFAUT, à activer
 * explicitement dans Réglages avec un dossier de destination choisi. */
export function getAutoBackupEnabled(): boolean {
  return localStorage.getItem(AUTO_BACKUP_ENABLED_KEY) === "true";
}

export function setAutoBackupEnabled(enabled: boolean): void {
  localStorage.setItem(AUTO_BACKUP_ENABLED_KEY, String(enabled));
}

/** Dossier local où écrire les sauvegardes automatiques — `null` tant que l'utilisateur n'en a
 * choisi aucun (la sauvegarde automatique reste alors sans effet même si activée). */
export function getAutoBackupFolder(): string | null {
  return localStorage.getItem(AUTO_BACKUP_FOLDER_KEY);
}

export function setAutoBackupFolder(path: string): void {
  localStorage.setItem(AUTO_BACKUP_FOLDER_KEY, path);
}

/** Horodatage ISO de la dernière sauvegarde automatique effectuée — sert à savoir si l'intervalle
 * (voir lib/autoBackup.ts::AUTO_BACKUP_INTERVAL_DAYS) est écoulé. `null` = jamais encore. */
export function getLastAutoBackupAt(): string | null {
  return localStorage.getItem(LAST_AUTO_BACKUP_AT_KEY);
}

export function setLastAutoBackupAt(isoDate: string): void {
  localStorage.setItem(LAST_AUTO_BACKUP_AT_KEY, isoDate);
}
