// Version réduite de frontend(app)/src/lib/settings.ts pour cette phase — seul le réglage
// vraiment nécessaire ici (l'URL du backend auto-hébergé) est repris ; les autres réglages
// (générateur, verrouillage automatique, sauvegarde...) n'ont pas encore d'écran dans la popup.

const BACKEND_URL_KEY = "passmanager.backendUrl";

/**
 * URL de base du backend — DÉFAUT fixé en dur (voir frontend(app)/src/lib/settings.ts, même
 * raisonnement, corrigé là-bas le 2026-09-01 mais jamais reporté ici jusqu'à ce test : ce popup
 * pointait vers une URL configurable par n'importe qui via l'écran de connexion, AVANT toute
 * authentification — repéré par un smoke test Playwright réel du popup, voir la conversation du
 * 2026-09-01). Reste modifiable, mais UNIQUEMENT par un modérateur, UNIQUEMENT depuis Réglages
 * une fois connecté (voir SettingsView.tsx, section "Serveur", déjà gardée par isModerator — CETTE
 * partie-là était déjà correcte, seul l'écran de connexion pré-authentification ne l'était pas).
 *
 * `localStorage` est propre au DOCUMENT de la popup (pas partagé avec l'app desktop, même si le
 * navigateur et l'app tournent sur la même machine) — chaque client reste indépendant, comme
 * prévu par l'architecture Zero-Knowledge (aucune donnée sensible dans ce réglage de toute façon).
 */
const PRODUCTION_BACKEND_URL = "https://backend-passmanager.duckdns.org:3557";
const DEV_BACKEND_URL = "http://localhost:3000";

export function getBackendUrl(): string {
  if (import.meta.env.DEV) return DEV_BACKEND_URL;
  return localStorage.getItem(BACKEND_URL_KEY) ?? PRODUCTION_BACKEND_URL;
}

export function setBackendUrl(url: string): void {
  // Retire un slash final éventuel pour éviter les doubles "//" lors de la concaténation des routes.
  localStorage.setItem(BACKEND_URL_KEY, url.replace(/\/+$/, ""));
}

const POPUP_LOCK_MINUTES_KEY = "passmanager.popupLockMinutes";
const DEFAULT_POPUP_LOCK_MINUTES = 5;

/** Fenêtre glissante avant laquelle la vault_key est effacée de chrome.storage.session (voir
 * lib/session.ts) — équivalent du verrouillage automatique par inactivité du desktop
 * (getAutoLockMinutes), mais mesuré entre deux ouvertures de la popup plutôt qu'un minuteur JS
 * continu (la popup ne tourne pas en arrière-plan entre deux ouvertures). */
export function getPopupLockMinutes(): number {
  const raw = localStorage.getItem(POPUP_LOCK_MINUTES_KEY);
  if (raw === null) return DEFAULT_POPUP_LOCK_MINUTES;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_POPUP_LOCK_MINUTES;
}

export function setPopupLockMinutes(minutes: number): void {
  localStorage.setItem(POPUP_LOCK_MINUTES_KEY, String(minutes));
}

const CLIPBOARD_CLEAR_SECONDS_KEY = "passmanager.clipboardClearSeconds";
const DEFAULT_CLIPBOARD_CLEAR_SECONDS = 20;

/** Délai (en secondes) avant effacement automatique du presse-papiers après copie d'un mot de
 * passe — même défaut que le desktop (getClipboardClearSeconds). 0 désactive l'effacement. */
export function getClipboardClearSeconds(): number {
  const raw = localStorage.getItem(CLIPBOARD_CLEAR_SECONDS_KEY);
  if (raw === null) return DEFAULT_CLIPBOARD_CLEAR_SECONDS;
  const parsed = Number(raw);
  return Number.isFinite(parsed) ? parsed : DEFAULT_CLIPBOARD_CLEAR_SECONDS;
}

export function setClipboardClearSeconds(seconds: number): void {
  localStorage.setItem(CLIPBOARD_CLEAR_SECONDS_KEY, String(seconds));
}

const STANDALONE_ON_TFA_KEY = "passmanager.standaloneOnTfa";

/** Ouvrir une fenêtre détachée dès que l'écran 2FA est atteint (voir App.tsx +
 * lib/popupWindow.ts) — activé PAR DÉFAUT (un popup ancré se ferme sinon dès qu'on clique
 * ailleurs, ex: pour aller lire le code dans un email). Réglable dans Réglages : certains
 * préfèrent rester en popup malgré ce risque (fenêtre plus discrète/rapide à fermer). */
export function getStandaloneOnTfa(): boolean {
  const raw = localStorage.getItem(STANDALONE_ON_TFA_KEY);
  return raw === null ? true : raw === "true";
}

export function setStandaloneOnTfa(enabled: boolean): void {
  localStorage.setItem(STANDALONE_ON_TFA_KEY, String(enabled));
}
