// Version réduite de frontend(app)/src/lib/settings.ts pour cette phase — seul le réglage
// vraiment nécessaire ici (l'URL du backend auto-hébergé) est repris ; les autres réglages
// (générateur, verrouillage automatique, sauvegarde...) n'ont pas encore d'écran dans la popup.

const BACKEND_URL_KEY = "passmanager.backendUrl";

/**
 * URL de base du backend (ex: "https://tonapp.duckdns.org" ou "http://localhost:3000" en dev).
 * `localStorage` est propre au DOCUMENT de la popup (pas partagé avec l'app desktop, même si le
 * navigateur et l'app tournent sur la même machine) — chaque client reste indépendant, comme
 * prévu par l'architecture Zero-Knowledge (aucune donnée sensible dans ce réglage de toute façon).
 */
export function getBackendUrl(): string {
  return localStorage.getItem(BACKEND_URL_KEY) ?? "http://localhost:3000";
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
