// État de connexion de la popup — équivalent réduit de frontend(app)/src/state/AuthContext.tsx
// pour cette phase (voir le plan pour le détail des décisions ci-dessous).
//
// Stocké dans chrome.storage.session : mémoire uniquement, jamais écrit sur disque, effacé à la
// fermeture du navigateur — jamais chrome.storage.local (qui, lui, persiste sur disque). La
// vault_key est encodée en base64 (jamais un Uint8Array brut : le support de structured-clone de
// chrome.storage.session pour les types binaires n'est pas garanti selon les versions de Chrome,
// alors qu'une chaîne base64 est JSON-safe sans ambiguïté).
//
// Décision de garde de la clé (tranchée avec l'utilisateur, voir le plan) : la clé vit dans
// chrome.storage.session accompagnée d'un horodatage `lockAt`. Tant que la popup est rouverte
// avant `lockAt`, `lockAt` est repoussé de LOCK_WINDOW_MS (session "active" prolongée, comme le
// minuteur d'inactivité du desktop — voir getAutoLockMinutes côté frontend(app)). Passé ce délai,
// la session est effacée et le mot de passe maître doit être ressaisi.

import * as api from "../api/client";
import * as wasmCrypto from "./wasmCrypto";
import { getDeviceId, getDeviceName } from "./deviceId";
import { getPopupLockMinutes } from "./settings";
import { bytesToBase64, base64ToBytes } from "./base64";
import { ApiError } from "../api/types";

const STORAGE_KEY = "passmanager.session";

/** Lue dynamiquement (pas figée au chargement du module) : un changement depuis l'écran Réglages
 * prend effet dès la prochaine ouverture de la popup, sans redémarrage nécessaire. */
function lockWindowMs(): number {
  return getPopupLockMinutes() * 60_000;
}

interface StoredSession {
  email: string;
  accessToken: string;
  refreshToken: string;
  vaultKeyB64: string;
  lockAt: number;
}

export interface ActiveSession {
  email: string;
  accessToken: string;
  refreshToken: string;
  vaultKey: Uint8Array;
}

export type LoginResult = { status: "OK" } | { status: "2FA_REQUIRED"; authHashHex: string; vaultKey: Uint8Array };

/** Type de authorizedRequest ci-dessous — réutilisé par lib/emergencyAccess.ts, lib/entrySharing.ts
 * et lib/emailChange.ts pour typer le paramètre qu'ils reçoivent en provenance de App.tsx, sans
 * dépendre d'un import circulaire vers ce module entier. */
export type AuthorizedRequest = <T>(fn: (accessToken: string) => Promise<T>) => Promise<T>;

async function readStored(): Promise<StoredSession | null> {
  const result = await chrome.storage.session.get(STORAGE_KEY);
  const stored = result[STORAGE_KEY] as StoredSession | undefined;
  return stored ?? null;
}

async function writeStored(session: StoredSession): Promise<void> {
  await chrome.storage.session.set({ [STORAGE_KEY]: session });
}

async function clearStored(): Promise<void> {
  await chrome.storage.session.remove(STORAGE_KEY);
}

async function persistSession(email: string, accessToken: string, refreshToken: string, vaultKey: Uint8Array): Promise<void> {
  await writeStored({
    email,
    accessToken,
    refreshToken,
    vaultKeyB64: bytesToBase64(vaultKey),
    lockAt: Date.now() + lockWindowMs(),
  });
}

/**
 * Lit la session active, si elle existe et n'a pas expiré. Repousse `lockAt` d'autant à chaque
 * appel réussi (voir la doc en tête de fichier) — appelée à l'ouverture de la popup ET avant
 * chaque usage de la vault_key, pour qu'une session laissée ouverte en arrière-plan (peu probable
 * pour une popup, qui se ferme dès qu'elle perd le focus, mais possible en mode "détaché") ne
 * prolonge pas indéfiniment la fenêtre d'exposition sans qu'un vrai geste utilisateur n'ait eu lieu.
 */
export async function getActiveSession(): Promise<ActiveSession | null> {
  const stored = await readStored();
  if (!stored) return null;

  if (Date.now() > stored.lockAt) {
    await clearStored();
    return null;
  }

  await writeStored({ ...stored, lockAt: Date.now() + lockWindowMs() });
  return {
    email: stored.email,
    accessToken: stored.accessToken,
    refreshToken: stored.refreshToken,
    vaultKey: base64ToBytes(stored.vaultKeyB64),
  };
}

export async function login(email: string, masterPassword: string, rememberMe: boolean): Promise<LoginResult> {
  const { authHashHex, vaultKey } = await wasmCrypto.deriveKeys(email, masterPassword);
  const result = await api.login({
    email,
    master_password_hash: authHashHex,
    device_id: getDeviceId(),
    remember_me: rememberMe,
  });

  if (api.isTfaRequired(result)) {
    return { status: "2FA_REQUIRED", authHashHex, vaultKey };
  }

  await persistSession(email, result.access_token, result.refresh_token, vaultKey);
  return { status: "OK" };
}

/**
 * Valide le code 2FA puis relance login() avec le MÊME authHashHex (déjà transmis une première
 * fois, voir AuthContext.tsx côté desktop pour la même logique) — vaultKey vient de la première
 * étape (login() ci-dessus), jamais re-dérivée.
 */
export async function verifyDeviceAndLogin(
  email: string,
  code: string,
  authHashHex: string,
  vaultKey: Uint8Array,
  rememberMe: boolean,
): Promise<void> {
  await api.verifyDevice({
    email,
    code,
    device_id: getDeviceId(),
    device_name: getDeviceName(),
  });

  const result = await api.login({
    email,
    master_password_hash: authHashHex,
    device_id: getDeviceId(),
    remember_me: rememberMe,
  });

  if (api.isTfaRequired(result)) {
    throw new Error("La connexion a échoué malgré la validation de l'appareil — réessaie.");
  }
  await persistSession(email, result.access_token, result.refresh_token, vaultKey);
}

/**
 * Enveloppe un appel API authentifié — même logique de retry-on-401 que
 * AuthContext.tsx::authorizedRequest côté desktop. Pas de verrou anti-double-refresh ici (pas
 * nécessaire pour une popup mono-fenêtre, contrairement au desktop où plusieurs composants
 * peuvent déclencher un appel authentifié au même instant).
 */
export async function authorizedRequest<T>(fn: (accessToken: string) => Promise<T>): Promise<T> {
  const session = await getActiveSession();
  if (!session) throw new ApiError(401, "Aucune session active.");

  try {
    return await fn(session.accessToken);
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      try {
        const tokens = await api.refresh({ refresh_token: session.refreshToken });
        await persistSession(session.email, tokens.access_token, tokens.refresh_token, session.vaultKey);
        return await fn(tokens.access_token);
      } catch (refreshErr) {
        await clearStored();
        throw refreshErr;
      }
    }
    throw err;
  }
}

export async function logout(): Promise<void> {
  const stored = await readStored();
  if (stored) {
    await api.logout({ refresh_token: stored.refreshToken }).catch(() => {});
  }
  await clearStored();
}
