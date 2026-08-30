// Orchestration du partage à USAGE LIMITÉ ("aveugle") — combine les appels réseau (api/client.ts)
// et les commandes Tauri de scellement (api/tauri.ts, voir src-tauri/src/blind_share.rs) pour les
// flux à plusieurs étapes, même principe que lib/entrySharing.ts. S'AJOUTE au partage d'entrée
// classique ET aux coffres partagés familiaux, ne remplace ni l'un ni l'autre.
//
// POINT CENTRAL DE CE MODULE : le destinataire ne doit JAMAIS voir l'identifiant ni le mot de
// passe. `unlockForOneTimeUse()` ci-dessous ne renvoie donc PAS les valeurs en clair à l'appelant
// (l'écran React qui l'invoque) — seulement deux FONCTIONS de copie déjà fermées sur les valeurs
// déchiffrées. Le composant qui affiche l'écran ne peut ainsi jamais les assigner à un état React
// rendu à l'écran, les logger, ou les exposer d'une autre façon : il ne peut que déclencher la
// copie, jamais lire la valeur lui-même. Cette contrainte de conception est LE mécanisme qui
// empêche une fuite accidentelle côté client — voir aussi le commentaire de la migration
// backend pour la limite honnête de cette protection face à un destinataire techniquement outillé.

import * as api from "../api/client";
import * as tauri from "../api/tauri";
import { ensureEmergencyKeys } from "./emergencyAccess";
import { copyPasswordWithAutoClear } from "./clipboard";
import type { PlainVaultEntry } from "./vaultCrypto";
import type { VaultBlindShare } from "../api/types";

type AuthorizedRequest = <T,>(fn: (accessToken: string) => Promise<T>) => Promise<T>;

interface SealableCredentials {
  username: string;
  loginEmail: string;
  password: string;
  preferredLoginType: "username" | "email";
}

/** Crée un partage à usage limité pour `entry`, à destination de `recipientEmail`, avec
 * `maxUses` usages (défaut 1). DEUX scellements distincts (voir le commentaire de la migration
 * backend pour le pourquoi) : le nom du site (librement consultable ensuite par le destinataire)
 * et les identifiants (accessibles uniquement via un "usage", voir unlockForOneTimeUse). */
export async function sendBlindShare(
  authorizedRequest: AuthorizedRequest,
  entry: PlainVaultEntry,
  recipientEmail: string,
  maxUses = 1,
): Promise<void> {
  const { public_key: publicKey } = await authorizedRequest((token) => api.getPublicKey(token, recipientEmail));

  const sealed_site_name = await tauri.sealForBlindShare(entry.siteName, publicKey);
  const credentials: SealableCredentials = {
    username: entry.username,
    loginEmail: entry.loginEmail,
    password: entry.password,
    preferredLoginType: entry.preferredLoginType,
  };
  const sealed_credentials = await tauri.sealForBlindShare(JSON.stringify(credentials), publicKey);

  await authorizedRequest((token) =>
    api.createBlindShare(token, entry.id, { shared_with_email: recipientEmail, sealed_site_name, sealed_credentials, max_uses: maxUses }),
  );
}

/** Les partages à usage limité actifs d'UNE entrée, vus par son PROPRIÉTAIRE. */
export function listMyBlindShares(authorizedRequest: AuthorizedRequest, vaultId: string): Promise<VaultBlindShare[]> {
  return authorizedRequest((token) => api.listBlindSharesForEntry(token, vaultId));
}

/** Révoque un partage à usage limité (propriétaire OU destinataire). */
export function revokeBlindShare(authorizedRequest: AuthorizedRequest, id: string): Promise<void> {
  return authorizedRequest((token) => api.revokeBlindShare(token, id));
}

/** Un partage à usage limité reçu — `siteName` DÉCHIFFRÉ (sûr à afficher), jamais les
 * identifiants (voir unlockForOneTimeUse pour les obtenir). */
export interface ReceivedBlindShare {
  id: string;
  ownerEmail: string;
  siteName: string;
  maxUses: number;
  remainingUses: number;
}

/** Liste tout ce qui a été partagé EN USAGE LIMITÉ avec l'utilisateur courant — descelle
 * uniquement le nom du site (ne consomme jamais d'usage, voir docs/API.md). Un partage dont le
 * descellement échouerait est omis plutôt que de faire échouer tout l'écran. */
export async function listReceivedBlindShares(authorizedRequest: AuthorizedRequest): Promise<ReceivedBlindShare[]> {
  await ensureEmergencyKeys(authorizedRequest);
  const [views, ownKeys] = await Promise.all([
    authorizedRequest((token) => api.listBlindSharesReceived(token)),
    authorizedRequest((token) => api.getOwnEmergencyKeys(token)),
  ]);

  const unlocked = await Promise.allSettled(
    views.map(async (view) => {
      const siteName = await tauri.unsealBlindShare(view.sealed_site_name, ownKeys.encrypted_private_key);
      return { id: view.id, ownerEmail: view.owner_email, siteName, maxUses: view.max_uses, remainingUses: view.remaining_uses };
    }),
  );

  return unlocked.filter((r): r is PromiseFulfilledResult<ReceivedBlindShare> => r.status === "fulfilled").map((r) => r.value);
}

/** Consomme UN usage (décrémenté atomiquement côté serveur) et renvoie deux fonctions de copie
 * déjà fermées sur les valeurs déchiffrées — voir le commentaire en tête de fichier pour pourquoi
 * c'est cette forme, et pas les valeurs elles-mêmes, qui est renvoyée à l'appelant. `remainingUses`
 * EST renvoyé directement (pas sensible, juste un compteur) pour mettre à jour l'affichage. */
export async function unlockForOneTimeUse(
  authorizedRequest: AuthorizedRequest,
  id: string,
): Promise<{ copyUsername: () => Promise<void>; copyPassword: () => Promise<void>; remainingUses: number }> {
  const ownKeys = await authorizedRequest((token) => api.getOwnEmergencyKeys(token));
  const { sealed_credentials, remaining_uses } = await authorizedRequest((token) => api.useBlindShare(token, id));

  const plaintext = await tauri.unsealBlindShare(sealed_credentials, ownKeys.encrypted_private_key);
  let credentials: SealableCredentials;
  try {
    const parsed = JSON.parse(plaintext) as Partial<SealableCredentials>;
    credentials = {
      username: typeof parsed.username === "string" ? parsed.username : "",
      loginEmail: typeof parsed.loginEmail === "string" ? parsed.loginEmail : "",
      password: typeof parsed.password === "string" ? parsed.password : "",
      preferredLoginType: parsed.preferredLoginType === "email" ? "email" : "username",
    };
  } catch {
    credentials = { username: "", loginEmail: "", password: "", preferredLoginType: "username" };
  }

  return {
    copyUsername: async () => {
      const identifier = credentials.preferredLoginType === "email" ? credentials.loginEmail : credentials.username;
      await navigator.clipboard.writeText(identifier);
    },
    copyPassword: async () => {
      await copyPasswordWithAutoClear(credentials.password);
    },
    remainingUses: remaining_uses,
  };
}
