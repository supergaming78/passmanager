// Orchestration du partage à USAGE LIMITÉ ("aveugle") — équivalent de
// frontend(app)/src/lib/blindShare.ts, recomposé à partir des fonctions WASM déjà exportées
// (sealForBlindShare/unsealBlindShare, isolées cryptographiquement des trois autres usages — voir
// wasmCrypto.ts). S'AJOUTE au partage d'entrée classique ET aux coffres partagés familiaux, ne
// remplace ni l'un ni l'autre.
//
// DIFFÉRENCE AVEC LE DESKTOP : l'extension peut vraiment REMPLIR un formulaire de connexion (voir
// lib/autofill.ts), contrairement à l'app desktop qui n'a que la copie dans le presse-papiers.
// `useBlindShareAndFill()` ci-dessous consomme donc l'usage puis appelle runAutofill()
// DIRECTEMENT, sans jamais renvoyer l'identifiant/le mot de passe déchiffrés à son appelant (voir
// le commentaire en tête de lib/entrySharing.ts pour le même principe appliqué au partage
// classique) — le composant React qui affiche l'écran ne reçoit qu'un résultat succès/échec,
// jamais la valeur elle-même.

import * as api from "../api/client";
import * as wasmCrypto from "./wasmCrypto";
import { ensureEmergencyKeys } from "./emergencyAccess";
import { runAutofill, canLikelyAutofillActiveTab, type FillResult } from "./autofill";
import type { AuthorizedRequest } from "./session";

interface SealableCredentials {
  username: string;
  loginEmail: string;
  password: string;
  preferredLoginType: "username" | "email";
}

/** Crée un partage à usage limité pour `entry`, à destination de `recipientEmail`, avec
 * `maxUses` usages (défaut 1). DEUX scellements distincts : le nom du site (librement
 * consultable ensuite par le destinataire) et les identifiants (accessibles uniquement via un
 * "usage", voir useBlindShareAndFill ci-dessous). */
export async function sendBlindShare(
  entry: { id: string; siteName: string; username: string; loginEmail: string; password: string; preferredLoginType: "username" | "email" },
  recipientEmail: string,
  maxUses: number,
  authorizedRequest: AuthorizedRequest,
): Promise<void> {
  const { public_key: publicKey } = await authorizedRequest((token) => api.getPublicKey(token, recipientEmail));

  const sealed_site_name = await wasmCrypto.sealForBlindShare(entry.siteName, publicKey);
  const credentials: SealableCredentials = {
    username: entry.username,
    loginEmail: entry.loginEmail,
    password: entry.password,
    preferredLoginType: entry.preferredLoginType,
  };
  const sealed_credentials = await wasmCrypto.sealForBlindShare(JSON.stringify(credentials), publicKey);

  await authorizedRequest((token) =>
    api.createBlindShare(token, entry.id, { shared_with_email: recipientEmail, sealed_site_name, sealed_credentials, max_uses: maxUses }),
  );
}

export function listMyBlindShares(vaultId: string, authorizedRequest: AuthorizedRequest) {
  return authorizedRequest((token) => api.listBlindSharesForEntry(token, vaultId));
}

export function revokeBlindShare(id: string, authorizedRequest: AuthorizedRequest): Promise<void> {
  return authorizedRequest((token) => api.revokeBlindShare(token, id));
}

/** Un partage à usage limité reçu — `siteName` DÉCHIFFRÉ (sûr à afficher), jamais les
 * identifiants. */
export interface ReceivedBlindShare {
  id: string;
  ownerEmail: string;
  siteName: string;
  maxUses: number;
  remainingUses: number;
}

/** Liste tout ce qui a été partagé EN USAGE LIMITÉ avec l'utilisateur courant — descelle
 * uniquement le nom du site (ne consomme jamais d'usage). Un partage dont le descellement
 * échouerait est omis plutôt que de faire échouer tout l'écran. */
export async function listReceivedBlindShares(vaultKey: Uint8Array, authorizedRequest: AuthorizedRequest): Promise<ReceivedBlindShare[]> {
  await ensureEmergencyKeys(vaultKey, authorizedRequest);
  const [views, ownKeys] = await Promise.all([
    authorizedRequest((token) => api.listBlindSharesReceived(token)),
    authorizedRequest((token) => api.getOwnEmergencyKeys(token)),
  ]);

  const privateKeyB64 = await wasmCrypto.decryptField(vaultKey, ownKeys.encrypted_private_key);

  const unlocked = await Promise.allSettled(
    views.map(async (view) => {
      const siteName = await wasmCrypto.unsealBlindShare(view.sealed_site_name, privateKeyB64);
      return { id: view.id, ownerEmail: view.owner_email, siteName, maxUses: view.max_uses, remainingUses: view.remaining_uses };
    }),
  );

  return unlocked.filter((r): r is PromiseFulfilledResult<ReceivedBlindShare> => r.status === "fulfilled").map((r) => r.value);
}

/** LE point central : consomme UN usage (décrémenté atomiquement côté serveur), déchiffre les
 * identifiants, et les REMPLIT DIRECTEMENT dans l'onglet actif — sans jamais renvoyer la valeur en
 * clair à l'appelant (voir le commentaire en tête de fichier). Renvoie seulement le résultat du
 * remplissage et le nouveau compteur d'usages restants. */
export async function useBlindShareAndFill(
  id: string,
  vaultKey: Uint8Array,
  authorizedRequest: AuthorizedRequest,
): Promise<{ result: FillResult; remainingUses: number }> {
  // CORRECTIF : vérifié AVANT tout appel serveur — le compteur d'usages (parfois un SEUL, jamais
  // récupérable une fois épuisé) était auparavant décrémenté même quand l'onglet actif ne pouvait
  // de toute façon pas recevoir de remplissage (page chrome://, Web Store, aucun onglet...), un
  // simple mauvais clic gaspillait alors définitivement l'unique usage d'un partage. Cette
  // vérification n'est qu'une heuristique (une page https sans aucun champ mot de passe la passera
  // quand même) — pas une garantie totale, mais elle écarte le cas le plus fréquent.
  if (!(await canLikelyAutofillActiveTab())) {
    throw new Error("Ouvre d'abord la page de connexion sur laquelle utiliser cet identifiant, puis réessaie.");
  }

  const ownKeys = await authorizedRequest((token) => api.getOwnEmergencyKeys(token));
  const { sealed_credentials, remaining_uses } = await authorizedRequest((token) => api.useBlindShare(token, id));

  const privateKeyB64 = await wasmCrypto.decryptField(vaultKey, ownKeys.encrypted_private_key);
  const plaintext = await wasmCrypto.unsealBlindShare(sealed_credentials, privateKeyB64);

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

  const usernameOrEmail = credentials.preferredLoginType === "email" ? credentials.loginEmail : credentials.username;
  const result = await runAutofill(usernameOrEmail, credentials.password);

  return { result, remainingUses: remaining_uses };
}
