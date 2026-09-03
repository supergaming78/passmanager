// Contexte d'authentification : orchestre les appels Tauri (dérivation de clé, voir api/tauri.ts)
// et les appels API (voir api/client.ts) pour les flux d'inscription/connexion/2FA/coffre. Les
// tokens vivent UNIQUEMENT en mémoire JS (state React) — jamais persistés sur disque : au
// redémarrage de l'app, la clé du coffre (côté Rust) est de toute façon reperdue par design
// (Zero-Knowledge, elle n'est jamais sauvegardée), donc persister les tokens seuls n'apporterait
// rien sans pouvoir redéverrouiller le coffre — l'utilisateur devra de toute façon ressaisir son
// mot de passe maître. Seul `device_id` est persisté (voir lib/deviceId.ts, non sensible) pour
// que l'appareil reste reconnu comme "de confiance" d'un lancement à l'autre.

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import * as api from "../api/client";
import * as tauri from "../api/tauri";
import { getDeviceId, getDeviceName } from "../lib/deviceId";
import { getAutoLockMinutes, getBackendUrl, getLockOnFocusLossDelaySeconds } from "../lib/settings";
import { isFocusLossLockSuppressed } from "../lib/focusLossLockSuppression";
import { setTheme, setCachedCustomTheme, setCachedThemeProfiles, clearAccountScopedThemeCache, toValidTheme, isThemeSyncEnabled } from "../lib/theme";
import { flattenForReencryption, rebuildAttachments, rebuildEntries, rebuildHistory } from "../lib/passwordChangeCrypto";
import { reseedAllContacts } from "../lib/emergencyAccess";
import { ApiError, type SyncEvent } from "../api/types";

interface AuthState {
  email: string | null;
  accessToken: string | null;
  refreshToken: string | null;
  /** Droits de modérateur (panneau Administration, gestion des comptes non-modérateur) — jamais
   * déduit du JWT (qui ne porte pas ce champ, voir GET /me côté backend) : toujours revérifié en
   * base par le serveur, récupéré ici via établishSession() après chaque connexion. */
  isModerator: boolean;
  /** Vrai UNIQUEMENT pour le compte configuré via ADMIN_EMAIL — il n'existe qu'UN SEUL "Admin",
   * seul autorisé à gérer les rôles modérateur d'autres comptes (voir Admin.tsx). */
  isAdmin: boolean;
  /** Autorisation à changer l'adresse du backend depuis les Réglages (voir
   * components/ServerUrlForm.tsx, monté dans pages/Settings.tsx) — valeur BRUTE de GET /me, PAS
   * OR'ée avec isAdmin ici : c'est à Settings.tsx de combiner les deux (isAdmin y a toujours accès
   * indépendamment de cette valeur, voir handlers/admin.rs côté backend). */
  canChooseServerInSettings: boolean;
}

export type LoginResult = { status: "OK" } | { status: "2FA_REQUIRED"; authHash: string };

interface AuthContextValue extends AuthState {
  isAuthenticated: boolean;
  registerAccount: (email: string, masterPassword: string) => Promise<void>;
  verifyEmail: (email: string, code: string) => Promise<void>;
  resendVerification: (email: string) => Promise<void>;
  login: (email: string, masterPassword: string, rememberMe: boolean) => Promise<LoginResult>;
  /**
   * Valide le code 2FA reçu par email, puis relance login() avec le hash d'authentification déjà
   * calculé lors de la première tentative (voir LoginResult) — pas besoin de re-dériver ni de
   * re-demander le mot de passe maître : ce hash a déjà été transmis au serveur une première
   * fois, le réutiliser ici n'expose rien de plus. La clé du coffre, elle, est restée en mémoire
   * côté Rust depuis le premier login() (jamais effacée entre les deux étapes).
   */
  verifyDeviceAndLogin: (email: string, code: string, authHash: string, rememberMe: boolean) => Promise<void>;
  logout: () => Promise<void>;
  /**
   * Change le mot de passe maître : récupère TOUT le coffre (export non paginé, voir
   * api/client.ts::exportVault), le re-chiffre entièrement côté Rust (voir
   * api/tauri.ts::preparePasswordChange), envoie le résultat au serveur, puis se reconnecte
   * automatiquement avec le nouveau mot de passe — update_password() invalide TOUTES les sessions
   * actives côté serveur (y compris celle-ci), une reconnexion est donc obligatoire après coup.
   */
  changeMasterPassword: (oldPassword: string, newPassword: string, rememberMe: boolean) => Promise<void>;
  /**
   * Change l'adresse email : redemande le mot de passe maître actuel pour reconfirmation (comme
   * le fait le serveur, voir UpdateEmailPayload), puis se reconnecte avec le nouvel email —
   * update_email() invalide aussi les sessions actives.
   */
  changeEmail: (newEmail: string, currentPassword: string, rememberMe: boolean) => Promise<void>;
  /**
   * Enveloppe un appel API authentifié (voir api/client.ts, fonctions coffre) : lui fournit
   * l'access token courant, et en cas de 401 (expiré — durée de vie 10 min par défaut, voir
   * ACCESS_TOKEN_SECONDS côté backend), rafraîchit UNE FOIS la session puis réessaie
   * automatiquement. Si le rafraîchissement lui-même échoue (refresh token expiré/révoqué), la
   * session est effacée — l'appelant doit alors rediriger vers /login. Sans ça, chaque écran
   * devrait réimplémenter cette logique de retry lui-même.
   */
  authorizedRequest: <T,>(fn: (accessToken: string) => Promise<T>) => Promise<T>;
  /**
   * S'abonne aux événements de synchronisation temps réel (voir handlers/vault.rs côté backend :
   * un événement est diffusé à chaque modification du coffre depuis N'IMPORTE quel appareil de ce
   * compte). Renvoie une fonction de désabonnement, à appeler au démontage du composant abonné
   * (ex: dans le cleanup d'un useEffect) — la connexion WebSocket elle-même est gérée une seule
   * fois ici, pour toute la durée de la session, pas par écran.
   */
  subscribeToVaultSync: (callback: () => void) => () => void;
  /** Vrai après verrouillage (manuel ou automatique par inactivité) — la session (tokens) reste
   * valide, seule la clé de chiffrement du coffre est effacée côté Rust. Les écrans protégés
   * doivent alors afficher un écran de reverrouillage plutôt que le contenu déchiffré. */
  isVaultLocked: boolean;
  /** Verrouille immédiatement le coffre (bouton "Verrouiller maintenant", ou déclenché par le
   * minuteur d'inactivité — voir plus bas). */
  lockVaultNow: () => Promise<void>;
  /**
   * Redéverrouille le coffre après un verrouillage (PAS une reconnexion complète — les tokens
   * sont toujours valides). Vérifie le mot de passe en tentant de déchiffrer une entrée existante
   * du coffre : une dérivation Argon2 "réussit" toujours quel que soit le mot de passe fourni,
   * seule l'authentification AES-GCM au déchiffrement peut réellement le valider. Si le coffre est
   * vide, il n'y a rien à vérifier — accepté tel quel (rien à protéger de toute façon).
   */
  unlockVault: (password: string) => Promise<void>;
  /**
   * Redéverrouille le coffre via Windows Hello (empreinte/visage/code PIN), sans redemander le
   * mot de passe maître — voir src-tauri/src/quick_unlock.rs. Suppose que le déverrouillage
   * rapide a déjà été activé au préalable (voir tauri.enableQuickUnlock()) ; échoue proprement
   * sinon (fichier absent) ou si la vérification biométrique échoue/est annulée.
   */
  quickUnlockVault: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

const LOGGED_OUT_STATE: AuthState = { email: null, accessToken: null, refreshToken: null, isModerator: false, isAdmin: false, canChooseServerInSettings: false };

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(LOGGED_OUT_STATE);
  // Voir la doc de isVaultLocked sur AuthContextValue. Déclaré tôt : establishSession() ci-dessous
  // en a besoin pour repartir déverrouillé à chaque nouvelle connexion.
  const [isVaultLocked, setIsVaultLocked] = useState(false);

  // Miroir synchrone de `state`, nécessaire pour authorizedRequest()/refreshSession() : le state
  // React ne se met à jour qu'au prochain rendu, alors que ces fonctions ont besoin de lire les
  // tokens les plus récents IMMÉDIATEMENT (ex: deux appels authentifiés qui expirent en même
  // temps ne doivent déclencher qu'UN SEUL rafraîchissement, pas deux qui se marcheraient dessus
  // — le refresh token est à usage unique côté serveur, voir refresh() dans handlers/auth/session.rs).
  const stateRef = useRef(state);
  const setTokens = useCallback((next: AuthState) => {
    stateRef.current = next;
    setState(next);
  }, []);

  // Efface la session JS ET verrouille le coffre côté Rust (voir tauri.lockVault) — pour toute fin
  // de session FORCÉE (refresh token invalide, sessions invalidées par un changement de mot de
  // passe/email suivi d'une reconnexion qui exige un 2FA manuel...), pas seulement le clic explicite
  // sur "Déconnexion" (voir logout() plus bas, qui fait ce même travail en plus d'appeler le
  // serveur). CORRECTIF SÉCURITÉ : ces cas oubliaient auparavant de verrouiller le coffre — l'état
  // React passait bien à "déconnecté", mais la clé du coffre restait active côté Rust, accessible à
  // n'importe quel appel direct des commandes Tauri encrypt_vault_field/decrypt_vault_field malgré
  // l'UI "déconnectée". Best-effort : ne doit jamais faire échouer l'appelant.
  const forceLocalLogout = useCallback(() => {
    void tauri.lockVault().catch(() => {});
    setIsVaultLocked(false);
    setTokens(LOGGED_OUT_STATE);
    // CORRECTIF SÉCURITÉ/VIE PRIVÉE (retour utilisateur : "n'oublie pas la sécurité est le plus
    // important") — voir clearAccountScopedThemeCache() dans lib/theme.ts pour le raisonnement
    // complet : sans ça, un compte B connecté sur ce même appareil juste après la déconnexion de A
    // pouvait voir les couleurs/noms de profils de personnalisation de A.
    clearAccountScopedThemeCache();
  }, [setTokens]);

  // Promesse de rafraîchissement en cours, partagée par tous les appelants concurrents plutôt que
  // d'en déclencher un chacun (voir le commentaire ci-dessus).
  const refreshInFlight = useRef<Promise<string> | null>(null);

  const refreshSession = useCallback((): Promise<string> => {
    if (refreshInFlight.current) return refreshInFlight.current;

    const currentRefreshToken = stateRef.current.refreshToken;
    const currentEmail = stateRef.current.email;
    if (!currentRefreshToken || !currentEmail) {
      return Promise.reject(new ApiError(401, "Session expirée, reconnecte-toi."));
    }

    const currentIsModerator = stateRef.current.isModerator;
    const currentIsAdmin = stateRef.current.isAdmin;
    const currentCanChooseServerInSettings = stateRef.current.canChooseServerInSettings;
    const promise = api
      .refresh({ refresh_token: currentRefreshToken })
      .then((tokens) => {
        // isModerator/isAdmin/canChooseServerInSettings inchangés : un rafraîchissement de session
        // ne modifie jamais les droits du compte.
        setTokens({ email: currentEmail, accessToken: tokens.access_token, refreshToken: tokens.refresh_token, isModerator: currentIsModerator, isAdmin: currentIsAdmin, canChooseServerInSettings: currentCanChooseServerInSettings });
        return tokens.access_token;
      })
      .catch((err) => {
        // Le refresh token est lui-même invalide/expiré : la session est définitivement finie,
        // pas la peine de laisser une session à moitié valide traîner en mémoire — voir
        // forceLocalLogout() ci-dessus (CORRECTIF SÉCURITÉ : verrouille aussi le coffre côté Rust,
        // pas seulement l'état React).
        forceLocalLogout();
        throw err;
      })
      .finally(() => {
        refreshInFlight.current = null;
      });

    refreshInFlight.current = promise;
    return promise;
  }, [setTokens, forceLocalLogout]);

  const authorizedRequest = useCallback(
    async <T,>(fn: (accessToken: string) => Promise<T>): Promise<T> => {
      const token = stateRef.current.accessToken;
      if (!token) throw new ApiError(401, "Aucune session active.");

      try {
        return await fn(token);
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          const newToken = await refreshSession();
          return fn(newToken);
        }
        throw err;
      }
    },
    [refreshSession],
  );

  /** Pose les tokens ET récupère le statut modérateur/admin (voir GET /me) — appelé après chaque
   * connexion réussie. Le fetch de /me est best-effort : s'il échoue (ex: coupure réseau juste
   * après le login), l'utilisateur reste connecté normalement, simplement sans interface
   * d'administration visible tant qu'un prochain appel authentifié ne la redéclenche pas (voir
   * authorizedRequest 401).
   *
   * Récupère AUSSI la personnalisation de thème du compte (voir lib/theme.ts, lib/customTheme.ts)
   * — SEUL réglage d'apparence synchronisé par compte plutôt que local à l'appareil (retour
   * utilisateur, 2026-09-03 : "tous tes appareils"). Contrairement à isModerator/isAdmin, qui ne
   * sont QUE lus ici et jamais réécrits depuis ce client, la personnalisation de thème peut aussi
   * être modifiée localement par ThemeSettings.tsx (voir setCachedCustomTheme côté client) — ce
   * fetch ne fait donc que RATTRAPER un changement fait depuis un AUTRE appareil, jamais écraser
   * une modification locale plus récente : comme les tokens ne sont jamais persistés sur disque
   * (voir le commentaire d'en-tête de ce fichier), CHAQUE lancement de l'app repasse forcément par
   * establishSession() — pas besoin d'un point de "restauration de session" séparé pour éviter le
   * bug de statut périmé déjà rencontré avec isModerator/isAdmin (qui, lui, ne se voyait qu'après
   * une reconnexion manuelle sur le web/l'extension, où la session PEUT survivre sans repasser
   * ici). Best-effort comme /me : une coupure réseau laisse simplement le thème local (preset ou
   * dernière personnalisation connue) inchangé. */
  const establishSession = useCallback(
    async (userEmail: string, accessToken: string, refreshToken: string) => {
      setTokens({ email: userEmail, accessToken, refreshToken, isModerator: false, isAdmin: false, canChooseServerInSettings: false });
      // Une nouvelle connexion vient de dériver la clé côté Rust (voir login()) : le coffre
      // redémarre forcément déverrouillé, même si la session précédente avait été verrouillée.
      setIsVaultLocked(false);

      // OPTIMISATION (retour utilisateur : "optimise l'utilisation [...] de la bande passante") :
      // GET /me et GET /theme-profiles sont deux appels INDÉPENDANTS (aucun n'a besoin du résultat
      // de l'autre) — les lancer en parallèle (Promise.allSettled, pas Promise.all : chacun reste
      // best-effort, l'échec de l'un ne doit jamais empêcher de traiter le résultat de l'autre)
      // évite d'attendre deux allers-retours réseau l'un après l'autre à CHAQUE connexion, pour un
      // seul temps d'attente au lieu de deux.
      const [meResult, profilesResult] = await Promise.allSettled([api.getMe(accessToken), api.listThemeProfiles(accessToken)]);

      if (meResult.status === "fulfilled") {
        const me = meResult.value;
        setTokens({ email: userEmail, accessToken, refreshToken, isModerator: me.is_moderator, isAdmin: me.is_admin, canChooseServerInSettings: me.can_choose_server_in_settings });
      }
      // sinon best-effort, voir la doc ci-dessus.

      // Un profil actif est chargé dans le cache DANS TOUS LES CAS (couleurs prêtes si le thème
      // choisi finit par être "custom") — mais c'est `preferred_theme` (ci-dessous) qui décide
      // désormais QUEL thème afficher, pas simplement "un profil actif existe" (retour
      // utilisateur : "je veux que lorsqu'on choisit un thème ce soit pour partout" — un compte qui
      // choisit explicitement un preset APRÈS avoir eu un profil actif ne doit plus se faire
      // reforcer sur "custom" juste parce que ce profil est resté actif côté serveur).
      let hasActiveProfile = false;
      if (profilesResult.status === "fulfilled") {
        const profiles = profilesResult.value;
        // Réutilisé par ThemeSettings.tsx (voir lib/theme.ts::getCachedThemeProfiles) pour éviter
        // de reposer la même question GET /theme-profiles au serveur quelques instants plus tard.
        setCachedThemeProfiles(profiles);
        const active = profiles.find((p) => p.is_active);
        if (active) {
          hasActiveProfile = true;
          setCachedCustomTheme({
            backgroundHue: active.background_hue,
            backgroundLightness: active.background_lightness,
            backgroundSaturation: active.background_saturation,
            accentHue: active.accent_hue,
            accentLightness: active.accent_lightness,
            accentSaturation: active.accent_saturation,
            dangerHue: active.danger_hue,
            dangerLightness: active.danger_lightness,
            dangerSaturation: active.danger_saturation,
            successHue: active.success_hue,
            successLightness: active.success_lightness,
            successSaturation: active.success_saturation,
            favoriteHue: active.favorite_hue,
            favoriteLightness: active.favorite_lightness,
            favoriteSaturation: active.favorite_saturation,
          });
        }
      }
      // sinon best-effort, voir la doc ci-dessus.

      // Retour utilisateur : "je veux que lorsqu'on choisit un thème ce soit pour partout (aussi
      // l'extension) que le thème soit appliqué partout", affiné ensuite par "pouvoir choisir si
      // [chaque appareil] a le thème synchronisé" — `preferred_theme` (GET /me) est la source de
      // vérité sur QUEL thème afficher, preset ou "custom", synchronisée par compte comme le
      // reste (voir ThemeSettings.tsx pour l'écriture de ce champ à chaque changement explicite),
      // MAIS uniquement si CET appareil a choisi de suivre le compte (voir
      // lib/theme.ts::isThemeSyncEnabled — désactivable par appareil, activé par défaut). Un
      // appareil qui a désactivé la synchro garde son thème local INCHANGÉ ici, quoi que dise le
      // compte. `toValidTheme` : filet de sécurité si le serveur renvoie une valeur que CETTE
      // version du client ne connaît pas encore (repli "dark", jamais planté).
      if (isThemeSyncEnabled()) {
        if (meResult.status === "fulfilled") {
          setTheme(toValidTheme(meResult.value.preferred_theme));
        } else if (hasActiveProfile) {
          // Repli si /me a échoué mais /theme-profiles a réussi (best-effort, voir la doc
          // ci-dessus) : comportement d'avant ce champ, encore raisonnable dans ce cas précis —
          // un profil actif reste un signal fort qu'il faut afficher "custom".
          setTheme("custom");
        }
      }
    },
    [setTokens],
  );

  const registerAccount = useCallback(async (email: string, masterPassword: string) => {
    const authHash = await tauri.deriveKeys(email, masterPassword);
    await api.register({
      email,
      master_password_hash: authHash,
      device_id: getDeviceId(),
    });
    // Le compte existe mais n'est pas encore utilisable (email non vérifié, voir backend) : on
    // verrouille tout de suite le coffre déverrouillé par deriveKeys() ci-dessus — il sera
    // re-dérivé au login(), une fois l'email confirmé, pas de raison de garder une clé en
    // mémoire pour un compte pas encore pleinement actif.
    await tauri.lockVault();
  }, []);

  const verifyEmail = useCallback(async (email: string, code: string) => {
    await api.verifyEmail({ email, code });
  }, []);

  const resendVerification = useCallback(async (email: string) => {
    await api.resendVerification({ email });
  }, []);

  const login = useCallback(
    async (email: string, masterPassword: string, rememberMe: boolean): Promise<LoginResult> => {
      const authHash = await tauri.deriveKeys(email, masterPassword);
      const result = await api.login({
        email,
        master_password_hash: authHash,
        device_id: getDeviceId(),
        remember_me: rememberMe,
      });

      if (api.isTfaRequired(result)) {
        return { status: "2FA_REQUIRED", authHash };
      }

      await establishSession(email, result.access_token, result.refresh_token);
      return { status: "OK" };
    },
    [establishSession],
  );

  const verifyDeviceAndLogin = useCallback(
    async (email: string, code: string, authHash: string, rememberMe: boolean) => {
      await api.verifyDevice({
        email,
        code,
        device_id: getDeviceId(),
        device_name: getDeviceName(),
      });

      // L'appareil est maintenant de confiance : on relance login() avec le MÊME hash
      // d'authentification (pas besoin de re-dériver, voir la doc de verifyDeviceAndLogin
      // ci-dessus) — il doit cette fois renvoyer directement des tokens.
      const result = await api.login({
        email,
        master_password_hash: authHash,
        device_id: getDeviceId(),
        remember_me: rememberMe,
      });

      if (api.isTfaRequired(result)) {
        throw new Error("La connexion a échoué malgré la validation de l'appareil — réessaie.");
      }
      await establishSession(email, result.access_token, result.refresh_token);
    },
    [establishSession],
  );

  const changeMasterPassword = useCallback(
    async (oldPassword: string, newPassword: string, rememberMe: boolean) => {
      const email = stateRef.current.email;
      if (!email) throw new Error("Aucune session active.");

      // 1. Confirme l'ancien mot de passe et récupère son hash — nécessaire AVANT le
      // re-chiffrement pour reconfirmer l'identité auprès de exportVault() ci-dessous (même
      // exigence que côté serveur, voir ExportVaultPayload). computeAuthHash() (PAS deriveKeys())
      // : le coffre est déjà déverrouillé avec la BONNE clé à ce stade — une faute de frappe dans
      // `oldPassword` ne doit jamais écraser la clé du coffre en mémoire par une clé dérivée d'un
      // mot de passe erroné avant même que le serveur n'ait rejeté ce hash (voir tauri.ts).
      const oldAuthHash = await tauri.computeAuthHash(email, oldPassword);

      // 2. Récupère TOUT le coffre actif ET tout l'historique de mots de passe en une fois
      // chacun (pas de pagination, contrairement à GET /vault — voir export_vault()/
      // export_vault_history() côté backend). L'historique doit LUI AUSSI être re-chiffré, sinon
      // il deviendrait indéchiffrable avec la nouvelle clé (voir lib/passwordChangeCrypto.ts).
      const [entries, history] = await Promise.all([
        authorizedRequest((token) => api.exportVault(token, { master_password_hash: oldAuthHash })),
        authorizedRequest((token) => api.exportVaultHistory(token, { master_password_hash: oldAuthHash })),
      ]);

      // 2bis. Récupère aussi TOUTES les pièces jointes de TOUTES les entrées — pas de bulk export
      // côté serveur pour elles (contrairement aux entrées/à l'historique) : on liste par entrée
      // (métadonnées seules), puis on récupère le contenu complet de chacune. CORRECTIF : un oubli
      // ici les laisserait indéfiniment chiffrées avec l'ANCIENNE clé après ce changement de mot
      // de passe, exactement comme l'aurait fait un oubli de `history` ci-dessus.
      const attachmentMetaByEntry = await Promise.all(
        entries.map((entry) => authorizedRequest((token) => api.getVaultAttachments(token, entry.id))),
      );
      const attachmentRefs = entries.flatMap((entry, i) =>
        attachmentMetaByEntry[i].map((meta) => ({ vaultId: entry.id, attachmentId: meta.id })),
      );
      const attachments = await Promise.all(
        attachmentRefs.map(({ vaultId, attachmentId }) =>
          authorizedRequest((token) => api.getVaultAttachment(token, vaultId, attachmentId)),
        ),
      );

      // 3. Re-chiffre tout côté Rust EN UN SEUL appel : ancien ET nouveau jeu de clés dérivés là-bas
      // (dérivation Argon2id volontairement lente — un second appel la déclencherait deux fois),
      // aucune clé ni contenu en clair ne transite par le JS (voir
      // src-tauri/src/lib.rs::prepare_password_change).
      const { ciphertexts, plans, historyPlans, attachmentPlans } = flattenForReencryption(entries, history, attachments);
      const result = await tauri.preparePasswordChange(email, oldPassword, newPassword, ciphertexts);
      const reencrypted_entries = rebuildEntries(plans, result.reencrypted_ciphertexts);
      const reencrypted_history = rebuildHistory(historyPlans, result.reencrypted_ciphertexts);
      const reencrypted_attachments = rebuildAttachments(attachmentPlans, result.reencrypted_ciphertexts);

      // 4. Envoie le changement complet au serveur, en une transaction atomique côté backend.
      await authorizedRequest((token) =>
        api.updatePassword(token, {
          old_master_password_hash: result.old_auth_hash,
          new_master_password_hash: result.new_auth_hash,
          reencrypted_entries,
          reencrypted_history,
          reencrypted_attachments,
        }),
      );

      // 4bis. Le mot de passe maître vient de changer -> la clé de chiffrement du coffre change
      // AUSSI (elle en dérive) : un éventuel déverrouillage rapide (voir tauri.enableQuickUnlock)
      // protège l'ANCIENNE clé, désormais fausse — le désactiver plutôt que de laisser un fichier
      // trompeur. Best-effort : ne doit jamais faire échouer un changement de mot de passe par
      // ailleurs réussi.
      await tauri.disableQuickUnlock().catch(() => {});

      // 5. update_password() invalide TOUTES les sessions actives (voir backend) — y compris
      // celle-ci. On se reconnecte immédiatement avec le nouveau mot de passe : même appareil,
      // déjà de confiance, ne redemande donc pas de 2FA.
      const loginResult = await login(email, newPassword, rememberMe);
      if (loginResult.status === "2FA_REQUIRED") {
        // CORRECTIF SÉCURITÉ : même raison que dans changeEmail() ci-dessus — update_password()
        // vient d'invalider TOUTES les sessions (y compris celle-ci), mais establishSession()
        // n'a jamais tourné puisque login() s'est arrêté au 2FA. forceLocalLogout() aligne
        // immédiatement l'état local sur la réalité serveur plutôt que de laisser les anciens
        // tokens, déjà révoqués, traîner dans l'état React.
        forceLocalLogout();
        throw new Error("Mot de passe changé avec succès, mais une reconnexion manuelle est nécessaire.");
      }

      // 6. Le mot de passe maître (et donc la clé du coffre) vient de changer : tout blob de clé
      // scellé pour un contact de confiance AVANT ce changement (voir tauri.sealVaultKeyForContact)
      // protège désormais l'ANCIENNE clé, inutile. Re-scelle avec la NOUVELLE clé, maintenant
      // active suite au login() ci-dessus — best-effort, ne doit jamais faire échouer un
      // changement de mot de passe par ailleurs réussi.
      await reseedAllContacts(authorizedRequest).catch(() => {});
    },
    [authorizedRequest, login, forceLocalLogout],
  );

  const changeEmail = useCallback(
    async (newEmail: string, currentPassword: string, rememberMe: boolean) => {
      const currentEmail = stateRef.current.email;
      if (!currentEmail) throw new Error("Aucune session active.");

      // computeAuthHash() (PAS deriveKeys()) : le coffre est déjà déverrouillé avec la BONNE clé —
      // voir le commentaire équivalent dans changeMasterPassword() ci-dessus.
      const authHash = await tauri.computeAuthHash(currentEmail, currentPassword);
      await authorizedRequest((token) =>
        api.updateEmail(token, { new_email: newEmail, master_password_hash: authHash }),
      );

      // update_email() invalide les sessions liées au compte (voir backend) — on se reconnecte
      // avec le NOUVEL email, même mot de passe.
      const loginResult = await login(newEmail, currentPassword, rememberMe);
      if (loginResult.status === "2FA_REQUIRED") {
        // CORRECTIF SÉCURITÉ : update_email() vient d'invalider TOUTES les sessions actives côté
        // serveur (y compris celle-ci), mais tant que login() ne s'est pas terminé avec succès,
        // establishSession() n'a jamais tourné — l'état React gardait donc les ANCIENS tokens,
        // déjà révoqués côté serveur, et continuait d'afficher l'app comme "connectée" jusqu'au
        // prochain appel authentifié qui échouerait (401 -> refreshSession, lui-même voué à
        // échouer). forceLocalLogout() aligne immédiatement l'état local sur la réalité serveur.
        forceLocalLogout();
        throw new Error("Email modifié avec succès, mais une reconnexion manuelle est nécessaire.");
      }
    },
    [authorizedRequest, login, forceLocalLogout],
  );

  const logout = useCallback(async () => {
    const currentRefreshToken = stateRef.current.refreshToken;
    if (currentRefreshToken) {
      // Best-effort : même si l'appel réseau échoue, on efface quand même l'état local — un
      // utilisateur qui clique "déconnexion" doit toujours voir son app se déconnecter localement.
      await api.logout({ refresh_token: currentRefreshToken }).catch(() => {});
    }
    // Le déverrouillage rapide (voir tauri.enableQuickUnlock) ne doit couvrir qu'un verrouillage
    // PONCTUEL au sein de la même session (perte de focus, inactivité), pas survivre à une
    // déconnexion complète — sans quoi Windows Hello suffirait seul à rouvrir une session
    // pourtant explicitement quittée. Best-effort, comme le reste de cette fonction.
    await tauri.disableQuickUnlock().catch(() => {});
    forceLocalLogout();
  }, [forceLocalLogout]);

  // =========================================================================
  // VERROUILLAGE DU COFFRE (manuel ou par inactivité) — voir doc de isVaultLocked/lockVaultNow/
  // unlockVault sur AuthContextValue. Distinct de logout() : la session (tokens) reste active, on
  // n'efface QUE la clé de chiffrement côté Rust.
  // =========================================================================
  const lockVaultNow = useCallback(async () => {
    await tauri.lockVault();
    setIsVaultLocked(true);
  }, []);

  const unlockVault = useCallback(
    async (password: string) => {
      const email = stateRef.current.email;
      if (!email) throw new Error("Aucune session active.");

      await tauri.deriveKeys(email, password);
      let entries;
      try {
        entries = await authorizedRequest((token) => api.getVault(token, 1, 0));
      } catch (err) {
        // Échec RÉSEAU/SESSION (ex: backend injoignable, refresh token expiré — authorizedRequest
        // a alors déjà appelé forceLocalLogout()) : le mot de passe n'a même pas pu être vérifié,
        // ce n'est donc PAS lui le problème. Le signaler comme tel plutôt que d'afficher "mot de
        // passe incorrect", qui enverrait l'utilisateur retaper indéfiniment un mot de passe
        // pourtant correct sans jamais lui indiquer qu'il doit en réalité se reconnecter.
        await tauri.lockVault();
        if (err instanceof ApiError) throw err;
        throw new Error("Impossible de vérifier le mot de passe (connexion au serveur impossible).");
      }
      try {
        if (entries.length > 0) {
          await tauri.decryptField(entries[0].encrypted_site_name);
        }
      } catch {
        // Ici, seul un échec de DÉCHIFFREMENT peut survenir (la requête réseau a réussi) : c'est
        // bien le mot de passe qui est en cause.
        await tauri.lockVault();
        throw new Error("Mot de passe maître incorrect.");
      }
      setIsVaultLocked(false);
    },
    [authorizedRequest],
  );

  const quickUnlockVault = useCallback(async () => {
    // Contrairement à unlockVault(password) ci-dessus, pas de vérification supplémentaire ici :
    // tryQuickUnlock() ne réussit QUE si la vérification Windows Hello a réussi ET que le blob
    // DPAPI s'est déchiffré correctement (authentifié, pas de "mauvaise clé silencieuse" possible
    // — voir src-tauri/src/dpapi.rs), contrairement à Argon2id qui "réussit" toujours quel que
    // soit le mot de passe fourni.
    await tauri.tryQuickUnlock();
    setIsVaultLocked(false);
  }, []);

  // Minuteur d'inactivité : réinitialisé à chaque interaction utilisateur, verrouille le coffre
  // s'il expire (délai configurable, voir lib/settings.ts — 0 désactive). Un seul minuteur pour
  // toute la session (pas un par écran), comme la connexion WebSocket ci-dessous.
  const inactivityTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (!state.email || isVaultLocked) return;

    function resetTimer() {
      if (inactivityTimerRef.current) clearTimeout(inactivityTimerRef.current);
      const minutes = getAutoLockMinutes();
      if (minutes <= 0) return;
      inactivityTimerRef.current = setTimeout(() => {
        void lockVaultNow();
      }, minutes * 60_000);
    }

    const activityEvents = ["mousemove", "mousedown", "keydown", "scroll", "touchstart"] as const;
    activityEvents.forEach((evt) => window.addEventListener(evt, resetTimer));
    resetTimer();

    return () => {
      activityEvents.forEach((evt) => window.removeEventListener(evt, resetTimer));
      if (inactivityTimerRef.current) clearTimeout(inactivityTimerRef.current);
    };
  }, [state.email, isVaultLocked, lockVaultNow]);

  // Verrouillage à la perte de focus de la fenêtre (alt-tab, clic ailleurs, réduction) — voir
  // lib/settings.ts::getLockOnFocusLossDelaySeconds. `onFocusChanged` de l'API Tauri se déclenche
  // aussi bien sur un simple changement de focus que sur une réduction (qui retire le focus au
  // passage), donc un seul abonnement couvre les deux cas sans logique séparée. PAS un verrouillage
  // instantané : un DÉLAI DE GRÂCE est armé à la perte de focus et annulé si le focus revient avant
  // qu'il expire — un simple alt-tab bref ne doit pas redemander le mot de passe maître. Ignoré
  // entièrement pendant qu'un dialogue natif ouvert par l'app elle-même est affiché (voir
  // lib/focusLossLockSuppression.ts, ex: export/import de fichier), qui fait perdre le focus sans
  // que ce soit un abandon de l'app. Import dynamique du module fenêtre : contexte natif Tauri
  // uniquement, pas de raison de l'alourdir au chargement initial pour une fonctionnalité
  // désactivable.
  useEffect(() => {
    if (!state.email || isVaultLocked) return;

    let unlisten: (() => void) | undefined;
    let cancelled = false;
    let pendingLock: ReturnType<typeof setTimeout> | null = null;

    function cancelPendingLock() {
      if (pendingLock) {
        clearTimeout(pendingLock);
        pendingLock = null;
      }
    }

    void import("@tauri-apps/api/window").then(({ getCurrentWindow }) => {
      if (cancelled) return;
      return getCurrentWindow()
        .onFocusChanged(({ payload: focused }) => {
          if (focused) {
            cancelPendingLock();
            return;
          }
          if (isFocusLossLockSuppressed()) return;
          // Lu à chaque événement plutôt qu'une seule fois à l'abonnement : un changement de ce
          // réglage depuis l'écran Réglages prend effet dès le prochain événement de focus, sans
          // attendre un verrouillage/déverrouillage pour que cet effet se réabonne.
          const delaySeconds = getLockOnFocusLossDelaySeconds();
          if (delaySeconds <= 0) return; // désactivé
          cancelPendingLock();
          pendingLock = setTimeout(() => {
            pendingLock = null;
            if (!isFocusLossLockSuppressed()) void lockVaultNow();
          }, delaySeconds * 1000);
        })
        .then((fn) => {
          if (cancelled) fn();
          else unlisten = fn;
        });
    });

    return () => {
      cancelled = true;
      cancelPendingLock();
      unlisten?.();
    };
  }, [state.email, isVaultLocked, lockVaultNow]);

  // =========================================================================
  // SYNCHRONISATION TEMPS RÉEL (WEBSOCKET) — voir handlers/sync.rs côté backend
  // =========================================================================
  // Une seule connexion pour toute la durée de la session (pas une par écran) : les composants
  // intéressés (ex: Vault.tsx) s'abonnent via subscribeToVaultSync() plutôt que d'ouvrir chacun
  // leur propre WebSocket. Reconnexion automatique avec backoff exponentiel (plafonné à 30s) si
  // la connexion tombe de façon inattendue — un ticket FRAIS est ré-échangé à chaque tentative,
  // jamais réutilisé (à usage unique côté serveur, 60s de durée de vie).
  const syncListenersRef = useRef<Set<() => void>>(new Set());
  const subscribeToVaultSync = useCallback((callback: () => void) => {
    syncListenersRef.current.add(callback);
    return () => {
      syncListenersRef.current.delete(callback);
    };
  }, []);

  useEffect(() => {
    // state.email (pas state.accessToken) comme déclencheur : ne change qu'à une VRAIE
    // transition de session (connexion/déconnexion/changement d'email), pas à chaque
    // rafraîchissement de token (~10 min) — sans quoi la connexion se rouvrirait inutilement.
    if (!state.email) return;

    let cancelled = false;
    let socket: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let reconnectAttempt = 0;

    function scheduleReconnect() {
      if (cancelled) return;
      const delay = Math.min(30_000, 1000 * 2 ** reconnectAttempt);
      reconnectAttempt += 1;
      reconnectTimer = setTimeout(connect, delay);
    }

    async function connect() {
      if (cancelled) return;
      try {
        const { ticket } = await authorizedRequest((token) => api.createWsTicket(token));
        if (cancelled) return;

        const wsUrl = `${getBackendUrl().replace(/^http/, "ws")}/ws?ticket=${encodeURIComponent(ticket)}`;
        socket = new WebSocket(wsUrl);

        socket.onopen = () => {
          reconnectAttempt = 0;
        };

        socket.onmessage = (event) => {
          let parsed: SyncEvent;
          try {
            parsed = JSON.parse(event.data as string) as SyncEvent;
          } catch {
            return; // message inattendu, pas critique (juste un signal de resynchro)
          }

          if (parsed.event_type === "SESSION_REVOKED") {
            void logout();
            return;
          }
          syncListenersRef.current.forEach((cb) => cb());
        };

        socket.onclose = () => {
          socket = null;
          if (!cancelled) scheduleReconnect();
        };

        socket.onerror = () => {
          socket?.close(); // déclenche onclose -> scheduleReconnect
        };
      } catch {
        // Échec de l'échange du ticket (ex: coupure réseau, session en cours de rafraîchissement) :
        // pas fatal, on retente avec le même backoff qu'une déconnexion.
        if (!cancelled) scheduleReconnect();
      }
    }

    void connect();

    return () => {
      cancelled = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, [state.email, authorizedRequest, logout]);

  const value = useMemo<AuthContextValue>(
    () => ({
      ...state,
      isAuthenticated: state.accessToken !== null,
      registerAccount,
      verifyEmail,
      resendVerification,
      login,
      verifyDeviceAndLogin,
      logout,
      changeMasterPassword,
      changeEmail,
      authorizedRequest,
      subscribeToVaultSync,
      isVaultLocked,
      lockVaultNow,
      unlockVault,
      quickUnlockVault,
    }),
    [
      state,
      registerAccount,
      verifyEmail,
      resendVerification,
      login,
      verifyDeviceAndLogin,
      logout,
      changeMasterPassword,
      changeEmail,
      authorizedRequest,
      subscribeToVaultSync,
      isVaultLocked,
      lockVaultNow,
      unlockVault,
      quickUnlockVault,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth() doit être appelé à l'intérieur d'un <AuthProvider>");
  return ctx;
}
