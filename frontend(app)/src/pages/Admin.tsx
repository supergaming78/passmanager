import { useEffect, useState, useCallback } from "react";
import { useAuth } from "../state/AuthContext";
import * as api from "../api/client";
import { getErrorMessage } from "../lib/errors";
import { getEffectiveListLayout } from "../lib/listLayout";
import { openUrl } from "@tauri-apps/plugin-opener";
import type { UserIpHistoryEntry, UserIpHistoryResponse, ServerHealth, AdminUserView, AuditLog, BugReportView, FeatureSuggestionView } from "../api/types";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-2xl border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-neutral-900">
      <h2 className="mb-3 text-base font-semibold text-neutral-900 dark:text-neutral-100">{title}</h2>
      {children}
    </section>
  );
}

function UsersSection() {
  // isAdmin : vrai UNIQUEMENT pour le compte ADMIN_EMAIL (voir state/AuthContext.tsx, alimenté
  // par GET /me) — masque les boutons promouvoir/rétrograder pour tout le monde d'autre plutôt
  // que de laisser un bouton qui échouerait toujours avec 403 (voir handlers/admin.rs::update_user_role()).
  const { email: myEmail, isAdmin, authorizedRequest } = useAuth();
  const [users, setUsers] = useState<AdminUserView[]>([]);
  // Réglage GLOBAL des inscriptions, lu depuis /public-config (voir son commentaire côté backend :
  // volontairement sans cache, pour que la valeur affichée ici soit toujours la vraie).
  const [registrationOpen, setRegistrationOpen] = useState<boolean | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyEmail, setBusyEmail] = useState<string | null>(null);
  // Historique IP du compte actuellement dépiauté (null = panneau fermé). Chargé à la demande :
  // c'est une donnée sensible, inutile de la tirer pour tous les comptes à chaque ouverture.
  // État du serveur, chargé à la demande : ces mesures parcourent des dossiers et interrogent la
  // base, inutile de les calculer pour quelqu'un qui vient juste gérer un compte.
  const [health, setHealth] = useState<ServerHealth | null>(null);
  const [healthOpen, setHealthOpen] = useState(false);
  // Action d'administration en cours. Sans cet état, un bouton dont l'action prend plusieurs
  // secondes (un envoi SMTP, un VACUUM) paraît mort et invite à re-cliquer — ce qui a réellement
  // produit quatre emails de test pour un seul clic voulu.
  const [busyAction, setBusyAction] = useState<"vacuum" | "email" | "export" | null>(null);
  const [ipHistoryFor, setIpHistoryFor] = useState<string | null>(null);
  const [ipHistory, setIpHistory] = useState<UserIpHistoryResponse | null>(null);
  // Réglé dans Réglages (voir components/ListLayoutSettings.tsx) — même préférence que le Coffre.
  const [listLayout] = useState(() => getEffectiveListLayout());

  const load = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      setUsers(await authorizedRequest((token) => api.listAllUsers(token)));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
  }, [authorizedRequest]);

  useEffect(() => {
    void load();
  }, [load]);

  // Réglage global lu séparément de la liste des comptes : il vient de /public-config (route
  // publique), pas du listage administrateur. Best-effort — un échec laisse simplement
  // l'interrupteur en attente plutôt que de faire échouer tout l'écran.
  useEffect(() => {
    let cancelled = false;
    void api
      .getPublicConfig()
      .then((config) => {
        // Un backend antérieur à ce réglage ne renvoie PAS le champ : il faut alors rester sur
        // null (interrupteur masqué) et surtout pas retomber sur `undefined`, qui est faux et
        // afficherait "fermées" sur un serveur ouvert. L'app pouvant viser plusieurs serveurs,
        // le cas ne se limite pas à la fenêtre de déploiement.
        if (!cancelled && typeof config.registration_open === "boolean") {
          setRegistrationOpen(config.registration_open);
        }
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, []);

  async function handleToggleRole(user: AdminUserView) {
    const action = user.is_moderator ? "retirer le rôle modérateur de" : "promouvoir modérateur";
    if (!confirm(`Confirmer : ${action} ${user.email} ?`)) return;
    setBusyEmail(user.email);
    setError(null);
    try {
      await authorizedRequest((token) => api.updateUserRole(token, user.email, { is_moderator: !user.is_moderator }));
      await load();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyEmail(null);
    }
  }

  async function handleRevokeSessions(targetEmail: string) {
    if (!confirm(`Déconnecter tous les appareils de ${targetEmail} ?`)) return;
    setBusyEmail(targetEmail);
    setError(null);
    try {
      await authorizedRequest((token) => api.revokeUserSessions(token, targetEmail));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyEmail(null);
    }
  }

  async function handleToggleExtensionEmailChange(user: AdminUserView) {
    setBusyEmail(user.email);
    setError(null);
    try {
      await authorizedRequest((token) =>
        api.updateExtensionEmailChange(token, user.email, { enabled: !user.can_change_email_via_extension }),
      );
      await load();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyEmail(null);
    }
  }

  async function handleSetExtensionEmailChangeForAll(enabled: boolean) {
    const action = enabled ? "activer" : "désactiver";
    if (!confirm(`Confirmer : ${action} le changement d'email via l'extension pour TOUS les comptes ?`)) return;
    setError(null);
    try {
      await authorizedRequest((token) => api.updateExtensionEmailChangeAll(token, { enabled }));
      await load();
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  // Réservé à l'Admin SEUL (pas juste modérateur, contrairement au changement d'email via
  // l'extension ci-dessus) — voir handlers/admin.rs::update_server_choice_in_settings().
  async function handleToggleServerChoiceInSettings(user: AdminUserView) {
    setBusyEmail(user.email);
    setError(null);
    try {
      await authorizedRequest((token) =>
        api.updateServerChoiceInSettings(token, user.email, { enabled: !user.can_choose_server_in_settings }),
      );
      await load();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyEmail(null);
    }
  }

  async function handleSetServerChoiceInSettingsForAll(enabled: boolean) {
    const action = enabled ? "activer" : "désactiver";
    if (!confirm(`Confirmer : ${action} le choix du serveur dans les Réglages pour TOUS les comptes ?`)) return;
    setError(null);
    try {
      await authorizedRequest((token) => api.updateServerChoiceInSettingsAll(token, { enabled }));
      await load();
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  /** Ouvre ou ferme les inscriptions sur tout le serveur. Fermées, seul l'Admin configuré peut
   * encore s'inscrire — sans quoi un serveur neuf se retrouverait sans administrateur possible. */
  async function handleToggleRegistration() {
    if (registrationOpen === null) return;
    const opening = !registrationOpen;
    if (opening && !confirm("Rouvrir les inscriptions ? N'importe qui connaissant l'adresse du serveur pourra créer un compte.")) {
      return;
    }
    setError(null);
    try {
      await authorizedRequest((token) => api.updateRegistrationOpen(token, { enabled: opening }));
      setRegistrationOpen(opening);
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  /** Suspend ou réactive un compte. Marche intermédiaire entre "ne rien faire" et la suppression
   * définitive, qui cascade sur tout le coffre et ne se rattrape pas — ici les données sont
   * conservées, et la suspension coupe immédiatement les sessions en cours (voir le backend). */
  /** Compacte la base. Confirmation explicite : l'opération prend un verrou exclusif (les
   * écritures attendent) et réécrit tout le fichier, donc demande temporairement de la place. */
  async function handleVacuum() {
    if (!confirm("Compacter la base ? Les écritures sont brièvement suspendues, et l'opération a besoin de place pour une copie temporaire. Aucune donnée n'est supprimée.")) return;
    setError(null);
    setBusyAction("vacuum");
    try {
      const res = await authorizedRequest((token) => api.vacuumDatabase(token));
      alert(
        res.freed_bytes > 0
          ? `Base compactée : ${formatBytes(res.freed_bytes)} rendus au disque (${formatBytes(res.before_bytes)} → ${formatBytes(res.after_bytes)}).`
          : "Base déjà compacte : il n'y avait rien à récupérer.",
      );
      setHealth(await authorizedRequest((token) => api.getServerHealth(token)));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyAction(null);
    }
  }

  /** Envoie un email de test à SA PROPRE adresse — jamais à une adresse saisie : une route
   * capable d'expédier du courrier n'importe où serait un relais ouvert si le compte était volé. */
  async function handleTestEmail() {
    setError(null);
    setBusyAction("email");
    try {
      await authorizedRequest((token) => api.sendTestEmail(token));
      alert("Email de test envoyé à ton adresse. S'il n'arrive pas d'ici quelques minutes (pense aux indésirables), la configuration SMTP du serveur est en cause — et c'est elle qui envoie aussi les codes de connexion et les réinitialisations.");
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyAction(null);
    }
  }

  /** Règle les quotas d'un compte. Une saisie vide vaut « plafond global », ce qui est différent
   * de 0 — d'où la distinction explicite plutôt qu'une conversion silencieuse. */
  async function handleEditQuotas(user: AdminUserView) {
    const lire = (label: string, actuel: number | null) => {
      const saisie = window.prompt(
        `${label} pour ${user.email}\n\nLaisse VIDE pour appliquer le plafond global du serveur.\nMets 0 pour interdire tout nouvel ajout.`,
        actuel === null ? "" : String(actuel),
      );
      if (saisie === null) return undefined; // annulé
      const nettoye = saisie.trim();
      if (nettoye === "") return null;
      const n = Number(nettoye);
      return Number.isInteger(n) && n >= 0 ? n : undefined;
    };

    const entrees = lire("Nombre maximum d'entrées", user.max_vault_entries);
    if (entrees === undefined) return;
    const pieces = lire("Nombre maximum de pièces jointes", user.max_attachments);
    if (pieces === undefined) return;

    setBusyEmail(user.email);
    setError(null);
    try {
      await authorizedRequest((token) =>
        api.updateQuotas(token, user.email, { max_vault_entries: entrees, max_attachments: pieces }),
      );
      await load();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyEmail(null);
    }
  }

  /** Télécharge le journal d'audit en CSV. Passe par l'API authentifiée puis crée un objet local :
   * un simple lien href ne porterait pas le jeton d'accès. */
  async function handleExportAudit() {
    setError(null);
    setBusyAction("export");
    try {
      const csv = await authorizedRequest((token) => api.exportAuditLogsCsv(token));
      const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
      const lien = document.createElement("a");
      lien.href = url;
      lien.download = `journal-audit-${new Date().toISOString().slice(0, 10)}.csv`;
      lien.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyAction(null);
    }
  }

  async function handleToggleHealth() {
    if (healthOpen) {
      setHealthOpen(false);
      return;
    }
    setHealthOpen(true);
    setHealth(null);
    setError(null);
    try {
      setHealth(await authorizedRequest((token) => api.getServerHealth(token)));
    } catch (err) {
      setError(getErrorMessage(err));
      setHealthOpen(false);
    }
  }

  /** Ouvre (ou referme) l'historique IP d'un compte. Chargé à la demande, jamais en masse. */
  async function handleShowIpHistory(user: AdminUserView) {
    if (ipHistoryFor === user.email) {
      setIpHistoryFor(null);
      setIpHistory(null);
      return;
    }
    setIpHistoryFor(user.email);
    setIpHistory(null);
    setError(null);
    try {
      setIpHistory(await authorizedRequest((token) => api.getUserIpHistory(token, user.email)));
    } catch (err) {
      setError(getErrorMessage(err));
      setIpHistoryFor(null);
    }
  }

  async function handleToggleSuspended(user: AdminUserView) {
    const suspending = !user.is_suspended;
    if (suspending && !confirm(`Suspendre ${user.email} ? Ses sessions seront coupées immédiatement et il ne pourra plus se connecter. Ses données sont conservées.`)) {
      return;
    }
    setBusyEmail(user.email);
    setError(null);
    try {
      await authorizedRequest((token) => api.updateSuspended(token, user.email, { is_suspended: suspending }));
      await load();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyEmail(null);
    }
  }

  async function handleChangeEmail(user: AdminUserView) {
    const newEmail = window.prompt(`Nouvel email pour ${user.email} :`, user.email);
    if (!newEmail || newEmail.trim().toLowerCase() === user.email) return;
    if (!confirm(`Confirmer : remplacer ${user.email} par ${newEmail.trim()} ? Une alerte de sécurité sera envoyée à l'ancienne adresse.`)) return;
    setBusyEmail(user.email);
    setError(null);
    try {
      await authorizedRequest((token) => api.adminUpdateUserEmail(token, user.email, { new_email: newEmail.trim() }));
      await load();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyEmail(null);
    }
  }

  async function handleDelete(targetEmail: string) {
    if (!confirm(`Supprimer DÉFINITIVEMENT le compte ${targetEmail} et tout son contenu ? Cette action est irréversible.`)) return;
    setBusyEmail(targetEmail);
    setError(null);
    try {
      await authorizedRequest((token) => api.deleteUser(token, targetEmail));
      await load();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyEmail(null);
    }
  }

  if (isLoading) return <p className="text-sm text-neutral-500">Chargement…</p>;

  /** Actions communes aux deux dispositions (voir listLayout ci-dessus, retour utilisateur
   * 2026-09-02, "disposition des listes") — extrait pour n'écrire les vérifications de permission
   * qu'UNE SEULE fois, réutilisé tel quel par la vue tableau ET la vue cartes, plutôt que risquer
   * une divergence entre les deux si l'une était modifiée sans l'autre. */
  function renderUserActions(user: AdminUserView, isSelf: boolean, isBusy: boolean, canActOnTarget: boolean) {
    return (
      <div className="flex flex-wrap gap-1.5">
        {canActOnTarget && (
          <button
            type="button"
            disabled={isSelf || isBusy}
            onClick={() => void handleChangeEmail(user)}
            title={isSelf ? "Impossible de changer son propre email ici — utilise Réglages" : "Changer l'email de ce compte (jamais le mot de passe maître)"}
            className="rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            Changer l'email
          </button>
        )}
        {isAdmin && (
          <button
            type="button"
            disabled={isSelf || isBusy}
            onClick={() => void handleToggleRole(user)}
            title={isSelf ? "Impossible de modifier son propre rôle" : undefined}
            className="rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            {user.is_moderator ? "Retirer modérateur" : "Promouvoir modérateur"}
          </button>
        )}
        <button
          type="button"
          onClick={() => void handleShowIpHistory(user)}
          title="Adresses IP vues pour ce compte sur les derniers jours"
          className={`rounded-lg border px-2 py-1 text-xs font-medium ${
            ipHistoryFor === user.email
              ? "border-neutral-400 bg-neutral-100 text-neutral-700 dark:border-neutral-600 dark:bg-neutral-800 dark:text-neutral-200"
              : "border-neutral-300 text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          }`}
        >
          {ipHistoryFor === user.email ? "Masquer les IP" : "Voir les IP"}
        </button>
        {isAdmin && (
          <button
            type="button"
            disabled={isBusy}
            onClick={() => void handleEditQuotas(user)}
            title="Limiter le nombre d'entrées et de pièces jointes de ce compte"
            className="rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            Quotas
          </button>
        )}
        {canActOnTarget && (
          <button
            type="button"
            disabled={isSelf || isBusy}
            onClick={() => void handleToggleSuspended(user)}
            title={isSelf ? "Impossible de se suspendre soi-même" : "Suspendre ce compte sans supprimer ses données — réversible"}
            className={`rounded-lg border px-2 py-1 text-xs font-medium disabled:cursor-not-allowed disabled:opacity-40 ${
              user.is_suspended
                ? "border-emerald-300 text-emerald-700 hover:bg-emerald-50 dark:border-emerald-800 dark:text-emerald-400 dark:hover:bg-emerald-950"
                : "border-amber-300 text-amber-700 hover:bg-amber-50 dark:border-amber-800 dark:text-amber-400 dark:hover:bg-amber-950"
            }`}
          >
            {user.is_suspended ? "Réactiver" : "Suspendre"}
          </button>
        )}
        {canActOnTarget && (
          <button
            type="button"
            disabled={isSelf || isBusy}
            onClick={() => void handleToggleExtensionEmailChange(user)}
            title={isSelf ? "Impossible de modifier ce réglage sur son propre compte ici" : "Autoriser/interdire le changement d'email depuis l'extension navigateur pour ce compte"}
            className="rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            {user.can_change_email_via_extension ? "Retirer email/ext." : "Autoriser email/ext."}
          </button>
        )}
        {isAdmin && (
          <button
            type="button"
            disabled={isSelf || isBusy}
            onClick={() => void handleToggleServerChoiceInSettings(user)}
            title={isSelf ? "Tu as déjà toujours accès à ce choix, indépendamment de ce réglage" : "Autoriser/interdire le choix du serveur dans les Réglages pour ce compte"}
            className="rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            {user.can_choose_server_in_settings ? "Retirer choix serveur" : "Autoriser choix serveur"}
          </button>
        )}
        {canActOnTarget && (
          <button
            type="button"
            disabled={isSelf || isBusy}
            onClick={() => void handleRevokeSessions(user.email)}
            title={isSelf ? "Impossible de déconnecter son propre compte ici" : undefined}
            className="rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            Déconnecter
          </button>
        )}
        {canActOnTarget && (
          <button
            type="button"
            disabled={isSelf || isBusy}
            onClick={() => void handleDelete(user.email)}
            title={isSelf ? "Impossible de supprimer son propre compte ici" : undefined}
            className="rounded-lg border border-red-300 px-2 py-1 text-xs font-medium text-red-600 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-40 dark:border-red-900 dark:text-red-400 dark:hover:bg-red-950"
          >
            Supprimer
          </button>
        )}
      </div>
    );
  }

  /** Espace occupé par un compte, en une ligne lisible. Sur un serveur auto-hébergé, voir qui
   * approche des plafonds évite de découvrir le problème par un disque plein. */
  function formatUsage(user: AdminUserView) {
    const mb = user.attachment_bytes / (1024 * 1024);
    const size = user.attachment_bytes === 0 ? "aucune pièce jointe" : mb < 0.1 ? "< 0,1 Mo de pièces jointes" : `${mb.toFixed(1)} Mo de pièces jointes`;
    return `${user.entry_count} entrée${user.entry_count > 1 ? "s" : ""} · ${size}`;
  }

  /** Ligne d'un réglage appliqué EN MASSE.
   *
   * Ces réglages sont stockés PAR COMPTE ; ces boutons ne font que les écrire sur tout le monde
   * d'un coup. Il n'existe donc aucun "état global" à lire côté serveur — c'est pourquoi rien
   * n'était affiché. Mais la vraie question ("est-ce actif en ce moment ?") se répond depuis la
   * liste déjà chargée : on la résume ici, sans appel réseau ni nouveau champ.
   *
   * Le résumé distingue les trois cas réels — activé partout, désactivé partout, et l'état MIXTE
   * qu'un simple interrupteur ne saurait pas représenter (il naît dès qu'un compte est réglé
   * individuellement). Le bouton qui ne changerait rien est désactivé, pour que l'état en cours
   * se lise aussi dans ce qui est cliquable. */
  function renderBulkFlagRow(label: string, flag: (u: AdminUserView) => boolean, apply: (enabled: boolean) => void) {
    const total = users.length;
    const on = users.filter(flag).length;
    const allOn = total > 0 && on === total;
    const allOff = total > 0 && on === 0;
    const summary = total === 0
      ? "aucun compte"
      : allOn
        ? `activé pour les ${total} comptes`
        : allOff
          ? "désactivé pour tous"
          : `mixte — activé pour ${on} compte${on > 1 ? "s" : ""} sur ${total}`;
    const btn = "rounded-lg border border-neutral-300 px-2 py-1 font-medium text-neutral-600 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800";
    return (
      <div className="mb-3 flex flex-wrap items-center gap-2 text-xs text-neutral-500">
        <span>{label}</span>
        <span className={allOn ? "font-medium text-emerald-600 dark:text-emerald-400" : allOff ? "font-medium text-neutral-500 dark:text-neutral-400" : "font-medium text-amber-600 dark:text-amber-400"}>
          {summary}
        </span>
        <button type="button" disabled={allOn || total === 0} onClick={() => apply(true)} className={btn}>
          Activer pour tous
        </button>
        <button type="button" disabled={allOff || total === 0} onClick={() => apply(false)} className={btn}>
          Désactiver pour tous
        </button>
      </div>
    );
  }

  /** Tailles en octets, rendues lisibles. Les paliers vont jusqu'au Go : sur un petit serveur, une
   * base qui passe de 400 Mo à 2 Go est exactement ce qu'on veut voir venir. */
  function formatBytes(n: number | null) {
    if (n === null) return "indisponible";
    if (n < 1024) return `${n} o`;
    const unites = ["Ko", "Mo", "Go", "To"];
    let valeur = n / 1024;
    let i = 0;
    while (valeur >= 1024 && i < unites.length - 1) {
      valeur /= 1024;
      i += 1;
    }
    return `${valeur.toFixed(valeur < 10 ? 1 : 0)} ${unites[i]}`;
  }

  function formatUptime(secondes: number) {
    const j = Math.floor(secondes / 86400);
    const h = Math.floor((secondes % 86400) / 3600);
    const m = Math.floor((secondes % 3600) / 60);
    if (j > 0) return `${j} j ${h} h`;
    if (h > 0) return `${h} h ${m} min`;
    return `${m} min`;
  }

  /** Panneau d'état du serveur.
   *
   * Construit autour du disque, parce que sur un serveur auto-hébergé c'est la panne la plus
   * probable : SQLite se comporte mal quand il ne peut plus écrire. Le reste répond à des
   * questions qu'on ne pourrait pas poser sans se connecter en SSH.
   *
   * Deux alertes seulement, sur les deux situations qui se dégradent en silence — le disque presque
   * plein, et la sauvegarde qui a cessé sans rien dire. Le reste est présenté sans couleur : un
   * écran où tout clignote n'apprend plus rien à personne. */
  function renderHealthPanel() {
    // `disabled:` explicite : un bouton grisé DOIT se voir, sinon on ne comprend pas pourquoi le
    // clic ne fait rien et on insiste.
    const actionButtonClass =
      "rounded-lg border border-neutral-300 px-2 py-1 font-medium text-neutral-600 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800";

    if (health === null) {
      return (
        <div className="mb-3 rounded-xl border border-neutral-200 bg-white p-3 text-xs text-neutral-500 dark:border-neutral-800 dark:bg-neutral-900">
          Chargement de l'état du serveur…
        </div>
      );
    }

    const { disk, database, activity, backup } = health;
    const utilise = disk.free_bytes !== null && disk.total_bytes !== null ? disk.total_bytes - disk.free_bytes : null;
    const pourcentUtilise = utilise !== null && disk.total_bytes ? Math.round((utilise / disk.total_bytes) * 100) : null;
    const disqueTendu = pourcentUtilise !== null && pourcentUtilise >= 85;
    // Le service de sauvegarde tourne toutes les 24 h : au-delà de 48 h, il a manqué un cycle.
    const sauvegardeMuette = backup.newest_age_hours === null || backup.newest_age_hours > 48;
    // Un dossier inaccessible n'est PAS une sauvegarde manquante : c'est un volume non monté, et
    // le conseil à donner est l'inverse (corriger la configuration, pas s'inquiéter des données).
    const dossierAbsent = !backup.directory_present;

    const ligne = (label: string, valeur: string) => (
      <div className="flex items-baseline justify-between gap-3 border-t border-neutral-100 py-1 dark:border-neutral-800">
        <span className="text-neutral-500">{label}</span>
        <span className="font-medium text-neutral-800 dark:text-neutral-200">{valeur}</span>
      </div>
    );

    return (
      <div className="mb-3 rounded-xl border border-neutral-200 bg-white p-3 text-xs dark:border-neutral-800 dark:bg-neutral-900">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <span className="font-medium text-neutral-700 dark:text-neutral-200">
            État du serveur · en marche depuis {formatUptime(health.uptime_seconds)} · mode {health.app_env}
          </span>
          <div className="flex gap-2">
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() => void handleTestEmail()}
              title="Envoie un email de test à ta propre adresse"
              className={actionButtonClass}
            >
              {busyAction === "email" ? "Envoi en cours…" : "Tester l'email"}
            </button>
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() => void handleExportAudit()}
              title="Télécharge le journal d'audit complet en CSV"
              className={actionButtonClass}
            >
              {busyAction === "export" ? "Export en cours…" : "Exporter le journal"}
            </button>
            <button
              type="button"
              onClick={() => void handleToggleHealth()}
              className="rounded-lg border border-neutral-300 px-2 py-1 font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              Actualiser
            </button>
            <button
              type="button"
              onClick={() => { setHealthOpen(false); setHealth(null); }}
              className="rounded-lg border border-neutral-300 px-2 py-1 font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              Fermer
            </button>
          </div>
        </div>

        {disqueTendu && (
          <p className="mb-2 rounded-lg border border-red-300 bg-red-50 px-2 py-1.5 font-medium text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-300">
            Le disque est occupé à {pourcentUtilise} %. En dessous de quelques centaines de Mo libres,
            la base refuse d'écrire et le coffre devient inaccessible en écriture. Purge d'anciennes
            sauvegardes, ou agrandis le volume.
          </p>
        )}

        {sauvegardeMuette && (
          <p className="mb-2 rounded-lg border border-amber-300 bg-amber-50 px-2 py-1.5 font-medium text-amber-800 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-300">
            {dossierAbsent
              ? "Le serveur ne voit pas le dossier des sauvegardes — il n'est probablement pas monté dans son conteneur. Tes sauvegardes existent peut-être très bien ; c'est cet écran qui ne peut pas les lire. Ajoute « ./backups:/app/backups:ro » aux volumes du service api, puis redéploie."
              : backup.newest_age_hours === null
                ? "Le dossier des sauvegardes est vide. Vérifie que le conteneur « backup » tourne — une base perdue sans sauvegarde ne se récupère pas."
                : `La dernière sauvegarde date de ${backup.newest_age_hours} h, alors qu'il s'en fait normalement une toutes les 24 h. Le service s'est peut-être arrêté sans prévenir.`}
          </p>
        )}

        <div className="grid gap-x-6 gap-y-1 sm:grid-cols-2">
          <div>
            <p className="mb-1 font-medium text-neutral-600 dark:text-neutral-300">Disque</p>
            {pourcentUtilise !== null && (
              <>
                <div className="mb-1 h-1.5 w-full overflow-hidden rounded-full bg-neutral-200 dark:bg-neutral-800">
                  <div
                    className={`h-full rounded-full ${disqueTendu ? "bg-red-500" : "bg-emerald-500"}`}
                    style={{ width: `${Math.min(pourcentUtilise, 100)}%` }}
                  />
                </div>
                {ligne("Libre", `${formatBytes(disk.free_bytes)} sur ${formatBytes(disk.total_bytes)}`)}
              </>
            )}
            {ligne("Base de données", formatBytes(disk.database_bytes))}
            {ligne("Journal d'écriture (WAL)", formatBytes(disk.wal_bytes))}
            {ligne("Pièces jointes", formatBytes(disk.attachments_bytes))}
            {ligne("Sauvegardes", `${formatBytes(disk.backups_bytes)} · ${backup.count} fichier${backup.count > 1 ? "s" : ""}`)}
            {ligne("Journaux", formatBytes(disk.logs_bytes))}
            {ligne("Mémoire du processus", formatBytes(health.memory_bytes))}
          </div>

          <div>
            <p className="mb-1 font-medium text-neutral-600 dark:text-neutral-300">Contenu et activité</p>
            {ligne("Comptes", String(database.users))}
            {ligne("Entrées de coffre", String(database.vault_entries))}
            {ligne("Dans la corbeille", String(database.deleted_entries))}
            {ligne("Entrées du journal", String(database.audit_logs))}
            {ligne("Adresses mémorisées", String(database.ip_history_rows))}
            {ligne("Sessions actives", String(activity.active_sessions))}
            {ligne("Appareils connectés en direct", String(activity.websocket_connections))}
            {ligne("Échecs de connexion (24 h)", String(activity.failed_logins_24h))}
            {ligne("Requêtes freinées (24 h)", String(activity.rate_limited_24h))}
          </div>
        </div>

        {database.reclaimable_bytes > 5 * 1024 * 1024 && (
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <p className="flex-1 text-neutral-400">
              {formatBytes(database.reclaimable_bytes)} sont alloués mais inutilisés dans la base :
              de la place libérée par des suppressions, que SQLite garde pour ses prochaines
              écritures. Compacter la rend au disque — inutile tant qu'il reste de la place.
            </p>
            <button
              type="button"
              disabled={busyAction !== null}
              onClick={() => void handleVacuum()}
              className={actionButtonClass}
            >
              {busyAction === "vacuum" ? "Compactage en cours…" : "Compacter la base"}
            </button>
          </div>
        )}
      </div>
    );
  }

  /** Panneau des adresses IP d'un compte.
   *
   * Lit account_ip_history, qui survit à la purge du journal : l'historique est COMPLET, pas
   * limité aux 10 derniers jours comme la première version de cet écran.
   *
   * L'ordre des colonnes suit ce qu'on cherche réellement. Une adresse nue ne dit rien ; ce qui
   * parle, c'est le couple échecs/réussites. Beaucoup d'échecs PUIS une réussite depuis la même
   * adresse est la signature d'une intrusion aboutie par tâtonnement — mis en évidence en rouge,
   * parce que c'est exactement le cas qu'on ne veut pas rater dans un tableau.
   *
   * "Autres comptes" est volontairement neutre et non alarmant : sur un serveur familial, tout le
   * monde partage l'IP publique de la maison, donc une adresse commune y est la NORME. Ce qui
   * compte est le croisement avec les échecs, pas le partage seul.
   *
   * Prévient enfin du piège du reverse proxy : sans TRUST_PROXY_HEADERS=true, le serveur
   * enregistre l'IP du proxy, identique pour tous, et la page afficherait une adresse privée
   * unique parfaitement inutile sans rien signaler. */
  function renderIpHistoryPanel() {
    // "YYYY-MM-DD HH:MM:SS" en UTC côté SQLite : rendu explicitement ISO+Z plutôt que de compter
    // sur la tolérance du moteur JS pour l'espace, qui n'est pas garantie par la spec.
    const parseUtc = (ts: string) => new Date(`${ts.replace(" ", "T")}Z`);
    // Doit rester aligné sur geoip.rs::is_private côté serveur : sinon une adresse que le serveur
    // considère sans lieu (donc jamais géolocalisée) se verrait proposer un bouton « Localiser »
    // ici, et pourrait déclencher l'alerte d'intrusion dont les adresses privées sont exclues.
    // 169.254.x (lien-local, attribué quand le DHCP échoue) manquait à cette liste.
    const isPrivate = (ip: string) =>
      /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0$|::1$|fc|fd|fe80:)/i.test(ip);

    // Le drapeau se dérive du code pays : chaque lettre A-Z correspond à un « indicateur régional »
    // Unicode, et deux d'entre eux accolés forment le drapeau. Aucune image à embarquer.
    const flagOf = (code: string | null) => {
      if (!code || code.length !== 2 || !/^[a-z]{2}$/i.test(code)) return "";
      return String.fromCodePoint(...[...code.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
    };

    const describeOrigin = (row: UserIpHistoryEntry) => {
      if (!row.location) return null;
      const { city, country_name, country_code } = row.location;
      const country = country_name ?? country_code;
      if (city && country) return `${city}, ${country}`;
      return city ?? country ?? null;
    };
    const rows = ipHistory?.entries ?? [];
    const looksLikeProxy = ipHistory !== null && rows.length === 1 && isPrivate(rows[0].ip_address);

    // CRITÈRE D'ALERTE — trois conditions, et il a fallu les trois.
    //
    // La première version signalait toute adresse ayant au moins un échec ET une réussite. Sur un
    // vrai compte, c'est le cas NORMAL : tout le monde se trompe de mot de passe de temps en
    // temps. Le premier écran réel affichait 93 réussites, 18 échecs... et une bannière rouge
    // d'intrusion. Une alerte qui se déclenche sur le cas courant, on apprend à l'ignorer — elle
    // est alors pire que pas d'alerte du tout, puisqu'elle masquerait la vraie.
    //
    // 1. Une adresse privée est écartée d'office : personne ne s'introduit depuis ton propre
    //    réseau local, et derrière un reverse proxy mal réglé TOUT le trafic y ressemble.
    // 2. Un plancher de 5 échecs : deux ou trois erreurs de frappe ne sont pas une attaque.
    // 3. Plus d'échecs que de réussites : c'est ce qui sépare un intrus qui tâtonne (beaucoup
    //    d'échecs, une réussite) du propriétaire du compte (beaucoup de réussites, quelques
    //    fautes de frappe). Un ratio, pas un compte absolu — sinon un compte utilisé depuis des
    //    années finirait fatalement par franchir n'importe quel seuil fixe.
    const MIN_ECHECS_SUSPECTS = 5;
    const isSuspicious = (row: UserIpHistoryEntry) =>
      !isPrivate(row.ip_address) &&
      row.failure_count >= MIN_ECHECS_SUSPECTS &&
      row.failure_count > row.success_count;
    // Deux situations très différentes derrière le même critère, à ne surtout pas confondre dans
    // le message : une adresse qui a fini par ENTRER (le compte est compromis, il faut agir tout
    // de suite), et une qui s'acharne SANS jamais réussir (le blocage fait son travail, c'est une
    // information, pas une urgence). Annoncer une intrusion qui n'a pas eu lieu serait une fausse
    // frayeur, et l'inverse une négligence.
    const intrusions = rows.filter((r) => isSuspicious(r) && r.success_count > 0);
    const tentatives = rows.filter((r) => isSuspicious(r) && r.success_count === 0);

    return (
      <div className="mb-3 rounded-xl border border-neutral-200 bg-white p-3 text-xs dark:border-neutral-800 dark:bg-neutral-900">
        <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
          <span className="font-medium text-neutral-700 dark:text-neutral-200">Adresses IP de {ipHistoryFor}</span>
          <button
            type="button"
            onClick={() => { setIpHistoryFor(null); setIpHistory(null); }}
            className="rounded-lg border border-neutral-300 px-2 py-1 font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            Fermer
          </button>
        </div>

        {ipHistory === null ? (
          <p className="text-neutral-500">Chargement…</p>
        ) : rows.length === 0 ? (
          <p className="text-neutral-500">Aucune activité enregistrée pour ce compte.</p>
        ) : (
          <>
            {looksLikeProxy && (
              <p className="mb-2 rounded-lg border border-amber-300 bg-amber-50 px-2 py-1.5 text-amber-800 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-300">
                Une seule adresse, et elle est privée : ton serveur enregistre probablement l'IP de
                son reverse proxy, pas celle des utilisateurs. Mets <code className="whitespace-nowrap">TRUST_PROXY_HEADERS=true</code>
                {" "}dans la configuration du backend pour voir les vraies adresses.
              </p>
            )}

            {intrusions.length > 0 && (
              <p className="mb-2 rounded-lg border border-red-300 bg-red-50 px-2 py-1.5 font-medium text-red-800 dark:border-red-800 dark:bg-red-950 dark:text-red-300">
                {intrusions.length === 1 ? "Une adresse a" : `${intrusions.length} adresses ont`} accumulé
                les échecs puis RÉUSSI à se connecter à ce compte. C'est le motif d'une intrusion
                aboutie par tâtonnement. Si tu ne {intrusions.length === 1 ? "reconnais pas cette adresse" : "reconnais pas ces adresses"},
                fais changer le mot de passe maître et révoque les sessions du compte.
              </p>
            )}

            {tentatives.length > 0 && (
              <p className="mb-2 rounded-lg border border-amber-300 bg-amber-50 px-2 py-1.5 text-amber-800 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-300">
                {tentatives.length === 1 ? "Une adresse a" : `${tentatives.length} adresses ont`} multiplié
                les échecs de connexion sans jamais y parvenir. Le compte n'a pas été compromis par
                {tentatives.length === 1 ? " cette adresse" : " ces adresses"} et le blocage a fait
                son travail — rien d'urgent, mais si cela se répète, un mot de passe maître plus
                long met le compte hors de portée.
              </p>
            )}

            <div className="overflow-x-auto">
              <table className="w-full text-left">
                <thead className="text-neutral-500">
                  <tr>
                    <th className="py-1 pr-3 font-medium">Adresse</th>
                    <th className="py-1 pr-3 font-medium">Connexions</th>
                    <th className="py-1 pr-3 font-medium">Échecs</th>
                    <th className="py-1 pr-3 font-medium">Première fois</th>
                    <th className="py-1 pr-3 font-medium">Dernière fois</th>
                    <th className="py-1 pr-3 font-medium">Autres comptes</th>
                    <th className="py-1 pr-3 font-medium">Origine</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((row) => (
                    <tr
                      key={row.ip_address}
                      className={`border-t border-neutral-100 dark:border-neutral-800 ${
                        !isSuspicious(row)
                          ? ""
                          : row.success_count > 0
                            ? "bg-red-50 dark:bg-red-950/40"
                            : "bg-amber-50 dark:bg-amber-950/40"
                      }`}
                    >
                      <td className="py-1 pr-3 font-mono text-neutral-700 dark:text-neutral-200">
                        {row.ip_address}
                        {isSuspicious(row) && (
                          <span
                            className={`ml-1 rounded px-1 py-0.5 text-[10px] font-medium ${
                              row.success_count > 0
                                ? "bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300"
                                : "bg-amber-100 text-amber-700 dark:bg-amber-900 dark:text-amber-300"
                            }`}
                          >
                            {row.success_count > 0
                              ? `${row.failure_count} échecs, puis entrée`
                              : `${row.failure_count} échecs, jamais entré`}
                          </span>
                        )}
                      </td>
                      <td className="py-1 pr-3 text-neutral-600 dark:text-neutral-400">{row.success_count}</td>
                      <td className={`py-1 pr-3 ${row.failure_count > 0 ? "font-medium text-amber-700 dark:text-amber-400" : "text-neutral-600 dark:text-neutral-400"}`}>
                        {row.failure_count}
                      </td>
                      <td className="whitespace-nowrap py-1 pr-3 text-neutral-600 dark:text-neutral-400">{parseUtc(row.first_seen).toLocaleString()}</td>
                      <td className="whitespace-nowrap py-1 pr-3 text-neutral-600 dark:text-neutral-400">{parseUtc(row.last_seen).toLocaleString()}</td>
                      <td className="py-1 pr-3 text-neutral-600 dark:text-neutral-400">
                        {row.other_accounts === 0 ? "—" : row.other_accounts}
                      </td>
                      <td className="whitespace-nowrap py-1 pr-3">
                        {isPrivate(row.ip_address) ? (
                          <span className="text-neutral-400">réseau local</span>
                        ) : describeOrigin(row) ? (
                          <span className="text-neutral-700 dark:text-neutral-200">
                            {flagOf(row.location?.country_code ?? null)} {describeOrigin(row)}
                          </span>
                        ) : (
                          <button
                            type="button"
                            onClick={() => void openUrl(`https://ipinfo.io/${encodeURIComponent(row.ip_address)}`)}
                            title="Ouvre un service tiers dans ton navigateur et lui transmet cette adresse"
                            className="text-neutral-500 underline hover:text-neutral-900 dark:text-neutral-400 dark:hover:text-neutral-200"
                          >
                            Localiser
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <p className="mt-2 text-neutral-400">
              {ipHistory.geoip_enabled
                ? "Les origines sont résolues par ton serveur contre une base locale : aucune adresse n'est envoyée à un service tiers. Une adresse privée n'a pas de lieu, c'est normal qu'elle reste sans origine."
                : "Aucune base de géolocalisation n'est installée sur ton serveur — voir GEOIP_DATABASE_PATH dans le README. En attendant, « Localiser » ouvre un service tiers dans ton navigateur et lui transmet l'adresse : ton serveur, lui, n'envoie jamais rien."}
              {" "}La localisation d'une IP reste une estimation : un VPN affiche le pays de son
              serveur, et une connexion mobile est souvent rattachée à une autre ville — elle
              change aussi d'adresse souvent, donc plusieurs adresses n'ont rien d'anormal en soi.
            </p>
          </>
        )}
      </div>
    );
  }

  /** Décrit l'inactivité d'un compte, ou rien s'il est actif.
   *
   * Trois états à ne pas confondre : jamais connecté (une adresse réservée mais jamais utilisée —
   * possiblement quelqu'un qui squatte l'adresse d'un autre), dormant depuis longtemps, et actif.
   * Le seuil est à 90 jours : en dessous, une absence est banale (vacances, appareil de secours).
   *
   * S'appuie sur `last_seen`, tiré de l'historique IP qui SURVIT à la purge du journal — sinon
   * tout compte inactif depuis plus de dix jours paraîtrait n'avoir jamais existé. */
  function describeDormancy(user: AdminUserView) {
    if (user.last_seen === null) return "jamais connecté";
    const jours = Math.floor((Date.now() - new Date(`${user.last_seen.replace(" ", "T")}Z`).getTime()) / 86400000);
    if (Number.isNaN(jours) || jours < 90) return null;
    return jours >= 365 ? `inactif depuis ${Math.floor(jours / 365)} an(s)` : `inactif depuis ${Math.floor(jours / 30)} mois`;
  }

  /** Badges "Admin"/"Modérateur"/"(toi)" — communs aux deux dispositions, même raisonnement que
   * renderUserActions ci-dessus. */
  function renderUserBadges(user: AdminUserView, isSelf: boolean) {
    return (
      <>
        {user.is_admin && (
          <span className="ml-2 rounded-full bg-indigo-100 px-2 py-0.5 text-xs text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300">Admin</span>
        )}
        {user.is_moderator && !user.is_admin && (
          <span className="ml-2 rounded-full bg-neutral-100 px-2 py-0.5 text-xs text-neutral-600 dark:bg-neutral-800 dark:text-neutral-300">Modérateur</span>
        )}
        {describeDormancy(user) && (
          <span className="ml-2 rounded-full bg-neutral-100 px-2 py-0.5 text-xs text-neutral-500 dark:bg-neutral-800 dark:text-neutral-400">
            {describeDormancy(user)}
          </span>
        )}
        {(user.max_vault_entries !== null || user.max_attachments !== null) && (
          <span className="ml-2 rounded-full bg-sky-100 px-2 py-0.5 text-xs text-sky-700 dark:bg-sky-950 dark:text-sky-300">
            quota
          </span>
        )}
        {user.is_suspended && (
          <span className="ml-2 rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-700 dark:bg-amber-950 dark:text-amber-400">
            Suspendu
          </span>
        )}
        {isSelf && <span className="ml-2 text-xs text-neutral-400">(toi)</span>}
      </>
    );
  }

  return (
    <div>
      {error && <p className="mb-3 text-sm text-red-600 dark:text-red-400">{error}</p>}

      {isAdmin && !healthOpen && (
        <button
          type="button"
          onClick={() => void handleToggleHealth()}
          className="mb-3 rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
        >
          État du serveur
        </button>
      )}

      {isAdmin && healthOpen && renderHealthPanel()}

      {ipHistoryFor && renderIpHistoryPanel()}

      {isAdmin && registrationOpen !== null && (
        <div className="mb-3 flex flex-wrap items-center gap-2 rounded-xl border border-neutral-200 bg-white px-3 py-2 text-xs dark:border-neutral-800 dark:bg-neutral-900">
          <span className="text-neutral-600 dark:text-neutral-400">Inscriptions sur ce serveur :</span>
          <span className={registrationOpen ? "font-medium text-amber-600 dark:text-amber-400" : "font-medium text-emerald-600 dark:text-emerald-400"}>
            {registrationOpen ? "ouvertes" : "fermées"}
          </span>
          <button
            type="button"
            onClick={() => void handleToggleRegistration()}
            className="rounded-lg border border-neutral-300 px-2 py-1 font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            {registrationOpen ? "Fermer" : "Ouvrir"}
          </button>
          <span className="basis-full text-neutral-400">
            {registrationOpen
              ? "N'importe qui connaissant l'adresse du serveur peut créer un compte. À fermer une fois tes comptes créés."
              : "Seul ton compte administrateur peut encore s'inscrire. Rouvre le temps d'ajouter quelqu'un."}
          </span>
        </div>
      )}

      {isAdmin && renderBulkFlagRow(
        "Changement d'email via l'extension, pour tout le monde :",
        (u) => u.can_change_email_via_extension,
        (enabled) => void handleSetExtensionEmailChangeForAll(enabled),
      )}

      {isAdmin && renderBulkFlagRow(
        "Choix du serveur dans les Réglages, pour tout le monde :",
        (u) => u.can_choose_server_in_settings,
        (enabled) => void handleSetServerChoiceInSettingsForAll(enabled),
      )}

      <p className="mb-3 text-xs text-neutral-500">
        Il n'existe qu'un seul <span className="font-medium text-indigo-700 dark:text-indigo-300">Admin</span> (le
        compte configuré via <code>ADMIN_EMAIL</code>) — lui seul peut gérer les rôles, et personne ne peut agir sur
        son compte. Les autres comptes promus sont des <span className="font-medium">Modérateurs</span> : ils peuvent
        gérer les comptes non-admin, mais pas les autres modérateurs.
      </p>

      {listLayout === "cards" ? (
        // CORRECTIF (retour utilisateur, 2026-09-02, plusieurs allers-retours) :
        // `repeat(auto-fit, minmax(260px, 1fr))` — voir lib/listLayout.ts::listContainerClass pour
        // l'historique complet. `1fr` : les cartes présentes sur une ligne comblent maintenant
        // TOUJOURS tout l'espace, comme le tableau juste en dessous en mode "list"/"compact" —
        // fonctionne SANS `@container`, plus besoin de ce wrapper pour "cards", contrairement à
        // avant.
        <div className="grid grid-cols-[repeat(auto-fit,minmax(260px,1fr))] gap-3">
          {users.map((user) => {
            const isSelf = user.email === myEmail;
            const isBusy = busyEmail === user.email;
            const canActOnTarget = isAdmin || !user.is_moderator;
            return (
              <div key={user.email} className="rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
                <p className="truncate text-neutral-800 dark:text-neutral-200">
                  {user.email}
                  {renderUserBadges(user, isSelf)}
                </p>
                <p className="mt-1 text-xs text-neutral-500">
                  Vérifié : {user.email_verified ? "Oui" : "Non"} · Créé le {new Date(user.created_at).toLocaleDateString()} · {formatUsage(user)}
                </p>
                <div className="mt-3">{renderUserActions(user, isSelf, isBusy, canActOnTarget)}</div>
              </div>
            );
          })}
        </div>
      ) : (
        // "compact" : mêmes lignes, juste un padding vertical réduit (py-1 au lieu de py-2) — pas
        // besoin d'une structure différente pour un tableau, contrairement à la grille de cartes
        // ci-dessus (retour utilisateur, 2026-09-02, "disposition des listes").
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-neutral-200 text-xs text-neutral-500 dark:border-neutral-800">
                <th className={`${listLayout === "compact" ? "py-1" : "py-2"} pr-3 font-medium`}>Compte</th>
                <th className={`${listLayout === "compact" ? "py-1" : "py-2"} pr-3 font-medium`}>Vérifié</th>
                <th className={`${listLayout === "compact" ? "py-1" : "py-2"} pr-3 font-medium`}>Créé le</th>
                <th className={`${listLayout === "compact" ? "py-1" : "py-2"} pr-3 font-medium`}>Espace</th>
                <th className={`${listLayout === "compact" ? "py-1" : "py-2"} pr-3 font-medium`}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => {
                const isSelf = user.email === myEmail;
                const isBusy = busyEmail === user.email;
                // Voir handlers/admin.rs::check_can_act_on_target() : un modérateur normal (pas
                // ADMIN_EMAIL) ne peut agir (déconnecter/supprimer/régler l'extension) que sur des
                // comptes non-modérateur — cible un autre modérateur (l'Admin y compris) reste
                // réservé à l'Admin.
                const canActOnTarget = isAdmin || !user.is_moderator;
                const cellPad = listLayout === "compact" ? "py-1" : "py-2";
                return (
                  <tr key={user.email} className="border-b border-neutral-100 dark:border-neutral-900">
                    <td className={`${cellPad} pr-3`}>
                      <span className="text-neutral-800 dark:text-neutral-200">{user.email}</span>
                      {renderUserBadges(user, isSelf)}
                    </td>
                    <td className={`${cellPad} pr-3 text-neutral-600 dark:text-neutral-400`}>{user.email_verified ? "Oui" : "Non"}</td>
                    <td className={`${cellPad} pr-3 text-neutral-600 dark:text-neutral-400`}>{new Date(user.created_at).toLocaleDateString()}</td>
                    <td className={`${cellPad} pr-3 text-neutral-600 dark:text-neutral-400`}>{formatUsage(user)}</td>
                    <td className={`${cellPad} pr-3`}>{renderUserActions(user, isSelf, isBusy, canActOnTarget)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function AuditSection() {
  const { authorizedRequest } = useAuth();
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        setLogs(await authorizedRequest((token) => api.getAuditLogs(token)));
      } catch (err) {
        setError(getErrorMessage(err));
      } finally {
        setIsLoading(false);
      }
    })();
  }, [authorizedRequest]);

  if (isLoading) return <p className="text-sm text-neutral-500">Chargement…</p>;
  if (error) return <p className="text-sm text-red-600 dark:text-red-400">{error}</p>;

  return (
    <div className="max-h-96 overflow-y-auto overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-neutral-200 text-xs text-neutral-500 dark:border-neutral-800">
            <th className="py-2 pr-3 font-medium">Date</th>
            <th className="py-2 pr-3 font-medium">Compte</th>
            <th className="py-2 pr-3 font-medium">Action</th>
            <th className="py-2 pr-3 font-medium">IP</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((log) => (
            <tr key={log.id} className="border-b border-neutral-100 dark:border-neutral-900">
              <td className="whitespace-nowrap py-2 pr-3 text-neutral-500">{new Date(log.created_at).toLocaleString()}</td>
              <td className="py-2 pr-3 text-neutral-800 dark:text-neutral-200">{log.user_email}</td>
              <td className="py-2 pr-3 font-mono text-xs text-neutral-600 dark:text-neutral-400">{log.action}</td>
              <td className="py-2 pr-3 text-neutral-500">{log.ip_address}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Signalements de bug envoyés depuis l'app desktop/Android (voir components/BugReportModal.tsx,
 * accessible même sans connexion) — pas de statut "résolu" séparé, supprimer un signalement EST
 * la façon de le marquer traité (voir handlers/bug_report.rs côté backend). */
function BugReportsSection() {
  const { authorizedRequest } = useAuth();
  const [reports, setReports] = useState<BugReportView[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      setReports(await authorizedRequest((token) => api.listBugReports(token)));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
  }, [authorizedRequest]);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleDelete(report: BugReportView) {
    // AVERTISSEMENT EXPLICITE si un email de contact est présent : cette route est PUBLIQUE (voir
    // POST /bug-reports, accessible sans compte) — n'importe qui a pu y mettre N'IMPORTE QUELLE
    // adresse, pas forcément la sienne. Marquer "traité" envoie un email à CETTE adresse (voir
    // mailer::send_bug_report_resolved côté serveur) — sans cet avertissement, il serait facile de
    // cliquer sans réaliser qu'un tiers potentiellement non consentant en reçoit un.
    const warning = report.reporter_email
      ? `Marquer ce signalement comme traité ? Un email sera envoyé à "${report.reporter_email}" — cette adresse n'a jamais été vérifiée (le formulaire est accessible sans compte), assure-toi qu'elle a un sens avant de continuer.`
      : "Marquer ce signalement comme traité (le supprimer de la liste) ?";
    if (!confirm(warning)) return;
    const id = report.id;
    setBusyId(id);
    setError(null);
    try {
      await authorizedRequest((token) => api.deleteBugReport(token, id));
      setReports((prev) => prev.filter((r) => r.id !== id));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  if (isLoading) return <p className="text-sm text-neutral-500">Chargement…</p>;
  if (error) return <p className="text-sm text-red-600 dark:text-red-400">{error}</p>;
  if (reports.length === 0) return <p className="text-sm text-neutral-500">Aucun signalement en attente.</p>;

  return (
    <ul className="flex max-h-96 flex-col gap-2 overflow-y-auto">
      {reports.map((report) => (
        <li key={report.id} className="rounded-lg border border-neutral-200 p-3 dark:border-neutral-800">
          <div className="mb-1 flex items-center justify-between gap-2">
            <span className="text-xs text-neutral-500">
              <span className="mr-1.5 rounded-full bg-neutral-100 px-2 py-0.5 font-medium text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300">
                {report.category}
              </span>
              {new Date(report.created_at).toLocaleString()} · {report.platform} · v{report.app_version}
              {report.reporter_email && <> · {report.reporter_email}</>}
            </span>
            <button
              type="button"
              disabled={busyId === report.id}
              onClick={() => void handleDelete(report)}
              className="shrink-0 rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              Marquer traité
            </button>
          </div>
          <p className="whitespace-pre-wrap text-sm text-neutral-800 dark:text-neutral-200">{report.description}</p>
        </li>
      ))}
    </ul>
  );
}

/** Suggestions de fonctionnalité envoyées depuis l'app desktop (voir
 * components/FeatureSuggestionModal.tsx, accessible aux comptes connectés uniquement) — même
 * fonctionnement que BugReportsSection ci-dessus : pas de statut "examinée" séparé, supprimer une
 * suggestion EST la façon de la marquer traitée (voir handlers/feature_suggestion.rs côté
 * backend), ce qui prévient TOUJOURS l'auteur par email (contrairement aux signalements de bug, où
 * l'email de contact est facultatif — author_email ici est toujours un compte réel authentifié). */
function FeatureSuggestionsSection() {
  const { authorizedRequest } = useAuth();
  const [suggestions, setSuggestions] = useState<FeatureSuggestionView[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      setSuggestions(await authorizedRequest((token) => api.listFeatureSuggestions(token)));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
  }, [authorizedRequest]);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleDelete(suggestion: FeatureSuggestionView) {
    if (!confirm(`Marquer cette suggestion comme examinée ? Un email sera envoyé à "${suggestion.author_email}".`)) return;
    const id = suggestion.id;
    setBusyId(id);
    setError(null);
    try {
      await authorizedRequest((token) => api.deleteFeatureSuggestion(token, id));
      setSuggestions((prev) => prev.filter((s) => s.id !== id));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  if (isLoading) return <p className="text-sm text-neutral-500">Chargement…</p>;

  // CORRECTIF (repéré en relecture) : un `if (error) return ...` ici, comme dans
  // BugReportsSection ci-dessus, ferait DISPARAÎTRE toute la liste dès qu'une seule suppression
  // échoue (ex: coupure réseau) — jusqu'à la prochaine action réussie, plus aucune suggestion
  // n'est visible/actionnable, alors qu'elles sont toujours bien là. L'erreur s'affiche maintenant
  // EN PLUS de la liste, jamais à sa place.
  return (
    <>
      {error && <p className="mb-2 text-sm text-red-600 dark:text-red-400">{error}</p>}
      {suggestions.length === 0 ? (
        <p className="text-sm text-neutral-500">Aucune suggestion en attente.</p>
      ) : (
        <ul className="flex max-h-96 flex-col gap-2 overflow-y-auto">
          {suggestions.map((suggestion) => (
            <li key={suggestion.id} className="rounded-lg border border-neutral-200 p-3 dark:border-neutral-800">
              <div className="mb-1 flex items-center justify-between gap-2">
                <span className="text-xs text-neutral-500">
                  {new Date(suggestion.created_at).toLocaleString()} · {suggestion.author_email}
                </span>
                <button
                  type="button"
                  disabled={busyId === suggestion.id}
                  onClick={() => void handleDelete(suggestion)}
                  className="shrink-0 rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                >
                  Marquer examinée
                </button>
              </div>
              <p className="whitespace-pre-wrap text-sm text-neutral-800 dark:text-neutral-200">{suggestion.description}</p>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

/** Réglage GLOBAL (pas par compte, voir handlers/admin.rs::update_server_choice_at_login() côté
 * backend) : visibilité du lien "Configurer le serveur" sur l'écran de connexion, AVANT toute
 * authentification. Lu via GET /public-config (sans auth, même endpoint que pages/Login.tsx) —
 * réutilisé ici tel quel plutôt que d'ajouter un endpoint GET admin dédié rien que pour ça. */
function ServerChoiceAtLoginSection() {
  const { authorizedRequest } = useAuth();
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isBusy, setIsBusy] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      const config = await api.getPublicConfig();
      setEnabled(config.server_choice_at_login_enabled);
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleToggle() {
    if (enabled === null) return;
    setIsBusy(true);
    setError(null);
    try {
      await authorizedRequest((token) => api.updateServerChoiceAtLogin(token, { enabled: !enabled }));
      await load();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsBusy(false);
    }
  }

  return (
    <div>
      <p className="mb-3 text-xs text-neutral-500">
        Contrôle si le lien "Configurer le serveur" est visible sur l'écran de connexion, AVANT
        toute authentification — réglage global (pas par compte), puisqu'aucun compte n'est encore
        identifié à ce stade.
      </p>
      {error && <p className="mb-3 text-sm text-red-600 dark:text-red-400">{error}</p>}
      {enabled === null ? (
        <p className="text-sm text-neutral-500">Chargement…</p>
      ) : (
        <button
          type="button"
          disabled={isBusy}
          onClick={() => void handleToggle()}
          className="rounded-lg border border-neutral-300 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-60 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
        >
          {enabled ? "Désactiver le lien à la connexion" : "Activer le lien à la connexion"}
        </button>
      )}
    </div>
  );
}

export default function Admin() {
  // isAdmin : vrai UNIQUEMENT pour le compte ADMIN_EMAIL (voir la note en tête de UsersSection) —
  // les signalements de bug sont réservés au SEUL Admin, PAS aux modérateurs (demande explicite),
  // contrairement au reste de cet écran. Masqué ici en plus de la garde côté serveur (déjà
  // suffisante à elle seule) : un modérateur ne doit même pas voir la section exister.
  const { isAdmin } = useAuth();

  return (
    <main className="min-h-screen bg-neutral-50 px-4 py-8 dark:bg-neutral-950">
      {/* Largeur progressive tablette/desktop — voir le commentaire équivalent dans Vault.tsx.
       * Déjà max-w-3xl en base (le tableau des comptes a besoin de plus de place qu'un formulaire
       * simple) — même logique, juste décalée d'un cran. */}
      <div className="mx-auto flex max-w-3xl flex-col gap-4 lg:max-w-5xl xl:max-w-6xl 2xl:max-w-[100rem]">
        {/* Plus de lien "← Retour au coffre" ici (retour utilisateur, 2026-09-02) : redondant
         * maintenant que la navigation vit dans components/AppShell.tsx. */}
        <header className="mb-2">
          <h1 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">Administration</h1>
        </header>

        <Section title="Comptes utilisateurs">
          <UsersSection />
        </Section>

        <Section title="Journal d'audit (100 dernières entrées, tous comptes)">
          <AuditSection />
        </Section>

        {isAdmin && (
          <Section title="Signalements de bug (desktop/Android) — visible par toi seul">
            <BugReportsSection />
          </Section>
        )}

        {isAdmin && (
          <Section title="Suggestions de fonctionnalité (desktop) — visible par toi seul">
            <FeatureSuggestionsSection />
          </Section>
        )}

        {/* L'override de CET appareil (isAdmin && ...) vit désormais dans pages/Settings.tsx —
            visible pour toi comme pour n'importe quel compte à qui tu as accordé l'accès
            (ci-dessus, dans "Comptes utilisateurs"). Ici : le réglage GLOBAL équivalent côté écran
            de connexion (Admin SEUL, voir handlers/admin.rs::update_server_choice_at_login()). */}
        {isAdmin && (
          <Section title="Choix du serveur à la connexion — visible par toi seul">
            <ServerChoiceAtLoginSection />
          </Section>
        )}
      </div>
    </main>
  );
}
