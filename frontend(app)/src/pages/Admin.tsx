import { useEffect, useState, useCallback } from "react";
import { useAuth } from "../state/AuthContext";
import * as api from "../api/client";
import { getErrorMessage } from "../lib/errors";
import { getEffectiveListLayout } from "../lib/listLayout";
import type { AdminUserView, AuditLog, BugReportView, FeatureSuggestionView } from "../api/types";

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
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyEmail, setBusyEmail] = useState<string | null>(null);
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
        {isSelf && <span className="ml-2 text-xs text-neutral-400">(toi)</span>}
      </>
    );
  }

  return (
    <div>
      {error && <p className="mb-3 text-sm text-red-600 dark:text-red-400">{error}</p>}

      {isAdmin && (
        <div className="mb-3 flex items-center gap-2 text-xs text-neutral-500">
          <span>Changement d'email via l'extension, pour tout le monde :</span>
          <button
            type="button"
            onClick={() => void handleSetExtensionEmailChangeForAll(true)}
            className="rounded-lg border border-neutral-300 px-2 py-1 font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            Activer pour tous
          </button>
          <button
            type="button"
            onClick={() => void handleSetExtensionEmailChangeForAll(false)}
            className="rounded-lg border border-neutral-300 px-2 py-1 font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            Désactiver pour tous
          </button>
        </div>
      )}

      {isAdmin && (
        <div className="mb-3 flex items-center gap-2 text-xs text-neutral-500">
          <span>Choix du serveur dans les Réglages, pour tout le monde :</span>
          <button
            type="button"
            onClick={() => void handleSetServerChoiceInSettingsForAll(true)}
            className="rounded-lg border border-neutral-300 px-2 py-1 font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            Activer pour tous
          </button>
          <button
            type="button"
            onClick={() => void handleSetServerChoiceInSettingsForAll(false)}
            className="rounded-lg border border-neutral-300 px-2 py-1 font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            Désactiver pour tous
          </button>
        </div>
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
                  Vérifié : {user.email_verified ? "Oui" : "Non"} · Créé le {new Date(user.created_at).toLocaleDateString()}
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
