import { useEffect, useState, useCallback } from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../state/AuthContext";
import * as api from "../api/client";
import { getErrorMessage } from "../lib/errors";
import type { AdminUserView, AuditLog } from "../api/types";
import ServerUrlForm from "../components/ServerUrlForm";

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

      <p className="mb-3 text-xs text-neutral-500">
        Il n'existe qu'un seul <span className="font-medium text-indigo-700 dark:text-indigo-300">Admin</span> (le
        compte configuré via <code>ADMIN_EMAIL</code>) — lui seul peut gérer les rôles, et personne ne peut agir sur
        son compte. Les autres comptes promus sont des <span className="font-medium">Modérateurs</span> : ils peuvent
        gérer les comptes non-admin, mais pas les autres modérateurs.
      </p>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-neutral-200 text-xs text-neutral-500 dark:border-neutral-800">
              <th className="py-2 pr-3 font-medium">Compte</th>
              <th className="py-2 pr-3 font-medium">Vérifié</th>
              <th className="py-2 pr-3 font-medium">Créé le</th>
              <th className="py-2 pr-3 font-medium">Actions</th>
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
              return (
                <tr key={user.email} className="border-b border-neutral-100 dark:border-neutral-900">
                  <td className="py-2 pr-3">
                    <span className="text-neutral-800 dark:text-neutral-200">{user.email}</span>
                    {user.is_admin && (
                      <span className="ml-2 rounded-full bg-indigo-100 px-2 py-0.5 text-xs text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300">
                        Admin
                      </span>
                    )}
                    {user.is_moderator && !user.is_admin && (
                      <span className="ml-2 rounded-full bg-neutral-100 px-2 py-0.5 text-xs text-neutral-600 dark:bg-neutral-800 dark:text-neutral-300">
                        Modérateur
                      </span>
                    )}
                    {isSelf && <span className="ml-2 text-xs text-neutral-400">(toi)</span>}
                  </td>
                  <td className="py-2 pr-3 text-neutral-600 dark:text-neutral-400">{user.email_verified ? "Oui" : "Non"}</td>
                  <td className="py-2 pr-3 text-neutral-600 dark:text-neutral-400">{new Date(user.created_at).toLocaleDateString()}</td>
                  <td className="py-2 pr-3">
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
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
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

export default function Admin() {
  return (
    <main className="min-h-screen bg-neutral-50 px-4 py-8 dark:bg-neutral-950">
      <div className="mx-auto flex max-w-3xl flex-col gap-4">
        <header className="mb-2 flex items-center justify-between">
          <h1 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">Administration</h1>
          <Link to="/vault" className="text-sm text-indigo-600 hover:underline dark:text-indigo-400">
            ← Retour au coffre
          </Link>
        </header>

        <Section title="Comptes utilisateurs">
          <UsersSection />
        </Section>

        <Section title="Journal d'audit (100 dernières entrées, tous comptes)">
          <AuditSection />
        </Section>

        <Section title="Serveur (cet appareil uniquement)">
          <ServerUrlForm />
        </Section>
      </div>
    </main>
  );
}
