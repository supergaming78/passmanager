import { useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../state/AuthContext";
import * as api from "../api/client";
import { ensureEmergencyKeys, seedContactKey } from "../lib/emergencyAccess";
import { getErrorMessage } from "../lib/errors";
import type { EmergencyContact } from "../api/types";

const WAITING_PERIOD_OPTIONS = [
  { value: 0, label: "Immédiat (0 jour)" },
  { value: 1, label: "1 jour" },
  { value: 3, label: "3 jours" },
  { value: 7, label: "7 jours" },
  { value: 30, label: "30 jours" },
];

const STATUS_LABELS: Record<EmergencyContact["status"], string> = {
  pending: "Invitation en attente",
  active: "Actif",
  access_requested: "Accès demandé",
  access_granted: "Accès accordé",
};

function StatusBadge({ status }: { status: EmergencyContact["status"] }) {
  const colors: Record<EmergencyContact["status"], string> = {
    pending: "bg-neutral-100 text-neutral-600 dark:bg-neutral-800 dark:text-neutral-400",
    active: "bg-emerald-100 text-emerald-700 dark:bg-emerald-950 dark:text-emerald-400",
    access_requested: "bg-amber-100 text-amber-700 dark:bg-amber-950 dark:text-amber-400",
    access_granted: "bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-400",
  };
  return <span className={`shrink-0 rounded-full px-2 py-0.5 text-[11px] font-medium ${colors[status]}`}>{STATUS_LABELS[status]}</span>;
}

/** Réglages de l'accès d'urgence (voir docs/API.md#endpoints--accès-durgence pour la machine à
 * états complète) — deux listes symétriques : les contacts que CET utilisateur a désignés
 * ("Mes contacts de confiance"), et les comptes où il a lui-même été désigné comme contact
 * ("Comptes où je suis contact"). Zero-Knowledge de bout en bout, voir lib/emergencyAccess.ts. */
export default function EmergencyAccessSettings() {
  const { authorizedRequest } = useAuth();
  const navigate = useNavigate();

  const [ownedContacts, setOwnedContacts] = useState<EmergencyContact[]>([]);
  const [grantedContacts, setGrantedContacts] = useState<EmergencyContact[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const [newContactEmail, setNewContactEmail] = useState("");
  const [newWaitingPeriod, setNewWaitingPeriod] = useState(7);
  const [isAdding, setIsAdding] = useState(false);

  async function loadAll() {
    setIsLoading(true);
    setError(null);
    try {
      const [owned, granted] = await Promise.all([
        authorizedRequest((token) => api.listEmergencyContactsAsOwner(token)),
        authorizedRequest((token) => api.listEmergencyGrantedToMe(token)),
      ]);
      setOwnedContacts(owned);
      setGrantedContacts(granted);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    void loadAll();
    // eslint pas configuré dans ce projet ; authorizedRequest est stable (voir AuthContext.tsx).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleAddContact(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setIsAdding(true);
    try {
      await authorizedRequest((token) => api.addEmergencyContact(token, { contact_email: newContactEmail, waiting_period_days: newWaitingPeriod }));
      setNewContactEmail("");
      await loadAll();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsAdding(false);
    }
  }

  async function handleSeed(contact: EmergencyContact) {
    setError(null);
    setBusyId(contact.id);
    try {
      await seedContactKey(authorizedRequest, contact.id, contact.contact_email);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  async function handleRevoke(id: string) {
    if (!confirm("Révoquer définitivement cette relation d'accès d'urgence ?")) return;
    setError(null);
    setBusyId(id);
    try {
      await authorizedRequest((token) => api.revokeEmergencyContact(token, id));
      await loadAll();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  async function handleApprove(id: string) {
    setError(null);
    setBusyId(id);
    try {
      await authorizedRequest((token) => api.approveEmergencyAccess(token, id));
      await loadAll();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  async function handleReject(id: string) {
    setError(null);
    setBusyId(id);
    try {
      await authorizedRequest((token) => api.rejectEmergencyAccess(token, id));
      await loadAll();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  async function handleAccept(id: string) {
    setError(null);
    setBusyId(id);
    try {
      // Génère ses propres clés d'accès d'urgence si ce n'est pas déjà fait — c'est ce qui
      // permettra plus tard de desceller la clé de coffre du propriétaire une fois l'accès
      // accordé (voir lib/emergencyAccess.ts::ensureEmergencyKeys).
      await ensureEmergencyKeys(authorizedRequest);
      await authorizedRequest((token) => api.acceptEmergencyContact(token, id));
      await loadAll();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  async function handleDecline(id: string) {
    setError(null);
    setBusyId(id);
    try {
      await authorizedRequest((token) => api.declineEmergencyContact(token, id));
      await loadAll();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  async function handleRequestAccess(id: string) {
    setError(null);
    setBusyId(id);
    try {
      await authorizedRequest((token) => api.requestEmergencyAccess(token, id));
      await loadAll();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  function handleViewVault(id: string) {
    // Le travail réel (récupération + descellement + déchiffrement) se fait dans
    // EmergencyVaultPage.tsx une fois arrivé sur cette route.
    navigate(`/emergency/${encodeURIComponent(id)}`);
  }

  if (isLoading) return <p className="text-sm text-neutral-500">Chargement…</p>;

  return (
    <div className="flex flex-col gap-5">
      {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}

      <div>
        <h3 className="mb-2 text-sm font-semibold text-neutral-800 dark:text-neutral-200">Mes contacts de confiance</h3>
        {ownedContacts.length === 0 ? (
          <p className="text-sm text-neutral-500">Aucun contact désigné pour l'instant.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {ownedContacts.map((c) => (
              <li key={c.id} className="rounded-lg border border-neutral-200 p-3 dark:border-neutral-800">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="min-w-0">
                    <p className="truncate text-sm text-neutral-800 dark:text-neutral-200">{c.contact_email}</p>
                    <p className="text-xs text-neutral-500">Délai d'attente : {c.waiting_period_days} jour(s)</p>
                  </div>
                  <StatusBadge status={c.status} />
                </div>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {c.status !== "pending" && (
                    <button
                      type="button"
                      onClick={() => void handleSeed(c)}
                      disabled={busyId === c.id}
                      className="rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                    >
                      Sceller la clé
                    </button>
                  )}
                  {c.status === "access_requested" && (
                    <>
                      <button
                        type="button"
                        onClick={() => void handleApprove(c.id)}
                        disabled={busyId === c.id}
                        className="rounded-lg border border-indigo-300 px-2 py-1 text-xs font-medium text-indigo-700 hover:bg-indigo-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-indigo-800 dark:text-indigo-300 dark:hover:bg-indigo-950"
                      >
                        Approuver maintenant
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleReject(c.id)}
                        disabled={busyId === c.id}
                        className="rounded-lg border border-red-300 px-2 py-1 text-xs font-medium text-red-600 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-900 dark:text-red-400 dark:hover:bg-red-950"
                      >
                        Refuser
                      </button>
                    </>
                  )}
                  <button
                    type="button"
                    onClick={() => void handleRevoke(c.id)}
                    disabled={busyId === c.id}
                    className="rounded-lg border border-red-300 px-2 py-1 text-xs font-medium text-red-600 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-900 dark:text-red-400 dark:hover:bg-red-950"
                  >
                    Révoquer
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}

        <form onSubmit={handleAddContact} className="mt-3 flex flex-wrap items-end gap-2">
          <div className="min-w-[160px] flex-1">
            <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">Email du contact</label>
            <input
              type="email"
              required
              value={newContactEmail}
              onChange={(e) => setNewContactEmail(e.target.value)}
              placeholder="quelqu'un@example.com"
              className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">Délai d'attente</label>
            <select
              value={newWaitingPeriod}
              onChange={(e) => setNewWaitingPeriod(Number(e.target.value))}
              className="rounded-lg border border-neutral-300 px-2 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
            >
              {WAITING_PERIOD_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>
          <button
            type="submit"
            disabled={isAdding}
            className="rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isAdding ? "…" : "Désigner"}
          </button>
        </form>
        <p className="mt-1 text-xs text-neutral-500">
          Après avoir été désigné, ce contact doit accepter l'invitation. Pense ensuite à cliquer
          "Sceller la clé" pour que sa demande d'accès future puisse aboutir.
        </p>
      </div>

      <div>
        <h3 className="mb-2 text-sm font-semibold text-neutral-800 dark:text-neutral-200">Comptes où je suis contact</h3>
        {grantedContacts.length === 0 ? (
          <p className="text-sm text-neutral-500">Aucun compte ne vous a désigné comme contact de confiance.</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {grantedContacts.map((c) => (
              <li key={c.id} className="rounded-lg border border-neutral-200 p-3 dark:border-neutral-800">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="min-w-0">
                    <p className="truncate text-sm text-neutral-800 dark:text-neutral-200">{c.owner_email}</p>
                    <p className="text-xs text-neutral-500">Délai d'attente : {c.waiting_period_days} jour(s)</p>
                  </div>
                  <StatusBadge status={c.status} />
                </div>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {c.status === "pending" && (
                    <>
                      <button
                        type="button"
                        onClick={() => void handleAccept(c.id)}
                        disabled={busyId === c.id}
                        className="rounded-lg border border-indigo-300 px-2 py-1 text-xs font-medium text-indigo-700 hover:bg-indigo-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-indigo-800 dark:text-indigo-300 dark:hover:bg-indigo-950"
                      >
                        Accepter
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleDecline(c.id)}
                        disabled={busyId === c.id}
                        className="rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                      >
                        Refuser
                      </button>
                    </>
                  )}
                  {c.status === "active" && (
                    <button
                      type="button"
                      onClick={() => void handleRequestAccess(c.id)}
                      disabled={busyId === c.id}
                      className="rounded-lg border border-amber-300 px-2 py-1 text-xs font-medium text-amber-700 hover:bg-amber-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-amber-900 dark:text-amber-400 dark:hover:bg-amber-950"
                    >
                      Demander l'accès d'urgence
                    </button>
                  )}
                  {c.status === "access_requested" && c.available_at && (
                    <p className="text-xs text-amber-600 dark:text-amber-400">
                      Accès accordé automatiquement le {new Date(c.available_at).toLocaleString()} sauf refus du propriétaire.
                    </p>
                  )}
                  {c.status === "access_granted" && (
                    <button
                      type="button"
                      onClick={() => handleViewVault(c.id)}
                      disabled={busyId === c.id}
                      className="rounded-lg bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      Consulter le coffre
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => void handleRevoke(c.id)}
                    disabled={busyId === c.id}
                    className="rounded-lg border border-red-300 px-2 py-1 text-xs font-medium text-red-600 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-900 dark:text-red-400 dark:hover:bg-red-950"
                  >
                    Me retirer
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
