// Accès d'urgence — port réduit de frontend(app)/src/components/EmergencyAccessSettings.tsx :
// deux listes symétriques ("mes contacts de confiance" / "comptes où je suis contact") avec les
// mêmes actions conditionnelles par statut.

import { useEffect, useState } from "react";
import * as api from "../api/client";
import * as session from "../lib/session";
import * as emergencyAccess from "../lib/emergencyAccess";
import type { EmergencyContact } from "../api/types";
import { getErrorMessage } from "../lib/errors";

const WAITING_PERIOD_OPTIONS = [0, 1, 3, 7, 30];

function StatusBadge({ status }: { status: EmergencyContact["status"] }) {
  const labels: Record<EmergencyContact["status"], string> = {
    pending: "En attente",
    active: "Actif",
    access_requested: "Accès demandé",
    access_granted: "Accès accordé",
  };
  return (
    <span className="rounded-full bg-neutral-100 px-2 py-0.5 text-[11px] text-neutral-600 dark:bg-neutral-800 dark:text-neutral-300">
      {labels[status]}
    </span>
  );
}

export default function EmergencyAccessView({
  vaultKey,
  onBack,
  onViewVault,
}: {
  vaultKey: Uint8Array;
  onBack: () => void;
  onViewVault: (contactId: string, ownerEmail: string) => void;
}) {
  const [owned, setOwned] = useState<EmergencyContact[] | null>(null);
  const [granted, setGranted] = useState<EmergencyContact[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [newEmail, setNewEmail] = useState("");
  const [waitingDays, setWaitingDays] = useState(3);

  async function load() {
    try {
      const [ownedList, grantedList] = await Promise.all([
        session.authorizedRequest((token) => api.listEmergencyContactsAsOwner(token)),
        session.authorizedRequest((token) => api.listEmergencyGrantedToMe(token)),
      ]);
      setOwned(ownedList);
      setGranted(grantedList);
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  useEffect(() => {
    void load();
  }, []);

  async function withBusy(id: string, fn: () => Promise<void>) {
    setBusyId(id);
    setError(null);
    try {
      await fn();
      await load();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  async function handleAddContact(e: React.FormEvent) {
    e.preventDefault();
    await withBusy("__add__", () =>
      session.authorizedRequest((token) => api.addEmergencyContact(token, { contact_email: newEmail, waiting_period_days: waitingDays })).then(() => {
        setNewEmail("");
      }),
    );
  }

  return (
    <div className="flex flex-col">
      <div className="flex items-center gap-2 border-b border-neutral-200 px-4 py-3 dark:border-neutral-800">
        <button onClick={onBack} className="text-sm text-neutral-500 hover:underline">
          ← Retour
        </button>
        <h1 className="text-sm font-medium text-neutral-900 dark:text-neutral-100">Accès d'urgence</h1>
      </div>

      {error && <p className="px-4 pt-2 text-sm text-red-600 dark:text-red-400">{error}</p>}

      <div className="px-4 py-3">
        <h2 className="mb-2 text-sm font-medium text-neutral-900 dark:text-neutral-100">Mes contacts de confiance</h2>
        {owned === null && <p className="text-sm text-neutral-500">Chargement…</p>}
        {owned !== null && owned.length === 0 && <p className="text-sm text-neutral-500">Aucun contact configuré.</p>}
        <ul className="flex flex-col gap-2">
          {(owned ?? []).map((c) => (
            <li key={c.id} className="rounded-lg border border-neutral-200 p-2 dark:border-neutral-800">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate text-sm text-neutral-900 dark:text-neutral-100">{c.contact_email}</span>
                <StatusBadge status={c.status} />
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                {c.status !== "pending" && (
                  <button
                    disabled={busyId === c.id}
                    onClick={() => void withBusy(c.id, () => emergencyAccess.seedContactKey(vaultKey, c.id, c.contact_email, session.authorizedRequest))}
                    className="rounded-md border border-neutral-300 px-2 py-1 text-xs text-neutral-600 dark:border-neutral-700 dark:text-neutral-300"
                  >
                    Sceller la clé
                  </button>
                )}
                {c.status === "access_requested" && (
                  <>
                    <button
                      disabled={busyId === c.id}
                      onClick={() => void withBusy(c.id, () => session.authorizedRequest((token) => api.approveEmergencyAccess(token, c.id)))}
                      className="rounded-md bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-700"
                    >
                      Approuver
                    </button>
                    <button
                      disabled={busyId === c.id}
                      onClick={() => void withBusy(c.id, () => session.authorizedRequest((token) => api.rejectEmergencyAccess(token, c.id)))}
                      className="rounded-md border border-neutral-300 px-2 py-1 text-xs text-neutral-600 dark:border-neutral-700 dark:text-neutral-300"
                    >
                      Refuser
                    </button>
                  </>
                )}
                <button
                  disabled={busyId === c.id}
                  onClick={() => void withBusy(c.id, () => session.authorizedRequest((token) => api.revokeEmergencyContact(token, c.id)))}
                  className="rounded-md border border-red-300 px-2 py-1 text-xs text-red-600 hover:bg-red-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
                >
                  Révoquer
                </button>
              </div>
            </li>
          ))}
        </ul>

        <form onSubmit={handleAddContact} className="mt-3 flex flex-col gap-2">
          <input
            type="email"
            required
            value={newEmail}
            onChange={(e) => setNewEmail(e.target.value)}
            placeholder="contact@example.com"
            className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
          />
          <div className="flex gap-2">
            <select
              value={waitingDays}
              onChange={(e) => setWaitingDays(Number(e.target.value))}
              className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
            >
              {WAITING_PERIOD_OPTIONS.map((d) => (
                <option key={d} value={d}>
                  {d === 0 ? "Immédiat" : `${d} jour${d > 1 ? "s" : ""} d'attente`}
                </option>
              ))}
            </select>
            <button
              type="submit"
              disabled={busyId === "__add__"}
              className="shrink-0 rounded-lg bg-indigo-600 px-3 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-60"
            >
              Ajouter
            </button>
          </div>
        </form>
      </div>

      <div className="border-t border-neutral-200 px-4 py-3 dark:border-neutral-800">
        <h2 className="mb-2 text-sm font-medium text-neutral-900 dark:text-neutral-100">Comptes où je suis contact</h2>
        {granted === null && <p className="text-sm text-neutral-500">Chargement…</p>}
        {granted !== null && granted.length === 0 && <p className="text-sm text-neutral-500">Aucun.</p>}
        <ul className="flex flex-col gap-2">
          {(granted ?? []).map((c) => (
            <li key={c.id} className="rounded-lg border border-neutral-200 p-2 dark:border-neutral-800">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate text-sm text-neutral-900 dark:text-neutral-100">{c.owner_email}</span>
                <StatusBadge status={c.status} />
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                {c.status === "pending" && (
                  <>
                    <button
                      disabled={busyId === c.id}
                      onClick={() =>
                        void withBusy(c.id, async () => {
                          await emergencyAccess.ensureEmergencyKeys(vaultKey, session.authorizedRequest);
                          await session.authorizedRequest((token) => api.acceptEmergencyContact(token, c.id));
                        })
                      }
                      className="rounded-md bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-700"
                    >
                      Accepter
                    </button>
                    <button
                      disabled={busyId === c.id}
                      onClick={() => void withBusy(c.id, () => session.authorizedRequest((token) => api.declineEmergencyContact(token, c.id)))}
                      className="rounded-md border border-neutral-300 px-2 py-1 text-xs text-neutral-600 dark:border-neutral-700 dark:text-neutral-300"
                    >
                      Refuser
                    </button>
                  </>
                )}
                {c.status === "active" && (
                  <button
                    disabled={busyId === c.id}
                    onClick={() => void withBusy(c.id, () => session.authorizedRequest((token) => api.requestEmergencyAccess(token, c.id)))}
                    className="rounded-md border border-neutral-300 px-2 py-1 text-xs text-neutral-600 dark:border-neutral-700 dark:text-neutral-300"
                  >
                    Demander l'accès d'urgence
                  </button>
                )}
                {c.status === "access_requested" && c.available_at && (
                  <span className="text-xs text-neutral-500">Disponible le {new Date(c.available_at).toLocaleString()}</span>
                )}
                {c.status === "access_granted" && (
                  <button
                    onClick={() => onViewVault(c.id, c.owner_email)}
                    className="rounded-md bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-700"
                  >
                    Consulter le coffre
                  </button>
                )}
                <button
                  disabled={busyId === c.id}
                  onClick={() => void withBusy(c.id, () => session.authorizedRequest((token) => api.revokeEmergencyContact(token, c.id)))}
                  className="rounded-md border border-red-300 px-2 py-1 text-xs text-red-600 hover:bg-red-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
                >
                  Me retirer
                </button>
              </div>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
