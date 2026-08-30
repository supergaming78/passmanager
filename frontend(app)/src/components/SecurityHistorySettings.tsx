import { useEffect, useState } from "react";
import { useAuth } from "../state/AuthContext";
import * as api from "../api/client";
import type { AuditLog } from "../api/types";
import { auditActionLabel } from "../lib/auditLogLabels";
import { formatRelativeAge } from "../lib/age";
import { getErrorMessage } from "../lib/errors";

/** Historique de sécurité SELF-SERVICE (voir GET /audit/me côté backend, scopé au compte connecté
 * uniquement — contrairement à l'endpoint admin GET /audit). Aucun contenu du coffre là-dedans,
 * juste action/IP/appareil/date en clair (voir backend/src/state.rs::log_audit) : rien à déchiffrer
 * ici, contrairement au reste de l'app. Les 100 entrées les plus récentes, comme côté admin. */
export default function SecurityHistorySettings() {
  const { authorizedRequest } = useAuth();
  const [logs, setLogs] = useState<AuditLog[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    authorizedRequest((token) => api.getMyAuditLogs(token))
      .then((result) => {
        if (!cancelled) setLogs(result);
      })
      .catch((err) => {
        if (!cancelled) setError(getErrorMessage(err));
      });
    return () => {
      cancelled = true;
    };
  }, [authorizedRequest]);

  if (error) return <p className="text-sm text-red-600 dark:text-red-400">{error}</p>;
  if (logs === null) return <p className="text-sm text-neutral-500">Chargement…</p>;
  if (logs.length === 0) return <p className="text-sm text-neutral-500">Aucune activité enregistrée pour l'instant.</p>;

  return (
    <div className="flex max-h-80 flex-col gap-2 overflow-y-auto">
      {logs.map((log) => (
        <div key={log.id} className="rounded-lg border border-neutral-200 px-3 py-2 text-sm dark:border-neutral-800">
          <div className="flex items-center justify-between gap-2">
            <span className="font-medium text-neutral-800 dark:text-neutral-200">{auditActionLabel(log.action)}</span>
            <span className="shrink-0 text-xs text-neutral-500">{formatRelativeAge(log.created_at).label}</span>
          </div>
          <p className="mt-0.5 text-xs text-neutral-500">
            {log.ip_address}
            {log.user_agent ? ` · ${log.user_agent}` : ""}
          </p>
        </div>
      ))}
    </div>
  );
}
