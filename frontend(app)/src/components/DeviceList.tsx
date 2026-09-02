import { useEffect, useState, useCallback, type FormEvent } from "react";
import { useAuth } from "../state/AuthContext";
import * as api from "../api/client";
import * as tauri from "../api/tauri";
import { getErrorMessage } from "../lib/errors";
import { getDeviceId } from "../lib/deviceId";
import type { TrustedDevice } from "../api/types";

export default function DeviceList() {
  const { email, authorizedRequest, logout } = useAuth();
  const [devices, setDevices] = useState<TrustedDevice[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [currentLimit, setCurrentLimit] = useState<number | null>(null);
  const [showLimitForm, setShowLimitForm] = useState(false);
  const [newLimit, setNewLimit] = useState(10);
  const [limitPassword, setLimitPassword] = useState("");
  const [limitStatus, setLimitStatus] = useState<string | null>(null);
  const [isSavingLimit, setIsSavingLimit] = useState(false);

  const load = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [deviceList, me] = await Promise.all([
        authorizedRequest((token) => api.listDevices(token)),
        authorizedRequest((token) => api.getMe(token)),
      ]);
      setDevices(deviceList);
      setCurrentLimit(me.max_trusted_devices);
      setNewLimit(me.max_trusted_devices);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
  }, [authorizedRequest]);

  useEffect(() => {
    void load();
  }, [load]);

  async function handleRevoke(deviceId: string) {
    if (!confirm("Révoquer cet appareil ? Il devra repasser par la validation en 2 étapes pour se reconnecter.")) return;
    try {
      await authorizedRequest((token) => api.revokeDevice(token, deviceId));
      setDevices((prev) => prev.filter((d) => d.device_id !== deviceId));
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  async function handleLogoutAll() {
    if (!confirm("Déconnecter TOUS les appareils, y compris celui-ci ? Une reconnexion sera nécessaire partout.")) return;
    try {
      await authorizedRequest((token) => api.logoutAllDevices(token));
      await logout();
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  async function handleSaveLimit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLimitStatus(null);
    setIsSavingLimit(true);
    try {
      // computeAuthHash() (PAS deriveKeys()) : le coffre est déjà déverrouillé avec la BONNE clé —
      // une faute de frappe dans ce champ ne doit jamais écraser la clé du coffre en mémoire.
      const authHash = await tauri.computeAuthHash(email!, limitPassword);
      await authorizedRequest((token) => api.updateDeviceLimit(token, { new_limit: newLimit, master_password_hash: authHash }));
      setCurrentLimit(newLimit);
      setLimitStatus(`Plafond mis à jour : ${newLimit} appareil(s) de confiance maximum.`);
      setLimitPassword("");
      setShowLimitForm(false);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsSavingLimit(false);
    }
  }

  const currentDeviceId = getDeviceId();

  return (
    <div>
      {isLoading ? (
        <p className="text-sm text-neutral-500">Chargement…</p>
      ) : devices.length === 0 ? (
        <p className="text-sm text-neutral-500">Aucun appareil de confiance enregistré.</p>
      ) : (
        <ul className="flex flex-col gap-2">
          {devices.map((device) => (
            <li
              key={device.device_id}
              className="flex items-center justify-between rounded-lg border border-neutral-200 px-3 py-2 text-sm dark:border-neutral-800"
            >
              <div>
                <p className="font-medium text-neutral-800 dark:text-neutral-200">
                  {device.device_name || "Appareil sans nom"}
                  {device.device_id === currentDeviceId && (
                    <span className="ml-2 rounded-full bg-indigo-100 px-2 py-0.5 text-xs text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300">
                      cet appareil
                    </span>
                  )}
                </p>
                <p className="text-xs text-neutral-500">
                  Dernière utilisation : {new Date(device.last_used_at).toLocaleString()}
                  {device.last_ip && <> · IP : {device.last_ip}</>}
                </p>
              </div>
              <button
                type="button"
                onClick={() => void handleRevoke(device.device_id)}
                className="rounded-lg border border-red-300 px-2.5 py-1 text-xs font-medium text-red-600 hover:bg-red-50 dark:border-red-900 dark:text-red-400 dark:hover:bg-red-950"
              >
                Révoquer
              </button>
            </li>
          ))}
        </ul>
      )}

      {error && <p className="mt-2 text-sm text-red-600 dark:text-red-400">{error}</p>}
      {limitStatus && <p className="mt-2 text-sm text-emerald-600 dark:text-emerald-400">{limitStatus}</p>}

      {currentLimit !== null && (
        <p className="mt-3 text-sm text-neutral-600 dark:text-neutral-400">
          Plafond actuel : <span className="font-medium text-neutral-900 dark:text-neutral-100">{currentLimit}</span> appareil(s) de confiance
          ({devices.length} enregistré(s) actuellement).
        </p>
      )}

      <div className="mt-2 flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => void handleLogoutAll()}
          className="rounded-lg border border-red-300 px-3 py-1.5 text-sm font-medium text-red-600 hover:bg-red-50 dark:border-red-900 dark:text-red-400 dark:hover:bg-red-950"
        >
          Déconnecter tous les appareils
        </button>
        {!showLimitForm && (
          <button
            type="button"
            onClick={() => setShowLimitForm(true)}
            className="rounded-lg border border-neutral-300 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            Modifier le plafond d'appareils
          </button>
        )}
      </div>

      {showLimitForm && (
        <form onSubmit={handleSaveLimit} className="mt-3 flex flex-wrap items-end gap-2 rounded-lg border border-neutral-200 p-3 dark:border-neutral-800">
          <div>
            <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">Nouveau plafond (1-50)</label>
            <input
              type="number"
              min={1}
              max={50}
              required
              value={newLimit}
              onChange={(e) => setNewLimit(Number(e.target.value))}
              className="w-24 rounded-lg border border-neutral-300 px-2 py-1.5 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
            />
          </div>
          <div className="flex-1">
            <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
              Mot de passe maître (confirmation)
            </label>
            <input
              type="password"
              required
              value={limitPassword}
              onChange={(e) => setLimitPassword(e.target.value)}
              className="w-full rounded-lg border border-neutral-300 px-2 py-1.5 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
            />
          </div>
          <button
            type="submit"
            disabled={isSavingLimit}
            className="rounded-lg bg-indigo-600 px-3 py-1.5 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:opacity-60"
          >
            {isSavingLimit ? "…" : "Enregistrer"}
          </button>
          <button
            type="button"
            onClick={() => setShowLimitForm(false)}
            className="rounded-lg border border-neutral-300 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            Annuler
          </button>
        </form>
      )}
    </div>
  );
}
