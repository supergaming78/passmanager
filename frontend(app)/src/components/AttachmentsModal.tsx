import { useEffect, useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";
import { readFile, writeFile, size as fileSize } from "@tauri-apps/plugin-fs";
import * as api from "../api/client";
import { getErrorMessage } from "../lib/errors";
import { withFocusLossLockSuppressed } from "../lib/focusLossLockSuppression";
import { decryptAttachmentContent, decryptAttachmentMeta, encryptAttachment, type PlainAttachmentMeta } from "../lib/vaultAttachments";
import type { PlainVaultEntry } from "../lib/vaultCrypto";

interface Props {
  entry: PlainVaultEntry;
  authorizedRequest: <T,>(fn: (accessToken: string) => Promise<T>) => Promise<T>;
  onClose: () => void;
}

// DOIT rester synchronisé avec backend/src/handlers/vault.rs::MAX_ATTACHMENTS_PER_ENTRY/PER_USER
// et models.rs::VaultAttachmentInput — vérifié côté serveur de toute façon, mais autant prévenir
// l'utilisateur avant l'aller-retour réseau plutôt qu'après.
const MAX_ATTACHMENT_BYTES = 5 * 1024 * 1024;
const MAX_ATTACHMENTS_PER_ENTRY = 5;

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} Mo`;
}

/** Nom de fichier à partir d'un chemin complet — le séparateur dépend de l'OS (Windows utilise
 * "\", pas "/"), on gère les deux plutôt que de supposer une plateforme. */
function basename(path: string): string {
  const parts = path.split(/[/\\]/);
  return parts[parts.length - 1] || path;
}

/** Pièces jointes chiffrées d'UNE entrée (voir GET/POST/DELETE /vault/{id}/attachments côté
 * backend) — nom de fichier ET contenu chiffrés côté client (voir lib/vaultAttachments.ts), le
 * serveur ne les lit ni ne les valide jamais. Plafonné à 5 fichiers par entrée / 5 Mo par fichier
 * (voir MAX_ATTACHMENT_BYTES/MAX_ATTACHMENTS_PER_ENTRY ci-dessus). */
export default function AttachmentsModal({ entry, authorizedRequest, onClose }: Props) {
  const [attachments, setAttachments] = useState<PlainAttachmentMeta[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [busyId, setBusyId] = useState<string | null>(null); // téléchargement ou suppression en cours

  async function loadAttachments() {
    setIsLoading(true);
    setError(null);
    try {
      const metas = await authorizedRequest((token) => api.getVaultAttachments(token, entry.id));
      const decrypted = await Promise.all(metas.map(decryptAttachmentMeta));
      setAttachments(decrypted);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
  }

  useEffect(() => {
    void loadAttachments();
  }, [entry.id, authorizedRequest]);

  async function handleUpload() {
    setError(null);
    const path = await withFocusLossLockSuppressed(() => open({ title: "Ajouter une pièce jointe", multiple: false }));
    if (!path || Array.isArray(path)) return;

    setIsUploading(true);
    try {
      // CORRECTIF PERFORMANCE : vérifie la taille AVANT de lire tout le contenu en mémoire — rien
      // n'empêche la boîte de dialogue native de sélectionner un fichier de plusieurs Go, et
      // l'ancien code chargeait ce fichier ENTIER (readFile) avant de découvrir qu'il dépassait
      // la limite, ce qui pouvait bloquer l'interface ou saturer la mémoire sur une machine
      // modeste — exactement ce que cette vérification est censée éviter.
      const knownSize = await fileSize(path);
      if (knownSize > MAX_ATTACHMENT_BYTES) {
        throw new Error(`Fichier trop volumineux (${formatFileSize(knownSize)}) — ${formatFileSize(MAX_ATTACHMENT_BYTES)} maximum.`);
      }

      const bytes = await readFile(path);
      if (bytes.length > MAX_ATTACHMENT_BYTES) {
        throw new Error(`Fichier trop volumineux (${formatFileSize(bytes.length)}) — ${formatFileSize(MAX_ATTACHMENT_BYTES)} maximum.`);
      }
      const filename = basename(path);
      const attachment = await encryptAttachment(filename, bytes);
      await authorizedRequest((token) => api.addVaultAttachment(token, entry.id, attachment));
      await loadAttachments();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsUploading(false);
    }
  }

  async function handleDownload(meta: PlainAttachmentMeta) {
    setError(null);
    setBusyId(meta.id);
    try {
      const full = await authorizedRequest((token) => api.getVaultAttachment(token, entry.id, meta.id));
      const bytes = await decryptAttachmentContent(full);
      const path = await withFocusLossLockSuppressed(() => save({ title: "Enregistrer la pièce jointe", defaultPath: meta.filename }));
      if (!path) return;
      await writeFile(path, bytes);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  async function handleDelete(meta: PlainAttachmentMeta) {
    if (!confirm(`Supprimer définitivement "${meta.filename}" ?`)) return;
    setError(null);
    setBusyId(meta.id);
    try {
      await authorizedRequest((token) => api.deleteVaultAttachment(token, entry.id, meta.id));
      setAttachments((prev) => prev.filter((a) => a.id !== meta.id));
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setBusyId(null);
    }
  }

  const atLimit = attachments.length >= MAX_ATTACHMENTS_PER_ENTRY;

  return (
    <div className="fixed inset-0 z-10 flex items-center justify-center bg-black/40 px-4 py-8">
      <div className="max-h-full w-full max-w-md overflow-y-auto rounded-2xl border border-neutral-200 bg-white p-6 shadow-xl dark:border-neutral-800 dark:bg-neutral-900">
        <div className="mb-1 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">Pièces jointes — {entry.siteName}</h2>
          <button type="button" onClick={onClose} className="text-sm text-neutral-500 hover:underline">
            Fermer
          </button>
        </div>
        <p className="mb-4 text-xs text-neutral-500">
          Chiffrées comme le reste du coffre (nom ET contenu) — {formatFileSize(MAX_ATTACHMENT_BYTES)} par fichier,{" "}
          {MAX_ATTACHMENTS_PER_ENTRY} fichiers maximum par entrée.
        </p>

        {isLoading ? (
          <p className="text-sm text-neutral-500">Chargement…</p>
        ) : attachments.length === 0 ? (
          <p className="mb-4 text-sm text-neutral-500">Aucune pièce jointe pour cette entrée.</p>
        ) : (
          <ul className="mb-4 flex flex-col gap-2">
            {attachments.map((meta) => (
              <li
                key={meta.id}
                className="flex items-center justify-between gap-2 rounded-lg border border-neutral-200 px-3 py-2 dark:border-neutral-800"
              >
                <div className="min-w-0">
                  <p className="truncate text-sm text-neutral-800 dark:text-neutral-200">{meta.filename}</p>
                  <p className="text-xs text-neutral-500">{formatFileSize(meta.contentSize)}</p>
                </div>
                <div className="flex shrink-0 gap-1.5">
                  <button
                    type="button"
                    onClick={() => void handleDownload(meta)}
                    disabled={busyId === meta.id}
                    className="rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                  >
                    Télécharger
                  </button>
                  <button
                    type="button"
                    onClick={() => void handleDelete(meta)}
                    disabled={busyId === meta.id}
                    className="rounded-lg border border-red-300 px-2 py-1 text-xs font-medium text-red-600 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-50 dark:border-red-900 dark:text-red-400 dark:hover:bg-red-950"
                  >
                    Supprimer
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}

        {error && <p className="mb-3 text-sm text-red-600 dark:text-red-400">{error}</p>}

        <button
          type="button"
          onClick={() => void handleUpload()}
          disabled={isUploading || atLimit}
          title={atLimit ? `Limite de ${MAX_ATTACHMENTS_PER_ENTRY} fichiers atteinte pour cette entrée` : undefined}
          className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm font-medium text-neutral-700 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
        >
          {isUploading ? "Chiffrement et envoi…" : "+ Ajouter un fichier"}
        </button>
      </div>
    </div>
  );
}
