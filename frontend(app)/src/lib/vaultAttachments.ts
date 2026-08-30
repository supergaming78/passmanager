// Chiffrement/déchiffrement des pièces jointes d'une entrée (voir api/types.ts::VaultAttachment*
// et components/AttachmentsModal.tsx). Le contenu binaire d'un fichier est d'abord encodé en
// base64 (texte) — seul format que les commandes Tauri de chiffrement acceptent en entrée (voir
// src-tauri/src/crypto.rs::encrypt_field, qui prend un &str) — PUIS chiffré. Cet encodage base64
// est une simple transformation de représentation des données, pas de la cryptographie : la
// cryptographie elle-même (chiffrement/déchiffrement AES-256-GCM) reste entièrement côté Rust,
// jamais en JS, comme le reste de cette app.

import * as tauri from "../api/tauri";
import type { VaultAttachment, VaultAttachmentInput, VaultAttachmentMeta } from "../api/types";

export interface PlainAttachmentMeta {
  id: string;
  filename: string;
  contentSize: number;
  createdAt: string;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  // Traité par blocs : passer TOUS les octets d'un gros fichier d'un coup à
  // String.fromCharCode(...bytes) peut dépasser la limite d'arguments d'un appel de fonction
  // (RangeError "Maximum call stack size exceeded" sur certains moteurs, au-delà de quelques
  // dizaines de milliers d'octets).
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Chiffre un fichier (nom + contenu binaire) pour l'envoyer au backend — voir
 * api/types.ts::VaultAttachmentInput. `contentSize` (octets du fichier ORIGINAL, avant tout
 * encodage) est envoyé EN CLAIR au serveur (seule métadonnée non chiffrée), pour l'affichage/les
 * quotas sans jamais avoir à déchiffrer quoi que ce soit côté serveur. */
export async function encryptAttachment(filename: string, bytes: Uint8Array): Promise<VaultAttachmentInput> {
  const base64Content = bytesToBase64(bytes);
  const [encrypted_filename, encrypted_content] = await Promise.all([
    tauri.encryptField(filename),
    tauri.encryptField(base64Content),
  ]);
  return { encrypted_filename, encrypted_content, content_size: bytes.length };
}

/** Déchiffre uniquement le NOM d'une pièce jointe (voir VaultAttachmentMeta — pas de contenu dans
 * un listing, voir le commentaire de GET /vault/{id}/attachments côté backend). */
export async function decryptAttachmentMeta(meta: VaultAttachmentMeta): Promise<PlainAttachmentMeta> {
  const filename = await tauri.decryptField(meta.encrypted_filename);
  return { id: meta.id, filename, contentSize: meta.content_size, createdAt: meta.created_at };
}

/** Déchiffre le CONTENU complet d'une pièce jointe (voir GET /vault/{id}/attachments/{id}) —
 * renvoie les octets bruts du fichier original, prêts à être écrits sur disque. */
export async function decryptAttachmentContent(attachment: VaultAttachment): Promise<Uint8Array> {
  const base64Content = await tauri.decryptField(attachment.encrypted_content);
  return base64ToBytes(base64Content);
}
