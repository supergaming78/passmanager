import { ApiError } from "../api/types";

/**
 * Extrait un message affichable d'une erreur de N'IMPORTE QUELLE provenance : réponse du backend
 * (ApiError, déjà un message propre), rejet d'une commande Tauri (souvent une simple chaîne, pas
 * un objet Error), ou erreur JS générique (ex: TypeError "Failed to fetch" si le serveur est
 * injoignable). AVANT ce helper, chaque écran remplaçait tout ce qui n'était pas une ApiError par
 * un message générique "Une erreur inattendue est survenue" — ce qui masquait la vraie cause
 * (backend éteint, mauvaise URL, CORS...) aussi bien à l'utilisateur qu'à qui essaie de
 * diagnostiquer le problème à distance.
 */
export function getErrorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (typeof err === "string") return err; // rejet Tauri typique (Result<T, String> côté Rust)
  if (err instanceof Error) return err.message;
  return "Une erreur inattendue est survenue.";
}
