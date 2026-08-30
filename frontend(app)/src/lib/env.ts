/**
 * `true` uniquement quand l'app tourne via `npm run tauri dev` (serveur Vite de développement),
 * `false` dans un build packagé (`npm run tauri build`) — fourni nativement par Vite
 * (`import.meta.env.DEV`), remplacé à la compilation, pas une variable lue à l'exécution.
 * Utilisé pour restreindre certains réglages (ex: URL du serveur, voir lib/settings.ts) aux
 * développeurs et aux admins déjà connectés — un utilisateur final en build de production n'a
 * aucune raison de changer à quel backend l'app se connecte.
 */
export const isDev = import.meta.env.DEV;
