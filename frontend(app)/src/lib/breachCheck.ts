// Vérification des mots de passe compromis via l'API "Pwned Passwords" de HaveIBeenPwned, en
// k-anonymat : SEULS les 5 premiers caractères hexadécimaux du hash SHA-1 du mot de passe
// quittent l'appareil (voir api/tauri.ts::sha1Hex, calculé côté Rust, jamais en JS) — jamais le
// mot de passe lui-même, ni même son hash complet. Le serveur répond avec TOUS les suffixes
// connus partageant ce préfixe (environ un millier), donc il ne peut jamais savoir lequel
// intéresse réellement l'appelant. Documentation de l'API :
// https://haveibeenpwned.com/API/v3#PwnedPasswords
//
// OPT-IN UNIQUEMENT : cette vérification n'est JAMAIS déclenchée automatiquement (ni à
// l'ouverture du coffre, ni en tâche de fond) — voir components/VaultHealthModal.tsx, où un
// bouton explicite lance la vérification. Envoyer quoi que ce soit vers un service externe doit
// rester une action délibérée de l'utilisateur.

import * as tauri from "../api/tauri";

const HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/";

/** Interroge l'API pour UN préfixe de hash et renvoie la table {suffixe -> nombre de fuites}
 * pour ce préfixe. */
async function fetchRangeSuffixes(prefix: string): Promise<Map<string, number>> {
  let response: Response;
  try {
    response = await fetch(`${HIBP_RANGE_URL}${prefix}`);
  } catch {
    throw new Error("Impossible de contacter le service de vérification (haveibeenpwned.com) — vérifie ta connexion.");
  }
  if (!response.ok) {
    throw new Error(`Le service de vérification a répondu une erreur (HTTP ${response.status}).`);
  }

  const text = await response.text();
  const suffixes = new Map<string, number>();
  for (const line of text.split("\n")) {
    const [suffix, countRaw] = line.trim().split(":");
    if (suffix && countRaw) suffixes.set(suffix, Number(countRaw) || 0);
  }
  return suffixes;
}

/** Vérifie UN mot de passe. Renvoie le nombre de fuites connues dans lesquelles il apparaît
 * (0 = non trouvé dans cette base — pas une garantie absolue de sécurité, juste "pas connu là"). */
export async function checkPasswordBreachCount(password: string): Promise<number> {
  if (!password) return 0;
  const hash = await tauri.sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const suffixes = await fetchRangeSuffixes(prefix);
  return suffixes.get(suffix) ?? 0;
}

export interface BreachCheckResult {
  entryId: string;
  count: number;
}

/** Vérifie plusieurs entrées d'un coup, en DÉDUPLIQUANT les mots de passe identiques — une seule
 * requête réseau par mot de passe DISTINCT, pas par entrée (un mot de passe réutilisé sur 10
 * entrées ne doit déclencher qu'UN appel, pas 10 — voir aussi le filtre rapide "Réutilisés" qui
 * détecte déjà ce cas en local, sans réseau). `onProgress` est appelé après chaque mot de passe
 * DISTINCT vérifié, pour une barre de progression fidèle au nombre réel de requêtes réseau plutôt
 * qu'au nombre d'entrées. Une courte pause entre deux appels reste un client raisonnable de ce
 * service public gratuit (pas de quota documenté sur l'API Range, mais pas de raison de la
 * marteler sans retenue pour autant). */
export async function checkEntriesForBreaches(
  entries: { id: string; password: string }[],
  onProgress?: (done: number, total: number) => void,
): Promise<BreachCheckResult[]> {
  const idsByPassword = new Map<string, string[]>();
  for (const e of entries) {
    if (!e.password) continue;
    if (!idsByPassword.has(e.password)) idsByPassword.set(e.password, []);
    idsByPassword.get(e.password)!.push(e.id);
  }

  const uniquePasswords = Array.from(idsByPassword.keys());
  const results: BreachCheckResult[] = [];

  for (let i = 0; i < uniquePasswords.length; i++) {
    const password = uniquePasswords[i];
    const count = await checkPasswordBreachCount(password);
    if (count > 0) {
      for (const id of idsByPassword.get(password)!) {
        results.push({ entryId: id, count });
      }
    }
    onProgress?.(i + 1, uniquePasswords.length);

    if (i < uniquePasswords.length - 1) {
      await new Promise((resolve) => setTimeout(resolve, 150));
    }
  }

  return results;
}
