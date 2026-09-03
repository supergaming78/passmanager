// Exécution d'une même opération sur une liste, avec un nombre d'appels SIMULTANÉS BORNÉ.
//
// CORRECTIF (trouvé à l'audit du frontend) : les actions en masse du coffre (tout supprimer, tout
// mettre en favori, déplacer dans un dossier, partager une sélection, remplacer des entrées à
// l'import) faisaient toutes un `Promise.allSettled(items.map(...))` — c'est-à-dire qu'elles
// lançaient AUTANT de requêtes HTTP SIMULTANÉES qu'il y avait d'éléments sélectionnés, sans
// aucune borne. Avec "tout sélectionner" sur un gros coffre, cela pouvait représenter des
// milliers de requêtes tirées dans la même milliseconde.
//
// Le rate limiter du serveur (200 req/s, rafale de 500 — voir backend/src/main.rs) répondait
// alors 429 à la plupart d'entre elles. Comme ces appels utilisent `allSettled`, l'opération ne
// s'arrêtait pas : elle se terminait en signalant "N suppressions ont échoué" — un message qui
// laisse croire à un refus du serveur ou à des données corrompues, alors que le client venait
// simplement de se saturer lui-même. Le même symptôme côté utilisateur ("trop de tentatives")
// pouvait apparaître ailleurs dans l'app juste après, le quota de l'IP étant épuisé.
//
// Traiter par petits lots successifs suffit à supprimer la rafale : le serveur traite chaque
// requête en quelques millisecondes (écriture SQLite + journal d'audit, sérialisées de toute
// façon par l'unique écrivain de SQLite), donc rien n'est réellement perdu en vitesse.

/** Nombre d'opérations réseau menées de front. Volontairement modeste : l'objectif est d'éliminer
 * la RAFALE, pas d'optimiser le débit — ces actions restent rares et l'utilisateur attend de toute
 * façon leur fin. Une valeur plus élevée rapprocherait à nouveau du plafond du rate limiter sans
 * gain perceptible, l'écriture en base étant sérialisée côté serveur. */
export const NETWORK_CONCURRENCY = 6;

/** Équivalent de `Promise.allSettled(items.map(fn))`, mais en ne laissant jamais plus de `limit`
 * opérations en vol simultanément. L'ORDRE des résultats correspond exactement à celui de `items`
 * — plusieurs appelants corrèlent les deux par index (voir ImportExportBar.tsx), le préserver
 * n'est donc pas cosmétique.
 *
 * Traitement par lots successifs plutôt qu'avec une file de travailleurs : à ces tailles, la
 * différence de débit est négligeable, et un lot est bien plus simple à relire (et donc à
 * vérifier) qu'un ordonnanceur maison. */
export async function allSettledWithLimit<T, R>(
  items: readonly T[],
  fn: (item: T) => Promise<R>,
  limit: number = NETWORK_CONCURRENCY,
): Promise<PromiseSettledResult<R>[]> {
  const results: PromiseSettledResult<R>[] = [];
  const size = Math.max(1, limit); // une limite <= 0 rendrait la boucle infinie
  for (let start = 0; start < items.length; start += size) {
    const batch = items.slice(start, start + size);
    results.push(...(await Promise.allSettled(batch.map(fn))));
  }
  return results;
}
