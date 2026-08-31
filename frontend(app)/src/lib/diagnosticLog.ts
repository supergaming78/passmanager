// Journal de diagnostic EN MÉMOIRE UNIQUEMENT (jamais persisté sur disque, jamais transmis nulle
// part sauf inclusion volontaire dans un signalement de bug, voir BugReportModal.tsx) — alimenté
// automatiquement par trois sources :
// 1. console.error()/console.warn() interceptés (voir installDiagnosticLogCapture, appelé une
//    seule fois depuis main.tsx) — capture aussi les erreurs qui n'ont PAS fait planter l'app
//    (contrairement à ErrorBoundary.tsx, qui n'attrape que les crashs de rendu).
// 2. Les rejets de promesse non gérés (`unhandledrejection`) — React ne les attrape jamais, ni
//    ErrorBoundary ni aucun mécanisme natif, sans cet écouteur ils disparaissent silencieusement.
// 3. Les appels API en échec (voir recordApiFailure(), appelée depuis api/client.ts::request()) —
//    UNIQUEMENT le chemin (endpoint) et le code HTTP, JAMAIS le corps de la requête/réponse (qui
//    pourrait contenir des champs chiffrés du coffre, sans intérêt pour le diagnostic de toute
//    façon puisque déjà illisible sans la clé).
//
// AUCUN contenu du coffre ne peut atterrir ici : ce fichier ne capture que des messages d'erreur
// techniques (noms de composants React, endpoints, codes HTTP) — jamais une valeur manipulée par
// l'app (vérifié : aucun autre `console.error`/`console.warn` dans tout ce projet au moment où ce
// fichier a été écrit, voir grep dans la conversation qui a motivé cet ajout).

const MAX_ENTRIES = 20;

interface LogEntry {
  timestamp: string;
  kind: "console.error" | "console.warn" | "unhandledrejection" | "api";
  message: string;
}

const buffer: LogEntry[] = [];

function push(kind: LogEntry["kind"], message: string) {
  buffer.push({ timestamp: new Date().toISOString(), kind, message });
  if (buffer.length > MAX_ENTRIES) buffer.shift();
}

/** Appelée depuis api/client.ts::request() sur CHAQUE appel en échec — chemin + code HTTP
 * uniquement, jamais le corps de la requête/réponse. */
export function recordApiFailure(path: string, status: number | "réseau"): void {
  push("api", `${path} → ${status}`);
}

/** À appeler UNE SEULE FOIS, au tout début de l'app (voir main.tsx) — intercepte console.error/
 * console.warn et les rejets de promesse non gérés sans changer leur comportement normal (toujours
 * affichés dans la console, en plus d'être gardés ici). */
export function installDiagnosticLogCapture(): void {
  const originalError = console.error;
  const originalWarn = console.warn;

  console.error = (...args: unknown[]) => {
    push("console.error", args.map((a) => (a instanceof Error ? a.message : String(a))).join(" "));
    originalError(...args);
  };
  console.warn = (...args: unknown[]) => {
    push("console.warn", args.map((a) => (a instanceof Error ? a.message : String(a))).join(" "));
    originalWarn(...args);
  };

  window.addEventListener("unhandledrejection", (event: PromiseRejectionEvent) => {
    const reason = event.reason instanceof Error ? event.reason.message : String(event.reason);
    push("unhandledrejection", reason);
  });
}

/** Formaté pour inclusion directe dans la description d'un signalement de bug (voir
 * BugReportModal.tsx) — les entrées les plus RÉCENTES en dernier (ordre de lecture naturel). */
export function getRecentDiagnosticLog(): string {
  if (buffer.length === 0) return "(aucune entrée)";
  return buffer.map((e) => `[${e.kind}] ${e.message}`).join("\n");
}
