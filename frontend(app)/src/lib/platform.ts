// Détection de plateforme — volontairement PAS via `@tauri-apps/plugin-os` (aucune autre partie
// de l'app n'a besoin d'un plugin natif dédié juste pour ça, et ce serait une dépendance Rust/
// capacité supplémentaire à maintenir pour un unique usage cosmétique/UI, voir isAndroid()
// ci-dessous). Le sniffing d'user-agent est fiable ici car la webview Android de Tauri est une
// vraie Android System WebView, qui expose "Android" dans son user-agent comme n'importe quel
// navigateur Android standard — PAS un contournement fragile, un comportement documenté de wry/tao.
export function isAndroid(): boolean {
  return /Android/i.test(navigator.userAgent);
}

/** Étiquette de plateforme lisible, pour le signalement de bug (voir lib/bugReport.ts) — un
 * diagnostic grossier suffit (utile pour trier "problème Windows only" vs "problème partout"),
 * pas besoin d'une détection précise ni d'un nouveau plugin natif pour ça (même raisonnement que
 * isAndroid() ci-dessus). */
export function getPlatformLabel(): string {
  const ua = navigator.userAgent;
  if (/Android/i.test(ua)) return "Android";
  if (/Windows/i.test(ua)) return "Windows";
  if (/Macintosh|Mac OS X/i.test(ua)) return "macOS";
  if (/Linux/i.test(ua)) return "Linux";
  return "Inconnu";
}
