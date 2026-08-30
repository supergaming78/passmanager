// Détection de plateforme — volontairement PAS via `@tauri-apps/plugin-os` (aucune autre partie
// de l'app n'a besoin d'un plugin natif dédié juste pour ça, et ce serait une dépendance Rust/
// capacité supplémentaire à maintenir pour un unique usage cosmétique/UI, voir isAndroid()
// ci-dessous). Le sniffing d'user-agent est fiable ici car la webview Android de Tauri est une
// vraie Android System WebView, qui expose "Android" dans son user-agent comme n'importe quel
// navigateur Android standard — PAS un contournement fragile, un comportement documenté de wry/tao.
export function isAndroid(): boolean {
  return /Android/i.test(navigator.userAgent);
}
