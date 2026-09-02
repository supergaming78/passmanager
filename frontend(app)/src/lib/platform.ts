// Détection de plateforme — volontairement PAS via `@tauri-apps/plugin-os` (aucune autre partie
// de l'app n'a besoin d'un plugin natif dédié juste pour ça, et ce serait une dépendance Rust/
// capacité supplémentaire à maintenir pour un unique usage cosmétique/UI, voir isAndroid()
// ci-dessous). Le sniffing d'user-agent est fiable ici car la webview Android de Tauri est une
// vraie Android System WebView, qui expose "Android" dans son user-agent comme n'importe quel
// navigateur Android standard — PAS un contournement fragile, un comportement documenté de wry/tao.
export function isAndroid(): boolean {
  return /Android/i.test(navigator.userAgent);
}

/** Même principe que isAndroid() ci-dessus — l'UA de la webview iOS de Tauri (WKWebView) expose
 * "iPhone"/"iPad" comme n'importe quel Safari iOS standard. */
export function isIOS(): boolean {
  return /iPhone|iPad|iPod/i.test(navigator.userAgent);
}

/** Vrai sur téléphone/tablette (Android ou iOS), faux sur PC (Windows/macOS/Linux) — retour
 * utilisateur (2026-09-02) : sert à réserver le choix de disposition du menu principal (voir
 * lib/menuLayout.ts) au desktop uniquement. Une disposition "barre latérale"/"compacte" pensée
 * pour un grand écran avec souris n'a pas vraiment de sens sur un écran tactile étroit — pas
 * interdit techniquement, juste jamais proposé côté mobile pour éviter une option qui ne rendrait
 * pas bien. */
export function isMobilePlatform(): boolean {
  return isAndroid() || isIOS();
}

/** Étiquette de plateforme lisible, pour le signalement de bug (voir components/BugReportModal.tsx)
 * — un diagnostic grossier suffit (utile pour trier "problème Windows only" vs "problème partout"),
 * pas besoin d'une détection précise ni d'un nouveau plugin natif pour ça (même raisonnement que
 * isAndroid() ci-dessus). */
export function getPlatformLabel(): string {
  const ua = navigator.userAgent;
  // iPhone/iPad AVANT macOS : l'UA d'iOS contient toujours "like Mac OS X" (ex: "iPhone; CPU
  // iPhone OS 17_5 like Mac OS X") — vérifier macOS en premier aurait classé un iPhone comme Mac.
  if (/iPhone|iPad|iPod/i.test(ua)) return "iOS";
  if (/Android/i.test(ua)) return "Android";
  if (/Windows/i.test(ua)) return "Windows";
  if (/Macintosh|Mac OS X/i.test(ua)) return "macOS";
  if (/Linux/i.test(ua)) return "Linux";
  return "Inconnu";
}

/** Étiquette de plateforme avec la version d'OS quand elle est repérable dans l'user-agent — pour
 * le signalement de bug, où "Windows 11" ou "Android 13" aide bien plus au diagnostic qu'un simple
 * "Windows"/"Android". Toujours un simple regex sur navigator.userAgent (pas un nouveau plugin
 * natif, voir getPlatformLabel ci-dessus) — retombe sur getPlatformLabel() si rien de plus précis
 * n'est trouvé, jamais une chaîne vide. */
export function getDetailedPlatformInfo(): string {
  const ua = navigator.userAgent;

  // iPhone/iPad AVANT macOS — voir getPlatformLabel() ci-dessus, même raison (UA iOS contenant
  // "like Mac OS X").
  const iosVersion = /OS (\d+[._]\d+(?:[._]\d+)?) like Mac OS X/i.exec(ua);
  if (iosVersion) return `iOS ${iosVersion[1].replace(/_/g, ".")}`;
  if (/iPhone|iPad|iPod/i.test(ua)) return "iOS";

  const androidVersion = /Android (\d+(?:\.\d+)?)/i.exec(ua);
  if (androidVersion) return `Android ${androidVersion[1]}`;

  // "Windows NT 10.0" couvre aussi bien Windows 10 que 11 (même version NT côté user-agent,
  // Microsoft n'a jamais distingué les deux à ce niveau) — le préciser serait mentir.
  const windowsVersion = /Windows NT (\d+\.\d+)/i.exec(ua);
  if (windowsVersion) {
    const known: Record<string, string> = { "10.0": "Windows 10/11", "6.3": "Windows 8.1", "6.1": "Windows 7" };
    return known[windowsVersion[1]] ?? `Windows (NT ${windowsVersion[1]})`;
  }

  const macVersion = /Mac OS X (\d+[._]\d+(?:[._]\d+)?)/i.exec(ua);
  if (macVersion) return `macOS ${macVersion[1].replace(/_/g, ".")}`;

  return getPlatformLabel();
}
