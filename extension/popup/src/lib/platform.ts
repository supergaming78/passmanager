// Détection de navigateur — même approche que frontend(app)/src/lib/platform.ts::isAndroid()
// (sniffing navigator.userAgent, fiable ici : Firefox inclut toujours "Firefox/" dans son UA,
// contrairement à Chrome/Edge/Brave/... qui ne l'incluent jamais).
export function isFirefox(): boolean {
  return navigator.userAgent.includes("Firefox");
}

/** Nom de navigateur lisible, pour lib/deviceId.ts::getDeviceName() ci-dessous — diagnostic
 * grossier volontaire (même raisonnement que getPlatformLabel() côté app desktop) : Edge AVANT
 * Chrome (Edge inclut aussi "Chrome/" dans son UA, en plus de son propre "Edg/" — l'ordre inverse
 * classerait systématiquement Edge comme Chrome). Opera/Brave/Vivaldi ne s'identifient PAS de
 * façon fiable dans leur UA par défaut (ils imitent délibérément Chrome) — regroupés sous
 * "Chrome" plutôt que de prétendre les distinguer. */
function getBrowserLabel(): string {
  const ua = navigator.userAgent;
  if (ua.includes("Firefox")) return "Firefox";
  if (ua.includes("Edg/")) return "Edge";
  if (ua.includes("Chrome")) return "Chrome";
  return "Navigateur";
}

/** Étiquette plateforme + navigateur lisible ("Windows 10/11", "Android"...) — même détection que
 * frontend(app)/src/lib/platform.ts::getPlatformLabel(), dupliquée ici plutôt que partagée (deux
 * bundles séparés, même principe que le reste de ce dossier lib/ vs celui de l'app desktop). */
function getPlatformLabel(): string {
  const ua = navigator.userAgent;
  // iPhone/iPad AVANT macOS : l'UA d'iOS contient toujours "like Mac OS X" (voir le même
  // commentaire côté app desktop) — vérifier macOS en premier aurait classé un iPhone comme Mac.
  if (/iPhone|iPad|iPod/i.test(ua)) return "iOS";
  if (/Android/i.test(ua)) return "Android";
  if (/Windows/i.test(ua)) return "Windows";
  if (/Macintosh|Mac OS X/i.test(ua)) return "macOS";
  if (/Linux/i.test(ua)) return "Linux";
  return "";
}

/** Nom lisible combinant navigateur + plateforme (ex: "Firefox sur Android") — voir
 * lib/deviceId.ts::getDeviceName(). Contrairement à l'app desktop (un seul "vrai" appareil par
 * installation), la MÊME machine peut avoir cette extension installée sur PLUSIEURS navigateurs à
 * la fois : le nom de plateforme seul ("Windows") ne suffirait pas à les distinguer dans
 * GET /devices, d'où le navigateur en plus ici. */
export function getDetailedPlatformInfo(): string {
  const platform = getPlatformLabel();
  const browser = getBrowserLabel();
  return platform ? `${browser} sur ${platform}` : browser;
}
