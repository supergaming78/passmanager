// Détection de navigateur — même approche que frontend(app)/src/lib/platform.ts::isAndroid()
// (sniffing navigator.userAgent, fiable ici : Firefox inclut toujours "Firefox/" dans son UA,
// contrairement à Chrome/Edge/Brave/... qui ne l'incluent jamais).
export function isFirefox(): boolean {
  return navigator.userAgent.includes("Firefox");
}
