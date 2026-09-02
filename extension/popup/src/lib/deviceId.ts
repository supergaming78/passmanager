import { getDetailedPlatformInfo } from "./platform";

// Identifiant STABLE de cet appareil (pas sensible, pas besoin d'être en Rust) — envoyé à chaque
// login/2FA (voir AuthPayload.device_id côté backend). Généré une seule fois puis persisté dans
// le stockage local du webview (survit aux redémarrages de l'app) : c'est ce qui permet au
// serveur de reconnaître un appareil déjà "de confiance" et de sauter le 2FA aux connexions
// suivantes, tant que ce même appareil s'authentifie avec le même identifiant.
const STORAGE_KEY = "passmanager.deviceId";

export function getDeviceId(): string {
  const existing = localStorage.getItem(STORAGE_KEY);
  if (existing) return existing;

  const generated = crypto.randomUUID();
  localStorage.setItem(STORAGE_KEY, generated);
  return generated;
}

/**
 * Nom lisible de l'appareil, envoyé une fois à la validation du 2FA (voir
 * VerifyTfaPayload.device_name côté backend) pour que l'utilisateur le reconnaisse dans
 * GET /devices. CORRECTIF (retour utilisateur, 2026-09-02) : générait auparavant un nom générique
 * ("Ordinateur (02/09/2026)"), peu utile pour distinguer plusieurs appareils dans la liste —
 * réutilise getDetailedPlatformInfo() (navigateur + plateforme, ex: "Firefox sur Android"),
 * toujours suivi de la date pour distinguer deux installations identiques approuvées séparément.
 */
export function getDeviceName(): string {
  const existing = localStorage.getItem("passmanager.deviceName");
  if (existing) return existing;

  const generated = `${getDetailedPlatformInfo()} (${new Date().toLocaleDateString()})`;
  localStorage.setItem("passmanager.deviceName", generated);
  return generated;
}
