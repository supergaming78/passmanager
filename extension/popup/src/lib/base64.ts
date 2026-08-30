// Conversion base64 <-> octets, utilisée partout où une clé binaire doit transiter par un
// stockage JSON-safe (chrome.storage.session, voir lib/session.ts) ou par les fonctions WASM qui
// renvoient une clé encodée en base64 plutôt qu'en Uint8Array brut (voir emergency::unseal côté
// crypto-core, qui renvoie la vault_key d'un AUTRE utilisateur sous cette forme).

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
