// Codes à usage unique (TOTP, RFC 6238) — le second facteur des SITES que l'utilisateur enregistre,
// à ne pas confondre avec la 2FA du compte PassManager lui-même (celle-ci passe par email, voir
// backend/src/handlers/auth/session.rs).
//
// POURQUOI EN TYPESCRIPT, et pas en Rust comme le reste de la cryptographie : le secret TOTP est
// stocké dans `extraFields`, qui arrive DÉJÀ déchiffré côté JS (voir vaultCrypto.ts::decryptEntry,
// exactement comme le mot de passe lui-même, qu'il faut bien afficher et copier). Le calculer en
// Rust ne le protégerait donc de rien de plus, tout en imposant de reconstruire le binaire WASM
// partagé avec l'extension. Web Crypto (`crypto.subtle`) fournit HMAC-SHA1, disponible aussi bien
// dans la webview Tauri que dans la popup de l'extension (contextes sécurisés tous les deux).
//
// Le secret ne quitte JAMAIS l'appareil : aucun appel réseau ici, le code se calcule uniquement à
// partir du secret et de l'heure courante.

/** Durée de validité d'un code, en secondes. 30 s est la valeur du RFC et celle qu'utilisent en
 * pratique tous les sites — les rares exceptions exposent leur période dans l'URI otpauth://. */
const DEFAULT_PERIOD_SECONDS = 30;
const DEFAULT_DIGITS = 6;

export interface TotpConfig {
  /** Secret décodé, en octets. */
  key: Uint8Array;
  digits: number;
  periodSeconds: number;
}

/** Alphabet base32 (RFC 4648). Les sites présentent toujours le secret sous cette forme. */
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Décode une chaîne base32 en octets. Tolère les espaces (les sites affichent souvent le secret
 * par groupes de 4), les minuscules et le remplissage `=` final. Renvoie `null` — plutôt que de
 * lever — si un caractère n'appartient pas à l'alphabet : un secret mal collé doit produire un
 * message clair, pas une exception au milieu d'un rendu de liste. */
export function decodeBase32(input: string): Uint8Array | null {
  const cleaned = input.replace(/[\s-]/g, "").replace(/=+$/, "").toUpperCase();
  if (!cleaned) return null;

  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of cleaned) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) return null;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return out.length > 0 ? new Uint8Array(out) : null;
}

/** Analyse ce que l'utilisateur a collé : soit un secret base32 brut, soit une URI `otpauth://`
 * complète (le contenu d'un QR code, que beaucoup de sites proposent en texte). Accepter l'URI
 * évite d'avoir à en extraire le secret à la main — et permet de respecter une période ou un
 * nombre de chiffres non standard quand le site en impose. Renvoie `null` si rien d'exploitable. */
export function parseTotpInput(raw: string): TotpConfig | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;

  if (/^otpauth:\/\//i.test(trimmed)) {
    let url: URL;
    try {
      url = new URL(trimmed);
    } catch {
      return null;
    }
    const secret = url.searchParams.get("secret");
    if (!secret) return null;
    // `algorithm` est volontairement ignoré : SHA-1 est ce qu'imposent le RFC par défaut ET la
    // quasi-totalité des sites. Prétendre gérer SHA-256/512 sans les avoir vérifiés produirait des
    // codes silencieusement faux — mieux vaut ne pas les annoncer.
    const key = decodeBase32(secret);
    if (!key) return null;
    const digits = Number(url.searchParams.get("digits")) || DEFAULT_DIGITS;
    const periodSeconds = Number(url.searchParams.get("period")) || DEFAULT_PERIOD_SECONDS;
    if (digits < 6 || digits > 10 || periodSeconds < 1) return null;
    return { key, digits, periodSeconds };
  }

  const key = decodeBase32(trimmed);
  return key ? { key, digits: DEFAULT_DIGITS, periodSeconds: DEFAULT_PERIOD_SECONDS } : null;
}

/** Calcule le code valide à l'instant `atMs` (par défaut : maintenant). Implémente RFC 6238 :
 * HMAC-SHA1 du numéro de tranche de temps, puis « troncature dynamique » (RFC 4226 §5.3) — un
 * décalage lu dans le dernier octet désigne les 4 octets à retenir, dont on masque le bit de signe
 * avant de les réduire au nombre de chiffres voulu. */
export async function generateTotp(config: TotpConfig, atMs: number = Date.now()): Promise<string> {
  const counter = Math.floor(atMs / 1000 / config.periodSeconds);

  // Compteur sur 8 octets, gros-boutiste. Écrit en deux moitiés de 32 bits : les opérateurs
  // binaires de JavaScript travaillent sur 32 bits, un décalage direct sur 64 bits serait faux.
  const counterBytes = new Uint8Array(8);
  new DataView(counterBytes.buffer).setUint32(0, Math.floor(counter / 0x100000000), false);
  new DataView(counterBytes.buffer).setUint32(4, counter >>> 0, false);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    config.key as unknown as BufferSource,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, counterBytes as unknown as BufferSource));

  const offset = signature[signature.length - 1] & 0x0f;
  const binary =
    ((signature[offset] & 0x7f) << 24) |
    ((signature[offset + 1] & 0xff) << 16) |
    ((signature[offset + 2] & 0xff) << 8) |
    (signature[offset + 3] & 0xff);

  return (binary % 10 ** config.digits).toString().padStart(config.digits, "0");
}

/** Secondes restantes avant que le code courant n'expire — pour le compte à rebours affiché à côté.
 * Toujours dans [1, periodSeconds] : on n'affiche jamais « 0 s », qui donnerait l'impression d'un
 * code déjà périmé alors qu'il est encore valide pendant cette dernière seconde. */
export function secondsUntilRotation(config: TotpConfig, atMs: number = Date.now()): number {
  const elapsed = Math.floor(atMs / 1000) % config.periodSeconds;
  return config.periodSeconds - elapsed;
}
