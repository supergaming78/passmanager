// Remplissage d'un formulaire de connexion sur l'onglet actif — voir le plan pour le choix
// d'architecture : sur demande depuis la popup (permission `activeTab`, accordée par le clic qui
// ouvre la popup elle-même), jamais de script tournant en permanence sur les pages visitées, pas
// de `host_permissions` large ni de service worker.

export interface FillResult {
  passwordFilled: boolean;
  usernameFilled: boolean;
}

/**
 * Injectée telle quelle dans la page par chrome.scripting.executeScript — DOIT rester autonome
 * (sérialisée vers le contexte de la page, aucune closure sur une variable extérieure à cette
 * fonction n'est possible). Heuristique volontairement simple pour cette phase (voir le plan) :
 * premier champ mot de passe trouvé sur la page, puis le champ identifiant le plus proche AVANT
 * lui dans le DOM.
 */
function fillCredentials(usernameOrEmail: string, password: string): FillResult {
  // Setter natif du PROTOTYPE plutôt que `element.value = ...` directement : les frameworks à
  // état contrôlé (React et assimilés) interceptent le setter sur l'INSTANCE et ignoreraient
  // silencieusement une simple assignation — voir le plan pour la source de cette technique.
  function setNativeValue(el: HTMLInputElement, value: string) {
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, "value")?.set;
    setter?.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  const passwordField = document.querySelector<HTMLInputElement>('input[type="password"]');
  let usernameFilled = false;
  let passwordFilled = false;

  if (passwordField) {
    // Cherche d'abord dans le même <form> (si le champ password en a un ancestor), sinon dans
    // tout le document — dans les deux cas, uniquement les champs qui précèdent le mot de passe
    // dans l'ordre du DOM (compareDocumentPosition), pour éviter d'attraper un champ "confirmer
    // le mot de passe" ou "email de récupération" placé APRÈS.
    const scope = passwordField.closest("form") ?? document;
    const candidates = Array.from(
      scope.querySelectorAll<HTMLInputElement>(
        'input[type="email"], input[type="text"], input[autocomplete*="user" i], input[autocomplete*="email" i]',
      ),
    ).filter((el) => {
      const position = el.compareDocumentPosition(passwordField);
      return (position & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
    });
    const usernameField = candidates[candidates.length - 1]; // le plus proche juste avant

    if (usernameField) {
      setNativeValue(usernameField, usernameOrEmail);
      usernameFilled = true;
    }

    setNativeValue(passwordField, password);
    passwordFilled = true;
  }

  return { passwordFilled, usernameFilled };
}

/** Retour utilisateur : "pouvoir l'utiliser avec l'extension pour automatiquement remplir les
 * champs de la carte bancaire lorsqu'on fait un achat" — le formulaire dédié "Carte bancaire"
 * (voir components/VaultEntryForm.tsx, déjà en place) existait déjà pour STOCKER une carte,
 * seul le remplissage automatique sur un formulaire de paiement manquait. */
export interface CardFillResult {
  numberFilled: boolean;
  nameFilled: boolean;
  expiryFilled: boolean;
  cvvFilled: boolean;
}

/**
 * Injectée telle quelle dans la page par chrome.scripting.executeScript — mêmes contraintes que
 * fillCredentials() ci-dessous (autonome, aucune closure externe). Détection PRIORITAIREMENT par
 * l'attribut `autocomplete` standard des formulaires de paiement (cc-number/cc-name/cc-exp/
 * cc-exp-month/cc-exp-year/cc-csc — voir la spec HTML "Autofill field name", déjà respectée par la
 * plupart des grandes plateformes de paiement — Stripe, Shopify...), avec un repli par mots-clés
 * dans name/id/placeholder/aria-label pour les formulaires qui ne le déclarent pas. Champ CVV
 * volontairement rempli comme les autres (aucun password manager grand public ne s'en abstient —
 * 1Password/Bitwarden/Chrome le font tous — c'est TA donnée, pour TON usage, pas une carte que ce
 * site conserverait).
 */
function fillCardCredentials(cardNumber: string, cardholderName: string, expiryMonth: string, expiryYear: string, cvv: string): CardFillResult {
  function setNativeValue(el: HTMLInputElement | HTMLSelectElement, value: string) {
    const proto = el.tagName === "SELECT" ? window.HTMLSelectElement.prototype : window.HTMLInputElement.prototype;
    const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set;
    setter?.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  function byAutocomplete(values: string[]): HTMLInputElement | HTMLSelectElement | null {
    for (const value of values) {
      const el = document.querySelector<HTMLInputElement | HTMLSelectElement>(`input[autocomplete="${value}"], select[autocomplete="${value}"]`);
      if (el) return el;
    }
    return null;
  }

  function byKeyword(keywords: string[]): HTMLInputElement | HTMLSelectElement | null {
    const candidates = document.querySelectorAll<HTMLInputElement | HTMLSelectElement>("input, select");
    for (const el of candidates) {
      const haystack = `${el.name} ${el.id} ${el.getAttribute("placeholder") ?? ""} ${el.getAttribute("aria-label") ?? ""}`.toLowerCase();
      if (keywords.some((k) => haystack.includes(k))) return el;
    }
    return null;
  }

  // Un <select> (courant pour le mois/année d'expiration) n'accepte pas n'importe quelle chaîne —
  // cherche l'<option> dont la VALEUR ou le TEXTE correspond à l'une des représentations plausibles
  // (ex: mois "03" écrit "3", "03" ou parfois le nom du mois) plutôt que de forcer une valeur qui
  // ne matcherait aucune option et laisserait le select sur son choix par défaut sans le signaler.
  function fillMonthOrYear(el: HTMLInputElement | HTMLSelectElement, value: string, isMonth: boolean): boolean {
    if (el instanceof HTMLSelectElement) {
      const candidates = isMonth
        ? [value, value.padStart(2, "0"), String(Number(value))]
        : [value, value.slice(-2), value.padStart(4, "20")];
      for (const opt of Array.from(el.options)) {
        if (candidates.includes(opt.value) || candidates.includes(opt.textContent?.trim() ?? "")) {
          setNativeValue(el, opt.value);
          return true;
        }
      }
      return false;
    }
    setNativeValue(el, isMonth ? value.padStart(2, "0") : value);
    return true;
  }

  const result: CardFillResult = { numberFilled: false, nameFilled: false, expiryFilled: false, cvvFilled: false };

  const numberField = byAutocomplete(["cc-number"]) ?? byKeyword(["cardnumber", "card-number", "cc-number", "ccnum", "numerocarte", "numéro de carte"]);
  if (numberField) {
    setNativeValue(numberField, cardNumber);
    result.numberFilled = true;
  }

  const nameField = byAutocomplete(["cc-name"]) ?? byKeyword(["cardholder", "card-name", "cc-name", "nomcarte", "titulaire"]);
  if (nameField) {
    setNativeValue(nameField, cardholderName);
    result.nameFilled = true;
  }

  const cvvField = byAutocomplete(["cc-csc", "cc-security-code"]) ?? byKeyword(["cvv", "cvc", "csc", "security-code", "securitycode", "cryptogramme"]);
  if (cvvField) {
    setNativeValue(cvvField, cvv);
    result.cvvFilled = true;
  }

  // Expiry : un seul champ combiné (format MM/AA le plus courant) d'abord, sinon deux champs
  // séparés mois/année (texte OU <select>, voir fillMonthOrYear ci-dessus).
  const combinedExpiry = byAutocomplete(["cc-exp"]);
  if (combinedExpiry) {
    setNativeValue(combinedExpiry, `${expiryMonth.padStart(2, "0")}/${expiryYear.slice(-2)}`);
    result.expiryFilled = true;
  } else {
    const monthField = byAutocomplete(["cc-exp-month"]) ?? byKeyword(["exp-month", "expmonth", "expirymonth", "cc-month", "moisexpiration"]);
    const yearField = byAutocomplete(["cc-exp-year"]) ?? byKeyword(["exp-year", "expyear", "expiryyear", "cc-year", "anneeexpiration"]);
    if (monthField && fillMonthOrYear(monthField, expiryMonth, true)) result.expiryFilled = true;
    if (yearField && fillMonthOrYear(yearField, expiryYear, false)) result.expiryFilled = true;
  }

  return result;
}

/**
 * Appelée depuis la popup pour une entrée "Carte bancaire" — voir runAutofill() ci-dessous pour le
 * même principe côté connexion. `expiryMonth`/`expiryYear` proviennent de `extraFields` (voir
 * lib/vaultCrypto.ts::EntryType "card"), potentiellement vides si l'utilisateur ne les a pas
 * renseignés — un champ non trouvé/non rempli ne fait jamais échouer les autres.
 */
export async function runCardAutofill(cardNumber: string, cardholderName: string, expiryMonth: string, expiryYear: string, cvv: string): Promise<CardFillResult> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) {
    throw new Error("Aucun onglet actif trouvé.");
  }

  try {
    const [injection] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: fillCardCredentials,
      args: [cardNumber, cardholderName, expiryMonth, expiryYear, cvv],
    });
    return injection.result as CardFillResult;
  } catch {
    throw new Error("Impossible de remplir sur cette page.");
  }
}

/** Vrai si la page est servie sur un canal où un secret n'est PAS exposé en clair sur le réseau.
 *
 * CORRECTIF SÉCURITÉ : remplir un mot de passe — et plus encore un numéro de carte accompagné de
 * son CVV — dans une page `http://` publique fait transiter ces valeurs EN CLAIR, lisibles par
 * n'importe quel intermédiaire réseau. Le remplissage de carte n'avait, lui, aucun garde-fou du
 * tout (contrairement au login, qui vérifie au moins la correspondance de domaine).
 *
 * Les exceptions ci-dessous évitent l'usure des alertes, qui est elle-même un problème de sécurité
 * (une alerte qui se déclenche à tort finit par être cliquée sans être lue) :
 * - localhost / boucle locale : traités comme contexte sécurisé par les navigateurs eux-mêmes ;
 * - adresses privées et noms .local : un routeur, un NAS ou une imprimante en http sur le réseau
 *   domestique est un usage courant et délibéré, jamais exposé à Internet.
 * Reste donc signalé le seul cas réellement dangereux : une page http PUBLIQUE. */
export function isSecurePageUrl(rawUrl: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return false; // URL inexploitable : mieux vaut avertir que supposer (voir l'appelant)
  }
  if (parsed.protocol === "https:") return true;
  if (parsed.protocol !== "http:") return false;

  const host = parsed.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost") || host === "127.0.0.1" || host === "[::1]") return true;
  if (host.endsWith(".local")) return true;
  // Plages privées IPv4 (RFC 1918) : 10.x, 192.168.x, et 172.16.x à 172.31.x
  if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
  if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$/.test(host)) return true;

  return false;
}

/** Extrait le nom d'hôte d'une URL saisie par l'utilisateur, avec ou sans schéma (ex: "example.com"
 * aussi bien que "https://example.com/login") — `null` si la valeur n'est décidément pas une URL. */
function safeHostname(rawUrl: string): string | null {
  try {
    return new URL(rawUrl).hostname.toLowerCase();
  } catch {
    try {
      return new URL(`https://${rawUrl}`).hostname.toLowerCase();
    } catch {
      return null;
    }
  }
}

/**
 * Compare le domaine ENREGISTRÉ dans l'entrée du coffre à celui de l'onglet actif — ce n'est PAS
 * du remplissage automatique suggéré (rien n'est proposé sans action explicite de l'utilisateur),
 * mais un simple avertissement avant de remplir un mot de passe sur un domaine qui ne correspond
 * pas à celui enregistré (ex: page de phishing visuellement identique sur un domaine voisin).
 * Autorise les sous-domaines dans les deux sens (ex: "accounts.google.com" correspond à une entrée
 * enregistrée pour "google.com", et inversement) : un mot de passe est fréquemment enregistré pour
 * le domaine racine alors que la connexion se fait sur un sous-domaine dédié, ou l'inverse.
 */
export function domainsLikelyMatch(entryUrl: string, tabUrl: string): boolean {
  const entryHost = safeHostname(entryUrl);
  const tabHost = safeHostname(tabUrl);
  if (!entryHost || !tabHost) return true; // rien de comparable -> ne bloque pas sur un faux positif
  if (entryHost === tabHost) return true;
  return entryHost.endsWith(`.${tabHost}`) || tabHost.endsWith(`.${entryHost}`);
}

/**
 * Appelée depuis la popup — récupère l'onglet actif puis y injecte fillCredentials() ci-dessus.
 * Lève une erreur lisible si l'injection échoue (page restreinte : chrome://, Web Store,
 * visionneuse PDF intégrée... — un refus de principe de Chrome, pas un bug de cette extension).
 */
export async function runAutofill(usernameOrEmail: string, password: string): Promise<FillResult> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) {
    throw new Error("Aucun onglet actif trouvé.");
  }

  try {
    const [injection] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: fillCredentials,
      args: [usernameOrEmail, password],
    });
    return injection.result as FillResult;
  } catch {
    throw new Error("Impossible de remplir sur cette page.");
  }
}

/** Renvoie l'URL de l'onglet actif, ou `null` si indisponible (page restreinte, `tab.url` non
 * exposé sans la permission `activeTab` déjà consommée...). Utilisé UNIQUEMENT pour comparer des
 * noms d'hôte avant remplissage (voir domainsLikelyMatch) — jamais transmis nulle part ailleurs. */
export async function getActiveTabUrl(): Promise<string | null> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url ?? null;
}

/**
 * Vérification RAPIDE, avant tout appel serveur, qu'un remplissage a une chance raisonnable de
 * réussir sur l'onglet actif — heuristique sur le schéma de l'URL (chrome://, la Web Store, un
 * PDF...), pas une garantie absolue (une page https normale sans aucun champ mot de passe passera
 * quand même ce test). Utilisée par lib/blindShare.ts::useBlindShareAndFill() pour éviter de
 * consommer un usage LIMITÉ (parfois un seul, jamais récupérable) sur un onglet manifestement
 * incompatible — l'erreur reste possible malgré tout (page sans champ mot de passe), mais le cas le
 * plus fréquent (mauvais onglet actif, page restreinte) est écarté AVANT de toucher le compteur.
 */
export async function canLikelyAutofillActiveTab(): Promise<boolean> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !tab.url) return false;
  const restricted = /^(chrome|chrome-extension|edge|about|devtools|view-source):/i.test(tab.url)
    || tab.url.startsWith("https://chrome.google.com/webstore")
    || tab.url.startsWith("https://chromewebstore.google.com");
  return !restricted;
}
