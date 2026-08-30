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
