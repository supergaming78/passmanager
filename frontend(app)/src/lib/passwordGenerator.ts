// Génération d'un mot de passe aléatoire selon des critères configurables PAR CATÉGORIE :
// longueur totale, et pour chaque type de caractère (minuscules/majuscules/chiffres/symboles) un
// nombre MINIMUM et MAXIMUM garanti dans le résultat — pas juste un minimum global. Plus des
// caractères explicitement interdits. CSPRNG du navigateur/webview (crypto.getRandomValues),
// jamais Math.random().
//
// Un second mode, plus bas dans ce fichier (generatePassphrase), génère une PHRASE de passe façon
// diceware (mots aléatoires plutôt que caractères) — plus facile à mémoriser/dicter à voix haute.

import { PASSPHRASE_WORDLIST } from "./passphraseWordlist";

export type CharCategory = "lowercase" | "uppercase" | "numbers" | "symbols";

const CATEGORY_CHARS: Record<CharCategory, string> = {
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  numbers: "0123456789",
  // Volontairement large — c'est ce qui rend possible COMMONLY_REJECTED_CHARS ci-dessous : ces
  // caractères font partie du pool exploitable, mais sont exclus par défaut (voir plus bas).
  symbols: "!@#$%^&*()-_=+[]{}~`'\";:,.<>?/| \\",
};

export const CATEGORY_LABELS: Record<CharCategory, string> = {
  lowercase: "Minuscules (a-z)",
  uppercase: "Majuscules (A-Z)",
  numbers: "Chiffres (0-9)",
  symbols: "Symboles (!@#…)",
};

/** Caractères visuellement ambigus (confondables à l'affichage : l/1/I, 0/O...) — proposés comme
 * exclusion rapide dans le panneau plutôt qu'à taper à la main. */
export const AMBIGUOUS_CHARS = "l1IO0o";

/** Caractères que beaucoup de sites/apps refusent purement et simplement dans un mot de passe —
 * espace (souvent tronqué ou rejeté), guillemets et antislash (bugs d'échappement côté
 * validation), chevrons (paranoïa anti-HTML), point-virgule et barre verticale (confondus avec un
 * délimiteur). PAS exclus par défaut — proposés comme bouton à activer dans le panneau (même
 * mécanique que "Exclure les ambigus" ci-dessous), pour rester un choix explicite plutôt qu'un
 * comportement caché : rien n'empêche un site d'accepter ces caractères. */
export const COMMONLY_REJECTED_CHARS = " \\`'\";<>|";

export interface CategoryOptions {
  include: boolean;
  min: number;
  max: number;
}

export interface PasswordGeneratorOptions {
  length: number;
  categories: Record<CharCategory, CategoryOptions>;
  excludedChars: string;
}

export const DEFAULT_GENERATOR_OPTIONS: PasswordGeneratorOptions = {
  length: 16,
  categories: {
    lowercase: { include: true, min: 1, max: 16 },
    uppercase: { include: true, min: 1, max: 16 },
    numbers: { include: true, min: 1, max: 16 },
    symbols: { include: true, min: 1, max: 16 },
  },
  excludedChars: "",
};

/** Indice aléatoire non biaisé dans [0, max) via rejet des valeurs qui casseraient l'uniformité
 * (l'espace de Uint32 n'est pas toujours un multiple exact de `max`). */
function randomIndex(max: number): number {
  const limit = Math.floor(0xffffffff / max) * max;
  const buffer = new Uint32Array(1);
  let value: number;
  do {
    crypto.getRandomValues(buffer);
    value = buffer[0];
  } while (value >= limit);
  return value % max;
}

function pickRandom(pool: string): string {
  return pool[randomIndex(pool.length)];
}

/** Mélange Fisher-Yates avec le même générateur non biaisé — indispensable ici : sans ça, les
 * caractères "garantis" par les minimums se retrouveraient toujours au début du mot de passe, un
 * motif prévisible qu'un générateur digne de ce nom ne doit pas produire. */
function shuffle(chars: string[]): string[] {
  const result = [...chars];
  for (let i = result.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

function withoutExcluded(pool: string, excluded: string): string {
  if (!excluded) return pool;
  const excludedSet = new Set(excluded);
  return Array.from(pool)
    .filter((c) => !excludedSet.has(c))
    .join("");
}

interface ResolvedCategory {
  key: CharCategory;
  pool: string;
  min: number;
  max: number; // 0 si le pool est vide après exclusion, quel que soit le max configuré
}

/** Génère un mot de passe respectant `options` — min ET max réellement respectés pour chaque
 * catégorie incluse, pas juste un minimum global — ou lève une Error avec un message explicite et
 * actionnable si les critères sont impossibles à satisfaire. */
export function generatePassword(options: PasswordGeneratorOptions): string {
  const included = (Object.keys(options.categories) as CharCategory[]).filter((key) => options.categories[key].include);

  if (included.length === 0) {
    throw new Error("Sélectionne au moins un type de caractère.");
  }

  const resolved: ResolvedCategory[] = included.map((key) => {
    const { min, max } = options.categories[key];
    const pool = withoutExcluded(CATEGORY_CHARS[key], options.excludedChars);
    return { key, pool, min, max: pool.length === 0 ? 0 : max };
  });

  for (const c of resolved) {
    if (c.min > c.max) {
      throw new Error(`${CATEGORY_LABELS[c.key]} : le minimum (${c.min}) dépasse le maximum (${c.max}).`);
    }
    if (c.min > 0 && c.pool.length === 0) {
      throw new Error(`${CATEGORY_LABELS[c.key]} est requis (minimum > 0) mais tous ses caractères sont exclus.`);
    }
  }

  const totalMin = resolved.reduce((sum, c) => sum + c.min, 0);
  const totalMax = resolved.reduce((sum, c) => sum + c.max, 0);

  if (totalMin > options.length) {
    throw new Error(`La longueur (${options.length}) est trop courte pour les minimums demandés (${totalMin} caractères garantis au total).`);
  }
  if (totalMax < options.length) {
    throw new Error(`Les maximums combinés (${totalMax}) ne permettent pas d'atteindre la longueur demandée (${options.length}).`);
  }

  // 1. Chaque catégorie démarre à son minimum garanti.
  const counts = new Map<CharCategory, number>(resolved.map((c) => [c.key, c.min]));

  // 2. Distribue le reste au hasard, sans jamais dépasser le maximum d'une catégorie — toujours
  // possible par construction (totalMax >= length, validé ci-dessus).
  let remaining = options.length - totalMin;
  while (remaining > 0) {
    const eligible = resolved.filter((c) => (counts.get(c.key) ?? 0) < c.max);
    const chosen = eligible[randomIndex(eligible.length)];
    counts.set(chosen.key, (counts.get(chosen.key) ?? 0) + 1);
    remaining -= 1;
  }

  // 3. Pioche réellement les caractères, puis mélange (voir shuffle() ci-dessus).
  const result: string[] = [];
  for (const c of resolved) {
    const count = counts.get(c.key) ?? 0;
    for (let i = 0; i < count; i++) {
      result.push(pickRandom(c.pool));
    }
  }

  return shuffle(result).join("");
}

// ---------------------------------------------------------------------------------------------
// Phrase de passe façon diceware — mode alternatif au générateur par caractères ci-dessus : des
// mots pris au hasard dans une liste fixe (voir passphraseWordlist.ts) plutôt que des caractères,
// plus faciles à mémoriser ou à dicter à voix haute (utile en particulier pour un mot de passe
// MAÎTRE, retapé à la main bien plus souvent que ceux stockés dans le coffre).
// ---------------------------------------------------------------------------------------------

export interface PassphraseOptions {
  wordCount: number;
  separator: string;
  capitalize: boolean;
  /** Ajoute un nombre à 4 chiffres en fin de phrase — contribue à l'entropie réelle (contrairement
   * à la capitalisation/au séparateur, fixes une fois choisis) sans nuire à la mémorisation autant
   * qu'un mot supplémentaire. */
  includeNumber: boolean;
}

export const DEFAULT_PASSPHRASE_OPTIONS: PassphraseOptions = {
  wordCount: 5,
  separator: "-",
  capitalize: true,
  includeNumber: true,
};

const PASSPHRASE_NUMBER_RANGE = 10000; // nombre à 4 chiffres, 0000-9999

function pickRandomWord(): string {
  return PASSPHRASE_WORDLIST[randomIndex(PASSPHRASE_WORDLIST.length)];
}

/** Génère une phrase de passe : `wordCount` mots tirés uniformément dans PASSPHRASE_WORDLIST,
 * assemblés avec `separator`, avec capitalisation et numéro final optionnels. */
export function generatePassphrase(options: PassphraseOptions): string {
  if (options.wordCount < 3) {
    throw new Error("Au moins 3 mots pour une phrase de passe correcte.");
  }
  const words = Array.from({ length: options.wordCount }, () => pickRandomWord());
  const rendered = words.map((w) => (options.capitalize ? w[0].toUpperCase() + w.slice(1) : w));
  if (options.includeNumber) {
    rendered.push(String(randomIndex(PASSPHRASE_NUMBER_RANGE)).padStart(4, "0"));
  }
  return rendered.join(options.separator);
}

/** Entropie de generatePassphrase() : log2(taille de la liste) bits par mot — la liste utilisée
 * (BIP-39 anglaise, 2048 mots, voir passphraseWordlist.ts) donne exactement 11 bits/mot — plus
 * log2(10000) ≈ 13,29 bits si un numéro est ajouté. La capitalisation et le séparateur sont fixes
 * une fois choisis (pas tirés au hasard entrée par entrée) : ils ne contribuent pas à l'entropie. */
export function estimatePassphraseEntropyBits(options: PassphraseOptions): number {
  const perWordBits = Math.log2(PASSPHRASE_WORDLIST.length);
  return options.wordCount * perWordBits + (options.includeNumber ? Math.log2(PASSPHRASE_NUMBER_RANGE) : 0);
}

// ---------------------------------------------------------------------------------------------
// Estimation d'entropie — affichée AVANT de générer, pendant que l'utilisateur ajuste les
// critères, pour qu'il voie l'effet de chaque réglage plutôt que de le découvrir après coup.
// ---------------------------------------------------------------------------------------------

/** Taille du pool de caractères réellement exploitable (catégories cochées, moins les caractères
 * interdits). Les catégories sont disjointes (pas de lettre à la fois dans "symboles" et
 * "chiffres"), une simple somme des tailles suffit donc — pas besoin d'un Set pour dédupliquer. */
export function estimatePoolSize(options: PasswordGeneratorOptions): number {
  return (Object.keys(options.categories) as CharCategory[])
    .filter((key) => options.categories[key].include)
    .reduce((sum, key) => sum + withoutExcluded(CATEGORY_CHARS[key], options.excludedChars).length, 0);
}

/** Coefficient binomial C(n, k) — précision flottante habituelle, largement suffisante ici (n
 * borné par la longueur max de l'UI, 64). */
function binomial(n: number, k: number): number {
  if (k < 0 || k > n) return 0;
  const kk = Math.min(k, n - k);
  let result = 1;
  for (let i = 0; i < kk; i++) {
    result = (result * (n - i)) / (i + 1);
  }
  return result;
}

/** Nombre de mots de passe DISTINCTS que le générateur peut produire avec ces réglages — en
 * respectant vraiment le minimum ET le maximum de chaque catégorie, pas juste "longueur ×
 * log2(pool total)" (qui suppose un tirage totalement libre position par position, alors qu'un
 * minimum/maximum par catégorie réduit l'espace réellement atteignable). Programmation dynamique,
 * catégorie par catégorie : `dp[j]` = nombre de façons de remplir j positions avec les catégories
 * déjà traitées. Pour la catégorie suivante, choisir combien de nouvelles positions c elle prend
 * (entre son min et son max), PARMI les j+c positions désormais utilisées — C(j+c, c) façons de
 * choisir lesquelles — puis les remplir avec ses caractères — pool^c façons. */
function countReachablePasswords(options: PasswordGeneratorOptions): number {
  const included = (Object.keys(options.categories) as CharCategory[]).filter((key) => options.categories[key].include);
  const length = options.length;
  if (included.length === 0 || length <= 0) return 0;

  let dp = new Array<number>(length + 1).fill(0);
  dp[0] = 1;

  for (const key of included) {
    const { min, max } = options.categories[key];
    const poolSize = withoutExcluded(CATEGORY_CHARS[key], options.excludedChars).length;
    const next = new Array<number>(length + 1).fill(0);

    for (let j = 0; j <= length; j++) {
      if (dp[j] === 0) continue;
      const cMin = Math.max(min, 0);
      const cMax = Math.min(max, length - j);
      for (let c = cMin; c <= cMax; c++) {
        next[j + c] += dp[j] * binomial(j + c, c) * Math.pow(poolSize, c);
      }
    }

    dp = next;
  }

  return dp[length];
}

/** Entropie en bits : log2 du nombre de mots de passe distincts réellement atteignables (voir
 * countReachablePasswords ci-dessus) — tient compte de la longueur, du pool par catégorie ET des
 * min/max par catégorie, pas seulement de la longueur et de la taille totale du pool. */
export function estimateEntropyBits(options: PasswordGeneratorOptions): number {
  const total = countReachablePasswords(options);
  if (!Number.isFinite(total) || total <= 1) return 0;
  return Math.log2(total);
}

// ---------------------------------------------------------------------------------------------
// Entropie d'un mot de passe QUELCONQUE (pas forcément généré par cette app) — utilisée à
// l'import, où on ne connaît ni les catégories ni les min/max qui ont servi à le créer, juste la
// chaîne finale. Estimation classique par classes de caractères PRÉSENTES dans le mot de passe
// (minuscules/majuscules/chiffres/symboles ASCII/autres), pas le calcul exact du générateur
// ci-dessus. Volontairement plus prudente qu'une vraie analyse de force : elle ne détecte ni les
// mots du dictionnaire ni les motifs ("azerty123", "password1"...) — seulement la diversité de
// caractères et la longueur, comme la plupart des indicateurs simples.
// ---------------------------------------------------------------------------------------------

const ASCII_SYMBOLS_PATTERN = /[ !"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/;

/** Taille du pool de caractères que le mot de passe *semble* utiliser, déduite des classes
 * effectivement présentes dedans (pas des classes exploitables — on n'a que le résultat final,
 * pas les réglages d'origine). Un caractère hors ASCII imprimable élargit fortement le pool
 * supposé (bonus volontairement large plutôt que de sous-estimer une vraie diversité unicode). */
function classifyPasswordPoolSize(password: string): number {
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (ASCII_SYMBOLS_PATTERN.test(password)) pool += 33;
  if (/[^\x20-\x7e]/.test(password)) pool += 1000;
  return pool;
}

/** Entropie estimée d'un mot de passe importé (ou tapé à la main) : longueur × log2(pool des
 * classes présentes). Une approximation reconnue plus grossière que estimateEntropyBits() —
 * affichée surtout pour repérer d'un coup d'œil les mots de passe importés visiblement faibles
 * (courts, une seule classe de caractères), pas comme un score de sécurité définitif. */
export function estimatePasswordEntropyBits(password: string): number {
  if (!password) return 0;
  const poolSize = classifyPasswordPoolSize(password);
  if (poolSize <= 1) return 0;
  return password.length * Math.log2(poolSize);
}

// ---------------------------------------------------------------------------------------------
// Temps de cassage estimé — affiché à côté de l'entropie. Le temps réel dépend ÉNORMÉMENT de la
// cible (comment LE SITE tiers stocke le mot de passe, pas cette app) : un hachage lent type
// bcrypt/Argon2 change tout par rapport à un hachage rapide voire un mot de passe en clair. Trois
// scénarios de référence plutôt qu'un seul chiffre trompeur.
// ---------------------------------------------------------------------------------------------

export interface CrackScenario {
  key: string;
  label: string;
  guessesPerSecond: number;
}

export const CRACK_SCENARIOS: CrackScenario[] = [
  { key: "online", label: "En ligne (site limité, ~100 essais/s)", guessesPerSecond: 1e2 },
  { key: "offline-slow", label: "Hors ligne, hachage lent type bcrypt/Argon2 (~10 000 essais/s)", guessesPerSecond: 1e4 },
  { key: "offline-fast", label: "Hors ligne, hachage rapide sur GPU (~10 milliards essais/s)", guessesPerSecond: 1e10 },
];

/** Temps MOYEN attendu pour retrouver le mot de passe par force brute — la moitié de l'espace de
 * recherche en moyenne, pas le pire cas (qui doublerait ce chiffre, sans changer grand-chose vu
 * l'ordre de grandeur en jeu). */
export function estimateCrackTimeSeconds(entropyBits: number, guessesPerSecond: number): number {
  if (entropyBits <= 0 || guessesPerSecond <= 0) return 0;
  const totalGuesses = Math.pow(2, entropyBits);
  return totalGuesses / (2 * guessesPerSecond);
}

interface DurationUnit {
  seconds: number;
  singular: string;
  plural: string;
}

const DURATION_UNITS: DurationUnit[] = [
  { seconds: 3_155_760_000, singular: "siècle", plural: "siècles" },
  { seconds: 31_557_600, singular: "an", plural: "ans" },
  { seconds: 2_629_800, singular: "mois", plural: "mois" },
  { seconds: 86_400, singular: "jour", plural: "jours" },
  { seconds: 3_600, singular: "heure", plural: "heures" },
  { seconds: 60, singular: "minute", plural: "minutes" },
  { seconds: 1, singular: "seconde", plural: "secondes" },
];

/** Formatte une durée en secondes vers l'unité la plus lisible ("3 jours", "2 siècles"...). Au-delà
 * d'un million de siècles, un compte en toutes lettres devient illisible et sans intérêt pratique
 * (le nombre exact de zéros n'apporte rien) — bascule en ordre de grandeur ("~10*42 ans"). */
export function formatCrackTime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 1) return "instantané";

  for (const unit of DURATION_UNITS) {
    if (seconds >= unit.seconds) {
      const value = seconds / unit.seconds;
      if (unit.singular === "siècle" && value > 1_000_000) {
        const exponent = Math.floor(Math.log10(seconds / 31_557_600));
        return `> 10*${exponent} ans`;
      }
      const rounded = value >= 100 ? Math.round(value) : Math.round(value * 10) / 10;
      const label = rounded > 1 ? unit.plural : unit.singular;
      return `${rounded.toLocaleString("fr-FR")} ${label}`;
    }
  }
  return "instantané";
}

export interface EntropyRating {
  label: string;
  // Classes Tailwind écrites en toutes lettres (pas construites/dérivées à l'exécution) : le
  // scanner Tailwind repère les noms de classe littéralement présents dans le code source, il
  // n'exécute rien — une classe assemblée via .replace()/template au runtime ne serait jamais
  // générée et le composant se retrouverait sans style.
  textClass: string;
  barClass: string;
}

// Sous "Raisonnable" (voir rateEntropy ci-dessous) — "Faible"/"Très faible". Partagé entre
// VaultHealthModal.tsx (tableau de bord) et Vault.tsx (filtre rapide "Faibles") pour que les deux
// désignent exactement le même ensemble d'entrées.
export const WEAK_THRESHOLD_BITS = 36;

/** Seuils usuels (repris de la littérature courante sur la force des mots de passe) : en dessous
 * de 28 bits un mot de passe se casse en quelques heures sur du matériel grand public, au-dessus
 * de 128 bits il est hors de portée de toute attaque par force brute envisageable. */
export function rateEntropy(bits: number): EntropyRating {
  if (bits < 28) return { label: "Très faible", textClass: "text-red-600 dark:text-red-400", barClass: "bg-red-600 dark:bg-red-400" };
  if (bits < 36) return { label: "Faible", textClass: "text-orange-600 dark:text-orange-400", barClass: "bg-orange-600 dark:bg-orange-400" };
  if (bits < 60) return { label: "Raisonnable", textClass: "text-yellow-600 dark:text-yellow-400", barClass: "bg-yellow-600 dark:bg-yellow-400" };
  if (bits < 128) return { label: "Forte", textClass: "text-emerald-600 dark:text-emerald-400", barClass: "bg-emerald-600 dark:bg-emerald-400" };
  return { label: "Excellente", textClass: "text-emerald-700 dark:text-emerald-300", barClass: "bg-emerald-700 dark:bg-emerald-300" };
}
