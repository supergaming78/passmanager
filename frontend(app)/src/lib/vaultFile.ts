// Import/export du coffre via un fichier local — voir l'avertissement affiché à l'utilisateur
// côté UI (ImportExportBar.tsx) : contrairement à tout le reste de cette app, ce fichier N'EST PAS
// chiffré par défaut une fois sur disque — c'est le prix à payer pour un format portable,
// réutilisable comme sauvegarde ou pour migrer vers un autre outil. Une protection par mot de
// passe SÉPARÉ (voir exportEntriesToFile/pickImportFile) reste possible pour qui veut éviter ça.
//
// EXPORT : trois formats au choix — JSON (le plus fiable pour un ré-import), TXT (lisible/éditable
// à la main, notre propre mise en forme) et CSV (compatibilité avec d'autres outils qui n'acceptent
// que ça).
//
// IMPORT : beaucoup plus tolérant, pour pouvoir relire aussi bien nos propres exports (même
// modifiés à la main) que ceux d'autres outils, sans que l'utilisateur ait à préciser quoi que ce
// soit — tout est détecté depuis l'extension et le contenu du fichier :
//   - notre JSON/TXT/CSV, avec des noms de champs/étiquettes en alias (site/nom/titre,
//     mdp/password, identifiant/username, ...), insensibles à la casse et aux accents ;
//   - un export Bitwarden non chiffré (JSON, structure `{ items: [...] }`) ;
//   - un CSV avec ligne d'en-tête, comme en exportent Chrome/Edge, Firefox, LastPass, KeePass ou
//     1Password (colonnes reconnues automatiquement, même sans colonne "nom" — dans ce cas le nom
//     du site est dérivé de l'URL ; pour 1Password, seules les entrées de type "Login" sont
//     importées, les autres types — notes sécurisées, cartes, identités... — sont ignorés
//     silencieusement, voir NON_LOGIN_TYPE_HINTS) ;
//   - un vieux format "une ligne = une entrée" du type `mot de passe : site` (sans étiquette),
//     tel qu'une ancienne version maison de cette app pouvait l'écrire ;
//   - un export chiffré produit par cette même app (voir ENCRYPTED_EXPORT_MAGIC ci-dessous).

import { save, open } from "@tauri-apps/plugin-dialog";
import { writeTextFile, readTextFile, readDir, remove } from "@tauri-apps/plugin-fs";
import { join } from "@tauri-apps/api/path";
import * as tauri from "../api/tauri";
import { normalizeEntryType, parseExtraFields, type PlainVaultEntry } from "./vaultCrypto";
import { withFocusLossLockSuppressed } from "./focusLossLockSuppression";

// "updatedAt"/"version"/"hasAttachments" exclus : métadonnées serveur (dernière modification,
// compteur de conflit d'édition, présence de pièce jointe), sans rapport avec l'import/export de
// contenu — un fichier importé n'a ni "dernière modification" ni "version" ni pièce jointe côté
// serveur avant d'y être ajouté (les pièces jointes elles-mêmes ne sont de toute façon jamais
// incluses dans l'export de fichier, voir plus bas).
export type ExportableEntry = Omit<PlainVaultEntry, "id" | "updatedAt" | "version" | "hasAttachments">;
export type FileFormat = "json" | "txt" | "csv";

// DOIT rester identique à ENCRYPTED_EXPORT_MAGIC dans src-tauri/src/crypto.rs — c'est ce marqueur
// qui permet à l'import de reconnaître un export chiffré sans avoir à deviner le format.
const ENCRYPTED_EXPORT_MAGIC = "PMVAULT-ENC-V1";

// Marqueur des sauvegardes chiffrées AUTOMATIQUES (voir lib/autoBackup.ts) — distinct
// d'ENCRYPTED_EXPORT_MAGIC ci-dessus : celles-ci sont chiffrées avec la clé du COFFRE déjà
// déverrouillée (tauri.encryptField/decryptField), pas avec un mot de passe d'export séparé —
// aucune saisie de mot de passe au moment d'écrire OU de relire une sauvegarde automatique,
// puisque l'app peut la déchiffrer elle-même dès que le coffre est déverrouillé.
const BACKUP_MAGIC = "PMVAULT-BACKUP-V1";
const BACKUP_FILENAME_PREFIX = "coffre-sauvegarde-";

const TXT_BLOCK_SEPARATOR = "\n---\n";
const TXT_LABELS = {
  siteName: "Site",
  username: "Identifiant",
  loginEmail: "Email",
  password: "Mot de passe",
  preferredLoginType: "Méthode préférée",
  isFavorite: "Favori",
  folder: "Dossier",
  notes: "Notes",
  url: "URL",
  entryType: "Type d'entrée",
  extraFields: "Champs additionnels",
} as const;

function formatAsJson(entries: ExportableEntry[]): string {
  return JSON.stringify(entries, null, 2);
}

function formatAsTxt(entries: ExportableEntry[]): string {
  return entries
    .map((e) =>
      [
        `${TXT_LABELS.siteName}: ${e.siteName}`,
        `${TXT_LABELS.url}: ${e.url}`,
        `${TXT_LABELS.username}: ${e.username}`,
        `${TXT_LABELS.loginEmail}: ${e.loginEmail}`,
        `${TXT_LABELS.password}: ${e.password}`,
        `${TXT_LABELS.preferredLoginType}: ${e.preferredLoginType === "email" ? "email" : "identifiant"}`,
        `${TXT_LABELS.isFavorite}: ${e.isFavorite ? "oui" : "non"}`,
        `${TXT_LABELS.folder}: ${e.folder}`,
        `${TXT_LABELS.notes}: ${e.notes}`,
        `${TXT_LABELS.entryType}: ${e.entryType}`,
        ...(Object.keys(e.extraFields).length > 0 ? [`${TXT_LABELS.extraFields}: ${JSON.stringify(e.extraFields)}`] : []),
      ].join("\n"),
    )
    .join(TXT_BLOCK_SEPARATOR);
}

// CORRECTIF SÉCURITÉ (injection de formule CSV) : une valeur commençant par =, +, -, @ ou une
// tabulation est interprétée comme une FORMULE par Excel/LibreOffice à l'ouverture du fichier —
// pas juste comme du texte — ce qui peut exécuter du code (DDE) ou exfiltrer des données
// (=HYPERLINK(...)). Un champ de coffre (notes, nom de site...) peut contenir n'importe quel texte,
// y compris venu d'un IMPORT non fiable ou d'une entrée reçue par PARTAGE (voir
// lib/entrySharing.ts, contenu choisi par un AUTRE utilisateur) — jamais garanti inoffensif.
const FORMULA_TRIGGER_PATTERN = /^[=+\-@\t]/;

/** Échappe une valeur pour un champ CSV (RFC4180) : entre guillemets si elle contient une virgule,
 * un guillemet ou un saut de ligne, avec les guillemets internes doublés — et neutralise une
 * éventuelle interprétation comme formule (voir FORMULA_TRIGGER_PATTERN) en préfixant d'une
 * apostrophe, la convention standard reconnue par Excel/LibreOffice pour forcer un contenu à être
 * traité comme du texte brut. */
function csvEscape(value: string): string {
  const safeValue = FORMULA_TRIGGER_PATTERN.test(value) ? `'${value}` : value;
  if (/[",\r\n]/.test(safeValue)) {
    return `"${safeValue.replace(/"/g, '""')}"`;
  }
  return safeValue;
}

const CSV_COLUMNS = [
  "site",
  "url",
  "username",
  "email",
  "password",
  "preferredLoginType",
  "favorite",
  "folder",
  "notes",
  "entrytype",
  "extrafields",
] as const;

function formatAsCsv(entries: ExportableEntry[]): string {
  const rows = entries.map((e) =>
    [
      e.siteName,
      e.url,
      e.username,
      e.loginEmail,
      e.password,
      e.preferredLoginType,
      e.isFavorite ? "true" : "false",
      e.folder,
      e.notes,
      e.entryType,
      Object.keys(e.extraFields).length > 0 ? JSON.stringify(e.extraFields) : "",
    ]
      .map(csvEscape)
      .join(","),
  );
  return [CSV_COLUMNS.join(","), ...rows].join("\r\n");
}

/** Ouvre la boîte de dialogue "Enregistrer sous" et écrit les entrées fournies (déjà filtrées
 * par l'appelant — voir ImportExportBar.tsx pour la sélection) au format choisi. Renvoie `false`
 * si l'utilisateur annule (pas une erreur). Si `encryptWithPassword` est fourni, le contenu est
 * chiffré (voir src-tauri/src/crypto.rs::encrypt_export_content) AVANT d'être écrit sur disque —
 * avec un mot de passe distinct du mot de passe maître, pour ne jamais avoir à le saisir dans un
 * contexte "juste pour un export". */
export async function exportEntriesToFile(entries: ExportableEntry[], format: FileFormat, encryptWithPassword?: string): Promise<boolean> {
  const extension = format;
  const formatName = format === "json" ? "JSON" : format === "csv" ? "CSV" : "Texte";
  // Suspend le verrouillage par perte de focus (voir focusLossLockSuppression.ts) : ce dialogue
  // natif fait perdre le focus à la fenêtre principale le temps de choisir un emplacement, ce
  // n'est pas un abandon de l'app.
  const path = await withFocusLossLockSuppressed(() =>
    save({
      title: "Exporter le coffre",
      defaultPath: `coffre-export.${extension}`,
      filters: [{ name: formatName, extensions: [extension] }],
    }),
  );
  if (!path) return false;

  let content = format === "json" ? formatAsJson(entries) : format === "csv" ? formatAsCsv(entries) : formatAsTxt(entries);
  if (encryptWithPassword) {
    content = await tauri.encryptExportContent(content, encryptWithPassword);
  }
  await writeTextFile(path, content);
  return true;
}

// ---------------------------------------------------------------------------------------------
// SAUVEGARDE AUTOMATIQUE — voir lib/autoBackup.ts pour la logique de déclenchement/planification ;
// ce qui suit n'est que l'écriture/le nettoyage des fichiers eux-mêmes, sans dialogue utilisateur
// (le dossier de destination est choisi une fois pour toutes dans Réglages, voir
// components/AutoBackupSettings.tsx).
// ---------------------------------------------------------------------------------------------

/** Écrit une sauvegarde chiffrée automatique dans `folderPath` — JSON chiffré avec la clé du
 * coffre actuellement déverrouillée (voir BACKUP_MAGIC), donc jamais de mot de passe séparé à
 * saisir ni à retenir. Nom de fichier horodaté (jamais réutilisé) pour ne jamais écraser une
 * sauvegarde précédente — le nettoyage des plus anciennes est séparé, voir pruneOldBackups(). */
export async function writeAutoBackup(entries: ExportableEntry[], folderPath: string): Promise<void> {
  const encrypted = await tauri.encryptField(formatAsJson(entries));
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const path = await join(folderPath, `${BACKUP_FILENAME_PREFIX}${timestamp}.json`);
  await writeTextFile(path, `${BACKUP_MAGIC}\n${encrypted}`);
}

/** Supprime les sauvegardes automatiques les plus anciennes dans `folderPath` au-delà de `keep`
 * exemplaires — évite une accumulation illimitée de fichiers au fil du temps. Reconnaît un
 * fichier de sauvegarde par son préfixe/extension de nom, pas besoin de lire son contenu pour ça.
 * Best-effort : une erreur sur un fichier individuel (déjà supprimé, permissions...) n'interrompt
 * pas le nettoyage des autres. */
export async function pruneOldBackups(folderPath: string, keep = 5): Promise<void> {
  const dirEntries = await readDir(folderPath);
  const backupNames = dirEntries
    .filter((e) => e.isFile && e.name.startsWith(BACKUP_FILENAME_PREFIX) && e.name.endsWith(".json"))
    .map((e) => e.name)
    // Le nom encode l'horodatage ISO (avec ":"/"." remplacés par "-") -> le tri alphabétique
    // correspond exactement au tri chronologique.
    .sort();
  const toDelete = backupNames.slice(0, Math.max(0, backupNames.length - keep));
  await Promise.all(
    toDelete.map(async (name) => {
      const path = await join(folderPath, name);
      await remove(path).catch(() => {});
    }),
  );
}

// ---------------------------------------------------------------------------------------------
// IMPORT — reconnaissance de champs par alias, indépendante du format d'origine.
// ---------------------------------------------------------------------------------------------

const DIACRITICS_PATTERN = /[̀-ͯ]/g;

/** Ramène un nom de champ/étiquette à une forme comparable : minuscules, sans accents, sans
 * espaces/ponctuation. "Mot de passe", "mot_de_passe" et "MotDePasse" deviennent tous
 * "motdepasse" — ce qui permet de reconnaître le même champ quel que soit le style d'écriture. */
function normalizeKey(key: string): string {
  return key
    .normalize("NFD")
    .replace(DIACRITICS_PATTERN, "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

const ALIASES = {
  siteName: ["sitename", "site", "name", "title", "nom", "titre", "service", "application", "app"],
  url: ["url", "uri", "website", "lien", "loginuri", "loginurl", "webaddress"],
  username: ["username", "user", "userid", "login", "identifiant", "utilisateur"],
  loginEmail: ["loginemail", "email", "mail", "courriel", "adresseemail"],
  password: ["password", "pass", "pwd", "passwd", "motdepasse", "mdp"],
  preferredLoginType: ["preferredlogintype", "logintype", "methode", "methodepreferee", "preferredmethod"],
  isFavorite: ["isfavorite", "favorite", "favori", "fav", "star", "starred"],
  folder: ["folder", "dossier", "category", "categorie", "group", "grouping", "collection"],
  notes: ["notes", "note", "comment", "comments", "commentaire", "commentaires", "extra", "remarque", "remarques"],
  // Distincts de TYPE_ALIASES plus bas (qui sert à autre chose : repérer et IGNORER les objets non-
  // Login d'un export Bitwarden/1Password, voir looksLikeNonLoginRecord) — "type"/"category" restent
  // réservés à cet usage, donc ces alias-ci sont volontairement différents pour ne jamais les confondre.
  entryType: ["entrytype", "typeentree", "entrykind"],
  extraFields: ["extrafields", "champsadditionnels", "champssupplementaires", "champsupplementaire"],
};

/** Normalisation "douce" — accents et casse en moins, mais SANS retirer la ponctuation interne —
 * utilisée uniquement pour reconnaître une étiquette écrite à la main ("Site", "Mot de passe"...).
 * Contrairement à normalizeKey() (utilisée pour l'appariement d'alias JSON/CSV), elle ne doit
 * jamais confondre un mot de passe contenant deux-points/símboles avec une étiquette : normalizeKey
 * réduirait par exemple "pass:word" à "password", qui ressemble à tort à l'étiquette du champ mot
 * de passe. */
function softNormalizeLabel(value: string): string {
  return value
    .normalize("NFD")
    .replace(DIACRITICS_PATTERN, "")
    .toLowerCase()
    .trim();
}

const KNOWN_LABEL_TEXTS = new Set(
  [
    "site",
    "nom",
    "titre",
    "name",
    "title",
    "service",
    "application",
    "app",
    "identifiant",
    "username",
    "user",
    "login",
    "utilisateur",
    "email",
    "mail",
    "courriel",
    "mot de passe",
    "password",
    "pass",
    "pwd",
    "mdp",
    "methode preferee",
    "preferred login type",
    "favori",
    "favorite",
    "fav",
    "dossier",
    "folder",
    "notes",
    "note",
    "url",
    "uri",
    "lien",
    "website",
  ].map(softNormalizeLabel),
);

// Exportées : réutilisées par lib/entrySharing.ts pour valider le contenu d'une entrée reçue par
// partage (JSON désérialisé venu d'un AUTRE utilisateur, jamais garanti bien typé), même besoin de
// coercition "tolérante" qu'ici pour un fichier importé.
export function asStr(value: unknown): string {
  if (typeof value === "string") return value.trim();
  if (typeof value === "number") return String(value);
  return "";
}

export function asBool(value: unknown): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value !== 0;
  if (typeof value === "string") {
    const v = value.trim().toLowerCase();
    return v === "true" || v === "1" || v === "oui" || v === "yes" || v === "y";
  }
  return false;
}

function findAlias(record: Record<string, unknown>, aliases: string[]): unknown {
  for (const alias of aliases) {
    if (alias in record) return record[alias];
  }
  return undefined;
}

// Colonne type/catégorie (PAS un champ de ExportableEntry, donc à part de ALIASES ci-dessus) — sert
// uniquement à repérer les lignes CSV à ignorer, voir looksLikeNonLoginRecord() plus bas.
const TYPE_ALIASES = ["type", "category", "itemtype", "categorie"];

// 1Password (entre autres) exporte souvent plusieurs types d'objets dans un même CSV (Login,
// Secure Note, Credit Card, Identity, ...) — sans filtrage, une ligne "Secure Note" (sans mot de
// passe) ferait échouer TOUT l'import via buildEntryFromRecord() plus bas, à l'identique de
// n'importe quelle ligne mal formée. Liste DÉNYLIST (types explicitement exclus) plutôt qu'une
// allowlist ("Login" uniquement) : un intitulé de type qu'on ne reconnaît pas (localisation,
// nouvelle catégorie...) continue d'être traité comme avant ce filtre, plutôt que rejeté à tort.
const NON_LOGIN_TYPE_HINTS = new Set(
  [
    "securenote", "note", "creditcard", "card", "identity", "bankaccount", "database",
    "driverlicense", "emailaccount", "membership", "outdoorlicense", "passport",
    "rewardprogram", "server", "socialsecuritynumber", "ssn", "softwarelicense",
    "wirelessrouter", "apicredential", "sshkey", "cryptowallet", "document", "medicalrecord",
  ].map(normalizeKey),
);

/** Vrai si l'enregistrement porte une colonne type/catégorie dont la valeur est reconnue comme
 * n'étant PAS un identifiant de connexion (voir NON_LOGIN_TYPE_HINTS) — sert à ignorer
 * silencieusement ces lignes plutôt que de faire échouer tout l'import, même principe que le
 * filtrage par bloc `login` dans parseBitwardenItems() ci-dessous, pour les CSV multi-types
 * (1Password). Sans colonne type/catégorie reconnue (Chrome, Firefox, LastPass, KeePass...),
 * renvoie toujours faux — aucun changement de comportement pour ces formats. */
function looksLikeNonLoginRecord(rawRecord: Record<string, unknown>): boolean {
  const normalized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(rawRecord)) {
    normalized[normalizeKey(key)] = value;
  }
  const typeValue = normalizeKey(asStr(findAlias(normalized, TYPE_ALIASES)));
  return typeValue !== "" && NON_LOGIN_TYPE_HINTS.has(typeValue);
}

/** Quand aucun nom de site n'est fourni (cas fréquent des exports de navigateur, qui n'ont
 * souvent qu'une URL), on se rabat sur le nom d'hôte de l'URL — plus lisible qu'un lien complet. */
function deriveSiteNameFromUrl(rawUrl: string): string {
  if (!rawUrl) return "";
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`;
    return new URL(withScheme).hostname.replace(/^www\./, "");
  } catch {
    return rawUrl;
  }
}

/** Construit une entrée à partir d'un enregistrement "clé -> valeur" quelconque (ligne CSV, objet
 * JSON, bloc TXT, item Bitwarden aplati...) en reconnaissant les champs par alias. Lève une Error
 * explicite si le site ou le mot de passe est introuvable — jamais d'import silencieux d'une
 * entrée incomplète. */
function buildEntryFromRecord(rawRecord: Record<string, unknown>, index: number, sourceLabel: string): ExportableEntry {
  const record: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(rawRecord)) {
    record[normalizeKey(key)] = value;
  }

  const siteNameField = asStr(findAlias(record, ALIASES.siteName));
  const urlField = asStr(findAlias(record, ALIASES.url));
  const siteName = siteNameField || deriveSiteNameFromUrl(urlField);
  const password = asStr(findAlias(record, ALIASES.password));

  if (!siteName) throw new Error(`${sourceLabel} — entrée #${index + 1} : aucun nom de site ni URL exploitable.`);
  if (!password) throw new Error(`${sourceLabel} — entrée #${index + 1} (${siteName}) : mot de passe manquant.`);

  let username = asStr(findAlias(record, ALIASES.username));
  let loginEmail = asStr(findAlias(record, ALIASES.loginEmail));
  // Beaucoup d'exports n'ont qu'un seul champ identifiant (pas de distinction username/email) —
  // s'il ressemble à une adresse email, on le range comme tel plutôt que comme "identifiant".
  if (!loginEmail && username.includes("@")) {
    loginEmail = username;
    username = "";
  }

  // "entryType"/"extraFields" : uniquement présents dans un export produit par CETTE app (voir
  // ALIASES.entryType/extraFields plus haut, volontairement distincts de TYPE_ALIASES) — absents
  // d'un CSV Chrome/Bitwarden/1Password, ce qui retombe naturellement sur "login"/{} ci-dessous,
  // comportement identique à avant l'existence des types dédiés.
  const entryType = normalizeEntryType(asStr(findAlias(record, ALIASES.entryType)));
  const extraFieldsRaw = asStr(findAlias(record, ALIASES.extraFields));
  const extraFields = parseExtraFields(extraFieldsRaw);

  const preferredRaw = normalizeKey(asStr(findAlias(record, ALIASES.preferredLoginType)));
  const preferredLoginType: "username" | "email" =
    preferredRaw === "email" || preferredRaw === "mail"
      ? "email"
      : preferredRaw === "username" || preferredRaw === "identifiant"
        ? "username"
        : loginEmail && !username
          ? "email"
          : "username";

  return {
    siteName,
    username,
    loginEmail,
    password,
    preferredLoginType,
    isFavorite: asBool(findAlias(record, ALIASES.isFavorite)),
    folder: asStr(findAlias(record, ALIASES.folder)),
    notes: asStr(findAlias(record, ALIASES.notes)),
    url: urlField,
    entryType,
    extraFields,
  };
}

// ---------------------------------------------------------------------------------------------
// IMPORT — sélection et lecture du fichier, détection du format.
// ---------------------------------------------------------------------------------------------

/** Résultat de pickImportFile() : soit des entrées déjà lisibles, soit un fichier chiffré qui
 * attend un mot de passe (voir decryptAndParseImportFile()) — l'appelant (ImportExportBar.tsx)
 * doit alors afficher un champ mot de passe avant de pouvoir continuer. */
export type PickedImportFile = { kind: "entries"; entries: ExportableEntry[] } | { kind: "encrypted"; rawContent: string };

/** Ouvre la boîte de dialogue "Ouvrir" (JSON, CSV, TXT, ou export chiffré produit par cette même
 * app), lit et parse le fichier. Renvoie `null` si l'utilisateur annule. Lève une Error avec un
 * message explicite si le fichier n'a pas une forme reconnaissable — jamais d'import partiel
 * silencieux d'un fichier mal formé. */
export async function pickImportFile(): Promise<PickedImportFile | null> {
  // Voir le commentaire équivalent dans exportEntriesToFile() ci-dessus.
  const path = await withFocusLossLockSuppressed(() =>
    open({
      title: "Importer des mots de passe",
      multiple: false,
      filters: [{ name: "JSON, CSV, Texte ou export chiffré", extensions: ["json", "csv", "txt"] }],
    }),
  );
  if (!path || Array.isArray(path)) return null;

  const content = await readTextFile(path);

  // Sauvegarde automatique (voir BACKUP_MAGIC) : déchiffrement TRANSPARENT via la clé du coffre
  // déjà déverrouillée, aucun mot de passe à demander — contrairement au cas ENCRYPTED_EXPORT_MAGIC
  // juste en dessous, qui utilise un mot de passe d'export séparé saisi par l'utilisateur.
  if (content.startsWith(BACKUP_MAGIC)) {
    const encrypted = content.slice(BACKUP_MAGIC.length + 1); // +1 : saute le "\n" séparateur
    const decrypted = await tauri.decryptField(encrypted);
    return { kind: "entries", entries: parseByContentSniffing(decrypted) };
  }
  if (content.startsWith(ENCRYPTED_EXPORT_MAGIC)) {
    return { kind: "encrypted", rawContent: content };
  }

  const lowerPath = path.toLowerCase();
  const trimmed = content.trimStart();

  if (lowerPath.endsWith(".csv")) return { kind: "entries", entries: parseCsvEntries(content) };
  if (lowerPath.endsWith(".json")) return { kind: "entries", entries: parseJsonEntries(content) };
  if (lowerPath.endsWith(".txt")) {
    return {
      kind: "entries",
      entries: trimmed.startsWith("[") || trimmed.startsWith("{") ? parseJsonEntries(content) : parseTxtEntries(content),
    };
  }

  // Extension absente/inconnue (rare vu le filtre du dialogue) : on devine depuis le contenu.
  return { kind: "entries", entries: parseByContentSniffing(content) };
}

function parseByContentSniffing(content: string): ExportableEntry[] {
  const trimmed = content.trimStart();
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) return parseJsonEntries(content);
  if (looksLikeCsvHeader(content)) return parseCsvEntries(content);
  return parseTxtEntries(content);
}

/** Déchiffre puis parse un fichier repéré comme chiffré par pickImportFile() (voir
 * PickedImportFile.rawContent) — appelée une fois que l'utilisateur a saisi le mot de passe
 * d'export dans l'UI. Le format du contenu déchiffré (JSON/TXT/CSV) est détecté de la même façon
 * que pour un fichier sans extension reconnue, puisqu'il n'y a plus d'extension de fichier à ce
 * stade — juste du texte en mémoire. */
export async function decryptAndParseImportFile(rawContent: string, password: string): Promise<ExportableEntry[]> {
  const decrypted = await tauri.decryptExportContent(rawContent, password);
  return parseByContentSniffing(decrypted);
}

function looksLikeCsvHeader(content: string): boolean {
  const firstLine = content.split(/\r?\n/, 1)[0] ?? "";
  if (!firstLine.includes(",")) return false;
  const columns = firstLine.split(",").map(normalizeKey);
  return columns.some((c) => ALIASES.password.includes(c));
}

/** JSON — accepte soit notre propre format (tableau d'entrées, avec alias de champs), soit un
 * export Bitwarden non chiffré (`{ items: [...] }`). */
function parseJsonEntries(content: string): ExportableEntry[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new Error("Ce fichier n'est pas du JSON valide.");
  }

  if (Array.isArray(parsed)) {
    if (parsed.length === 0) throw new Error("Le fichier ne contient aucune entrée.");
    return parsed.map((raw, index) => {
      if (typeof raw !== "object" || raw === null) {
        throw new Error(`Entrée #${index + 1} : format invalide (attendu un objet).`);
      }
      return buildEntryFromRecord(raw as Record<string, unknown>, index, "JSON");
    });
  }

  if (typeof parsed === "object" && parsed !== null && Array.isArray((parsed as Record<string, unknown>).items)) {
    const root = parsed as Record<string, unknown>;
    return parseBitwardenItems(root.items as unknown[], Array.isArray(root.folders) ? (root.folders as unknown[]) : []);
  }

  throw new Error("Structure JSON non reconnue (ni tableau d'entrées, ni export Bitwarden).");
}

/** Export Bitwarden non chiffré : `items[].login.{username,password,uris[].uri}`. On ne garde que
 * les items qui ont bien un bloc `login` — les notes sécurisées, cartes et identités Bitwarden ne
 * correspondent à rien dans notre coffre et sont ignorées silencieusement (pas une erreur : c'est
 * attendu qu'un export Bitwarden contienne d'autres types d'éléments). `folders` (le tableau
 * top-level de l'export, `{id, name}`) sert à résoudre `item.folderId` en un nom de dossier lisible
 * — Bitwarden ne stocke que la référence sur l'item lui-même. */
function parseBitwardenItems(items: unknown[], folders: unknown[]): ExportableEntry[] {
  const folderNameById = new Map<string, string>();
  for (const f of folders) {
    if (typeof f === "object" && f !== null) {
      const { id, name } = f as Record<string, unknown>;
      if (typeof id === "string" && typeof name === "string") folderNameById.set(id, name);
    }
  }

  const loginItems = items.filter(
    (item): item is Record<string, unknown> =>
      typeof item === "object" &&
      item !== null &&
      typeof (item as Record<string, unknown>).login === "object" &&
      (item as Record<string, unknown>).login !== null,
  );
  if (loginItems.length === 0) {
    throw new Error("Aucune entrée de connexion trouvée dans cet export Bitwarden.");
  }

  return loginItems.map((item, index) => {
    const login = item.login as Record<string, unknown>;
    const uris = Array.isArray(login.uris) ? (login.uris as Record<string, unknown>[]) : [];
    const firstUri = uris.length > 0 && typeof uris[0].uri === "string" ? (uris[0].uri as string) : "";
    const folder = typeof item.folderId === "string" ? (folderNameById.get(item.folderId) ?? "") : "";

    return buildEntryFromRecord(
      {
        name: item.name,
        username: login.username,
        password: login.password,
        url: firstUri,
        favorite: item.favorite,
        folder,
        notes: item.notes,
      },
      index,
      "Bitwarden",
    );
  });
}

/** Parseur CSV minimal (RFC4180) : gère les champs entre guillemets, les guillemets échappés
 * (`""`) et les valeurs contenant des virgules. Suffisant pour les exports Chrome/Edge, Firefox,
 * LastPass ou KeePass, qui sont tous de simples CSV avec ligne d'en-tête. */
function parseCsvRows(content: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;

  for (let i = 0; i < content.length; i++) {
    const char = content[i];

    if (inQuotes) {
      if (char === '"') {
        if (content[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += char;
      }
      continue;
    }

    if (char === '"') {
      inQuotes = true;
    } else if (char === ",") {
      row.push(field);
      field = "";
    } else if (char === "\r") {
      // ignoré, la fin de ligne est gérée via \n
    } else if (char === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else {
      field += char;
    }
  }
  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }

  return rows.filter((r) => r.some((cell) => cell.trim() !== ""));
}

function parseCsvEntries(content: string): ExportableEntry[] {
  const rows = parseCsvRows(content);
  if (rows.length === 0) throw new Error("Le fichier CSV est vide.");

  const header = rows[0];
  const dataRows = rows.slice(1);
  if (dataRows.length === 0) throw new Error("Le fichier CSV ne contient aucune ligne de données.");

  const records = dataRows.map((cells) => {
    const record: Record<string, unknown> = {};
    header.forEach((key, colIndex) => {
      record[key] = cells[colIndex] ?? "";
    });
    return record;
  });

  // Voir looksLikeNonLoginRecord() : ignore silencieusement les lignes explicitement identifiées
  // comme un autre type d'objet (notes sécurisées, cartes...) — un CSV mono-type (Chrome, LastPass,
  // KeePass...) n'a de toute façon pas de colonne type/catégorie reconnue, donc rien n'est filtré.
  const loginRecords = records.filter((record) => !looksLikeNonLoginRecord(record));
  if (loginRecords.length === 0) {
    throw new Error("Aucune entrée de connexion trouvée dans ce fichier CSV (uniquement des types non pris en charge, ex. notes sécurisées ou cartes).");
  }

  return loginRecords.map((record, index) => buildEntryFromRecord(record, index, "CSV"));
}

/** TXT — notre propre mise en forme (voir formatAsTxt), en version tolérante : le séparateur de
 * blocs peut être une ligne "---", "===", "***"/"___" (au moins 3 caractères identiques) ou
 * simplement une ligne vide si aucun séparateur explicite n'est présent ; les étiquettes sont
 * reconnues par alias comme pour le JSON/CSV (français, anglais, avec ou sans accents/casse). */
function splitTxtBlocks(content: string): string[] {
  const separatorPattern = /^[-=*_]{3,}$/;
  const lines = content.split(/\r?\n/);
  const hasExplicitSeparator = lines.some((line) => separatorPattern.test(line.trim()));
  const isBoundary = hasExplicitSeparator
    ? (line: string) => separatorPattern.test(line.trim())
    : (line: string) => line.trim() === "";

  const blocks: string[] = [];
  let current: string[] = [];
  for (const line of lines) {
    if (isBoundary(line)) {
      if (current.some((l) => l.trim())) blocks.push(current.join("\n"));
      current = [];
    } else {
      current.push(line);
    }
  }
  if (current.some((l) => l.trim())) blocks.push(current.join("\n"));

  return blocks.map((b) => b.trim()).filter((b) => b.length > 0);
}

// Vieux format "une ligne = une entrée", sans étiquette : `mot de passe : site` (ex. une ancienne
// version, moins aboutie, de cette même app). Se distingue de notre format normal en ce que la
// partie avant les deux-points n'est PAS une étiquette reconnue (Site/Password/...) mais déjà la
// valeur du mot de passe lui-même.
//
// Le séparateur exigé est bien " : " — un espace de chaque côté des deux-points — car le mot de
// passe lui-même peut contenir un ":" (ex. "pass:word : bricks"). Sans cette exigence d'espaces,
// on coupait au premier ":" venu, qui pouvait tomber EN PLEIN MILIEU du mot de passe plutôt qu'à
// la vraie frontière mot de passe/site. Le premier groupe est gourmand (`.+` et non `.+?`), donc
// il matche la DERNIÈRE occurrence de " : " dans la ligne : un ":" sans espaces autour de lui
// (à l'intérieur du mot de passe) ne coupe jamais la ligne au mauvais endroit.
const LEGACY_LINE_PATTERN = /^(.+) +: +(.+)$/;

function looksLikeLegacyPasswordSiteLines(lines: string[]): boolean {
  if (lines.length === 0) return false;
  return lines.every((line) => {
    const match = LEGACY_LINE_PATTERN.exec(line);
    if (!match) return false;
    return !KNOWN_LABEL_TEXTS.has(softNormalizeLabel(match[1]));
  });
}

function parseLegacyPasswordSiteLine(line: string, index: number): ExportableEntry {
  const match = LEGACY_LINE_PATTERN.exec(line);
  if (!match) {
    throw new Error(`Texte (ancien format) — ligne #${index + 1} : "mot de passe : site" attendu.`);
  }
  const password = match[1].trim();
  const siteName = match[2].trim();
  if (!password) throw new Error(`Texte (ancien format) — ligne #${index + 1} : mot de passe manquant.`);
  if (!siteName) throw new Error(`Texte (ancien format) — ligne #${index + 1} : nom de site manquant.`);
  return {
    siteName,
    username: "",
    loginEmail: "",
    password,
    preferredLoginType: "username",
    isFavorite: false,
    folder: "",
    notes: "",
    url: "",
    entryType: "login",
    extraFields: {},
  };
}

function parseTxtEntries(content: string): ExportableEntry[] {
  const nonEmptyLines = content
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
  const hasBlockSeparator = nonEmptyLines.some((l) => /^[-=*_]{3,}$/.test(l));

  if (!hasBlockSeparator && looksLikeLegacyPasswordSiteLines(nonEmptyLines)) {
    return nonEmptyLines.map((line, index) => parseLegacyPasswordSiteLine(line, index));
  }

  const blocks = splitTxtBlocks(content);
  if (blocks.length === 0) {
    throw new Error("Le fichier ne contient aucune entrée reconnaissable.");
  }

  return blocks.map((block, index) => {
    const record: Record<string, unknown> = {};
    for (const line of block.split(/\r?\n/)) {
      const separatorIndex = line.indexOf(":");
      if (separatorIndex === -1) continue;
      const key = line.slice(0, separatorIndex).trim();
      const value = line.slice(separatorIndex + 1).trim();
      if (key) record[key] = value;
    }
    return buildEntryFromRecord(record, index, "Texte");
  });
}
