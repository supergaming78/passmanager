import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { useAuth } from "../state/AuthContext";
import * as api from "../api/client";
import { decryptEntries, encryptEntry, type PlainVaultEntry, type EntryType } from "../lib/vaultCrypto";
import { allSettledWithLimit } from "../lib/concurrency";
import { maybeRunAutoBackup } from "../lib/autoBackup";
import { fuzzyIncludes } from "../lib/fuzzyMatch";
import { getErrorMessage } from "../lib/errors";
import { copyPasswordWithAutoClear } from "../lib/clipboard";
import TotpCode from "../components/TotpCode";
import { openEntryUrl } from "../lib/openExternalUrl";
import { WEAK_THRESHOLD_BITS, estimatePasswordEntropyBits, rateEntropy } from "../lib/passwordGenerator";
import { OLD_PASSWORD_DAYS, daysSince, formatRelativeAge } from "../lib/age";
import { getPreferredIdentifier } from "../lib/entryIdentifier";
import VaultEntryForm, { type VaultEntryFormValues } from "../components/VaultEntryForm";
import ImportExportBar, { type ImportExportBarHandle } from "../components/ImportExportBar";
import TrashModal from "../components/TrashModal";
import VaultHealthModal from "../components/VaultHealthModal";
import VaultHistoryModal from "../components/VaultHistoryModal";
import AttachmentsModal from "../components/AttachmentsModal";
import ShareEntryModal from "../components/ShareEntryModal";
import BlindShareModal from "../components/BlindShareModal";
import BulkShareModal from "../components/BulkShareModal";
import { reseedEntryShares } from "../lib/entrySharing";
import { recordEntryUse } from "../lib/vaultUsage";
import { getEffectiveListLayout } from "../lib/listLayout";
import EntryActionsMenu from "../components/EntryActionsMenu";
import KeyboardShortcutsModal from "../components/KeyboardShortcutsModal";
import SiteAvatar from "../components/SiteAvatar";

/** Petit indicateur de force (même logique qu'au générateur/à l'import — voir lib/passwordGenerator.ts)
 * affiché directement dans la liste, pour repérer d'un coup d'œil les mots de passe faibles sans
 * avoir à ouvrir/révéler chaque entrée une par une. */
function StrengthDot({ password }: { password: string }) {
  const bits = estimatePasswordEntropyBits(password);
  if (bits <= 0) return null;
  const rating = rateEntropy(bits);
  return (
    <span
      title={`${Math.round(bits)} bits — ${rating.label}`}
      className={`inline-block h-2 w-2 shrink-0 rounded-full ${rating.barClass}`}
    />
  );
}

/** Icône par type dédié (voir lib/vaultCrypto.ts::EntryType) — remplace SiteAvatar (favicon/logo de
 * marque, qui n'a de sens que pour un login associé à un site réel) pour les 3 autres types. */
function EntryTypeIcon({ entryType }: { entryType: PlainVaultEntry["entryType"] }) {
  const emoji = entryType === "card" ? "💳" : entryType === "identity" ? "🪪" : "📝";
  return (
    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-neutral-100 text-base dark:bg-neutral-800">
      {emoji}
    </span>
  );
}

/** Regroupement AUTOMATIQUE de l'affichage par type d'entrée (voir typeSections plus bas) — retour
 * utilisateur : "je ne veux pas un filtre [...], je ne veux juste pas que les cartes bancaires
 * soient avec les mots de passe, et la même chose avec les cartes d'identité" — pas un filtre à
 * activer à la main (première tentative, écartée), une séparation systématique de l'affichage,
 * toujours active dès qu'il y a plus d'un type dans le coffre. Ordre d'affichage fixe (mots de
 * passe d'abord, le contenu le plus consulté) plutôt qu'alphabétique. Mêmes 4 types que
 * components/VaultEntryForm.tsx::TYPE_LABELS, ici seulement le nom au pluriel pour un en-tête. */
/** RENDU PROGRESSIF de la liste du coffre.
 *
 * `content-visibility: auto` (voir App.css) empêche déjà le navigateur de METTRE EN PAGE et de
 * PEINDRE les lignes hors écran, mais il ne change rien au coût en amont : React construit quand
 * même un composant et des nœuds DOM pour CHAQUE entrée, et les recompare à chaque rendu. Sur un
 * coffre proche du plafond serveur (5000 entrées), c'est ce travail-là qui rend le premier
 * affichage lourd, pas la peinture.
 *
 * On ne monte donc qu'un budget d'entrées, augmenté par paliers quand le bas de la liste approche
 * (voir le sentinelle plus bas). Choisi plutôt qu'une virtualisation "fenêtrée" classique : la
 * liste vit dans le défilement de la PAGE (pas un conteneur à hauteur fixe), s'affiche en grilles
 * multi-colonnes dont le nombre de colonnes dépend de la largeur, et s'imbrique en sections
 * (type -> dossier). Fenêtrer tout ça demanderait de mesurer hauteurs de lignes et colonnes par
 * section — beaucoup de fragilité pour un gain qui ne se manifeste qu'au-delà de quelques
 * milliers d'entrées. Le budget, lui, borne le coût réel sans toucher aux dispositions, au
 * regroupement ni à la sélection.
 *
 * Compromis assumé : après avoir déroulé tout un très grand coffre, les entrées déjà atteintes
 * restent montées (une vraie virtualisation les démonterait). `content-visibility` les garde
 * néanmoins hors du coût de mise en page. */
const INITIAL_RENDER_BUDGET = 150;
const RENDER_BUDGET_STEP = 150;

/** Compteur d'entrées restant à monter pour CE passage de rendu. Volontairement un objet mutable
 * plutôt qu'une valeur : le budget est PARTAGÉ entre toutes les sections (type, puis dossier), qui
 * sont rendues les unes après les autres — chacune doit consommer ce que la précédente a laissé.
 * Recréé à chaque rendu (voir son instanciation juste avant le `return` du composant), donc jamais
 * d'état qui traîne d'un rendu à l'autre. */
interface RenderBudget {
  remaining: number;
}

/** Prélève sur le budget partagé les entrées à monter pour une section, dans l'ordre. Une section
 * dont le budget est déjà épuisé rend une grille vide (son en-tête, lui, reste affiché avec son
 * VRAI compteur — voir renderFolderSections) : l'utilisateur voit donc que la section existe et
 * combien elle contient, et son contenu se remplit dès qu'il descend jusqu'à elle. */
function takeFromBudget(entries: PlainVaultEntry[], budget: RenderBudget): PlainVaultEntry[] {
  if (budget.remaining <= 0) return [];
  const taken = entries.slice(0, budget.remaining);
  budget.remaining -= taken.length;
  return taken;
}

const TYPE_ORDER: EntryType[] = ["login", "card", "identity", "note"];
const TYPE_SECTION_LABELS: Record<EntryType, string> = { login: "Mots de passe", card: "Cartes bancaires", identity: "Identités", note: "Notes sécurisées" };

/** Regroupe une liste d'entrées par dossier (nom du dossier en en-tête) — factorisé pour être
 * appelé soit UNE fois sur tout le coffre (pas de séparation par type, voir groupedSections),
 * soit une fois PAR section de type (voir typeSections) : même logique dans les deux cas, y
 * compris le tri des dossiers eux-mêmes par usage agrégé quand `sortBy === "usage"`. */
function groupEntriesByFolder(entries: PlainVaultEntry[], sortBy: "name" | "updated" | "strength" | "usage") {
  const groups = new Map<string, PlainVaultEntry[]>();
  for (const entry of entries) {
    const key = entry.folder;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(entry);
  }
  const named = Array.from(groups.keys())
    .filter((k) => k !== "")
    .sort((a, b) => {
      if (sortBy === "usage") {
        const usageA = groups.get(a)!.reduce((sum, e) => sum + e.useCount, 0);
        const usageB = groups.get(b)!.reduce((sum, e) => sum + e.useCount, 0);
        if (usageA !== usageB) return usageB - usageA;
      }
      return a.localeCompare(b);
    })
    .map((name) => ({ name, entries: groups.get(name)! }));
  const withoutFolder = groups.get("");
  return withoutFolder ? [...named, { name: "Sans dossier", entries: withoutFolder }] : named;
}

type ModalState = { mode: "add"; prefill?: VaultEntryFormValues } | { mode: "edit"; entry: PlainVaultEntry } | null;

export default function Vault() {
  const { authorizedRequest, subscribeToVaultSync } = useAuth();

  const [entries, setEntries] = useState<PlainVaultEntry[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  // `search` reste mis à jour à CHAQUE frappe pour que le champ de saisie reste instantané, mais
  // filteredEntries (ci-dessous) ne recalcule qu'à partir de `debouncedSearch` — sans ça, la
  // recherche floue (voir lib/fuzzyMatch.ts, un calcul de distance d'édition PAR entrée et par mot
  // quand la correspondance exacte ne trouve rien) tournerait sur CHAQUE frappe pour un coffre de
  // plusieurs milliers d'entrées, un délai perceptible pendant une saisie rapide.
  const [debouncedSearch, setDebouncedSearch] = useState("");
  useEffect(() => {
    const timeout = setTimeout(() => setDebouncedSearch(search), 150);
    return () => clearTimeout(timeout);
  }, [search]);
  // "" = tous les dossiers, "__none__" = sans dossier assigné, sinon le nom exact du dossier.
  const [folderFilter, setFolderFilter] = useState("");
  // Filtre rapide directement dans le coffre — un raccourci vers ce que le tableau de bord "Santé
  // du coffre" détaille déjà (VaultHealthModal), pour ne pas avoir à l'ouvrir juste pour retrouver
  // ces entrées-là. Un seul actif à la fois, se combine avec la recherche/le dossier/le tri.
  const [quickFilter, setQuickFilter] = useState<"" | "weak" | "reused" | "old" | "favorite" | "attachment">("");
  const [sortBy, setSortBy] = useState<"name" | "updated" | "strength" | "usage">("name");
  // Réglée dans Réglages (voir components/ListLayoutSettings.tsx) — lue une fois au montage, se
  // met à jour naturellement en revenant sur cette page (React Router démonte/remonte Vault en
  // changeant de route, voir App.tsx) sans avoir besoin d'un contexte partagé pour ça.
  const [listLayout] = useState(() => getEffectiveListLayout());
  const [modal, setModal] = useState<ModalState>(null);
  const [showTrash, setShowTrash] = useState(false);
  const [showHealth, setShowHealth] = useState(false);
  const [showShortcutsHelp, setShowShortcutsHelp] = useState(false);
  const [historyEntry, setHistoryEntry] = useState<PlainVaultEntry | null>(null);
  const [attachmentsEntry, setAttachmentsEntry] = useState<PlainVaultEntry | null>(null);
  const [sharingEntry, setSharingEntry] = useState<PlainVaultEntry | null>(null);
  const [blindSharingEntry, setBlindSharingEntry] = useState<PlainVaultEntry | null>(null);
  // Partager PLUSIEURS entrées à la fois avec un seul destinataire (voir components/BulkShareModal.tsx)
  // — retour utilisateur (2026-09-02), accessible depuis le mode "Sélectionner" ci-dessous. Un
  // tableau plutôt qu'un booléen : capture les entrées CONCERNÉES au moment du clic, indépendant de
  // selectedIds qui pourrait continuer à changer pendant que la modale reste ouverte.
  const [bulkSharingEntries, setBulkSharingEntries] = useState<PlainVaultEntry[] | null>(null);
  const [revealedId, setRevealedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedIdentifierId, setCopiedIdentifierId] = useState<string | null>(null);
  const [copiedTotpId, setCopiedTotpId] = useState<string | null>(null);
  // Id de l'entrée dont le menu "⋯" (actions secondaires, voir EntryActionsMenu) est ouvert — un
  // seul à la fois, comme revealedId/copiedId ci-dessus.
  const [openMenuId, setOpenMenuId] = useState<string | null>(null);
  const [isSelecting, setIsSelecting] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [isBulkBusy, setIsBulkBusy] = useState(false);
  const [bulkFolderInput, setBulkFolderInput] = useState("");
  const [bulkFolderIsNew, setBulkFolderIsNew] = useState(false);
  const searchInputRef = useRef<HTMLInputElement>(null);
  // Menu ⋮ MOBILE UNIQUEMENT (voir le bouton dans le header, `sm:hidden`) — regroupe tout ce qui,
  // en boutons individuels, encombrait un écran étroit sans la moindre adaptation (bug remonté par
  // l'utilisateur, voir la conversation du 2026-09-01) : navigation, Corbeille, Santé du coffre,
  // Import/Export, Signaler un bug. Réutilise EntryActionsMenu (déjà utilisé pour le menu "⋯" de
  // chaque entrée) plutôt qu'un nouveau composant — même mécanique (clic dehors/Échap ferme),
  // juste une liste d'actions différente. Sur `sm:` et plus, ce bouton disparaît (`sm:hidden`) et
  // toutes ces actions restent visibles directement comme avant, AUCUN changement desktop.
  const [showMobileMenu, setShowMobileMenu] = useState(false);
  const importExportRef = useRef<ImportExportBarHandle>(null);

  const loadEntries = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      // getFullVault() (PAS getVault() seul) : le serveur plafonne toujours une page à 100
      // entrées, un simple appel tronquerait silencieusement tout coffre plus grand.
      const encrypted = await authorizedRequest((token) => api.getFullVault(token));
      const decrypted = await decryptEntries(encrypted);
      setEntries(decrypted);
      // Best-effort, jamais bloquant ni remonté à l'utilisateur — voir lib/autoBackup.ts (ne fait
      // rien tant que la sauvegarde automatique n'est pas explicitement activée dans Réglages).
      void maybeRunAutoBackup(decrypted).catch(() => {});
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
  }, [authorizedRequest]);

  useEffect(() => {
    void loadEntries();
  }, [loadEntries]);

  // Resynchronise automatiquement quand un AUTRE appareil du même compte modifie le coffre (voir
  // handlers/vault.rs côté backend + state/AuthContext.tsx::subscribeToVaultSync) — sans ça, il
  // faudrait recharger l'app manuellement pour voir les changements faits ailleurs.
  useEffect(() => {
    return subscribeToVaultSync(() => {
      void loadEntries();
    });
  }, [subscribeToVaultSync, loadEntries]);

  // Entrées dont le mot de passe est identique à celui d'AU MOINS une autre entrée du coffre —
  // détection en continu, pas seulement au moment d'importer (voir lib/importDuplicates.ts pour
  // la variante utilisée à l'import). Comparaison exacte, en clair, en mémoire uniquement — jamais
  // envoyée nulle part. Calculé AVANT filteredEntries : le filtre rapide "Réutilisés" en a besoin.
  // Seules les entrées "login" participent — un numéro de carte/document (types "card"/"identity")
  // n'a pas de notion de "réutilisation" pertinente au sens sécurité, et "note" n'a de toute façon
  // pas de vrai mot de passe (juste un placeholder fixe, voir NOTE_TYPE_PASSWORD_PLACEHOLDER).
  const reusedPasswordIds = useMemo(() => {
    const loginEntries = entries.filter((e) => e.entryType === "login");
    const countByPassword = new Map<string, number>();
    for (const e of loginEntries) {
      if (!e.password) continue;
      countByPassword.set(e.password, (countByPassword.get(e.password) ?? 0) + 1);
    }
    const ids = new Set<string>();
    for (const e of loginEntries) {
      if (e.password && (countByPassword.get(e.password) ?? 0) > 1) ids.add(e.id);
    }
    return ids;
  }, [entries]);

  // Recherche entièrement CÔTÉ CLIENT sur les valeurs déjà déchiffrées en mémoire — le serveur ne
  // voit jamais ces valeurs en clair, une recherche côté serveur sur du contenu chiffré n'aurait
  // de toute façon aucun sens (voir backend/src/repository.rs pour la même remarque côté API).
  const filteredEntries = useMemo(() => {
    const query = debouncedSearch.trim().toLowerCase();
    // Les favoris restent toujours épinglés en premier, quel que soit le tri choisi (comportement
    // habituel des gestionnaires de mots de passe) — le tri lui-même ne s'applique QU'À L'INTÉRIEUR
    // de chaque groupe (favoris entre eux, non-favoris entre eux).
    const sorted = [...entries].sort((a, b) => {
      if (a.isFavorite !== b.isFavorite) return Number(b.isFavorite) - Number(a.isFavorite);
      switch (sortBy) {
        case "updated":
          return new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime(); // plus récent d'abord
        case "usage":
          // Le plus utilisé d'abord (voir VaultEntry.use_count/lib/vaultUsage.ts) — départage
          // alphabétique si deux entrées ont le même compteur (ex: deux entrées jamais utilisées).
          return b.useCount - a.useCount || a.siteName.localeCompare(b.siteName);
        case "strength": {
          // Uniquement pertinent pour "login" (voir le commentaire sur reusedPasswordIds plus haut) —
          // un numéro de carte/document/le placeholder d'une note n'a pas de notion de "force".
          // Les entrées non-login sont poussées à la fin (Infinity), jamais mélangées au hasard
          // parmi les vrais mots de passe faibles/forts.
          const bitsA = a.entryType === "login" ? estimatePasswordEntropyBits(a.password) : Infinity;
          const bitsB = b.entryType === "login" ? estimatePasswordEntropyBits(b.password) : Infinity;
          return bitsA - bitsB; // plus faible d'abord
        }
        case "name":
        default:
          return a.siteName.localeCompare(b.siteName);
      }
    });
    return sorted
      .filter((e) => {
        if (!folderFilter) return true;
        if (folderFilter === "__none__") return !e.folder;
        return e.folder === folderFilter;
      })
      .filter((e) => {
        switch (quickFilter) {
          // "faible"/"réutilisé"/"ancien" : uniquement pertinents pour un vrai mot de passe (type
          // "login") — voir le commentaire sur reusedPasswordIds ci-dessus.
          case "weak": {
            if (e.entryType !== "login") return false;
            const bits = estimatePasswordEntropyBits(e.password);
            return bits > 0 && bits < WEAK_THRESHOLD_BITS;
          }
          case "reused":
            return reusedPasswordIds.has(e.id);
          case "old":
            return e.entryType === "login" && Boolean(e.updatedAt) && daysSince(e.updatedAt) > OLD_PASSWORD_DAYS;
          case "favorite":
            return e.isFavorite;
          case "attachment":
            return e.hasAttachments;
          default:
            return true;
        }
      })
      .filter(
        (e) =>
          !query ||
          e.siteName.toLowerCase().includes(query) ||
          e.username.toLowerCase().includes(query) ||
          e.loginEmail.toLowerCase().includes(query) ||
          e.folder.toLowerCase().includes(query) ||
          // Élargie aux notes et à l'URL — un utilisateur qui se souvient avoir noté "code postal
          // 12345" ou "compte pro" dans les notes d'une entrée doit pouvoir la retrouver par ce
          // texte, pas seulement par le nom du site.
          e.notes.toLowerCase().includes(query) ||
          e.url.toLowerCase().includes(query) ||
          // Repli tolérant aux fautes de frappe (voir lib/fuzzyMatch.ts) — UNIQUEMENT si aucune des
          // correspondances exactes ci-dessus n'a rien trouvé (grâce au || paresseux, ce repli n'est
          // même pas évalué dans le cas courant). Volontairement limité à site/identifiant/email —
          // pas dossier/notes/URL, où une tolérance aux fautes produirait trop de faux positifs sur
          // du texte libre plus long.
          fuzzyIncludes(e.siteName, query) ||
          fuzzyIncludes(e.username, query) ||
          fuzzyIncludes(e.loginEmail, query),
      );
  }, [entries, debouncedSearch, folderFilter, sortBy, quickFilter, reusedPasswordIds]);

  // Rendu progressif (voir INITIAL_RENDER_BUDGET en tête de fichier).
  const [renderBudget, setRenderBudget] = useState(INITIAL_RENDER_BUDGET);

  // Repart du budget initial dès que la liste AFFICHÉE change (recherche, filtre, tri,
  // rechargement après une action) : sans ça, revenir d'un gros coffre déroulé vers une recherche
  // très sélective garderait un budget devenu inutilement grand.
  useEffect(() => {
    setRenderBudget(INITIAL_RENDER_BUDGET);
  }, [filteredEntries]);

  // Sentinelle placée après la liste : dès qu'elle approche du champ de vision, on monte un palier
  // de plus. `rootMargin` généreux pour que le palier suivant soit prêt AVANT que l'utilisateur
  // n'atteigne réellement le bas — le défilement reste continu, sans à-coup ni indicateur de
  // chargement. La garde `budget < total` évite de re-rendre pour rien quand tout est déjà monté
  // (renvoyer la même valeur d'état est un no-op côté React).
  const loadMoreRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    const node = loadMoreRef.current;
    if (!node) return;
    const total = filteredEntries.length;
    const observer = new IntersectionObserver(
      (observed) => {
        if (observed.some((e) => e.isIntersecting)) {
          setRenderBudget((current) => (current < total ? current + RENDER_BUDGET_STEP : current));
        }
      },
      { rootMargin: "800px" },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [filteredEntries, renderBudget]);

  // Types d'entrée distincts déjà présents dans le coffre — détermine si un regroupement par type
  // a un intérêt (voir typeSections plus bas) : inutile d'afficher un unique en-tête "Mots de passe"
  // au-dessus de tout le coffre pour quelqu'un qui n'a que des mots de passe.
  const existingTypes = useMemo(() => Array.from(new Set(entries.map((e) => e.entryType))), [entries]);

  // Dossiers distincts déjà utilisés dans le coffre — triés, pour le filtre et l'autocomplétion
  // du formulaire (voir VaultEntryForm.tsx::existingFolders).
  const existingFolders = useMemo(
    () => Array.from(new Set(entries.map((e) => e.folder).filter(Boolean))).sort((a, b) => a.localeCompare(b)),
    [entries],
  );

  // Regroupe l'affichage par dossier (nom du dossier en en-tête, ses entrées en dessous) — SEULEMENT
  // si l'utilisateur a effectivement commencé à utiliser des dossiers (sinon on ne change rien à
  // l'affichage plat habituel), qu'aucun filtre de dossier n'est déjà actif (le filtre réduit
  // déjà à un seul dossier, un en-tête répété par-dessus serait redondant avec le sélecteur), ET
  // qu'aucun regroupement par type n'est déjà en jeu (voir typeSections ci-dessous — dans ce cas
  // le regroupement par dossier se fait DANS chaque section de type, pas ici).
  const groupedSections = useMemo(() => {
    if (folderFilter || existingFolders.length === 0 || existingTypes.length > 1) return null;
    // Retour utilisateur (2026-09-02) : quand le tri actif est "le plus utilisé", les DOSSIERS
    // eux-mêmes remontent aussi par usage (somme des use_count de leurs entrées) — le dossier le
    // plus utilisé en haut, pas juste les entrées à l'intérieur d'un dossier resté à sa place
    // alphabétique. Pour tout autre tri, comportement inchangé (alphabétique). Voir
    // groupEntriesByFolder en tête de fichier.
    return groupEntriesByFolder(filteredEntries, sortBy);
  }, [filteredEntries, folderFilter, existingFolders, existingTypes, sortBy]);

  // Regroupement AUTOMATIQUE de l'affichage par type d'entrée — voir le commentaire de TYPE_ORDER
  // en tête de fichier pour le retour utilisateur à l'origine. `null` quand il n'y a qu'un seul
  // type dans le coffre (rien à séparer). Dans chaque section de type, le regroupement par dossier
  // continue de s'appliquer normalement (même logique que groupedSections ci-dessus, juste scopée
  // à ce type) — un dossier peut très bien contenir un mélange de mots de passe et de cartes, par
  // exemple, et doit rester visible comme tel à l'intérieur de chaque section.
  const typeSections = useMemo(() => {
    if (existingTypes.length <= 1) return null;
    return TYPE_ORDER.filter((type) => existingTypes.includes(type))
      .map((type) => {
        const entriesOfType = filteredEntries.filter((e) => e.entryType === type);
        return {
          type,
          label: TYPE_SECTION_LABELS[type],
          entries: entriesOfType,
          folderGroups: folderFilter || existingFolders.length === 0 ? null : groupEntriesByFolder(entriesOfType, sortBy),
        };
      })
      .filter((section) => section.entries.length > 0);
  }, [filteredEntries, existingTypes, folderFilter, existingFolders, sortBy]);

  async function handleAdd(values: VaultEntryFormValues) {
    const encrypted = await encryptEntry(values);
    await authorizedRequest((token) => api.addToVault(token, encrypted));
    setModal(null);
    await loadEntries();
  }

  async function handleEdit(id: string, values: VaultEntryFormValues, passwordChanged: boolean, expectedVersion?: number) {
    const encrypted = await encryptEntry(values, passwordChanged, expectedVersion);
    await authorizedRequest((token) => api.updateVaultEntry(token, id, encrypted));
    setModal(null);
    // Le contenu vient de changer : si cette entrée est partagée avec quelqu'un (voir
    // components/ShareEntryModal.tsx), le blob scellé côté serveur est désormais périmé — le
    // re-sceller avec le nouveau contenu. Best-effort, ne doit jamais faire échouer l'enregistrement
    // par ailleurs réussi de l'entrée (voir lib/entrySharing.ts::reseedEntryShares). `version`/
    // `updatedAt`/`hasAttachments`/`useCount` factices : reseedEntryShares() n'en a pas besoin (il
    // ne fait que re-sceller le contenu déjà accepté par le serveur ci-dessus, pas une nouvelle
    // vérification de conflit, et les pièces jointes/le compteur d'usage sont hors périmètre du
    // partage — voir entrySharing.ts).
    void reseedEntryShares(authorizedRequest, { id, updatedAt: "", version: 0, hasAttachments: false, useCount: 0, ...values }).catch(() => {});
    await loadEntries();
  }

  async function handleDelete(id: string) {
    if (!confirm("Déplacer cette entrée vers la corbeille ?")) return;
    try {
      await authorizedRequest((token) => api.deleteVaultEntry(token, id));
      setEntries((prev) => prev.filter((e) => e.id !== id));
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  /** Ouvre le formulaire d'ajout pré-rempli avec les valeurs d'une entrée existante — pratique
   * pour créer une variante proche (ex: un second compte sur le même site) sans tout retaper.
   * "(copie)" sur le nom du site pour éviter deux entrées identiques d'un simple clic distrait. */
  function handleDuplicate(entry: PlainVaultEntry) {
    const { id: _id, updatedAt: _updatedAt, ...values } = entry;
    setModal({ mode: "add", prefill: { ...values, siteName: `${entry.siteName} (copie)` } });
  }

  /** "Restaurer cette version" depuis l'historique (voir VaultHistoryModal) : remet le mot de
   * passe COURANT à une ancienne valeur — un changement RÉEL comme un autre, donc passwordChanged
   * reste à true (l'actuel devient à son tour une ligne d'historique). */
  async function handleRestoreHistoricalPassword(entry: PlainVaultEntry, oldPassword: string) {
    const { id: _id, updatedAt: _updatedAt, ...values } = entry;
    await handleEdit(entry.id, { ...values, password: oldPassword }, true, entry.version);
    setHistoryEntry(null);
  }

  async function handleToggleFavorite(entry: PlainVaultEntry) {
    // Optimiste : bascule immédiatement à l'écran, puis confirme côté serveur — annule
    // silencieusement en cas d'échec plutôt que de bloquer l'UI en attendant la réponse réseau.
    setEntries((prev) => prev.map((e) => (e.id === entry.id ? { ...e, isFavorite: !e.isFavorite } : e)));
    try {
      await authorizedRequest((token) => api.toggleFavorite(token, entry.id));
    } catch (err) {
      setEntries((prev) => prev.map((e) => (e.id === entry.id ? { ...e, isFavorite: entry.isFavorite } : e)));
      setError(getErrorMessage(err));
    }
  }

  async function handleCopyPassword(entry: PlainVaultEntry) {
    await copyPasswordWithAutoClear(entry.password);
    setCopiedId(entry.id);
    setTimeout(() => setCopiedId((current) => (current === entry.id ? null : current)), 1500);
    // Best-effort, jamais attendu (voir lib/vaultUsage.ts) : ne doit jamais ralentir la copie
    // elle-même, qui doit rester instantanée pour l'utilisateur.
    recordEntryUse(authorizedRequest, entry.id);
  }

  /** Copie le code à usage unique affiché. Passe par le MÊME effacement automatique du
   * presse-papiers que le mot de passe (voir lib/clipboard.ts) : un code TOTP oublié dans le
   * presse-papiers est un secret de moins courte portée qu'il n'y paraît — il reste valide
   * jusqu'à la fin de sa tranche, et le presse-papiers, lui, est lisible par toute application. */
  async function handleCopyTotp(entryId: string, code: string) {
    await copyPasswordWithAutoClear(code);
    setCopiedTotpId(entryId);
    setTimeout(() => setCopiedTotpId((current) => (current === entryId ? null : current)), 1500);
  }

  async function handleCopyIdentifier(entry: PlainVaultEntry) {
    const identifier = getPreferredIdentifier(entry);
    if (!identifier) return;
    await navigator.clipboard.writeText(identifier);
    setCopiedIdentifierId(entry.id);
    setTimeout(() => setCopiedIdentifierId((current) => (current === entry.id ? null : current)), 1500);
  }

  function exitSelection() {
    setIsSelecting(false);
    setSelectedIds(new Set());
    setBulkFolderInput("");
    setBulkFolderIsNew(false);
  }

  function toggleSelected(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleSelectAll() {
    setSelectedIds((prev) =>
      prev.size === filteredEntries.length ? new Set() : new Set(filteredEntries.map((e) => e.id)),
    );
  }

  /** Suppression groupée — pas d'endpoint dédié côté backend (voir api/client.ts), donc une requête
   * par entrée en parallèle, puis un rechargement complet pour resynchroniser avec le serveur quel
   * que soit le résultat individuel de chaque appel (plus simple et plus sûr qu'un rollback
   * optimiste partiel sur un lot). */
  async function handleBulkDelete() {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;
    if (!confirm(`Déplacer ${ids.length} entrée(s) vers la corbeille ?`)) return;

    setError(null);
    setIsBulkBusy(true);
    try {
      // Concurrence bornée (voir lib/concurrency.ts) : "tout sélectionner" puis supprimer envoyait
      // auparavant une requête par entrée D'UN SEUL COUP, ce qui déclenchait le rate limiter du
      // serveur et faisait échouer une partie des suppressions pour cette seule raison.
      const results = await allSettledWithLimit(ids, (id) => authorizedRequest((token) => api.deleteVaultEntry(token, id)));
      const failed = results.filter((r) => r.status === "rejected").length;
      if (failed > 0) setError(`${failed} suppression(s) sur ${ids.length} ont échoué.`);
    } finally {
      exitSelection();
      await loadEntries();
      setIsBulkBusy(false);
    }
  }

  /** Idem pour le favori : l'API n'a qu'un "toggleFavorite" (bascule), donc on ne l'appelle que
   * sur les entrées qui n'ont pas déjà l'état voulu — sinon on inverserait par erreur celles déjà
   * dans l'état demandé. */
  async function handleBulkSetFavorite(desired: boolean) {
    const targets = entries.filter((e) => selectedIds.has(e.id) && e.isFavorite !== desired);
    if (targets.length === 0) {
      exitSelection();
      return;
    }

    setError(null);
    setIsBulkBusy(true);
    try {
      const results = await allSettledWithLimit(targets, (e) => authorizedRequest((token) => api.toggleFavorite(token, e.id)));
      const failed = results.filter((r) => r.status === "rejected").length;
      if (failed > 0) setError(`${failed} mise(s) à jour sur ${targets.length} ont échoué.`);
    } finally {
      exitSelection();
      await loadEntries();
      setIsBulkBusy(false);
    }
  }

  /** Ré-encrypte et renvoie chaque entrée de `targets` avec `folder` comme nouveau dossier, en
   * parallèle. Pas d'endpoint dédié côté backend : PUT /vault/{id} remplace l'entrée ENTIÈRE (voir
   * repository.rs::update), donc chaque appel doit renvoyer tous les champs re-chiffrés, pas juste
   * le dossier — d'où le ré-encryptEntry() complet à partir de l'entrée déjà déchiffrée en
   * mémoire, avec seulement `folder` changé. Renvoie le nombre d'échecs (0 = tout est passé). */
  async function reassignFolder(targets: PlainVaultEntry[], folder: string): Promise<number> {
    const results = await allSettledWithLimit(
      targets,
      async (e) => {
        const { id: _id, ...withoutId } = e;
        const encrypted = await encryptEntry({ ...withoutId, folder }, false, e.version);
        await authorizedRequest((token) => api.updateVaultEntry(token, e.id, encrypted));
        // Même raison que dans handleEdit() : le dossier fait partie du contenu scellé pour un
        // éventuel partage (voir lib/entrySharing.ts), donc lui aussi périmé après ce changement.
        void reseedEntryShares(authorizedRequest, { ...e, folder }).catch(() => {});
      },
    );
    return results.filter((r) => r.status === "rejected").length;
  }

  /** Assigne (ou retire, avec folder="") un dossier à toute la sélection en une fois — c'est ce qui
   * permet de peupler une section après coup : sélectionner des entrées existantes et les
   * "déposer" dans un dossier. */
  async function handleBulkSetFolder(folder: string) {
    const targets = entries.filter((e) => selectedIds.has(e.id) && e.folder !== folder);
    if (targets.length === 0) {
      exitSelection();
      return;
    }

    setError(null);
    setIsBulkBusy(true);
    try {
      const failed = await reassignFolder(targets, folder);
      if (failed > 0) setError(`${failed} mise(s) à jour sur ${targets.length} ont échoué.`);
    } finally {
      exitSelection();
      await loadEntries();
      setIsBulkBusy(false);
    }
  }

  /** Renomme un dossier entier — toutes les entrées qui le portent actuellement basculent vers le
   * nouveau nom, en un clic depuis l'en-tête de section (voir groupedSections). Si le nouveau nom
   * coïncide avec un dossier déjà existant, les deux fusionnent simplement (pas un cas d'erreur). */
  async function handleRenameFolder(oldName: string) {
    const input = prompt(`Renommer le dossier "${oldName}" en :`, oldName);
    if (input === null) return; // annulé
    const newName = input.trim();
    if (!newName || newName === oldName) return;

    const targets = entries.filter((e) => e.folder === oldName);
    if (targets.length === 0) return;

    setError(null);
    setIsBulkBusy(true);
    try {
      const failed = await reassignFolder(targets, newName);
      if (failed > 0) setError(`${failed} mise(s) à jour sur ${targets.length} ont échoué lors du renommage.`);
    } finally {
      await loadEntries();
      setIsBulkBusy(false);
    }
  }

  // Raccourcis clavier : Ctrl/Cmd+F focus la recherche, Ctrl/Cmd+N ouvre "Ajouter", "?" affiche
  // l'aide (voir KeyboardShortcutsModal), Échap ferme la fenêtre ouverte (formulaire, corbeille)
  // ou quitte le mode sélection — dans cet ordre de priorité. Désactivés pendant qu'une fenêtre
  // est ouverte pour Ctrl+F/Ctrl+N/"?" (pas de sens à voler le focus de la recherche ou à ouvrir
  // un 2e formulaire par-dessus). "?" ignoré si la frappe vient d'un champ de saisie (sinon
  // impossible de taper un "?" dans les notes d'une entrée sans rouvrir cette aide).
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      const isModifier = e.ctrlKey || e.metaKey;
      const hasOpenModal = modal !== null || showTrash || showHealth || showShortcutsHelp;
      const isTypingInField = e.target instanceof HTMLElement && ["INPUT", "TEXTAREA", "SELECT"].includes(e.target.tagName);

      if (isModifier && e.key.toLowerCase() === "f" && !hasOpenModal) {
        e.preventDefault();
        searchInputRef.current?.focus();
      } else if (isModifier && e.key.toLowerCase() === "n" && !hasOpenModal) {
        e.preventDefault();
        setModal({ mode: "add" });
      } else if (e.key === "?" && !hasOpenModal && !isTypingInField) {
        e.preventDefault();
        setShowShortcutsHelp(true);
      } else if (e.key === "Escape") {
        if (showShortcutsHelp) setShowShortcutsHelp(false);
        else if (showHealth) setShowHealth(false);
        else if (showTrash) setShowTrash(false);
        else if (modal) setModal(null);
        else if (isSelecting) exitSelection();
      }
    }

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [modal, showTrash, showHealth, showShortcutsHelp, isSelecting]);

  // Une seule entrée du coffre, réutilisée aussi bien pour la liste plate que pour l'affichage
  // groupé par dossier (voir groupedSections) — `hideFolderBadge` évite de répéter le nom du
  // dossier sur chaque ligne quand il est déjà porté par l'en-tête de section au-dessus.
  function renderEntryRow(entry: PlainVaultEntry, options?: { hideFolderBadge?: boolean }) {
    return (
      <li
        key={entry.id}
        onClick={() => isSelecting && toggleSelected(entry.id)}
        // items-start (pas items-center) : ancre les deux colonnes (contenu / actions) en haut de
        // la carte de façon fixe, quel que soit le nombre de lignes que prend chacune — sinon,
        // avec items-center, la colonne d'actions se recentre verticalement par rapport à la
        // hauteur totale de la carte, qui varie elle-même selon le nombre de badges affichés
        // (favori/force/réutilisé/dossier) : deux cartes voisines avec un contenu légèrement
        // différent finissaient avec leurs boutons à des hauteurs différentes, d'où l'impression
        // d'une mise en forme incohérente d'une carte à l'autre.
        // CORRECTIF (retour utilisateur mobile, écran étroit) : flex-col en dessous de sm (les
        // téléphones n'ont pas tous la même largeur — plutôt que viser une taille d'écran précise,
        // on empile systématiquement nom+badges au-dessus et actions en dessous dès que la carte
        // n'a plus la place de mettre les deux côte à côte). En row (sm et +), comportement
        // identique à avant. Les boutons d'action, sur leur propre ligne pleine largeur en mobile,
        // ont enfin la place de se disposer sur 1-2 lignes au lieu d'être écrasés à droite du nom
        // du site dans l'espace restant. CSS pur (aucune logique JS) : rendu strictement identique
        // sur iPhone (même WebView, mêmes classes Tailwind) sans rien à adapter côté iOS.
        className={`vault-row-cv flex flex-col gap-3 rounded-xl border p-4 transition sm:flex-row sm:items-start sm:justify-between ${
          isSelecting ? "cursor-pointer" : ""
        } ${
          isSelecting && selectedIds.has(entry.id)
            ? "border-indigo-300 bg-indigo-50 dark:border-indigo-800 dark:bg-indigo-950"
            : "border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-900"
        }`}
      >
        <div className="flex min-w-0 flex-1 items-center gap-3">
          {isSelecting && (
            <input
              type="checkbox"
              checked={selectedIds.has(entry.id)}
              onChange={() => toggleSelected(entry.id)}
              onClick={(e) => e.stopPropagation()}
              className="shrink-0 rounded border-neutral-300 text-indigo-600 focus:ring-indigo-500"
            />
          )}
          {entry.entryType === "login" ? <SiteAvatar siteName={entry.siteName} url={entry.url} /> : <EntryTypeIcon entryType={entry.entryType} />}
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              {!isSelecting && (
                <button
                  type="button"
                  onClick={() => void handleToggleFavorite(entry)}
                  aria-label="Basculer favori"
                  className={`shrink-0 ${entry.isFavorite ? "text-amber-500" : "text-neutral-300 hover:text-amber-400 dark:text-neutral-700"}`}
                >
                  ★
                </button>
              )}
              {isSelecting && entry.isFavorite && <span className="shrink-0 text-amber-500">★</span>}
              {/* min-w-0 est indispensable ici : à l'intérieur d'un flex, un élément avec `truncate`
               * ne rétrécit PAS sous sa largeur de contenu naturelle sans min-w-0 — sans lui, un nom
               * de site un peu long refuse de se tronquer et pousse/chevauche les badges suivants. */}
              <p className="min-w-0 shrink truncate font-medium text-neutral-900 dark:text-neutral-100">{entry.siteName}</p>
              {entry.entryType === "login" && <StrengthDot password={entry.password} />}
              {reusedPasswordIds.has(entry.id) && (
                <span
                  title="Ce mot de passe est utilisé par au moins une autre entrée du coffre"
                  className="shrink-0 rounded-full bg-orange-100 px-1.5 py-0.5 text-[11px] font-medium text-orange-700 dark:bg-orange-950 dark:text-orange-400"
                >
                  Réutilisé
                </span>
              )}
              {entry.folder && !options?.hideFolderBadge && (
                <span className="shrink-0 rounded-full bg-neutral-100 px-1.5 py-0.5 text-[11px] text-neutral-500 dark:bg-neutral-800 dark:text-neutral-400">
                  {entry.folder}
                </span>
              )}
            </div>
            {entry.entryType !== "note" && (
              <p className="truncate text-sm text-neutral-500">
                {entry.entryType === "login" ? getPreferredIdentifier(entry) || "—" : entry.username || "—"}
              </p>
            )}
            {entry.updatedAt &&
              (() => {
                const age = formatRelativeAge(entry.updatedAt);
                return (
                  <p className={`text-xs ${entry.entryType === "login" && age.days > OLD_PASSWORD_DAYS ? "text-amber-600 dark:text-amber-400" : "text-neutral-400"}`}>
                    Modifié {age.label}
                  </p>
                );
              })()}
            {revealedId === entry.id && entry.entryType !== "note" && (
              <p className="mt-1 select-all font-mono text-sm text-neutral-700 dark:text-neutral-300">{entry.password}</p>
            )}
            {/* Code à usage unique du site (voir lib/totp.ts) — affiché en permanence, sans avoir à
                révéler l'entrée : c'est précisément la valeur qu'on vient chercher au moment de se
                connecter, et elle change de toute façon toutes les 30 secondes. Le secret, lui,
                reste masqué (champ `sensitive` du formulaire). */}
            {entry.extraFields.totpSecret && (
              <div className="mt-1">
                <TotpCode
                  secret={entry.extraFields.totpSecret}
                  copied={copiedTotpId === entry.id}
                  onCopy={(code) => void handleCopyTotp(entry.id, code)}
                />
              </div>
            )}
          </div>
        </div>

        {!isSelecting && (
          // Seules les actions les plus courantes restent des boutons texte directement visibles
          // (au plus 5, quasi jamais sur 2 lignes) — dupliquer/historique/supprimer, plus rares,
          // sont regroupées dans le menu "⋯" (voir EntryActionsMenu) : c'est ce qui évite à cette
          // rangée de passer à la ligne différemment d'une carte à l'autre selon le nom de site ou
          // les badges affichés à gauche (voir le commentaire sur items-start plus haut).
          // ml-3/shrink-0/justify-end n'ont de sens qu'en mode ligne (sm et +, voir le <li>
          // ci-dessus) : en dessous de sm, cette rangée est sur sa propre ligne pleine largeur
          // (justify-start par défaut), elle n'a donc plus besoin d'être compressée à droite.
          <div className="flex flex-wrap items-start gap-1.5 sm:ml-3 sm:shrink-0 sm:justify-end">
            {entry.url && (
              <button
                type="button"
                onClick={() => void openEntryUrl(entry.url)}
                className="rounded-lg border border-neutral-300 px-2.5 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                Ouvrir le site
              </button>
            )}
            {entry.entryType !== "note" && (
              <button
                type="button"
                onClick={() => setRevealedId((current) => (current === entry.id ? null : entry.id))}
                className="rounded-lg border border-neutral-300 px-2.5 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                {revealedId === entry.id ? "Cacher" : "Voir"}
              </button>
            )}
            {entry.entryType === "login" && (
              <button
                type="button"
                onClick={() => void handleCopyIdentifier(entry)}
                disabled={!entry.username && !entry.loginEmail}
                className="rounded-lg border border-neutral-300 px-2.5 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                {copiedIdentifierId === entry.id ? "Copié !" : "Copier l'identifiant"}
              </button>
            )}
            {entry.entryType !== "note" && (
              <button
                type="button"
                onClick={() => void handleCopyPassword(entry)}
                className="rounded-lg border border-neutral-300 px-2.5 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                {copiedId === entry.id ? "Copié !" : "Copier"}
              </button>
            )}
            <button
              type="button"
              onClick={() => setModal({ mode: "edit", entry })}
              className="rounded-lg border border-neutral-300 px-2.5 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              Modifier
            </button>
            <EntryActionsMenu
              isOpen={openMenuId === entry.id}
              onToggle={() => setOpenMenuId((current) => (current === entry.id ? null : entry.id))}
              onClose={() => setOpenMenuId((current) => (current === entry.id ? null : current))}
              items={[
                { label: "Dupliquer", onClick: () => handleDuplicate(entry) },
                { label: "Historique", onClick: () => setHistoryEntry(entry) },
                { label: "Pièces jointes", onClick: () => setAttachmentsEntry(entry) },
                { label: "Partager", onClick: () => setSharingEntry(entry) },
                { label: "Partager (usage limité)", onClick: () => setBlindSharingEntry(entry) },
                { label: "Supprimer", onClick: () => void handleDelete(entry.id), danger: true },
              ]}
            />
          </div>
        )}
      </li>
    );
  }

  /** Actions secondaires communes à renderEntryCompact/renderEntryCard ci-dessous — TOUTES les
   * actions de renderEntryRow (Ouvrir le site/Voir/Copier l'identifiant/Dupliquer/Historique/
   * Pièces jointes/Partager/Partager limité/Supprimer) SAUF Copier (mot de passe) et Modifier, qui
   * restent des boutons visibles à part (voir les deux fonctions ci-dessous) — rien n'est retiré,
   * juste réorganisé pour tenir dans un espace plus restreint (retour utilisateur, 2026-09-02,
   * "disposition des listes"). `includeUrlAndReveal` (défaut true) : retour utilisateur, suite —
   * "Ouvrir le site"/"Voir le mot de passe" deviennent des boutons visibles en mode "cards" (assez
   * de place désormais, voir renderEntryCard), donc renderEntryCard passe `false` ici pour ne pas
   * les DUPLIQUER dans "⋯". "compact" (aucune place à perdre) garde le défaut `true` — ils restent
   * cachés là-bas. */
  function secondaryActionItems(entry: PlainVaultEntry, includeUrlAndReveal = true) {
    return [
      ...(includeUrlAndReveal && entry.url ? [{ label: "Ouvrir le site", onClick: () => void openEntryUrl(entry.url) }] : []),
      ...(includeUrlAndReveal && entry.entryType !== "note"
        ? [{ label: revealedId === entry.id ? "Cacher le mot de passe" : "Voir le mot de passe", onClick: () => setRevealedId((current) => (current === entry.id ? null : entry.id)) }]
        : []),
      ...(entry.entryType === "login" ? [{ label: "Copier l'identifiant", onClick: () => void handleCopyIdentifier(entry) }] : []),
      { label: "Dupliquer", onClick: () => handleDuplicate(entry) },
      { label: "Historique", onClick: () => setHistoryEntry(entry) },
      { label: "Pièces jointes", onClick: () => setAttachmentsEntry(entry) },
      { label: "Partager", onClick: () => setSharingEntry(entry) },
      { label: "Partager (usage limité)", onClick: () => setBlindSharingEntry(entry) },
      { label: "Supprimer", onClick: () => void handleDelete(entry.id), danger: true },
    ];
  }

  /** Disposition "Compacte" — retour utilisateur (2026-09-02) : une seule ligne dense par entrée,
   * plus d'entrées visibles à l'écran sans défiler. Mêmes actions que renderEntryRow.
   * ÉLARGI (retour utilisateur, suite — "essaie d'ajouter les boutons aussi aux colonnes des deux
   * autres modes") : "Ouvrir le site"/"Voir le mot de passe" rejoignent Copier/Modifier comme
   * boutons visibles, comme déjà fait pour "cards". Compromis assumé : sur une ligne UNIQUE (pas
   * les 2 lignes d'une carte), 4 boutons au lieu de 2 poussent le texte tronqué (nom du site,
   * identifiant) à se réduire davantage — le `min-w-0 flex-1 truncate` déjà en place l'absorbe
   * sans jamais casser la mise en page (juste "…" plus tôt dans le texte), mais c'est le vrai
   * compromis "compact" : plus d'actions à portée de clic, un peu moins de texte visible par
   * ligne. À garder si ça reste lisible en usage réel, sinon facile à revenir en arrière (juste
   * enlever `false` de secondaryActionItems ci-dessous et les deux boutons ajoutés). */
  function renderEntryCompact(entry: PlainVaultEntry) {
    return (
      <li
        key={entry.id}
        onClick={() => isSelecting && toggleSelected(entry.id)}
        // flex-wrap : sans effet en usage normal (rien ne dépasse d'une seule ligne), mais laisse
        // le mot de passe révélé (voir tout en bas) retomber sur sa PROPRE ligne plutôt que de se
        // faire comprimer dans la même ligne que le reste — nécessaire depuis que "Voir" est
        // devenu un bouton visible ici (voir le commentaire de la fonction).
        className={`vault-compact-cv flex flex-wrap items-center gap-2 rounded-lg border px-3 py-1.5 transition ${isSelecting ? "cursor-pointer" : ""} ${
          isSelecting && selectedIds.has(entry.id)
            ? "border-indigo-300 bg-indigo-50 dark:border-indigo-800 dark:bg-indigo-950"
            : "border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-900"
        }`}
      >
        {isSelecting && (
          <input
            type="checkbox"
            checked={selectedIds.has(entry.id)}
            onChange={() => toggleSelected(entry.id)}
            onClick={(e) => e.stopPropagation()}
            className="shrink-0 rounded border-neutral-300 text-indigo-600 focus:ring-indigo-500"
          />
        )}
        {!isSelecting && (
          <button
            type="button"
            onClick={() => void handleToggleFavorite(entry)}
            aria-label="Basculer favori"
            className={`shrink-0 text-sm ${entry.isFavorite ? "text-amber-500" : "text-neutral-300 hover:text-amber-400 dark:text-neutral-700"}`}
          >
            ★
          </button>
        )}
        {entry.entryType === "login" ? <SiteAvatar siteName={entry.siteName} url={entry.url} size={24} /> : <EntryTypeIcon entryType={entry.entryType} />}
        <p className="min-w-0 shrink truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">{entry.siteName}</p>
        {entry.entryType !== "note" && (
          <p className="min-w-0 flex-1 truncate text-xs text-neutral-500">{entry.entryType === "login" ? getPreferredIdentifier(entry) || "—" : entry.username || "—"}</p>
        )}
        {!isSelecting && (
          <div className="flex shrink-0 items-center gap-1">
            {entry.url && (
              <button
                type="button"
                onClick={() => void openEntryUrl(entry.url)}
                title="Ouvrir le site"
                className="rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                Ouvrir
              </button>
            )}
            {entry.entryType !== "note" && (
              <button
                type="button"
                onClick={() => setRevealedId((current) => (current === entry.id ? null : entry.id))}
                title={revealedId === entry.id ? "Cacher le mot de passe" : "Voir le mot de passe"}
                className="rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                {revealedId === entry.id ? "Cacher" : "Voir"}
              </button>
            )}
            {entry.entryType !== "note" && (
              <button
                type="button"
                onClick={() => void handleCopyPassword(entry)}
                title="Copier le mot de passe"
                className="rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                {copiedId === entry.id ? "Copié !" : "Copier"}
              </button>
            )}
            <button
              type="button"
              onClick={() => setModal({ mode: "edit", entry })}
              title="Modifier"
              className="rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              Modifier
            </button>
            <EntryActionsMenu
              isOpen={openMenuId === entry.id}
              onToggle={() => setOpenMenuId((current) => (current === entry.id ? null : entry.id))}
              onClose={() => setOpenMenuId((current) => (current === entry.id ? null : current))}
              items={secondaryActionItems(entry, false)}
            />
          </div>
        )}
        {revealedId === entry.id && entry.entryType !== "note" && (
          <p className="w-full select-all break-all font-mono text-xs text-neutral-700 dark:text-neutral-300">{entry.password}</p>
        )}
      </li>
    );
  }

  /** Disposition "Grille de cartes" — retour utilisateur (2026-09-02) : avatar/logo bien plus
   * visible que dans la liste, idéal pour repérer une entrée d'un coup d'œil. Mêmes actions que
   * renderEntryRow, réorganisées comme pour renderEntryCompact ci-dessus (voir son commentaire). */
  function renderEntryCard(entry: PlainVaultEntry) {
    return (
      <div
        key={entry.id}
        onClick={() => isSelecting && toggleSelected(entry.id)}
        className={`vault-card-cv flex flex-col items-center gap-2 rounded-xl border p-4 text-center transition ${isSelecting ? "cursor-pointer" : ""} ${
          isSelecting && selectedIds.has(entry.id)
            ? "border-indigo-300 bg-indigo-50 dark:border-indigo-800 dark:bg-indigo-950"
            : "border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-900"
        }`}
      >
        <div className="flex w-full items-center justify-between">
          {isSelecting ? (
            <input
              type="checkbox"
              checked={selectedIds.has(entry.id)}
              onChange={() => toggleSelected(entry.id)}
              onClick={(e) => e.stopPropagation()}
              className="rounded border-neutral-300 text-indigo-600 focus:ring-indigo-500"
            />
          ) : (
            <button
              type="button"
              onClick={() => void handleToggleFavorite(entry)}
              aria-label="Basculer favori"
              className={entry.isFavorite ? "text-amber-500" : "text-neutral-300 hover:text-amber-400 dark:text-neutral-700"}
            >
              ★
            </button>
          )}
          {entry.entryType === "login" && <StrengthDot password={entry.password} />}
        </div>
        {entry.entryType === "login" ? <SiteAvatar siteName={entry.siteName} url={entry.url} size={48} /> : <EntryTypeIcon entryType={entry.entryType} />}
        <p className="w-full truncate font-medium text-neutral-900 dark:text-neutral-100">{entry.siteName}</p>
        {entry.entryType !== "note" && (
          <p className="w-full truncate text-xs text-neutral-500">{entry.entryType === "login" ? getPreferredIdentifier(entry) || "—" : entry.username || "—"}</p>
        )}
        {!isSelecting && (
          // CORRECTIF (retour utilisateur, 2026-09-02) : "Ouvrir le site"/"Voir le mot de passe"
          // rejoignent Copier/Modifier comme boutons visibles — assez de place désormais sur une
          // carte (voir le correctif des colonnes de grille) pour ne plus les cacher dans "⋯"
          // comme avant. Retirés de secondaryActionItems() ci-dessous (2e argument `false`) pour
          // ne pas les y dupliquer. flex-wrap : jusqu'à 4 boutons ici selon le type d'entrée (avec/
          // sans URL, note ou pas) — une carte étroite (beaucoup de colonnes sur très grand écran)
          // peut passer sur 2 lignes, accepté (même compromis que renderEntryRow, où ces mêmes
          // boutons coexistent déjà).
          <div className="mt-1 flex flex-wrap items-center justify-center gap-1">
            {entry.url && (
              <button
                type="button"
                onClick={() => void openEntryUrl(entry.url)}
                title="Ouvrir le site"
                className="rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                Ouvrir
              </button>
            )}
            {entry.entryType !== "note" && (
              <button
                type="button"
                onClick={() => setRevealedId((current) => (current === entry.id ? null : entry.id))}
                title={revealedId === entry.id ? "Cacher le mot de passe" : "Voir le mot de passe"}
                className="rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                {revealedId === entry.id ? "Cacher" : "Voir"}
              </button>
            )}
            {entry.entryType !== "note" && (
              <button
                type="button"
                onClick={() => void handleCopyPassword(entry)}
                title="Copier le mot de passe"
                className="rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                {copiedId === entry.id ? "Copié !" : "Copier"}
              </button>
            )}
            <button
              type="button"
              onClick={() => setModal({ mode: "edit", entry })}
              title="Modifier"
              className="rounded-lg border border-neutral-300 px-2 py-1 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              Modifier
            </button>
            <EntryActionsMenu
              isOpen={openMenuId === entry.id}
              onToggle={() => setOpenMenuId((current) => (current === entry.id ? null : entry.id))}
              onClose={() => setOpenMenuId((current) => (current === entry.id ? null : current))}
              items={secondaryActionItems(entry, false)}
            />
            {revealedId === entry.id && entry.entryType !== "note" && (
              <p className="mt-1 w-full select-all break-all font-mono text-xs text-neutral-700 dark:text-neutral-300">{entry.password}</p>
            )}
          </div>
        )}
      </div>
    );
  }

  /** Choisit le rendu selon la disposition réglée dans Réglages (voir lib/listLayout.ts) — un seul
   * point d'appel pour les deux endroits qui affichent des entrées (groupé par dossier ou à plat,
   * voir plus bas). */
  function renderEntry(entry: PlainVaultEntry, options?: { hideFolderBadge?: boolean }) {
    if (listLayout === "cards") return renderEntryCard(entry);
    if (listLayout === "compact") return renderEntryCompact(entry);
    return renderEntryRow(entry, options);
  }

  /** Classes du conteneur — grille pour "cards". CORRECTIF (retour utilisateur, 2026-09-02,
   * plusieurs allers-retours) : `repeat(auto-fit, minmax(210px, 1fr))` — voir
   * lib/listLayout.ts::listContainerClass pour l'historique complet des deux défauts corrigés dans
   * l'ordre (paliers fixes qui faisaient sauter brusquement le format des cartes, PUIS une taille
   * rigide qui laissait un vide à droite dès qu'un dossier a peu d'entrées — chaque section de
   * dossier est SA PROPRE grille, voir groupedSections plus bas). `1fr` (comme "list" juste en
   * dessous, plus un écart modeste fixe) : les cartes présentes sur une ligne comblent maintenant
   * TOUJOURS tout l'espace, exactement comme "list" — comparé côte à côte, "Cartes" ne doit plus
   * jamais paraître moins large que "Liste". Compromis assumé : un dossier avec très peu d'entrées
   * verra sa/ses carte(s) s'étirer nettement, mais ÇA RESTE CONTINU (dépend du nombre réel de
   * cartes sur CETTE ligne, jamais de la largeur de fenêtre en elle-même) — pas un retour au
   * problème d'origine (un saut brusque à un seuil arbitraire).
   *
   * "list"/"compact" : CORRECTIF (retour utilisateur, 2026-09-02, suite — captures d'écran plein
   * écran 1440p) — une seule colonne quelle que soit la largeur laissait chaque ligne s'étirer sur
   * toute la largeur du conteneur élargi (voir plus bas, jusqu'à 110rem désormais), avec un grand
   * vide entre le contenu (à gauche) et les boutons d'action (poussés loin à droite par
   * `justify-between`) au milieu de chaque ligne. Devient une grille à plusieurs colonnes selon la
   * largeur du conteneur (via `@container`, ICI toujours nécessaire — contrairement à "cards"
   * ci-dessus, ces paliers restent des seuils fixes @4xl/@6xl, pas un auto-fill) — "compact" pousse
   * plus loin que "list" (une ligne compacte, sur une seule ligne de texte, tient dans un espace
   * bien plus étroit qu'une ligne "list" sur deux lignes) — même paliers/même raisonnement que
   * lib/listLayout.ts::listContainerClass, dupliqué ici parce que le Coffre a sa propre logique de
   * conteneur (gère aussi "cards", que ce module ne gère pas). */
  const entryListContainerClass =
    listLayout === "cards"
      ? "grid gap-3 grid-cols-[repeat(auto-fit,minmax(210px,1fr))]"
      : listLayout === "compact"
        ? "grid grid-cols-1 gap-1.5 @4xl:grid-cols-2 @6xl:grid-cols-3"
        : "grid grid-cols-1 gap-2 @6xl:grid-cols-2";
  const EntryListContainer = listLayout === "cards" ? "div" : "ul";

  // Budget partagé par TOUTES les sections de ce passage de rendu (voir RenderBudget). Recréé ici
  // à chaque rendu, donc toujours reparti de `renderBudget` — les sections le consomment ensuite
  // dans leur ordre d'affichage.
  const budget: RenderBudget = { remaining: renderBudget };
  const hasMoreToRender = renderBudget < filteredEntries.length;

  /** Rendu d'une liste de sections "par dossier" (voir groupedSections/typeSections) — factorisé
   * pour être appelé soit directement (coffre pas séparé par type), soit UNE fois par section de
   * type (coffre séparé par type — voir le bloc principal plus bas). */
  function renderFolderSections(sections: { name: string; entries: PlainVaultEntry[] }[], budget: RenderBudget) {
    // Le budget est prélevé ICI, dans l'ordre d'affichage, PUIS les sections qui n'ont rien reçu
    // sont écartées. Sans ce filtre, un coffre à beaucoup de dossiers afficherait, sous les
    // sections remplies, une longue traînée d'en-têtes de dossiers VIDES — la liste s'arrête
    // maintenant net, et la suite apparaît en descendant.
    const visible = sections
      .map((section) => ({ section, entries: takeFromBudget(section.entries, budget) }))
      .filter((slice) => slice.entries.length > 0);

    return (
      <div className="flex flex-col gap-5">
        {visible.map(({ section, entries: visibleEntries }) => (
          <div key={section.name}>
            <div className="mb-2 flex items-center gap-2">
              <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                {/* Compteur VRAI (section.entries.length), jamais le nombre réellement monté :
                    l'en-tête doit annoncer ce que contient le dossier, pas où en est le rendu
                    progressif. */}
                {section.name} <span className="font-normal normal-case text-neutral-400">({section.entries.length})</span>
              </h2>
              {section.name !== "Sans dossier" && (
                <button
                  type="button"
                  disabled={isBulkBusy}
                  onClick={() => void handleRenameFolder(section.name)}
                  className="text-xs font-normal normal-case text-indigo-600 hover:underline disabled:cursor-not-allowed disabled:opacity-40 dark:text-indigo-400"
                >
                  Renommer
                </button>
              )}
            </div>
            {/* @container : voir le commentaire de entryListContainerClass ci-dessus. */}
            <div className="@container">
              <EntryListContainer className={entryListContainerClass}>
                {visibleEntries.map((entry) => renderEntry(entry, { hideFolderBadge: true }))}
              </EntryListContainer>
            </div>
          </div>
        ))}
      </div>
    );
  }

  return (
    <main className="min-h-screen bg-neutral-50 px-4 py-8 dark:bg-neutral-950">
      {/* CORRECTIF (retour utilisateur, 2026-09-01, puis ÉLARGI le 2026-09-02 — captures d'écran
       * plein écran sur un moniteur 1440p, beaucoup d'espace vide des deux côtés) : max-w-2xl
       * (672px) restait fixe quelle que soit la largeur de fenêtre — sur tablette (Android/iPad) ou
       * desktop, cette limite était atteinte bien avant le bord de l'écran. md/lg/xl/2xl élargissent
       * PROGRESSIVEMENT le contenu à partir de la largeur d'une tablette portrait (768px) jusqu'à un
       * très grand écran (2xl, ≥1536px de fenêtre) — CSS pur, un même comportement sur Android
       * tablette/iPad et desktop (pas de détection de plateforme). Le Coffre va plus loin que les
       * autres pages (2xl:max-w-[110rem] au lieu de 100rem, voir plus bas) : c'est l'écran le plus
       * consulté, celui où profiter de tout l'espace dispo (plus de colonnes de cartes) apporte le
       * plus — voir entryListContainerClass ci-dessus, dont les paliers @4xl/@6xl suivent cet
       * élargissement (plus de colonnes uniquement si le conteneur est vraiment assez large pour les
       * accueillir sans comprimer les cartes, jamais juste parce que la fenêtre l'est). */}
      <div className="mx-auto max-w-2xl md:max-w-3xl lg:max-w-4xl xl:max-w-6xl 2xl:max-w-[110rem]">
        {/* CORRECTIF (retour utilisateur, 2026-09-02) : la navigation (Administration/Partagé avec
         * moi/Coffres partagés/Réglages/Signaler un bug/Déconnexion) vit maintenant dans
         * components/AppShell.tsx, commune à TOUTES les pages authentifiées — cet en-tête ne garde
         * que le TITRE de CETTE page, plus le menu "⋮" MOBILE UNIQUEMENT pour les actions
         * spécifiques au Coffre (Sélectionner/Corbeille/Santé du coffre/Importer/Exporter, masquées
         * sur mobile plus bas dans la rangée d'actions — voir son propre commentaire). Un second
         * "⋮" distinct de celui d'AppShell (nav de toute l'app) : celui-ci reste à cet endroit,
         * juste à côté des boutons qu'il remplace sur petit écran, pas dans le bandeau du haut. */}
        <header className="mb-6 flex items-center justify-between gap-3">
          <h1 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">Coffre</h1>
          <div className="shrink-0 sm:hidden">
            <EntryActionsMenu
              isOpen={showMobileMenu}
              onToggle={() => setShowMobileMenu((v) => !v)}
              onClose={() => setShowMobileMenu(false)}
              items={[
                { label: isSelecting ? "Annuler la sélection" : "Sélectionner", onClick: () => (isSelecting ? exitSelection() : setIsSelecting(true)) },
                { label: "Corbeille", onClick: () => setShowTrash(true) },
                { label: "Santé du coffre", onClick: () => setShowHealth(true) },
                { label: "Importer", onClick: () => importExportRef.current?.triggerImport() },
                { label: "Exporter", onClick: () => importExportRef.current?.triggerExport() },
              ]}
            />
          </div>
        </header>

        {/* Trois rangées INDÉPENDANTES (pas une seule rangée flex-wrap partagée) plutôt qu'une
         * seule rangée de 10 éléments indifférenciés : 1) recherche + tri/dossier, 2) filtres
         * rapides (étiquetés "Filtres :" pour qu'on comprenne que ce sont des bascules, pas des
         * actions), 3) actions, alignées à droite via justify-end sur SA PROPRE rangée. Chaque
         * rangée porte son propre `gap-3` externe (via le conteneur flex-col parent) : sans ça,
         * deux groupes qui débordent sur une fenêtre étroite et retombent chacun à la ligne
         * n'étaient espacés QUE du petit gap qui sépare aussi chaque bouton individuel entre eux —
         * visuellement collés l'un à l'autre plutôt que clairement distincts. flex-wrap sur chaque
         * rangée : sans min-w-0/flex-1 correctement posé, un élément flex ne rétrécit jamais sous
         * sa largeur de contenu naturelle sur une fenêtre étroite (même bug de fond que les cartes
         * d'entrée, voir StrengthDot/badges plus bas). */}
        <div className="mb-4 flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <input
              ref={searchInputRef}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Rechercher… (Ctrl+F)"
              className="min-w-[180px] flex-1 rounded-lg border border-neutral-300 px-3 py-2 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
            />
            {existingFolders.length > 0 && (
              <select
                value={folderFilter}
                onChange={(e) => setFolderFilter(e.target.value)}
                className="shrink-0 rounded-lg border border-neutral-300 px-2 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
              >
                <option value="">Tous les dossiers</option>
                <option value="__none__">Sans dossier</option>
                {existingFolders.map((folder) => (
                  <option key={folder} value={folder}>
                    {folder}
                  </option>
                ))}
              </select>
            )}
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as "name" | "updated" | "strength" | "usage")}
              className="shrink-0 rounded-lg border border-neutral-300 px-2 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
            >
              <option value="name">Trier : nom</option>
              <option value="updated">Trier : dernière modification</option>
              <option value="usage">Trier : le plus utilisé</option>
              <option value="strength">Trier : force (faible d'abord)</option>
            </select>
          </div>

          {/* Filtres rapides — raccourci vers ce que "Santé du coffre" détaille déjà, sans avoir
           * à l'ouvrir. Un second clic sur le filtre actif le désactive (retour à "tous"). */}
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="text-xs font-medium text-neutral-500 dark:text-neutral-400">Filtres :</span>
            <button
                type="button"
                onClick={() => setQuickFilter((f) => (f === "weak" ? "" : "weak"))}
                className={`shrink-0 rounded-full border px-3 py-1 text-xs font-medium transition ${
                  quickFilter === "weak"
                    ? "border-red-300 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950 dark:text-red-400"
                    : "border-neutral-300 text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-400 dark:hover:bg-neutral-900"
                }`}
              >
                Faibles
              </button>
              <button
                type="button"
                onClick={() => setQuickFilter((f) => (f === "reused" ? "" : "reused"))}
                className={`shrink-0 rounded-full border px-3 py-1 text-xs font-medium transition ${
                  quickFilter === "reused"
                    ? "border-orange-300 bg-orange-50 text-orange-700 dark:border-orange-900 dark:bg-orange-950 dark:text-orange-400"
                    : "border-neutral-300 text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-400 dark:hover:bg-neutral-900"
                }`}
              >
                Réutilisés
              </button>
              <button
                type="button"
                onClick={() => setQuickFilter((f) => (f === "old" ? "" : "old"))}
                className={`shrink-0 rounded-full border px-3 py-1 text-xs font-medium transition ${
                  quickFilter === "old"
                    ? "border-amber-300 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-400"
                    : "border-neutral-300 text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-400 dark:hover:bg-neutral-900"
                }`}
              >
                Anciens
              </button>
              <button
                type="button"
                onClick={() => setQuickFilter((f) => (f === "favorite" ? "" : "favorite"))}
                className={`shrink-0 rounded-full border px-3 py-1 text-xs font-medium transition ${
                  quickFilter === "favorite"
                    ? "border-indigo-300 bg-indigo-50 text-indigo-700 dark:border-indigo-900 dark:bg-indigo-950 dark:text-indigo-400"
                    : "border-neutral-300 text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-400 dark:hover:bg-neutral-900"
                }`}
              >
                Favoris
              </button>
              <button
                type="button"
                onClick={() => setQuickFilter((f) => (f === "attachment" ? "" : "attachment"))}
                className={`shrink-0 rounded-full border px-3 py-1 text-xs font-medium transition ${
                  quickFilter === "attachment"
                    ? "border-teal-300 bg-teal-50 text-teal-700 dark:border-teal-900 dark:bg-teal-950 dark:text-teal-400"
                    : "border-neutral-300 text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-400 dark:hover:bg-neutral-900"
                }`}
              >
                Pièce jointe
              </button>
            </div>

          {/* "?"/Sélectionner/Corbeille/Santé du coffre : masqués sur mobile (`hidden sm:...` sur
           * CHAQUE bouton, pas sur le conteneur — voir le menu ⋮ du header, qui donne accès aux
           * mêmes actions là-bas) ; "+ Ajouter" reste toujours visible, l'action la plus fréquente. */}
          <div className="flex flex-wrap items-center justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowShortcutsHelp(true)}
                title="Raccourcis clavier (?)"
                aria-label="Afficher les raccourcis clavier"
                className="hidden shrink-0 rounded-lg border border-neutral-300 px-3 py-2 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-900 sm:inline-flex"
              >
                ?
              </button>
              <button
                type="button"
                onClick={() => (isSelecting ? exitSelection() : setIsSelecting(true))}
                disabled={entries.length === 0}
                className={`hidden shrink-0 rounded-lg border px-3 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-40 sm:inline-flex ${
                  isSelecting
                    ? "border-indigo-300 bg-indigo-50 text-indigo-700 dark:border-indigo-800 dark:bg-indigo-950 dark:text-indigo-300"
                    : "border-neutral-300 text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-900"
                }`}
              >
                {isSelecting ? "Annuler" : "Sélectionner"}
              </button>
              <button
                type="button"
                onClick={() => setShowTrash(true)}
                className="hidden shrink-0 rounded-lg border border-neutral-300 px-3 py-2 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-900 sm:inline-flex"
              >
                Corbeille
              </button>
              <button
                type="button"
                onClick={() => setShowHealth(true)}
                disabled={entries.length === 0}
                className="hidden shrink-0 rounded-lg border border-neutral-300 px-3 py-2 text-sm font-medium text-neutral-700 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-900 sm:inline-flex"
              >
                Santé du coffre
              </button>
              <button
                type="button"
                onClick={() => setModal({ mode: "add" })}
                className="shrink-0 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-700"
              >
                + Ajouter
              </button>
          </div>
        </div>

        {isSelecting && (
          <div className="mb-4 flex flex-wrap items-center gap-2 rounded-lg border border-indigo-200 bg-indigo-50 px-3 py-2 dark:border-indigo-900 dark:bg-indigo-950">
            <label className="flex items-center gap-1.5 text-sm text-indigo-800 dark:text-indigo-200">
              <input
                type="checkbox"
                checked={filteredEntries.length > 0 && selectedIds.size === filteredEntries.length}
                onChange={toggleSelectAll}
                className="rounded border-indigo-300 text-indigo-600 focus:ring-indigo-500"
              />
              Tout sélectionner
            </label>
            <span className="text-sm text-indigo-700 dark:text-indigo-300">{selectedIds.size} sélectionnée(s)</span>
            <div className="ml-auto flex flex-wrap gap-1.5">
              <button
                type="button"
                disabled={selectedIds.size === 0 || isBulkBusy}
                onClick={() => void handleBulkSetFavorite(true)}
                className="rounded-lg border border-neutral-300 bg-white px-2.5 py-1 text-xs font-medium text-neutral-700 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                ★ Mettre en favori
              </button>
              <button
                type="button"
                disabled={selectedIds.size === 0 || isBulkBusy}
                onClick={() => void handleBulkSetFavorite(false)}
                className="rounded-lg border border-neutral-300 bg-white px-2.5 py-1 text-xs font-medium text-neutral-700 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                ☆ Retirer des favoris
              </button>
              {/* Un <select> plutôt qu'un champ libre + <datalist> : une fois un dossier choisi via
               * une datalist, la plupart des moteurs de rendu ne réaffichent plus les AUTRES
               * suggestions tant que le texte tapé les "filtre" (le champ contient déjà une
               * correspondance exacte) — bug remonté par l'utilisateur. Un <select> montre
               * toujours la liste complète, à chaque ouverture, sans cet effet de bord. */}
              <select
                value={bulkFolderIsNew ? "__new__" : bulkFolderInput}
                onChange={(e) => {
                  if (e.target.value === "__new__") {
                    setBulkFolderIsNew(true);
                    setBulkFolderInput("");
                  } else {
                    setBulkFolderIsNew(false);
                    setBulkFolderInput(e.target.value);
                  }
                }}
                disabled={isBulkBusy}
                className="rounded-lg border border-neutral-300 px-2 py-1 text-xs outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:bg-neutral-900"
              >
                <option value="" disabled>
                  Dossier…
                </option>
                {existingFolders.map((f) => (
                  <option key={f} value={f}>
                    {f}
                  </option>
                ))}
                <option value="__new__">➕ Nouveau dossier…</option>
              </select>
              {bulkFolderIsNew && (
                <input
                  autoFocus
                  value={bulkFolderInput}
                  onChange={(e) => setBulkFolderInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && selectedIds.size > 0 && bulkFolderInput.trim()) {
                      void handleBulkSetFolder(bulkFolderInput.trim());
                    }
                  }}
                  placeholder="Nom du nouveau dossier"
                  disabled={isBulkBusy}
                  className="w-32 rounded-lg border border-neutral-300 px-2 py-1 text-xs outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:bg-neutral-900"
                />
              )}
              <button
                type="button"
                disabled={selectedIds.size === 0 || isBulkBusy || !bulkFolderInput.trim()}
                onClick={() => void handleBulkSetFolder(bulkFolderInput.trim())}
                className="rounded-lg border border-neutral-300 bg-white px-2.5 py-1 text-xs font-medium text-neutral-700 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                📁 Déplacer vers
              </button>
              <button
                type="button"
                disabled={selectedIds.size === 0 || isBulkBusy}
                onClick={() => void handleBulkSetFolder("")}
                className="rounded-lg border border-neutral-300 bg-white px-2.5 py-1 text-xs font-medium text-neutral-700 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                Retirer du dossier
              </button>
              <button
                type="button"
                disabled={selectedIds.size === 0 || isBulkBusy}
                onClick={() => setBulkSharingEntries(entries.filter((e) => selectedIds.has(e.id)))}
                className="rounded-lg border border-neutral-300 bg-white px-2.5 py-1 text-xs font-medium text-neutral-700 hover:bg-neutral-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                Partager
              </button>
              <button
                type="button"
                disabled={selectedIds.size === 0 || isBulkBusy}
                onClick={() => void handleBulkDelete()}
                className="rounded-lg border border-red-300 bg-white px-2.5 py-1 text-xs font-medium text-red-600 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-40 dark:border-red-900 dark:bg-neutral-900 dark:text-red-400 dark:hover:bg-red-950"
              >
                Supprimer
              </button>
            </div>
          </div>
        )}

        <div className="mb-4">
          <ImportExportBar
            ref={importExportRef}
            existingEntries={entries}
            preselectedIds={selectedIds}
            onImported={() => void loadEntries()}
          />
        </div>

        {error && <p className="mb-4 text-sm text-red-600 dark:text-red-400">{error}</p>}

        {isLoading ? (
          <p className="text-sm text-neutral-500">Chargement…</p>
        ) : filteredEntries.length === 0 ? (
          <p className="text-sm text-neutral-500">
            {entries.length === 0
              ? "Le coffre est vide — ajoute ta première entrée."
              : "Aucune entrée ne correspond à la recherche ou aux filtres actifs."}
          </p>
        ) : (
          typeSections ? (
            // Retour utilisateur : "je ne veux juste pas que les cartes bancaires soient avec les
            // mots de passe et la même chose avec les cartes d'identité" — une section par type,
            // TOUJOURS séparée (pas de filtre à activer), voir typeSections ci-dessus.
            <div className="flex flex-col gap-8">
              {typeSections.map((section) => (
                // Budget épuisé : on n'affiche RIEN pour cette section (pas même son en-tête) —
                // les sections étant parcourues dans l'ordre, toutes celles qui suivent sont
                // écartées de la même façon, et réapparaîtront au palier suivant.
                budget.remaining <= 0 ? null : (
                <div key={section.type}>
                  <h2 className="mb-3 border-b border-neutral-200 pb-1.5 text-sm font-semibold text-neutral-700 dark:border-neutral-800 dark:text-neutral-200">
                    {section.label} <span className="font-normal text-neutral-400">({section.entries.length})</span>
                  </h2>
                  {section.folderGroups ? (
                    renderFolderSections(section.folderGroups, budget)
                  ) : (
                    <div className="@container">
                      <EntryListContainer className={entryListContainerClass}>
                        {takeFromBudget(section.entries, budget).map((entry) => renderEntry(entry))}
                      </EntryListContainer>
                    </div>
                  )}
                </div>
                )
              ))}
            </div>
          ) : groupedSections ? (
            renderFolderSections(groupedSections, budget)
          ) : (
            <div className="@container">
              <EntryListContainer className={entryListContainerClass}>
                {takeFromBudget(filteredEntries, budget).map((entry) => renderEntry(entry))}
              </EntryListContainer>
            </div>
          )
        )}

        {/* Sentinelle du rendu progressif (voir INITIAL_RENDER_BUDGET) : montée seulement s'il
            reste des entrées à afficher. Son apparition dans le champ de vision — anticipée de
            800px — déclenche le palier suivant. Le texte sert d'accusé de réception discret pour
            l'utilisateur d'un très gros coffre ; il n'apparaît jamais en usage courant, où tout
            tient dans le premier budget. */}
        {hasMoreToRender && (
          <div ref={loadMoreRef} className="py-6 text-center text-xs text-neutral-400">
            {renderBudget} entrée(s) affichée(s) sur {filteredEntries.length} — la suite se charge en descendant…
          </div>
        )}
      </div>

      {modal?.mode === "add" && (
        <VaultEntryForm
          title={modal.prefill ? "Dupliquer l'entrée" : "Nouvelle entrée"}
          submitLabel="Ajouter"
          initialValues={modal.prefill}
          onSubmit={handleAdd}
          onCancel={() => setModal(null)}
          existingFolders={existingFolders}
        />
      )}
      {modal?.mode === "edit" && (
        <VaultEntryForm
          title="Modifier l'entrée"
          submitLabel="Enregistrer"
          existingFolders={existingFolders}
          initialValues={modal.entry}
          onSubmit={(values) => handleEdit(modal.entry.id, values, values.password !== modal.entry.password, modal.entry.version)}
          onCancel={() => setModal(null)}
        />
      )}
      {showTrash && (
        <TrashModal onClose={() => setShowTrash(false)} onRestored={() => void loadEntries()} />
      )}
      {showHealth && (
        <VaultHealthModal
          entries={entries}
          onClose={() => setShowHealth(false)}
          onSelectEntry={(entry) => {
            setShowHealth(false);
            setModal({ mode: "edit", entry });
          }}
        />
      )}
      {historyEntry && (
        <VaultHistoryModal
          entry={historyEntry}
          authorizedRequest={authorizedRequest}
          onClose={() => setHistoryEntry(null)}
          onRestore={(oldPassword) => void handleRestoreHistoricalPassword(historyEntry, oldPassword)}
        />
      )}
      {attachmentsEntry && (
        <AttachmentsModal
          entry={attachmentsEntry}
          authorizedRequest={authorizedRequest}
          onClose={() => setAttachmentsEntry(null)}
        />
      )}
      {sharingEntry && (
        <ShareEntryModal
          entry={sharingEntry}
          authorizedRequest={authorizedRequest}
          onClose={() => setSharingEntry(null)}
        />
      )}
      {blindSharingEntry && (
        <BlindShareModal
          entry={blindSharingEntry}
          authorizedRequest={authorizedRequest}
          onClose={() => setBlindSharingEntry(null)}
        />
      )}
      {bulkSharingEntries && (
        <BulkShareModal
          entries={bulkSharingEntries}
          authorizedRequest={authorizedRequest}
          onClose={() => {
            setBulkSharingEntries(null);
            exitSelection();
          }}
        />
      )}
      {showShortcutsHelp && <KeyboardShortcutsModal onClose={() => setShowShortcutsHelp(false)} />}
    </main>
  );
}
