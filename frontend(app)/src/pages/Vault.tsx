import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../state/AuthContext";
import * as api from "../api/client";
import { decryptEntry, encryptEntry, type PlainVaultEntry } from "../lib/vaultCrypto";
import { maybeRunAutoBackup } from "../lib/autoBackup";
import { fuzzyIncludes } from "../lib/fuzzyMatch";
import { getErrorMessage } from "../lib/errors";
import { copyPasswordWithAutoClear } from "../lib/clipboard";
import { openEntryUrl } from "../lib/openExternalUrl";
import { WEAK_THRESHOLD_BITS, estimatePasswordEntropyBits, rateEntropy } from "../lib/passwordGenerator";
import { OLD_PASSWORD_DAYS, daysSince, formatRelativeAge } from "../lib/age";
import VaultEntryForm, { type VaultEntryFormValues } from "../components/VaultEntryForm";
import ImportExportBar, { type ImportExportBarHandle } from "../components/ImportExportBar";
import TrashModal from "../components/TrashModal";
import VaultHealthModal from "../components/VaultHealthModal";
import VaultHistoryModal from "../components/VaultHistoryModal";
import AttachmentsModal from "../components/AttachmentsModal";
import ShareEntryModal from "../components/ShareEntryModal";
import BlindShareModal from "../components/BlindShareModal";
import BugReportModal from "../components/BugReportModal";
import { reseedEntryShares } from "../lib/entrySharing";
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

type ModalState = { mode: "add"; prefill?: VaultEntryFormValues } | { mode: "edit"; entry: PlainVaultEntry } | null;

export default function Vault() {
  const { email, isModerator, logout, authorizedRequest, subscribeToVaultSync } = useAuth();
  const navigate = useNavigate();

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
  const [sortBy, setSortBy] = useState<"name" | "updated" | "strength">("name");
  const [modal, setModal] = useState<ModalState>(null);
  const [showTrash, setShowTrash] = useState(false);
  const [showHealth, setShowHealth] = useState(false);
  const [showShortcutsHelp, setShowShortcutsHelp] = useState(false);
  const [showBugReport, setShowBugReport] = useState(false);
  const [historyEntry, setHistoryEntry] = useState<PlainVaultEntry | null>(null);
  const [attachmentsEntry, setAttachmentsEntry] = useState<PlainVaultEntry | null>(null);
  const [sharingEntry, setSharingEntry] = useState<PlainVaultEntry | null>(null);
  const [blindSharingEntry, setBlindSharingEntry] = useState<PlainVaultEntry | null>(null);
  const [revealedId, setRevealedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copiedIdentifierId, setCopiedIdentifierId] = useState<string | null>(null);
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
      const decrypted = await Promise.all(encrypted.map(decryptEntry));
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

  // Dossiers distincts déjà utilisés dans le coffre — triés, pour le filtre et l'autocomplétion
  // du formulaire (voir VaultEntryForm.tsx::existingFolders).
  const existingFolders = useMemo(
    () => Array.from(new Set(entries.map((e) => e.folder).filter(Boolean))).sort((a, b) => a.localeCompare(b)),
    [entries],
  );

  // Regroupe l'affichage par dossier (nom du dossier en en-tête, ses entrées en dessous) — SEULEMENT
  // si l'utilisateur a effectivement commencé à utiliser des dossiers (sinon on ne change rien à
  // l'affichage plat habituel) et qu'aucun filtre de dossier n'est déjà actif (le filtre réduit
  // déjà à un seul dossier, un en-tête répété par-dessus serait redondant avec le sélecteur).
  const groupedSections = useMemo(() => {
    if (folderFilter || existingFolders.length === 0) return null;

    const groups = new Map<string, PlainVaultEntry[]>();
    for (const entry of filteredEntries) {
      const key = entry.folder;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key)!.push(entry);
    }

    const named = Array.from(groups.keys())
      .filter((k) => k !== "")
      .sort((a, b) => a.localeCompare(b))
      .map((name) => ({ name, entries: groups.get(name)! }));
    const withoutFolder = groups.get("");
    return withoutFolder ? [...named, { name: "Sans dossier", entries: withoutFolder }] : named;
  }, [filteredEntries, folderFilter, existingFolders]);

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
    // `updatedAt`/`hasAttachments` factices : reseedEntryShares() n'en a pas besoin (il ne fait que
    // re-sceller le contenu déjà accepté par le serveur ci-dessus, pas une nouvelle vérification de
    // conflit, et les pièces jointes sont hors périmètre du partage — voir entrySharing.ts).
    void reseedEntryShares(authorizedRequest, { id, updatedAt: "", version: 0, hasAttachments: false, ...values }).catch(() => {});
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
  }

  async function handleCopyIdentifier(entry: PlainVaultEntry) {
    const identifier = entry.preferredLoginType === "email" ? entry.loginEmail : entry.username || entry.loginEmail;
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
      const results = await Promise.allSettled(ids.map((id) => authorizedRequest((token) => api.deleteVaultEntry(token, id))));
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
      const results = await Promise.allSettled(targets.map((e) => authorizedRequest((token) => api.toggleFavorite(token, e.id))));
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
    const results = await Promise.allSettled(
      targets.map(async (e) => {
        const { id: _id, ...withoutId } = e;
        const encrypted = await encryptEntry({ ...withoutId, folder }, false, e.version);
        await authorizedRequest((token) => api.updateVaultEntry(token, e.id, encrypted));
        // Même raison que dans handleEdit() : le dossier fait partie du contenu scellé pour un
        // éventuel partage (voir lib/entrySharing.ts), donc lui aussi périmé après ce changement.
        void reseedEntryShares(authorizedRequest, { ...e, folder }).catch(() => {});
      }),
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
        className={`flex items-start justify-between gap-3 rounded-xl border p-4 transition ${
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
                {entry.entryType === "login"
                  ? entry.preferredLoginType === "email"
                    ? entry.loginEmail
                    : entry.username || entry.loginEmail || "—"
                  : entry.username || "—"}
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
          </div>
        </div>

        {!isSelecting && (
          // Seules les actions les plus courantes restent des boutons texte directement visibles
          // (au plus 5, quasi jamais sur 2 lignes) — dupliquer/historique/supprimer, plus rares,
          // sont regroupées dans le menu "⋯" (voir EntryActionsMenu) : c'est ce qui évite à cette
          // rangée de passer à la ligne différemment d'une carte à l'autre selon le nom de site ou
          // les badges affichés à gauche (voir le commentaire sur items-start plus haut).
          <div className="ml-3 flex shrink-0 flex-wrap items-start justify-end gap-1.5">
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

  return (
    <main className="min-h-screen bg-neutral-50 px-4 py-8 dark:bg-neutral-950">
      <div className="mx-auto max-w-2xl">
        <header className="mb-6 flex flex-col gap-3">
          <div className="flex items-center justify-between gap-3">
            <div className="min-w-0">
              <h1 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">Coffre</h1>
              <p className="truncate text-sm text-neutral-500">{email}</p>
            </div>
            {/* Menu ⋮ — MOBILE UNIQUEMENT (`sm:hidden`), voir sa déclaration plus haut. Regroupe la
             * navigation ci-dessous + les actions accessoires de la rangée d'outils (voir plus bas
             * dans ce fichier) qui, sinon, s'empilaient en une quinzaine de boutons individuels sur
             * un écran étroit. */}
            <div className="shrink-0 sm:hidden">
              <EntryActionsMenu
                isOpen={showMobileMenu}
                onToggle={() => setShowMobileMenu((v) => !v)}
                onClose={() => setShowMobileMenu(false)}
                items={[
                  ...(isModerator ? [{ label: "Administration", onClick: () => navigate("/admin") }] : []),
                  { label: "Partagé avec moi", onClick: () => navigate("/shared-with-me") },
                  { label: "Coffres partagés", onClick: () => navigate("/shared-vaults") },
                  { label: "Réglages", onClick: () => navigate("/settings") },
                  { label: "Aide raccourcis", onClick: () => setShowShortcutsHelp(true) },
                  { label: isSelecting ? "Annuler la sélection" : "Sélectionner", onClick: () => (isSelecting ? exitSelection() : setIsSelecting(true)) },
                  { label: "Corbeille", onClick: () => setShowTrash(true) },
                  { label: "Santé du coffre", onClick: () => setShowHealth(true) },
                  { label: "Importer", onClick: () => importExportRef.current?.triggerImport() },
                  { label: "Exporter", onClick: () => importExportRef.current?.triggerExport() },
                  { label: "Signaler un bug", onClick: () => setShowBugReport(true) },
                ]}
              />
            </div>
            <button
              type="button"
              onClick={() => void logout()}
              className="shrink-0 rounded-lg border border-neutral-300 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-900"
            >
              Se déconnecter
            </button>
          </div>
          {/* Navigation séparée du bandeau titre/déconnexion ci-dessus — sur sa propre ligne,
           * `flex-wrap` pour se répartir proprement sur plusieurs lignes si la fenêtre est étroite
           * plutôt que d'écraser tous les boutons ensemble (voir les rangées filtres/actions plus
           * bas, qui suivent déjà ce même principe). `hidden sm:flex` : sur mobile, ces mêmes liens
           * sont déjà dans le menu ⋮ ci-dessus (voir son commentaire) — inutile de les répéter deux
           * fois sur un écran étroit. */}
          <nav className="hidden flex-wrap gap-2 sm:flex">
            {isModerator && (
              <Link
                to="/admin"
                className="rounded-lg border border-indigo-300 px-3 py-1.5 text-sm font-medium text-indigo-700 hover:bg-indigo-50 dark:border-indigo-800 dark:text-indigo-300 dark:hover:bg-indigo-950"
              >
                Administration
              </Link>
            )}
            <Link
              to="/shared-with-me"
              className="rounded-lg border border-neutral-300 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-900"
            >
              Partagé avec moi
            </Link>
            <Link
              to="/shared-vaults"
              className="rounded-lg border border-neutral-300 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-900"
            >
              Coffres partagés
            </Link>
            <Link
              to="/settings"
              className="rounded-lg border border-neutral-300 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-900"
            >
              Réglages
            </Link>
            <button
              type="button"
              onClick={() => setShowBugReport(true)}
              className="rounded-lg border border-neutral-300 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-900"
            >
              Signaler un bug
            </button>
          </nav>
        </header>

        {showBugReport && <BugReportModal onClose={() => setShowBugReport(false)} defaultEmail={email ?? undefined} />}

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
              onChange={(e) => setSortBy(e.target.value as "name" | "updated" | "strength")}
              className="shrink-0 rounded-lg border border-neutral-300 px-2 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
            >
              <option value="name">Trier : nom</option>
              <option value="updated">Trier : dernière modification</option>
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
          groupedSections ? (
            <div className="flex flex-col gap-5">
              {groupedSections.map((section) => (
                <div key={section.name}>
                  <div className="mb-2 flex items-center gap-2">
                    <h2 className="text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
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
                  <ul className="flex flex-col gap-2">{section.entries.map((entry) => renderEntryRow(entry, { hideFolderBadge: true }))}</ul>
                </div>
              ))}
            </div>
          ) : (
            <ul className="flex flex-col gap-2">{filteredEntries.map((entry) => renderEntryRow(entry))}</ul>
          )
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
      {showShortcutsHelp && <KeyboardShortcutsModal onClose={() => setShowShortcutsHelp(false)} />}
    </main>
  );
}
