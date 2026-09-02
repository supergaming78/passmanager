// Popup de l'extension — connexion (email/mot de passe maître, avec 2FA si nécessaire) puis coffre
// (recherche, copie, remplissage automatique, édition, corbeille, partage, accès d'urgence,
// réglages). Pas de routeur : un état local par écran, chaque écran plein remplace le contenu de
// la popup (voir le plan — cohérent avec la taille modeste de chaque écran, 380×580px).

import { useEffect, useState, type FormEvent } from "react";
import * as api from "./api/client";
import * as session from "./lib/session";
import { decryptEntry, encryptEntry, type PlainVaultEntry } from "./lib/vaultCrypto";
import { getPreferredIdentifier } from "./lib/entryIdentifier";
import { isStandaloneWindow, openStandaloneAndClose } from "./lib/popupWindow";
import { getWindowMode } from "./lib/settings";
import { runAutofill, getActiveTabUrl, domainsLikelyMatch } from "./lib/autofill";
import { getErrorMessage } from "./lib/errors";
import { copyPasswordWithAutoClear } from "./lib/clipboard";
import * as entrySharing from "./lib/entrySharing";
import { recordEntryUse } from "./lib/vaultUsage";
import VaultEntryForm, { type VaultEntryFormValues } from "./components/VaultEntryForm";
import TrashView from "./components/TrashView";
import ShareEntryView from "./components/ShareEntryView";
import SharedReceivedView from "./components/SharedReceivedView";
import SharedEntryView from "./components/SharedEntryView";
import EmergencyAccessView from "./components/EmergencyAccessView";
import EmergencyVaultView from "./components/EmergencyVaultView";
import SharedVaultsListView from "./components/SharedVaultsListView";
import SharedVaultDetailView from "./components/SharedVaultDetailView";
import BlindShareView from "./components/BlindShareView";
import SettingsView from "./components/SettingsView";
import UpdateBanner from "./components/UpdateBanner";

type Screen =
  | { kind: "loading" }
  | { kind: "login" }
  | { kind: "tfa"; email: string; authHashHex: string; vaultKey: Uint8Array; rememberMe: boolean }
  | { kind: "vault"; email: string; vaultKey: Uint8Array };

export default function App() {
  const [screen, setScreen] = useState<Screen>({ kind: "loading" });

  useEffect(() => {
    // Mode "always" (voir lib/settings.ts::getWindowMode) : bascule vers la fenêtre détachée dès
    // le tout premier montage, avant même de savoir quel écran afficher — rien de significatif
    // n'a encore pu être saisi à ce stade, donc rien à persister avant de basculer (contrairement
    // au mode "tfa", voir onTfaRequired plus bas). Le petit popup ancré reste inévitablement
    // visible une fraction de seconde (impossible d'empêcher le navigateur de l'ouvrir au clic sur
    // l'icône), mais la vraie fenêtre prend le relais immédiatement. Ne PAS re-basculer si on est
    // déjà dans la fenêtre détachée (sinon boucle : cette fenêtre se recréerait elle-même à l'infini).
    if (getWindowMode() === "always" && !isStandaloneWindow()) {
      void openStandaloneAndClose();
      return;
    }

    // Une 2FA en attente (voir lib/session.ts::savePendingTfa) a priorité sur la session active
    // normale : c'est précisément l'état qu'on vient de sauvegarder juste avant de fermer le
    // popup ancré et d'ouvrir cette fenêtre (détachée ou reouverte) — reprendre exactement là où
    // on en était plutôt que de repartir de l'écran de connexion.
    void session.readPendingTfa().then((pending) => {
      if (pending) {
        setScreen({ kind: "tfa", ...pending });
        return;
      }
      void session.getActiveSession().then((active) => {
        setScreen(active ? { kind: "vault", email: active.email, vaultKey: active.vaultKey } : { kind: "login" });
      });
    });
  }, []);

  async function goToVault() {
    const active = await session.getActiveSession();
    if (active) setScreen({ kind: "vault", email: active.email, vaultKey: active.vaultKey });
  }

  // Bandeau de mise à jour (voir components/UpdateBanner.tsx — Chrome/Edge uniquement, ne fait
  // rien sur Firefox) : au-dessus de TOUS les écrans plutôt que dupliqué dans chacun, monté une
  // seule fois ici puis affiché quel que soit l'écran courant.
  let content: React.ReactNode;

  if (screen.kind === "loading") {
    content = <Centered>Chargement…</Centered>;
  } else if (screen.kind === "login") {
    content = (
      <LoginScreen
        onTfaRequired={(email, authHashHex, vaultKey, rememberMe) => {
          setScreen({ kind: "tfa", email, authHashHex, vaultKey, rememberMe });
          // CORRECTIF (voir lib/popupWindow.ts) : un popup ancré se ferme dès qu'on clique
          // ailleurs — systématique en pleine saisie 2FA, le temps d'aller lire le code dans un
          // email. Bascule vers une vraie fenêtre détachée, qui ne se ferme pas en perdant le
          // focus. Uniquement en mode "tfa" (voir lib/settings.ts::getWindowMode) : le mode
          // "always" a déjà basculé dès le montage (voir l'effet ci-dessus, !isStandaloneWindow()
          // y est alors déjà faux) ; le mode "never" reste volontairement en popup malgré le
          // risque. Fire-and-forget : l'écran 2FA local s'affiche immédiatement pendant que la
          // nouvelle fenêtre s'ouvre en arrière-plan, avant que celle-ci ne se ferme.
          if (getWindowMode() === "tfa" && !isStandaloneWindow()) {
            void session.savePendingTfa(email, authHashHex, vaultKey, rememberMe).then(openStandaloneAndClose);
          }
        }}
        onLoggedIn={goToVault}
      />
    );
  } else if (screen.kind === "tfa") {
    content = (
      <TfaScreen
        email={screen.email}
        authHashHex={screen.authHashHex}
        vaultKey={screen.vaultKey}
        rememberMe={screen.rememberMe}
        onVerified={() => {
          void session.clearPendingTfa();
          // Demande explicite : une fois le code accepté, on repasse en mode popup normal plutôt
          // que d'afficher le coffre dans la fenêtre détachée — celle-ci n'avait de raison d'être
          // qu'à cause de la saisie 2FA. Rouvrir l'extension depuis la barre d'outils retrouve
          // directement le coffre (session déjà persistée par verifyDeviceAndLogin), pas besoin
          // de se reconnecter. UNIQUEMENT en mode "tfa" : en mode "always", la fenêtre détachée
          // EST le mode d'usage normal du coffre, elle doit rester ouverte ; en mode "never", on
          // n'est de toute façon jamais passé par une fenêtre détachée.
          if (isStandaloneWindow() && getWindowMode() === "tfa") {
            window.close();
          } else {
            void goToVault();
          }
        }}
        onCancel={() => {
          void session.clearPendingTfa();
          setScreen({ kind: "login" });
        }}
      />
    );
  } else {
    content = (
      <VaultScreen
        email={screen.email}
        vaultKey={screen.vaultKey}
        onLoggedOut={() => setScreen({ kind: "login" })}
      />
    );
  }

  return (
    <>
      <UpdateBanner />
      {content}
    </>
  );
}

function Centered({ children }: { children: React.ReactNode }) {
  return <div className="flex min-h-[200px] items-center justify-center p-6 text-sm text-neutral-500">{children}</div>;
}

function LoginScreen({
  onTfaRequired,
  onLoggedIn,
}: {
  onTfaRequired: (email: string, authHashHex: string, vaultKey: Uint8Array, rememberMe: boolean) => void;
  onLoggedIn: () => void;
}) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [rememberMe, setRememberMe] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);
    try {
      const result = await session.login(email, password, rememberMe);
      if (result.status === "2FA_REQUIRED") {
        onTfaRequired(email, result.authHashHex, result.vaultKey, rememberMe);
      } else {
        onLoggedIn();
      }
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="p-5">
      <h1 className="mb-4 text-lg font-semibold text-neutral-900 dark:text-neutral-100">PassManager</h1>
      <form onSubmit={handleSubmit} className="flex flex-col gap-3">
        <div>
          <label htmlFor="email" className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
            Adresse email
          </label>
          <input
            id="email"
            type="email"
            required
            autoFocus
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
            placeholder="toi@example.com"
          />
        </div>

        <div>
          <label htmlFor="password" className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
            Mot de passe maître
          </label>
          <input
            id="password"
            type="password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
          />
        </div>

        <label className="flex items-center gap-2 text-sm text-neutral-700 dark:text-neutral-300">
          <input
            type="checkbox"
            checked={rememberMe}
            onChange={(e) => setRememberMe(e.target.checked)}
            className="rounded border-neutral-300 text-indigo-600 focus:ring-indigo-500"
          />
          Se souvenir de cet appareil
        </label>

        {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}

        <button
          type="submit"
          disabled={isSubmitting}
          className="mt-1 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {isSubmitting ? "Connexion…" : "Se connecter"}
        </button>
      </form>
    </div>
  );
}

function TfaScreen({
  email,
  authHashHex,
  vaultKey,
  rememberMe,
  onVerified,
  onCancel,
}: {
  email: string;
  authHashHex: string;
  vaultKey: Uint8Array;
  rememberMe: boolean;
  onVerified: () => void;
  onCancel: () => void;
}) {
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);
    try {
      await session.verifyDeviceAndLogin(email, code, authHashHex, vaultKey, rememberMe);
      onVerified();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="p-5">
      <h1 className="mb-1 text-lg font-semibold text-neutral-900 dark:text-neutral-100">Code de vérification</h1>
      <p className="mb-4 text-sm text-neutral-500">Un code vient d'être envoyé à {email}.</p>
      <form onSubmit={handleSubmit} className="flex flex-col gap-3">
        <input
          type="text"
          inputMode="numeric"
          required
          autoFocus
          value={code}
          onChange={(e) => setCode(e.target.value)}
          className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm tracking-widest outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
          placeholder="123456"
        />

        {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}

        <button
          type="submit"
          disabled={isSubmitting}
          className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {isSubmitting ? "Vérification…" : "Valider"}
        </button>
        <button type="button" onClick={onCancel} className="text-sm text-neutral-500 hover:underline">
          Annuler
        </button>
      </form>
    </div>
  );
}

type VaultView =
  | { kind: "list" }
  | { kind: "addEntry" }
  | { kind: "editEntry"; entry: PlainVaultEntry }
  | { kind: "trash" }
  | { kind: "share"; entry: PlainVaultEntry }
  | { kind: "sharedReceived" }
  | { kind: "viewSharedEntry"; shareId: string }
  | { kind: "blindShare"; entry: PlainVaultEntry }
  | { kind: "emergencyAccess" }
  | { kind: "emergencyVault"; contactId: string; ownerEmail: string }
  | { kind: "sharedVaults" }
  | { kind: "sharedVaultDetail"; vaultId: string }
  | { kind: "settings" };

function VaultScreen({ email, vaultKey, onLoggedOut }: { email: string; vaultKey: Uint8Array; onLoggedOut: () => void }) {
  const [entries, setEntries] = useState<PlainVaultEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  // Retour utilisateur (2026-09-02) : même tri que côté app desktop (voir pages/Vault.tsx::sortBy),
  // sans "force" (nécessiterait de porter l'estimation d'entropie, absente ici — hors périmètre de
  // cette popup volontairement réduite, voir extension/README.md).
  const [sortBy, setSortBy] = useState<"name" | "updated" | "usage">("name");
  // "" = tous les dossiers, "__none__" = sans dossier assigné, sinon le nom exact du dossier —
  // même convention que pages/Vault.tsx côté app desktop.
  const [folderFilter, setFolderFilter] = useState("");
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [filledId, setFilledId] = useState<string | null>(null);
  const [view, setView] = useState<VaultView>({ kind: "list" });

  async function reload() {
    try {
      // getFullVault() (PAS getVault() seul) : le serveur plafonne toujours une page à 100
      // entrées — sans boucler sur `offset`, un coffre plus grand serait tronqué en silence.
      const raw = await session.authorizedRequest((token) => api.getFullVault(token));
      const decrypted = await Promise.all(raw.map((entry) => decryptEntry(entry, vaultKey)));
      setEntries(decrypted);
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  useEffect(() => {
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vaultKey]);

  async function handleLogout() {
    await session.logout();
    onLoggedOut();
  }

  async function handleCopy(entry: PlainVaultEntry) {
    await copyPasswordWithAutoClear(entry.password);
    setCopiedId(entry.id);
    setTimeout(() => setCopiedId((id) => (id === entry.id ? null : id)), 1500);
    // Best-effort, jamais attendu (voir lib/vaultUsage.ts) : ne doit jamais ralentir la copie.
    recordEntryUse(session.authorizedRequest, entry.id);
  }

  async function handleFill(entry: PlainVaultEntry) {
    setError(null);
    try {
      // Avertit avant de remplir sur un domaine différent de celui enregistré pour cette entrée
      // (ex: page de phishing sur un domaine voisin) — voir domainsLikelyMatch() pour le détail.
      // N'a rien à comparer (entrée sans URL, ou onglet sans URL exploitable) -> ne bloque pas.
      if (entry.url) {
        const tabUrl = await getActiveTabUrl();
        if (tabUrl && !domainsLikelyMatch(entry.url, tabUrl)) {
          const proceed = window.confirm(
            `Cette entrée est enregistrée pour "${entry.url}", mais l'onglet actif ne correspond pas à ce domaine. Remplir quand même ?`,
          );
          if (!proceed) return;
        }
      }

      const usernameOrEmail = getPreferredIdentifier(entry);
      const result = await runAutofill(usernameOrEmail, entry.password);
      if (!result.passwordFilled) {
        setError("Aucun champ mot de passe trouvé sur cette page.");
        return;
      }
      setFilledId(entry.id);
      setTimeout(() => setFilledId((id) => (id === entry.id ? null : id)), 1500);
      // Uniquement si le remplissage a réellement réussi (voir le "return" ci-dessus sinon) —
      // best-effort, jamais attendu (voir lib/vaultUsage.ts).
      recordEntryUse(session.authorizedRequest, entry.id);
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  async function handleToggleFavorite(entry: PlainVaultEntry) {
    setEntries((prev) => (prev ? prev.map((e) => (e.id === entry.id ? { ...e, isFavorite: !e.isFavorite } : e)) : prev));
    try {
      await session.authorizedRequest((token) => api.toggleFavorite(token, entry.id));
    } catch (err) {
      setEntries((prev) => (prev ? prev.map((e) => (e.id === entry.id ? { ...e, isFavorite: entry.isFavorite } : e)) : prev));
      setError(getErrorMessage(err));
    }
  }

  async function handleDelete(entry: PlainVaultEntry) {
    if (!confirm(`Mettre "${entry.siteName}" à la corbeille ?`)) return;
    try {
      await session.authorizedRequest((token) => api.deleteVaultEntry(token, entry.id));
      setEntries((prev) => (prev ? prev.filter((e) => e.id !== entry.id) : prev));
      setView({ kind: "list" });
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  async function handleAdd(values: VaultEntryFormValues) {
    const encrypted = await encryptEntry(values, vaultKey);
    await session.authorizedRequest((token) => api.addToVault(token, encrypted));
    setView({ kind: "list" });
    await reload();
  }

  async function handleEdit(original: PlainVaultEntry, values: VaultEntryFormValues) {
    const passwordChanged = values.password !== original.password;
    const encrypted = await encryptEntry(values, vaultKey, passwordChanged, original.version);
    await session.authorizedRequest((token) => api.updateVaultEntry(token, original.id, encrypted));
    // Best-effort : garde les copies partagées à jour avec le nouveau contenu — ne doit jamais
    // faire échouer la modification elle-même.
    await entrySharing
      .reseedEntryShares({ ...values, id: original.id, updatedAt: "", version: 0, hasAttachments: false, useCount: 0 }, session.authorizedRequest)
      .catch(() => {});
    setView({ kind: "list" });
    await reload();
  }

  // Favoris toujours épinglés en premier (même comportement que côté app desktop, voir
  // pages/Vault.tsx) — le tri choisi ne s'applique QU'À L'INTÉRIEUR de chaque groupe.
  const filtered = (entries ?? [])
    .filter((e) => {
      const q = query.trim().toLowerCase();
      if (!q) return true;
      return e.siteName.toLowerCase().includes(q) || e.username.toLowerCase().includes(q) || e.loginEmail.toLowerCase().includes(q);
    })
    .filter((e) => {
      if (!folderFilter) return true;
      if (folderFilter === "__none__") return !e.folder;
      return e.folder === folderFilter;
    })
    .sort((a, b) => {
      if (a.isFavorite !== b.isFavorite) return Number(b.isFavorite) - Number(a.isFavorite);
      switch (sortBy) {
        case "updated":
          return new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime(); // plus récent d'abord
        case "usage":
          return b.useCount - a.useCount || a.siteName.localeCompare(b.siteName);
        case "name":
        default:
          return a.siteName.localeCompare(b.siteName);
      }
    });

  // Dossiers distincts déjà utilisés dans le coffre — même principe que
  // pages/Vault.tsx::existingFolders côté app desktop.
  const existingFolders = Array.from(new Set((entries ?? []).map((e) => e.folder).filter(Boolean))).sort((a, b) => a.localeCompare(b));

  // Regroupe l'affichage par dossier — SEULEMENT si aucun filtre de dossier n'est déjà actif (le
  // filtre réduit déjà à un seul dossier) et qu'il existe au moins un dossier. Même retour
  // utilisateur que côté app desktop : quand le tri actif est "le plus utilisé", les DOSSIERS
  // eux-mêmes remontent aussi par usage agrégé (somme des use_count de leurs entrées), pas
  // seulement les entrées à l'intérieur d'un dossier resté à sa place alphabétique.
  const groupedSections = (() => {
    if (folderFilter || existingFolders.length === 0) return null;
    const groups = new Map<string, PlainVaultEntry[]>();
    for (const entry of filtered) {
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
  })();

  if (view.kind === "addEntry") {
    return (
      <div className="flex flex-col">
        <ViewHeader title="Ajouter une entrée" onBack={() => setView({ kind: "list" })} />
        <VaultEntryForm onSubmit={handleAdd} onCancel={() => setView({ kind: "list" })} />
      </div>
    );
  }

  if (view.kind === "editEntry") {
    return (
      <div className="flex flex-col">
        <ViewHeader title="Modifier l'entrée" onBack={() => setView({ kind: "list" })} />
        <div className="flex gap-2 px-4 pt-3">
          <button
            onClick={() => setView({ kind: "share", entry: view.entry })}
            className="rounded-md border border-neutral-300 px-2 py-1 text-xs text-neutral-600 dark:border-neutral-700 dark:text-neutral-300"
          >
            Partager
          </button>
          <button
            onClick={() => setView({ kind: "blindShare", entry: view.entry })}
            className="rounded-md border border-neutral-300 px-2 py-1 text-xs text-neutral-600 dark:border-neutral-700 dark:text-neutral-300"
          >
            Partager (limité)
          </button>
          <button
            onClick={() => void handleDelete(view.entry)}
            className="rounded-md border border-red-300 px-2 py-1 text-xs text-red-600 hover:bg-red-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950"
          >
            Supprimer
          </button>
        </div>
        <VaultEntryForm
          initial={view.entry}
          onSubmit={(values) => handleEdit(view.entry, values)}
          onCancel={() => setView({ kind: "list" })}
        />
      </div>
    );
  }

  if (view.kind === "trash") {
    return <TrashView vaultKey={vaultKey} onBack={() => setView({ kind: "list" })} onRestored={() => void reload()} />;
  }

  if (view.kind === "share") {
    return <ShareEntryView entry={view.entry} onBack={() => setView({ kind: "editEntry", entry: view.entry })} />;
  }

  if (view.kind === "sharedReceived") {
    return (
      <SharedReceivedView
        vaultKey={vaultKey}
        onBack={() => setView({ kind: "list" })}
        onViewClassic={(shareId) => setView({ kind: "viewSharedEntry", shareId })}
      />
    );
  }

  if (view.kind === "blindShare") {
    return <BlindShareView entry={view.entry} onBack={() => setView({ kind: "editEntry", entry: view.entry })} />;
  }

  if (view.kind === "viewSharedEntry") {
    return <SharedEntryView shareId={view.shareId} vaultKey={vaultKey} onBack={() => setView({ kind: "sharedReceived" })} />;
  }

  if (view.kind === "emergencyAccess") {
    return (
      <EmergencyAccessView
        vaultKey={vaultKey}
        onBack={() => setView({ kind: "list" })}
        onViewVault={(contactId, ownerEmail) => setView({ kind: "emergencyVault", contactId, ownerEmail })}
      />
    );
  }

  if (view.kind === "emergencyVault") {
    return (
      <EmergencyVaultView
        vaultKey={vaultKey}
        contactId={view.contactId}
        ownerEmail={view.ownerEmail}
        onBack={() => setView({ kind: "emergencyAccess" })}
      />
    );
  }

  if (view.kind === "sharedVaults") {
    return (
      <SharedVaultsListView
        vaultKey={vaultKey}
        onBack={() => setView({ kind: "list" })}
        onOpen={(vaultId) => setView({ kind: "sharedVaultDetail", vaultId })}
      />
    );
  }

  if (view.kind === "sharedVaultDetail") {
    return (
      <SharedVaultDetailView
        vaultId={view.vaultId}
        vaultKey={vaultKey}
        myEmail={email}
        onBack={() => setView({ kind: "sharedVaults" })}
      />
    );
  }

  if (view.kind === "settings") {
    return <SettingsView email={email} onBack={() => setView({ kind: "list" })} onLoggedOut={onLoggedOut} />;
  }

  return (
    <div className="flex flex-col">
      <div className="flex items-center justify-between border-b border-neutral-200 px-4 py-3 dark:border-neutral-800">
        <div className="min-w-0">
          <p className="truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">{email}</p>
        </div>
        <button onClick={handleLogout} className="shrink-0 text-xs text-neutral-500 hover:underline">
          Déconnexion
        </button>
      </div>

      <div className="flex flex-wrap gap-2 px-4 py-2 text-xs">
        <button onClick={() => setView({ kind: "addEntry" })} className="rounded-md bg-indigo-600 px-2 py-1 font-medium text-white hover:bg-indigo-700">
          + Ajouter
        </button>
        <button onClick={() => setView({ kind: "trash" })} className="rounded-md border border-neutral-300 px-2 py-1 text-neutral-600 dark:border-neutral-700 dark:text-neutral-300">
          Corbeille
        </button>
        <button onClick={() => setView({ kind: "sharedReceived" })} className="rounded-md border border-neutral-300 px-2 py-1 text-neutral-600 dark:border-neutral-700 dark:text-neutral-300">
          Partagé avec moi
        </button>
        <button onClick={() => setView({ kind: "sharedVaults" })} className="rounded-md border border-neutral-300 px-2 py-1 text-neutral-600 dark:border-neutral-700 dark:text-neutral-300">
          Coffres partagés
        </button>
        <button onClick={() => setView({ kind: "emergencyAccess" })} className="rounded-md border border-neutral-300 px-2 py-1 text-neutral-600 dark:border-neutral-700 dark:text-neutral-300">
          Urgence
        </button>
        <button onClick={() => setView({ kind: "settings" })} className="rounded-md border border-neutral-300 px-2 py-1 text-neutral-600 dark:border-neutral-700 dark:text-neutral-300">
          Réglages
        </button>
      </div>

      <div className="flex flex-col gap-2 px-4 py-2">
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Rechercher…"
          className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
        />
        <div className="flex gap-2">
          {existingFolders.length > 0 && (
            <select
              value={folderFilter}
              onChange={(e) => setFolderFilter(e.target.value)}
              className="min-w-0 flex-1 rounded-lg border border-neutral-300 px-2 py-1.5 text-xs outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
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
            onChange={(e) => setSortBy(e.target.value as "name" | "updated" | "usage")}
            className="min-w-0 flex-1 rounded-lg border border-neutral-300 px-2 py-1.5 text-xs outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900"
          >
            <option value="name">Trier : nom</option>
            <option value="updated">Trier : dernière modification</option>
            <option value="usage">Trier : le plus utilisé</option>
          </select>
        </div>
      </div>

      {error && <p className="px-4 pb-2 text-sm text-red-600 dark:text-red-400">{error}</p>}

      {entries === null && !error && <Centered>Déchiffrement du coffre…</Centered>}

      {entries !== null && filtered.length === 0 && (
        <p className="px-4 pb-4 text-sm text-neutral-500">Aucune entrée ne correspond.</p>
      )}

      {groupedSections ? (
        <div className="flex flex-col gap-3 pb-2">
          {groupedSections.map((section) => (
            <div key={section.name}>
              <h2 className="px-4 pb-1 text-xs font-semibold uppercase tracking-wide text-neutral-500 dark:text-neutral-400">
                {section.name} <span className="font-normal normal-case text-neutral-400">({section.entries.length})</span>
              </h2>
              <ul className="flex flex-col divide-y divide-neutral-200 dark:divide-neutral-800">
                {section.entries.map((entry) => renderEntryRow(entry))}
              </ul>
            </div>
          ))}
        </div>
      ) : (
        <ul className="flex flex-col divide-y divide-neutral-200 pb-2 dark:divide-neutral-800">{filtered.map((entry) => renderEntryRow(entry))}</ul>
      )}
    </div>
  );

  /** Ligne d'une entrée — factorisée pour être réutilisée à la fois par la liste plate et la vue
   * groupée par dossier (voir groupedSections ci-dessus) sans dupliquer ce balisage. */
  function renderEntryRow(entry: PlainVaultEntry) {
    return (
      <li key={entry.id} className="flex items-center justify-between gap-2 px-4 py-2">
        <div className="flex min-w-0 items-center gap-2">
          <button
            onClick={() => void handleToggleFavorite(entry)}
            title={entry.isFavorite ? "Retirer des favoris" : "Ajouter aux favoris"}
            className="shrink-0 text-sm"
          >
            {entry.isFavorite ? "★" : "☆"}
          </button>
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">{entry.siteName}</p>
            <p className="truncate text-xs text-neutral-500">
              {getPreferredIdentifier(entry)}
            </p>
          </div>
        </div>
        <div className="flex shrink-0 flex-wrap items-center justify-end gap-2">
          {entry.url && (
            <button
              onClick={() => window.open(entry.url, "_blank", "noopener,noreferrer")}
              title="Ouvrir le site"
              className="rounded-md border border-neutral-300 px-2 py-1 text-xs text-neutral-600 hover:bg-neutral-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              Ouvrir
            </button>
          )}
          <button
            onClick={() => void handleFill(entry)}
            title="Remplir le formulaire de connexion de l'onglet actif"
            className="rounded-md bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-700"
          >
            {filledId === entry.id ? "Rempli !" : "Remplir"}
          </button>
          <button
            onClick={() => void handleCopy(entry)}
            title="Copier le mot de passe"
            className="rounded-md border border-neutral-300 px-2 py-1 text-xs text-neutral-600 hover:bg-neutral-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            {copiedId === entry.id ? "Copié !" : "Copier"}
          </button>
          <button
            onClick={() => setView({ kind: "editEntry", entry })}
            title="Modifier"
            className="rounded-md border border-neutral-300 px-2 py-1 text-xs text-neutral-600 hover:bg-neutral-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
          >
            Modifier
          </button>
        </div>
      </li>
    );
  }
}

function ViewHeader({ title, onBack }: { title: string; onBack: () => void }) {
  return (
    <div className="flex items-center gap-2 border-b border-neutral-200 px-4 py-3 dark:border-neutral-800">
      <button onClick={onBack} className="text-sm text-neutral-500 hover:underline">
        ← Retour
      </button>
      <h1 className="text-sm font-medium text-neutral-900 dark:text-neutral-100">{title}</h1>
    </div>
  );
}
