import { useCallback, useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useAuth } from "../state/AuthContext";
import * as sharedVault from "../lib/sharedVault";
import type { UnlockedSharedVault, PlainSharedVaultEntry } from "../lib/sharedVault";
import type { SharedVaultMemberView } from "../api/types";
import { generatePassword, DEFAULT_GENERATOR_OPTIONS } from "../lib/passwordGenerator";
import { copyPasswordWithAutoClear } from "../lib/clipboard";
import { openEntryUrl } from "../lib/openExternalUrl";
import { getErrorMessage } from "../lib/errors";
import { getPreferredIdentifier } from "../lib/entryIdentifier";
import { getListLayout, listContainerClass } from "../lib/listLayout";

const EMPTY_FORM = { siteName: "", username: "", loginEmail: "", password: "", preferredLoginType: "username" as "username" | "email", notes: "", url: "" };

/** Un coffre partagé précis : ses entrées (ajout/modification/suppression), ses membres
 * (invitation/retrait/départ). Voir lib/sharedVault.ts pour toute l'orchestration crypto —
 * cette page ne fait qu'appeler ce module et afficher le résultat, jamais de crypto ici. */
export default function SharedVaultDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { authorizedRequest, email: myEmail, subscribeToVaultSync } = useAuth();
  const navigate = useNavigate();

  const [vault, setVault] = useState<UnlockedSharedVault | null>(null);
  const [entries, setEntries] = useState<PlainSharedVaultEntry[] | null>(null);
  const [members, setMembers] = useState<SharedVaultMemberView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revealedId, setRevealedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const [showEntryForm, setShowEntryForm] = useState(false);
  const [editingEntry, setEditingEntry] = useState<PlainSharedVaultEntry | null>(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [isSavingEntry, setIsSavingEntry] = useState(false);

  const [showInviteForm, setShowInviteForm] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [isInviting, setIsInviting] = useState(false);
  // Réglé dans Réglages (voir components/ListLayoutSettings.tsx) — même préférence que le Coffre.
  const [listLayout] = useState(() => getListLayout());

  const load = useCallback(async () => {
    if (!id) return;
    setError(null);
    try {
      const v = await sharedVault.getUnlockedSharedVault(authorizedRequest, id);
      if (!v) {
        setError("Ce coffre partagé n'existe plus, ou tu n'y as plus accès.");
        setVault(null);
        return;
      }
      setVault(v);
      const [entryList, memberList] = await Promise.all([
        sharedVault.listEntries(authorizedRequest, id, v.vaultKeyB64),
        sharedVault.listMembers(authorizedRequest, id),
      ]);
      setEntries(entryList);
      setMembers(memberList);
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }, [id, authorizedRequest]);

  useEffect(() => {
    void load();
  }, [load]);

  // Recharge en direct quand un AUTRE membre modifie ce coffre partagé (voir
  // handlers/shared_vault.rs::broadcast_to_members côté backend, event_type
  // "SHARED_VAULT_UPDATE"/"SHARED_VAULT_MEMBERS_CHANGED"/"SHARED_VAULT_DELETED") — même mécanisme
  // que Vault.tsx pour le coffre personnel, sans filtrage par type d'événement (un rechargement
  // pour un événement sans rapport, ex: le coffre personnel, est un simple aller-retour réseau
  // superflu, jamais une erreur).
  useEffect(() => {
    return subscribeToVaultSync(() => {
      void load();
    });
  }, [subscribeToVaultSync, load]);

  function openAddForm() {
    setEditingEntry(null);
    setForm(EMPTY_FORM);
    setShowEntryForm(true);
  }

  function openEditForm(entry: PlainSharedVaultEntry) {
    setEditingEntry(entry);
    // CORRECTIF : reprenait auparavant `entry.preferredLoginType === "email" ? "username" :
    // entry.preferredLoginType` — inversait silencieusement la préférence "email" en "identifiant"
    // à chaque modification d'une entrée qui préférait l'email (aucun sélecteur n'existait non plus
    // dans ce formulaire pour la corriger à la main, voir le <select> ajouté plus bas). Une entrée
    // ainsi modifiée se retrouvait donc avec un `preferredLoginType` erroné, ce qui pouvait faire
    // remplir automatiquement (côté extension) le mauvais champ à la prochaine utilisation.
    setForm({
      siteName: entry.siteName, username: entry.username, loginEmail: entry.loginEmail,
      password: entry.password, preferredLoginType: entry.preferredLoginType,
      notes: entry.notes, url: entry.url,
    });
    setShowEntryForm(true);
  }

  async function handleSaveEntry(e: React.FormEvent) {
    e.preventDefault();
    if (!id || !vault || !form.siteName.trim() || !form.password) return;
    setIsSavingEntry(true);
    setError(null);
    try {
      const plain = { ...form, entryType: "login" as const, extraFields: {} };
      if (editingEntry) {
        await sharedVault.updateEntry(authorizedRequest, id, editingEntry.id, vault.vaultKeyB64, plain, editingEntry.version);
      } else {
        await sharedVault.addEntry(authorizedRequest, id, vault.vaultKeyB64, plain);
      }
      setShowEntryForm(false);
      setEditingEntry(null);
      setForm(EMPTY_FORM);
      await load();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsSavingEntry(false);
    }
  }

  async function handleDeleteEntry(entryId: string) {
    if (!id) return;
    if (!confirm("Supprimer définitivement cette entrée ? Aucune corbeille pour les coffres partagés.")) return;
    try {
      await sharedVault.deleteEntry(authorizedRequest, id, entryId);
      await load();
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  async function handleCopy(entry: PlainSharedVaultEntry) {
    await copyPasswordWithAutoClear(entry.password);
    setCopiedId(entry.id);
    setTimeout(() => setCopiedId((cur) => (cur === entry.id ? null : cur)), 1500);
  }

  async function handleInvite(e: React.FormEvent) {
    e.preventDefault();
    if (!id || !vault || !inviteEmail.trim()) return;
    setIsInviting(true);
    setError(null);
    try {
      await sharedVault.inviteMember(authorizedRequest, id, vault.vaultKeyB64, inviteEmail.trim());
      setInviteEmail("");
      setShowInviteForm(false);
      await load();
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsInviting(false);
    }
  }

  async function handleRemoveMember(memberEmail: string) {
    if (!id) return;
    const isSelf = memberEmail === myEmail;
    if (!confirm(isSelf ? "Quitter ce coffre partagé ?" : `Retirer ${memberEmail} de ce coffre ?`)) return;
    try {
      await sharedVault.removeMember(authorizedRequest, id, memberEmail);
      if (isSelf) {
        navigate("/shared-vaults");
        return;
      }
      await load();
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  async function handleDeleteVault() {
    if (!id) return;
    if (!confirm("Supprimer DÉFINITIVEMENT ce coffre partagé, ses entrées et retirer tous les membres ? Cette action est irréversible.")) return;
    try {
      await sharedVault.deleteSharedVault(authorizedRequest, id);
      navigate("/shared-vaults");
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  // Contenu partagé entre le mode "cards" (grille, une bordure par entrée) et "list"/"compact"
  // (liste à séparateurs) — voir les deux appels ci-dessous. CORRECTIF (retour utilisateur,
  // 2026-09-02) : "compact" ne changeait auparavant QUE le padding vertical — trop proche
  // visuellement de "list" pour être perçu. Fusionne maintenant nom + identifiant sur UNE seule
  // ligne (l'auteur de l'ajout, moins utile au quotidien, est retiré ICI pour la place — reste
  // visible en "list"/"cards") et réduit texte/boutons, comme
  // pages/Vault.tsx::renderEntryCompact pour le Coffre.
  function renderEntryRow(entry: PlainSharedVaultEntry, isCompact: boolean) {
    const actionButtonClass = `rounded-md border border-neutral-300 text-neutral-600 hover:bg-neutral-50 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800 ${
      isCompact ? "px-1.5 py-0.5 text-[11px]" : "px-2 py-1 text-xs"
    }`;
    return (
      <div className={`flex items-center justify-between gap-3 px-4 ${isCompact ? "py-1" : "py-3"}`}>
        <div className="min-w-0 flex-1">
          {isCompact ? (
            <p className="truncate text-xs text-neutral-800 dark:text-neutral-200">
              <span className="font-medium text-neutral-900 dark:text-neutral-100">{entry.siteName}</span>
              {" · "}{getPreferredIdentifier(entry) || "—"}
            </p>
          ) : (
            <>
              <p className="truncate font-medium text-neutral-900 dark:text-neutral-100">{entry.siteName}</p>
              <p className="truncate text-xs text-neutral-500">
                {getPreferredIdentifier(entry) || "—"}
                {" · ajouté par "}{entry.createdBy}
              </p>
            </>
          )}
          {revealedId === entry.id && <p className="mt-1 select-all font-mono text-xs text-neutral-700 dark:text-neutral-300">{entry.password}</p>}
        </div>
        <div className={`flex shrink-0 flex-wrap ${isCompact ? "gap-1" : "gap-1.5"}`}>
          {entry.url && (
            <button type="button" onClick={() => void openEntryUrl(entry.url)} className={actionButtonClass}>
              Ouvrir
            </button>
          )}
          <button type="button" onClick={() => setRevealedId((cur) => (cur === entry.id ? null : entry.id))} className={actionButtonClass}>
            {revealedId === entry.id ? "Cacher" : "Voir"}
          </button>
          <button type="button" onClick={() => void handleCopy(entry)} className={actionButtonClass}>
            {copiedId === entry.id ? "Copié !" : "Copier"}
          </button>
          <button type="button" onClick={() => openEditForm(entry)} className={actionButtonClass}>
            Modifier
          </button>
          <button
            type="button"
            onClick={() => void handleDeleteEntry(entry.id)}
            className={`rounded-md border border-red-300 text-red-600 hover:bg-red-50 dark:border-red-900 dark:text-red-400 dark:hover:bg-red-950 ${
              isCompact ? "px-1.5 py-0.5 text-[11px]" : "px-2 py-1 text-xs"
            }`}
          >
            Supprimer
          </button>
        </div>
      </div>
    );
  }

  if (!id) return null;

  return (
    <main className="min-h-screen bg-neutral-50 px-4 py-8 dark:bg-neutral-950">
      {/* Largeur progressive tablette/desktop — voir le commentaire équivalent dans Vault.tsx. */}
      <div className="mx-auto max-w-2xl md:max-w-3xl lg:max-w-4xl">
        {/* Plus de lien "← Retour" ici (retour utilisateur, 2026-09-02) : redondant maintenant
         * que la navigation vit dans components/AppShell.tsx ("Coffres partagés" y est toujours
         * accessible d'un clic) — "Supprimer le coffre" reste, action propre à CETTE page. */}
        <header className="mb-6 flex items-center justify-between">
          <div className="min-w-0">
            <h1 className="truncate text-xl font-semibold text-neutral-900 dark:text-neutral-100">{vault?.name ?? "Coffre partagé"}</h1>
            <p className="text-sm text-neutral-500">{vault?.isOwner ? "Tu es propriétaire de ce coffre" : `Créé par ${vault?.createdBy ?? "?"}`}</p>
          </div>
          {vault?.isOwner && (
            <button
              type="button"
              onClick={() => void handleDeleteVault()}
              className="shrink-0 rounded-lg border border-red-300 px-3 py-1.5 text-sm font-medium text-red-600 hover:bg-red-50 dark:border-red-900 dark:text-red-400 dark:hover:bg-red-950"
            >
              Supprimer le coffre
            </button>
          )}
        </header>

        {error && <p className="mb-4 text-sm text-red-600 dark:text-red-400">{error}</p>}

        {/* --- Membres --- */}
        <section className="mb-6 rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
          <div className="mb-2 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">Membres</h2>
            {vault?.isOwner && !showInviteForm && (
              <button type="button" onClick={() => setShowInviteForm(true)} className="text-xs font-medium text-indigo-600 hover:underline dark:text-indigo-400">
                + Inviter
              </button>
            )}
          </div>

          {showInviteForm && (
            <form onSubmit={(e) => void handleInvite(e)} className="mb-3 flex gap-2">
              <input
                type="email"
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
                placeholder="email@exemple.com"
                autoFocus
                className="flex-1 rounded-lg border border-neutral-300 px-3 py-1.5 text-sm dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-100"
              />
              <button type="submit" disabled={isInviting} className="rounded-lg bg-indigo-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50">
                {isInviting ? "…" : "Inviter"}
              </button>
              <button type="button" onClick={() => { setShowInviteForm(false); setInviteEmail(""); }} className="rounded-lg border border-neutral-300 px-3 py-1.5 text-sm text-neutral-600 dark:border-neutral-700 dark:text-neutral-300">
                Annuler
              </button>
            </form>
          )}

          <ul className="flex flex-col gap-1.5">
            {members?.map((m) => (
              <li key={m.member_email} className="flex items-center justify-between text-sm">
                <span className="text-neutral-700 dark:text-neutral-300">
                  {m.member_email} {m.is_owner && <span className="ml-1 rounded-full bg-indigo-100 px-1.5 py-0.5 text-[11px] text-indigo-700 dark:bg-indigo-950 dark:text-indigo-400">Propriétaire</span>}
                </span>
                {(m.member_email === myEmail ? !m.is_owner : vault?.isOwner) && (
                  <button type="button" onClick={() => void handleRemoveMember(m.member_email)} className="text-xs text-neutral-500 hover:text-red-600 dark:hover:text-red-400">
                    {m.member_email === myEmail ? "Quitter" : "Retirer"}
                  </button>
                )}
              </li>
            ))}
          </ul>
        </section>

        {/* --- Entrées --- */}
        {showEntryForm ? (
          <form onSubmit={(e) => void handleSaveEntry(e)} className="mb-6 flex flex-col gap-3 rounded-xl border border-neutral-200 bg-white p-4 dark:border-neutral-800 dark:bg-neutral-900">
            <input
              type="text" placeholder="Nom du site *" value={form.siteName} autoFocus
              onChange={(e) => setForm((f) => ({ ...f, siteName: e.target.value }))}
              className="rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-100"
            />
            <input
              type="text" placeholder="Identifiant" value={form.username}
              onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))}
              className="rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-100"
            />
            <input
              type="email" placeholder="Email de connexion" value={form.loginEmail}
              onChange={(e) => setForm((f) => ({ ...f, loginEmail: e.target.value }))}
              className="rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-100"
            />
            <div>
              <label className="mb-1 block text-xs font-medium text-neutral-600 dark:text-neutral-400">
                Méthode de connexion préférée
              </label>
              <select
                value={form.preferredLoginType}
                onChange={(e) => setForm((f) => ({ ...f, preferredLoginType: e.target.value as "username" | "email" }))}
                className="w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-100"
              >
                <option value="email">Email</option>
                <option value="username">Identifiant</option>
              </select>
            </div>
            <div className="flex gap-2">
              <input
                type="text" placeholder="Mot de passe *" value={form.password}
                onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
                className="flex-1 rounded-lg border border-neutral-300 px-3 py-2 font-mono text-sm dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-100"
              />
              <button
                type="button"
                onClick={() => setForm((f) => ({ ...f, password: generatePassword(DEFAULT_GENERATOR_OPTIONS) }))}
                className="rounded-lg border border-neutral-300 px-3 py-2 text-xs font-medium text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                Générer
              </button>
            </div>
            <input
              type="url" placeholder="URL du site" value={form.url}
              onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
              className="rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-100"
            />
            <textarea
              placeholder="Notes" value={form.notes} rows={2}
              onChange={(e) => setForm((f) => ({ ...f, notes: e.target.value }))}
              className="rounded-lg border border-neutral-300 px-3 py-2 text-sm dark:border-neutral-700 dark:bg-neutral-950 dark:text-neutral-100"
            />
            <div className="flex gap-2">
              <button
                type="submit" disabled={isSavingEntry || !form.siteName.trim() || !form.password}
                className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isSavingEntry ? "Enregistrement…" : editingEntry ? "Enregistrer" : "Ajouter"}
              </button>
              <button
                type="button"
                onClick={() => { setShowEntryForm(false); setEditingEntry(null); setForm(EMPTY_FORM); }}
                className="rounded-lg border border-neutral-300 px-3 py-2 text-sm text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
              >
                Annuler
              </button>
            </div>
          </form>
        ) : (
          <button
            type="button"
            onClick={openAddForm}
            disabled={!vault}
            className="mb-6 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700 disabled:opacity-50"
          >
            + Ajouter une entrée
          </button>
        )}

        {entries === null ? (
          <p className="text-sm text-neutral-500">Chargement…</p>
        ) : entries.length === 0 ? (
          <p className="text-sm text-neutral-500">Aucune entrée pour l'instant.</p>
        ) : listLayout === "cards" ? (
          // "cards" : une bordure PAR entrée (pas de séparateurs partagés `divide-y`, qui n'ont pas
          // de sens sur une grille) — voir renderEntryRow ci-dessus, contenu identique au mode liste.
          <ul className={listContainerClass("cards", "grid-cols-1 sm:grid-cols-2")}>
            {entries.map((entry) => (
              <li key={entry.id} className="overflow-hidden rounded-xl border border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-900">
                {renderEntryRow(entry, false)}
              </li>
            ))}
          </ul>
        ) : (
          <ul className="flex flex-col divide-y divide-neutral-200 overflow-hidden rounded-xl border border-neutral-200 bg-white dark:divide-neutral-800 dark:border-neutral-800 dark:bg-neutral-900">
            {entries.map((entry) => (
              <li key={entry.id}>{renderEntryRow(entry, listLayout === "compact")}</li>
            ))}
          </ul>
        )}
      </div>
    </main>
  );
}
