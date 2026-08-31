// Un coffre partagé précis : ses entrées (ajout/modification/suppression, avec remplissage
// automatique — voir handleFill) et ses membres (invitation/retrait/départ) — équivalent de
// frontend(app)/src/pages/SharedVaultDetailPage.tsx. Voir lib/sharedVault.ts pour toute
// l'orchestration crypto.

import { useEffect, useState } from "react";
import * as session from "../lib/session";
import * as sharedVault from "../lib/sharedVault";
import type { UnlockedSharedVault, PlainSharedVaultEntry } from "../lib/sharedVault";
import type { SharedVaultMemberView } from "../api/types";
import { runAutofill, getActiveTabUrl, domainsLikelyMatch } from "../lib/autofill";
import { copyPasswordWithAutoClear } from "../lib/clipboard";
import { getErrorMessage } from "../lib/errors";

const EMPTY_FORM = { siteName: "", username: "", loginEmail: "", password: "", preferredLoginType: "username" as "username" | "email", notes: "", url: "" };

export default function SharedVaultDetailView({
  vaultId,
  vaultKey,
  myEmail,
  onBack,
}: {
  vaultId: string;
  vaultKey: Uint8Array;
  myEmail: string;
  onBack: () => void;
}) {
  const [vault, setVault] = useState<UnlockedSharedVault | null>(null);
  const [entries, setEntries] = useState<PlainSharedVaultEntry[] | null>(null);
  const [members, setMembers] = useState<SharedVaultMemberView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revealedId, setRevealedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [filledId, setFilledId] = useState<string | null>(null);

  const [showEntryForm, setShowEntryForm] = useState(false);
  const [editingEntry, setEditingEntry] = useState<PlainSharedVaultEntry | null>(null);
  const [form, setForm] = useState(EMPTY_FORM);
  const [isSavingEntry, setIsSavingEntry] = useState(false);

  const [showInviteForm, setShowInviteForm] = useState(false);
  const [inviteEmail, setInviteEmail] = useState("");
  const [isInviting, setIsInviting] = useState(false);

  async function load() {
    setError(null);
    try {
      const v = await sharedVault.getUnlockedSharedVault(vaultKey, vaultId, session.authorizedRequest);
      if (!v) {
        setError("Ce coffre partagé n'existe plus, ou tu n'y as plus accès.");
        setVault(null);
        return;
      }
      setVault(v);
      const [entryList, memberList] = await Promise.all([
        sharedVault.listEntries(vaultId, v.vaultKeyB64, session.authorizedRequest),
        sharedVault.listMembers(vaultId, session.authorizedRequest),
      ]);
      setEntries(entryList);
      setMembers(memberList);
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vaultId, vaultKey]);

  function openAddForm() {
    setEditingEntry(null);
    setForm(EMPTY_FORM);
    setShowEntryForm(true);
  }

  function openEditForm(entry: PlainSharedVaultEntry) {
    setEditingEntry(entry);
    // CORRECTIF (même bug que côté desktop, voir SharedVaultDetailPage.tsx) : inversait
    // silencieusement "email" en "identifiant" à chaque modification — sans même de sélecteur dans
    // ce formulaire pour le corriger à la main (ajouté plus bas). Faussait ensuite handleFill()
    // ci-dessus, qui pouvait remplir un champ identifiant VIDE plutôt que l'email réellement
    // enregistré pour cette entrée.
    setForm({
      siteName: entry.siteName, username: entry.username, loginEmail: entry.loginEmail,
      password: entry.password, preferredLoginType: entry.preferredLoginType,
      notes: entry.notes, url: entry.url,
    });
    setShowEntryForm(true);
  }

  async function handleSaveEntry(e: React.FormEvent) {
    e.preventDefault();
    if (!vault || !form.siteName.trim() || !form.password) return;
    setIsSavingEntry(true);
    setError(null);
    try {
      const plain = { ...form, entryType: "login" as const, extraFields: {} };
      if (editingEntry) {
        await sharedVault.updateEntry(vaultId, editingEntry.id, vault.vaultKeyB64, plain, editingEntry.version, session.authorizedRequest);
      } else {
        await sharedVault.addEntry(vaultId, vault.vaultKeyB64, plain, session.authorizedRequest);
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
    if (!confirm("Supprimer définitivement cette entrée ? Aucune corbeille pour les coffres partagés.")) return;
    try {
      await sharedVault.deleteEntry(vaultId, entryId, session.authorizedRequest);
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

  /** Même logique que App.tsx::handleFill pour le coffre personnel — avertit avant de remplir sur
   * un domaine différent de celui enregistré pour l'entrée. */
  async function handleFill(entry: PlainSharedVaultEntry) {
    setError(null);
    try {
      if (entry.url) {
        const tabUrl = await getActiveTabUrl();
        if (tabUrl && !domainsLikelyMatch(entry.url, tabUrl)) {
          const proceed = confirm(
            `Cette entrée est enregistrée pour "${entry.url}", mais l'onglet actif ne correspond pas à ce domaine. Remplir quand même ?`,
          );
          if (!proceed) return;
        }
      }

      // CORRECTIF : sans repli sur loginEmail, une entrée "identifiant" avec un champ username vide
      // (identifiant/email tous deux optionnels, voir le formulaire) remplissait un champ vide
      // plutôt que la valeur réellement disponible — même repli que l'affichage juste en dessous.
      const usernameOrEmail = entry.preferredLoginType === "email" ? entry.loginEmail : entry.username || entry.loginEmail;
      const result = await runAutofill(usernameOrEmail, entry.password);
      if (!result.passwordFilled) {
        setError("Aucun champ mot de passe trouvé sur cette page.");
        return;
      }
      setFilledId(entry.id);
      setTimeout(() => setFilledId((id) => (id === entry.id ? null : id)), 1500);
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  async function handleInvite(e: React.FormEvent) {
    e.preventDefault();
    if (!vault || !inviteEmail.trim()) return;
    setIsInviting(true);
    setError(null);
    try {
      await sharedVault.inviteMember(vaultId, vault.vaultKeyB64, inviteEmail.trim(), session.authorizedRequest);
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
    const isSelf = memberEmail === myEmail;
    if (!confirm(isSelf ? "Quitter ce coffre partagé ?" : `Retirer ${memberEmail} de ce coffre ?`)) return;
    try {
      await sharedVault.removeMember(vaultId, memberEmail, session.authorizedRequest);
      if (isSelf) {
        onBack();
        return;
      }
      await load();
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  async function handleDeleteVault() {
    if (!confirm("Supprimer DÉFINITIVEMENT ce coffre partagé, ses entrées et retirer tous les membres ? Cette action est irréversible.")) return;
    try {
      await sharedVault.deleteSharedVault(vaultId, session.authorizedRequest);
      onBack();
    } catch (err) {
      setError(getErrorMessage(err));
    }
  }

  return (
    <div className="flex flex-col">
      <div className="flex items-center justify-between gap-2 border-b border-neutral-200 px-4 py-3 dark:border-neutral-800">
        <div className="flex min-w-0 items-center gap-2">
          <button onClick={onBack} className="shrink-0 text-sm text-neutral-500 hover:underline">
            ← Retour
          </button>
          <h1 className="truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">{vault?.name ?? "Coffre partagé"}</h1>
        </div>
        {vault?.isOwner && (
          <button onClick={() => void handleDeleteVault()} className="shrink-0 text-xs text-red-600 hover:underline dark:text-red-400">
            Supprimer
          </button>
        )}
      </div>

      {error && <p className="px-4 pt-2 text-sm text-red-600 dark:text-red-400">{error}</p>}

      {/* --- Membres --- */}
      <div className="border-b border-neutral-200 px-4 py-2 dark:border-neutral-800">
        <div className="mb-1 flex items-center justify-between">
          <h2 className="text-xs font-semibold text-neutral-900 dark:text-neutral-100">Membres</h2>
          {vault?.isOwner && !showInviteForm && (
            <button onClick={() => setShowInviteForm(true)} className="text-xs font-medium text-indigo-600 hover:underline dark:text-indigo-400">
              + Inviter
            </button>
          )}
        </div>

        {showInviteForm && (
          <form onSubmit={(e) => void handleInvite(e)} className="mb-2 flex gap-2">
            <input
              type="email"
              value={inviteEmail}
              onChange={(e) => setInviteEmail(e.target.value)}
              placeholder="email@exemple.com"
              autoFocus
              className="flex-1 rounded-md border border-neutral-300 px-2 py-1 text-xs dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-100"
            />
            <button type="submit" disabled={isInviting} className="rounded-md bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-700 disabled:opacity-60">
              {isInviting ? "…" : "Inviter"}
            </button>
            <button type="button" onClick={() => { setShowInviteForm(false); setInviteEmail(""); }} className="rounded-md border border-neutral-300 px-2 py-1 text-xs text-neutral-600 dark:border-neutral-700 dark:text-neutral-300">
              Annuler
            </button>
          </form>
        )}

        <ul className="flex flex-col gap-1">
          {members?.map((m) => (
            <li key={m.member_email} className="flex items-center justify-between text-xs">
              <span className="truncate text-neutral-700 dark:text-neutral-300">
                {m.member_email} {m.is_owner && <span className="ml-1 rounded-full bg-indigo-100 px-1.5 py-0.5 text-[10px] text-indigo-700 dark:bg-indigo-950 dark:text-indigo-400">Propriétaire</span>}
              </span>
              {(m.member_email === myEmail ? !m.is_owner : vault?.isOwner) && (
                <button onClick={() => void handleRemoveMember(m.member_email)} className="shrink-0 text-neutral-500 hover:text-red-600 dark:hover:text-red-400">
                  {m.member_email === myEmail ? "Quitter" : "Retirer"}
                </button>
              )}
            </li>
          ))}
        </ul>
      </div>

      {/* --- Entrées --- */}
      <div className="px-4 py-2">
        {showEntryForm ? (
          <form onSubmit={(e) => void handleSaveEntry(e)} className="flex flex-col gap-2">
            <input
              type="text" placeholder="Nom du site *" value={form.siteName} autoFocus
              onChange={(e) => setForm((f) => ({ ...f, siteName: e.target.value }))}
              className="rounded-md border border-neutral-300 px-2 py-1 text-sm dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-100"
            />
            <input
              type="text" placeholder="Identifiant" value={form.username}
              onChange={(e) => setForm((f) => ({ ...f, username: e.target.value }))}
              className="rounded-md border border-neutral-300 px-2 py-1 text-sm dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-100"
            />
            <input
              type="email" placeholder="Email de connexion" value={form.loginEmail}
              onChange={(e) => setForm((f) => ({ ...f, loginEmail: e.target.value }))}
              className="rounded-md border border-neutral-300 px-2 py-1 text-sm dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-100"
            />
            <select
              value={form.preferredLoginType}
              onChange={(e) => setForm((f) => ({ ...f, preferredLoginType: e.target.value as "username" | "email" }))}
              className="rounded-md border border-neutral-300 px-2 py-1 text-sm dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-100"
            >
              <option value="email">Préférer l'email à la connexion</option>
              <option value="username">Préférer l'identifiant à la connexion</option>
            </select>
            <input
              type="text" placeholder="Mot de passe *" value={form.password}
              onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
              className="rounded-md border border-neutral-300 px-2 py-1 font-mono text-sm dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-100"
            />
            <input
              type="url" placeholder="URL du site" value={form.url}
              onChange={(e) => setForm((f) => ({ ...f, url: e.target.value }))}
              className="rounded-md border border-neutral-300 px-2 py-1 text-sm dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-100"
            />
            <textarea
              placeholder="Notes" value={form.notes} rows={2}
              onChange={(e) => setForm((f) => ({ ...f, notes: e.target.value }))}
              className="rounded-md border border-neutral-300 px-2 py-1 text-sm dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-100"
            />
            <div className="flex gap-2">
              <button
                type="submit" disabled={isSavingEntry || !form.siteName.trim() || !form.password}
                className="rounded-md bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-700 disabled:opacity-60"
              >
                {isSavingEntry ? "…" : editingEntry ? "Enregistrer" : "Ajouter"}
              </button>
              <button
                type="button"
                onClick={() => { setShowEntryForm(false); setEditingEntry(null); setForm(EMPTY_FORM); }}
                className="rounded-md border border-neutral-300 px-2 py-1 text-xs text-neutral-600 dark:border-neutral-700 dark:text-neutral-300"
              >
                Annuler
              </button>
            </div>
          </form>
        ) : (
          <button onClick={openAddForm} disabled={!vault} className="rounded-md bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-700 disabled:opacity-60">
            + Ajouter une entrée
          </button>
        )}
      </div>

      {entries === null && !error && <p className="p-4 text-sm text-neutral-500">Chargement…</p>}
      {entries !== null && entries.length === 0 && <p className="p-4 text-sm text-neutral-500">Aucune entrée pour l'instant.</p>}

      <ul className="flex flex-col divide-y divide-neutral-200 pb-2 dark:divide-neutral-800">
        {(entries ?? []).map((entry) => (
          <li key={entry.id} className="flex flex-col gap-1.5 px-4 py-2">
            <div className="flex items-center justify-between gap-2">
              <div className="min-w-0">
                <p className="truncate text-sm font-medium text-neutral-900 dark:text-neutral-100">{entry.siteName}</p>
                <p className="truncate text-xs text-neutral-500">
                  {entry.preferredLoginType === "email" ? entry.loginEmail : entry.username || entry.loginEmail || "—"}
                </p>
              </div>
            </div>
            {revealedId === entry.id && <p className="select-all font-mono text-xs text-neutral-700 dark:text-neutral-300">{entry.password}</p>}
            <div className="flex flex-wrap gap-1.5">
              {entry.url && (
                <button onClick={() => window.open(entry.url, "_blank", "noopener,noreferrer")} className="rounded-md border border-neutral-300 px-2 py-1 text-xs text-neutral-600 dark:border-neutral-700 dark:text-neutral-300">
                  Ouvrir
                </button>
              )}
              <button onClick={() => void handleFill(entry)} className="rounded-md bg-indigo-600 px-2 py-1 text-xs font-medium text-white hover:bg-indigo-700">
                {filledId === entry.id ? "Rempli !" : "Remplir"}
              </button>
              <button onClick={() => setRevealedId((cur) => (cur === entry.id ? null : entry.id))} className="rounded-md border border-neutral-300 px-2 py-1 text-xs text-neutral-600 dark:border-neutral-700 dark:text-neutral-300">
                {revealedId === entry.id ? "Cacher" : "Voir"}
              </button>
              <button onClick={() => void handleCopy(entry)} className="rounded-md border border-neutral-300 px-2 py-1 text-xs text-neutral-600 dark:border-neutral-700 dark:text-neutral-300">
                {copiedId === entry.id ? "Copié !" : "Copier"}
              </button>
              <button onClick={() => openEditForm(entry)} className="rounded-md border border-neutral-300 px-2 py-1 text-xs text-neutral-600 dark:border-neutral-700 dark:text-neutral-300">
                Modifier
              </button>
              <button onClick={() => void handleDeleteEntry(entry.id)} className="rounded-md border border-red-300 px-2 py-1 text-xs text-red-600 hover:bg-red-50 dark:border-red-800 dark:text-red-400 dark:hover:bg-red-950">
                Supprimer
              </button>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
