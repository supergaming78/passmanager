// Formulaire d'ajout/modification d'entrée — port simplifié de
// frontend(app)/src/components/VaultEntryForm.tsx : mêmes 4 types d'entrée et leurs champs
// additionnels, MAIS pas de générateur de mot de passe intégré (hors périmètre de cette phase —
// champ texte simple comme les autres, voir le plan).

import { useState, type FormEvent } from "react";
import { NOTE_TYPE_PASSWORD_PLACEHOLDER, type EntryType, type PlainVaultEntry } from "../lib/vaultCrypto";
import { getErrorMessage } from "../lib/errors";

export type VaultEntryFormValues = Omit<PlainVaultEntry, "id" | "updatedAt" | "version" | "hasAttachments">;

const TYPE_LABELS: Record<EntryType, string> = {
  login: "Identifiant",
  card: "Carte bancaire",
  identity: "Document d'identité",
  note: "Note sécurisée",
};

const SITE_NAME_LABEL: Record<EntryType, string> = {
  login: "Site / application",
  card: "Nom de la carte",
  identity: "Nom du document",
  note: "Titre",
};

const USERNAME_LABEL: Record<EntryType, string> = {
  login: "Identifiant",
  card: "Titulaire",
  identity: "Nom complet",
  note: "",
};

const PASSWORD_LABEL: Record<EntryType, string> = {
  login: "Mot de passe",
  card: "Numéro de carte",
  identity: "Numéro de document",
  note: "",
};

interface ExtraFieldDef {
  key: string;
  label: string;
  sensitive?: boolean;
}

const EXTRA_FIELDS_BY_TYPE: Record<EntryType, ExtraFieldDef[]> = {
  login: [],
  card: [
    { key: "expiryMonth", label: "Mois d'expiration" },
    { key: "expiryYear", label: "Année d'expiration" },
    { key: "cvv", label: "CVV", sensitive: true },
  ],
  identity: [
    { key: "dateOfBirth", label: "Date de naissance" },
    { key: "nationality", label: "Nationalité" },
    { key: "issueDate", label: "Date de délivrance" },
    { key: "expiryDate", label: "Date d'expiration" },
    { key: "address", label: "Adresse" },
  ],
  note: [],
};

const EMPTY_VALUES: VaultEntryFormValues = {
  siteName: "",
  username: "",
  loginEmail: "",
  password: "",
  preferredLoginType: "username",
  isFavorite: false,
  folder: "",
  notes: "",
  url: "",
  entryType: "login",
  extraFields: {},
};

function inputClass() {
  return "w-full rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-900";
}

function labelClass() {
  return "mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300";
}

export default function VaultEntryForm({
  initial,
  onSubmit,
  onCancel,
}: {
  initial?: VaultEntryFormValues;
  onSubmit: (values: VaultEntryFormValues) => Promise<void>;
  onCancel: () => void;
}) {
  const [values, setValues] = useState<VaultEntryFormValues>(initial ?? EMPTY_VALUES);
  const [revealedExtraFields, setRevealedExtraFields] = useState<Set<string>>(new Set());
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  function updateType(entryType: EntryType) {
    setValues((v) => ({ ...v, entryType, extraFields: {} }));
    setRevealedExtraFields(new Set());
  }

  function updateExtraField(key: string, value: string) {
    setValues((v) => ({ ...v, extraFields: { ...v.extraFields, [key]: value } }));
  }

  function toggleReveal(key: string) {
    setRevealedExtraFields((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);
    try {
      // Le type "note" n'a pas de mot de passe à proprement parler, mais le backend exige
      // encrypted_password non vide pour tous les types — voir NOTE_TYPE_PASSWORD_PLACEHOLDER.
      const toSubmit = values.entryType === "note" ? { ...values, password: NOTE_TYPE_PASSWORD_PLACEHOLDER } : values;
      await onSubmit(toSubmit);
    } catch (err) {
      setError(getErrorMessage(err));
    } finally {
      setIsSubmitting(false);
    }
  }

  const extraFieldDefs = EXTRA_FIELDS_BY_TYPE[values.entryType];

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-3 p-4">
      <div>
        <label className={labelClass()}>Type d'entrée</label>
        <select
          value={values.entryType}
          onChange={(e) => updateType(e.target.value as EntryType)}
          className={inputClass()}
        >
          {(Object.keys(TYPE_LABELS) as EntryType[]).map((t) => (
            <option key={t} value={t}>
              {TYPE_LABELS[t]}
            </option>
          ))}
        </select>
      </div>

      <div>
        <label className={labelClass()}>{SITE_NAME_LABEL[values.entryType]}</label>
        <input
          type="text"
          required
          autoFocus
          value={values.siteName}
          onChange={(e) => setValues((v) => ({ ...v, siteName: e.target.value }))}
          className={inputClass()}
        />
      </div>

      {values.entryType === "login" && (
        <>
          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className={labelClass()}>Identifiant</label>
              <input
                type="text"
                value={values.username}
                onChange={(e) => setValues((v) => ({ ...v, username: e.target.value }))}
                className={inputClass()}
              />
            </div>
            <div>
              <label className={labelClass()}>Email</label>
              <input
                type="email"
                value={values.loginEmail}
                onChange={(e) => setValues((v) => ({ ...v, loginEmail: e.target.value }))}
                className={inputClass()}
              />
            </div>
          </div>
          <div>
            <label className={labelClass()}>Connexion préférée</label>
            <select
              value={values.preferredLoginType}
              onChange={(e) => setValues((v) => ({ ...v, preferredLoginType: e.target.value as "username" | "email" }))}
              className={inputClass()}
            >
              <option value="username">Identifiant</option>
              <option value="email">Email</option>
            </select>
          </div>
        </>
      )}

      {(values.entryType === "card" || values.entryType === "identity") && (
        <div>
          <label className={labelClass()}>{USERNAME_LABEL[values.entryType]}</label>
          <input
            type="text"
            value={values.username}
            onChange={(e) => setValues((v) => ({ ...v, username: e.target.value }))}
            className={inputClass()}
          />
        </div>
      )}

      {values.entryType !== "note" && (
        <div>
          <label className={labelClass()}>{PASSWORD_LABEL[values.entryType]}</label>
          <div className="flex gap-2">
            <input
              type={showPassword ? "text" : "password"}
              required
              value={values.password}
              onChange={(e) => setValues((v) => ({ ...v, password: e.target.value }))}
              className={inputClass()}
            />
            <button
              type="button"
              onClick={() => setShowPassword((s) => !s)}
              className="shrink-0 rounded-lg border border-neutral-300 px-2 text-xs text-neutral-600 dark:border-neutral-700 dark:text-neutral-300"
            >
              {showPassword ? "Cacher" : "Voir"}
            </button>
          </div>
        </div>
      )}

      {extraFieldDefs.map((def) => (
        <div key={def.key}>
          <label className={labelClass()}>{def.label}</label>
          <div className="flex gap-2">
            <input
              type={def.sensitive && !revealedExtraFields.has(def.key) ? "password" : "text"}
              value={values.extraFields[def.key] ?? ""}
              onChange={(e) => updateExtraField(def.key, e.target.value)}
              className={inputClass()}
            />
            {def.sensitive && (
              <button
                type="button"
                onClick={() => toggleReveal(def.key)}
                className="shrink-0 rounded-lg border border-neutral-300 px-2 text-xs text-neutral-600 dark:border-neutral-700 dark:text-neutral-300"
              >
                {revealedExtraFields.has(def.key) ? "Cacher" : "Voir"}
              </button>
            )}
          </div>
        </div>
      ))}

      <div>
        <label className={labelClass()}>Dossier</label>
        <input
          type="text"
          value={values.folder}
          onChange={(e) => setValues((v) => ({ ...v, folder: e.target.value }))}
          className={inputClass()}
          placeholder="(aucun)"
        />
      </div>

      <div>
        <label className={labelClass()}>URL</label>
        <input
          type="text"
          value={values.url}
          onChange={(e) => setValues((v) => ({ ...v, url: e.target.value }))}
          className={inputClass()}
          placeholder="https://…"
        />
      </div>

      <div>
        <label className={labelClass()}>{values.entryType === "note" ? "Contenu de la note" : "Notes"}</label>
        <textarea
          rows={values.entryType === "note" ? 6 : 2}
          value={values.notes}
          onChange={(e) => setValues((v) => ({ ...v, notes: e.target.value }))}
          className={inputClass()}
        />
      </div>

      <label className="flex items-center gap-2 text-sm text-neutral-700 dark:text-neutral-300">
        <input
          type="checkbox"
          checked={values.isFavorite}
          onChange={(e) => setValues((v) => ({ ...v, isFavorite: e.target.checked }))}
          className="rounded border-neutral-300 text-indigo-600 focus:ring-indigo-500"
        />
        Favori
      </label>

      {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}

      <div className="flex gap-2">
        <button
          type="submit"
          disabled={isSubmitting}
          className="flex-1 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {isSubmitting ? "Enregistrement…" : "Enregistrer"}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="rounded-lg border border-neutral-300 px-4 py-2 text-sm text-neutral-600 dark:border-neutral-700 dark:text-neutral-300"
        >
          Annuler
        </button>
      </div>
    </form>
  );
}
