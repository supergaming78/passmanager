import { useState, type FormEvent } from "react";
import { NOTE_TYPE_PASSWORD_PLACEHOLDER, type EntryType, type PlainVaultEntry } from "../lib/vaultCrypto";
import { openEntryUrl } from "../lib/openExternalUrl";
import PasswordGeneratorPanel from "./PasswordGeneratorPanel";

export type VaultEntryFormValues = Omit<PlainVaultEntry, "id" | "updatedAt" | "version" | "hasAttachments">;

/** Libellés/placeholders par type dédié — voir EntryType (lib/vaultCrypto.ts). Les champs
 * génériques (siteName/username/password) sont RÉUTILISÉS pour chaque type avec un sens différent
 * plutôt que d'ajouter une colonne dédiée par type par champ (voir le commentaire de la migration
 * 20260830000000_vault_entry_types.sql) — ce tableau centralise uniquement leur étiquette. */
const TYPE_LABELS: Record<EntryType, { typeLabel: string; siteName: string; sitePlaceholder: string; username: string; password: string }> = {
  login: { typeLabel: "Identifiant", siteName: "Site / application", sitePlaceholder: "ex: GitHub", username: "Identifiant", password: "Mot de passe" },
  card: { typeLabel: "Carte bancaire", siteName: "Nom de la carte", sitePlaceholder: "ex: Visa Perso", username: "Titulaire", password: "Numéro de carte" },
  identity: { typeLabel: "Identité", siteName: "Nom du document", sitePlaceholder: "ex: Passeport", username: "Nom complet", password: "Numéro de document" },
  note: { typeLabel: "Note sécurisée", siteName: "Titre", sitePlaceholder: "ex: Code du digicode", username: "", password: "" },
};

/** Champs additionnels affichés pour "card"/"identity" (voir PlainVaultEntry.extraFields) — "note"
 * et "login" n'en ont aucun. `key` correspond à la clé stockée dans l'objet extraFields. */
const EXTRA_FIELDS_BY_TYPE: Record<EntryType, { key: string; label: string; placeholder?: string; sensitive?: boolean }[]> = {
  login: [],
  card: [
    { key: "expiryMonth", label: "Mois d'expiration", placeholder: "MM" },
    { key: "expiryYear", label: "Année d'expiration", placeholder: "AAAA" },
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

interface Props {
  title: string;
  initialValues?: VaultEntryFormValues;
  submitLabel: string;
  onSubmit: (values: VaultEntryFormValues) => Promise<void>;
  onCancel: () => void;
  /** Noms de dossiers déjà utilisés ailleurs dans le coffre — proposés dans un menu déroulant
   * pour retomber facilement sur un dossier existant plutôt que d'en créer un doublon à cause
   * d'une faute de frappe ("Travail" vs "travail"). "➕ Nouveau dossier…" reste disponible pour
   * en créer un qui n'existe pas encore. */
  existingFolders?: string[];
}

const emptyValues: VaultEntryFormValues = {
  siteName: "",
  username: "",
  loginEmail: "",
  password: "",
  preferredLoginType: "email",
  isFavorite: false,
  folder: "",
  notes: "",
  url: "",
  entryType: "login",
  extraFields: {},
};

export default function VaultEntryForm({ title, initialValues, submitLabel, onSubmit, onCancel, existingFolders = [] }: Props) {
  const [values, setValues] = useState<VaultEntryFormValues>(initialValues ?? emptyValues);
  const [showPassword, setShowPassword] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isNewFolder, setIsNewFolder] = useState(false);
  // Champs additionnels "sensibles" (ex: CVV) révélés — INDÉPENDANT de showPassword ci-dessus :
  // révéler le numéro de carte ne doit pas révéler automatiquement le CVV en même temps (et
  // inversement), ce sont deux secrets distincts avec des risques d'exposition différents.
  const [revealedExtraFields, setRevealedExtraFields] = useState<Set<string>>(new Set());

  function update<K extends keyof VaultEntryFormValues>(key: K, value: VaultEntryFormValues[K]) {
    setValues((prev) => ({ ...prev, [key]: value }));
  }

  /** Changer de type réinitialise extraFields — les champs additionnels d'un type (ex: CVV d'une
   * carte) n'ont pas de sens pour un autre, autant ne pas les faire traîner silencieusement. */
  function updateType(entryType: EntryType) {
    setValues((prev) => ({ ...prev, entryType, extraFields: {} }));
    setRevealedExtraFields(new Set());
  }

  function updateExtraField(key: string, value: string) {
    setValues((prev) => ({ ...prev, extraFields: { ...prev.extraFields, [key]: value } }));
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);
    try {
      // Type "note" : pas de champ mot de passe affiché (voir plus bas) — le backend en exige
      // pourtant un non vide (partagé avec "login"), d'où ce placeholder fixe jamais montré.
      const toSubmit = values.entryType === "note" ? { ...values, password: NOTE_TYPE_PASSWORD_PLACEHOLDER } : values;
      await onSubmit(toSubmit);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Une erreur inattendue est survenue.");
      setIsSubmitting(false);
    }
  }

  const labels = TYPE_LABELS[values.entryType];
  const extraFieldDefs = EXTRA_FIELDS_BY_TYPE[values.entryType];

  return (
    <div className="fixed inset-0 z-10 flex items-center justify-center bg-black/40 px-4 py-8">
      <div className="max-h-full w-full max-w-md overflow-y-auto rounded-2xl bg-white p-6 shadow-xl dark:bg-neutral-900">
        <h2 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">{title}</h2>

        <form onSubmit={handleSubmit} className="mt-4 flex flex-col gap-3">
          <div>
            <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">Type d'entrée</label>
            <select
              value={values.entryType}
              onChange={(e) => updateType(e.target.value as EntryType)}
              className="w-full rounded-lg border border-neutral-300 px-3 py-2 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
            >
              {(Object.keys(TYPE_LABELS) as EntryType[]).map((t) => (
                <option key={t} value={t}>
                  {TYPE_LABELS[t].typeLabel}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">{labels.siteName}</label>
            <input
              required
              autoFocus
              value={values.siteName}
              onChange={(e) => update("siteName", e.target.value)}
              className="w-full rounded-lg border border-neutral-300 px-3 py-2 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
              placeholder={labels.sitePlaceholder}
            />
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">URL du site</label>
            <div className="flex gap-2">
              <input
                type="text"
                value={values.url}
                onChange={(e) => update("url", e.target.value)}
                className="min-w-0 flex-1 rounded-lg border border-neutral-300 px-3 py-2 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
                placeholder="optionnel — ex: https://github.com"
              />
              {values.url.trim() && (
                <button
                  type="button"
                  onClick={() => void openEntryUrl(values.url)}
                  className="shrink-0 rounded-lg border border-neutral-300 px-3 text-sm text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                >
                  Ouvrir le site
                </button>
              )}
            </div>
          </div>

          <div>
            <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">Dossier</label>
            {/* Un <select> plutôt qu'un champ libre + <datalist> : une fois un dossier choisi via
             * une datalist, le champ contient déjà une correspondance exacte, et la plupart des
             * moteurs de rendu ne réaffichent alors plus les AUTRES suggestions à l'ouverture
             * suivante. Un <select> montre toujours la liste complète, à chaque fois. */}
            <select
              value={isNewFolder ? "__new__" : values.folder}
              onChange={(e) => {
                if (e.target.value === "__new__") {
                  setIsNewFolder(true);
                  update("folder", "");
                } else {
                  setIsNewFolder(false);
                  update("folder", e.target.value);
                }
              }}
              className="w-full rounded-lg border border-neutral-300 px-3 py-2 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
            >
              <option value="">Aucun dossier</option>
              {existingFolders.map((folder) => (
                <option key={folder} value={folder}>
                  {folder}
                </option>
              ))}
              <option value="__new__">➕ Nouveau dossier…</option>
            </select>
            {isNewFolder && (
              <input
                autoFocus
                value={values.folder}
                onChange={(e) => update("folder", e.target.value)}
                className="mt-2 w-full rounded-lg border border-neutral-300 px-3 py-2 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
                placeholder="Nom du nouveau dossier"
              />
            )}
          </div>

          {values.entryType === "login" && (
            <>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">{labels.username}</label>
                  <input
                    value={values.username}
                    onChange={(e) => update("username", e.target.value)}
                    className="w-full rounded-lg border border-neutral-300 px-3 py-2 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
                    placeholder="optionnel"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">Email de connexion</label>
                  <input
                    type="email"
                    value={values.loginEmail}
                    onChange={(e) => update("loginEmail", e.target.value)}
                    className="w-full rounded-lg border border-neutral-300 px-3 py-2 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
                    placeholder="optionnel"
                  />
                </div>
              </div>

              <div>
                <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
                  Méthode de connexion préférée
                </label>
                <select
                  value={values.preferredLoginType}
                  onChange={(e) => update("preferredLoginType", e.target.value as "username" | "email")}
                  className="w-full rounded-lg border border-neutral-300 px-3 py-2 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
                >
                  <option value="email">Email</option>
                  <option value="username">Identifiant</option>
                </select>
              </div>
            </>
          )}

          {(values.entryType === "card" || values.entryType === "identity") && (
            <div>
              <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">{labels.username}</label>
              <input
                value={values.username}
                onChange={(e) => update("username", e.target.value)}
                className="w-full rounded-lg border border-neutral-300 px-3 py-2 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
                placeholder="optionnel"
              />
            </div>
          )}

          {values.entryType !== "note" && (
            <div>
              <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">{labels.password}</label>
              <div className="flex gap-2">
                <input
                  required
                  type={showPassword ? "text" : "password"}
                  value={values.password}
                  onChange={(e) => update("password", e.target.value)}
                  className="w-full rounded-lg border border-neutral-300 px-3 py-2 font-mono outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((v) => !v)}
                  className="shrink-0 rounded-lg border border-neutral-300 px-3 text-sm text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                >
                  {showPassword ? "Cacher" : "Voir"}
                </button>
                {values.entryType === "login" && (
                  <button
                    type="button"
                    onClick={() => setShowGenerator((v) => !v)}
                    className="shrink-0 rounded-lg border border-neutral-300 px-3 text-sm text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                  >
                    Générer
                  </button>
                )}
              </div>

              {showGenerator && values.entryType === "login" && (
                <PasswordGeneratorPanel
                  onGenerate={(generated) => {
                    update("password", generated);
                    setShowPassword(true);
                  }}
                  onClose={() => setShowGenerator(false)}
                />
              )}
            </div>
          )}

          {extraFieldDefs.length > 0 && (
            <div className="grid grid-cols-2 gap-3">
              {extraFieldDefs.map((field) => {
                const isRevealed = revealedExtraFields.has(field.key);
                return (
                  <div key={field.key}>
                    <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">{field.label}</label>
                    <div className="flex gap-1.5">
                      <input
                        type={field.sensitive && !isRevealed ? "password" : "text"}
                        value={values.extraFields[field.key] ?? ""}
                        onChange={(e) => updateExtraField(field.key, e.target.value)}
                        className="w-full min-w-0 rounded-lg border border-neutral-300 px-3 py-2 outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
                        placeholder={field.placeholder ?? "optionnel"}
                      />
                      {field.sensitive && (
                        <button
                          type="button"
                          onClick={() =>
                            setRevealedExtraFields((prev) => {
                              const next = new Set(prev);
                              if (next.has(field.key)) next.delete(field.key);
                              else next.add(field.key);
                              return next;
                            })
                          }
                          className="shrink-0 rounded-lg border border-neutral-300 px-2 text-xs text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
                        >
                          {isRevealed ? "Cacher" : "Voir"}
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          <div>
            <label className="mb-1 block text-sm font-medium text-neutral-700 dark:text-neutral-300">
              {values.entryType === "note" ? "Contenu de la note" : "Notes"}
            </label>
            <textarea
              value={values.notes}
              onChange={(e) => update("notes", e.target.value)}
              rows={values.entryType === "note" ? 8 : 3}
              className="w-full resize-y rounded-lg border border-neutral-300 px-3 py-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-950"
              placeholder={values.entryType === "note" ? "ex: code du digicode, réponses à des questions de sécurité…" : "optionnel — ex: réponses aux questions de sécurité"}
            />
          </div>

          <label className="flex items-center gap-2 text-sm text-neutral-700 dark:text-neutral-300">
            <input
              type="checkbox"
              checked={values.isFavorite}
              onChange={(e) => update("isFavorite", e.target.checked)}
              className="rounded border-neutral-300 text-indigo-600 focus:ring-indigo-500"
            />
            Favori
          </label>

          {error && <p className="text-sm text-red-600 dark:text-red-400">{error}</p>}

          <div className="mt-2 flex justify-end gap-2">
            <button
              type="button"
              onClick={onCancel}
              className="rounded-lg border border-neutral-300 px-4 py-2 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              Annuler
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition hover:bg-indigo-700 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {isSubmitting ? "Enregistrement…" : submitLabel}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
