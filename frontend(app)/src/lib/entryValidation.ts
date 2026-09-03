// Validation des champs d'une entrée AVANT chiffrement (voir VaultEntryForm.tsx::handleSubmit).
// Architecture Zero-Knowledge (voir lib/vaultCrypto.ts) : le serveur ne voit jamais le contenu en
// clair d'une entrée, donc cette validation ne peut exister QUE côté client, ici — le backend ne
// peut valider que la taille du blob chiffré (voir handlers/vault.rs), jamais son contenu.
//
// Retour utilisateur : "je veux qu'on vérifie ce qu'il y a dans les entrées lorsqu'on ajoute une
// carte bancaire ou carte d'identité pour qu'il n'y ait pas de lettre là où il faut avoir
// uniquement des numéros [...] et s'assurer qu'une URL commence toujours par http, https." Puis,
// en clarifiant ce que "aussi au mot de passe" voulait dire : PAS le mot de passe lui-même, mais
// les AUTRES champs du formulaire d'un type "Mot de passe" (ex: email de connexion) — voir
// l'entrée loginEmail ci-dessous.
//
// Champs volontairement PAS validés en format ici :
// - Le numéro de document d'identité (extraFields identity) : contrairement à une carte bancaire,
//   les numéros de document mélangent souvent lettres ET chiffres selon le pays/document (passeport
//   français "12AB34567", nouvelle carte d'identité française post-2021...) — une contrainte
//   "chiffres uniquement" y rejetterait à tort des numéros parfaitement valides.
// - Le mot de passe lui-même (type "Mot de passe", ex-"Identifiant") : aucune contrainte de format
//   n'a de sens pour un mot de passe, au contraire (autoriser n'importe quel caractère est le
//   comportement correct).
// - username (identifiant de connexion), nationality/address (identity) : texte libre, trop
//   variable pour une règle de format fiable (un identifiant peut être un pseudo, un numéro de
//   téléphone, etc. — pas toujours une adresse email, contrairement à loginEmail).

import type { EntryType } from "./vaultCrypto";
import { normalizeAndValidateUrl } from "./openExternalUrl";

/** Sous-ensemble de VaultEntryFormValues effectivement nécessaire ici — évite un import depuis
 * components/VaultEntryForm.tsx (qui importe déjà ce module), donc toute dépendance circulaire. */
interface ValidatableEntry {
  entryType: EntryType;
  password: string;
  extraFields: Record<string, string>;
  url: string;
  loginEmail: string;
}

// Volontairement simple (pas la monstrueuse regex RFC 5322 complète) : attrape les fautes de
// frappe courantes (email sans "@", sans domaine) sans risquer de rejeter à tort une adresse
// valide mais inhabituelle.
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const CARD_EXPIRY_YEAR_TOLERANCE_PAST = 1; // années dans le passé encore tolérées (carte qui vient d'expirer)
const CARD_EXPIRY_YEAR_TOLERANCE_FUTURE = 30; // au-delà, presque certainement une faute de frappe

/** Valide les champs spécifiques au type d'entrée choisi. Retourne un message d'erreur (à afficher
 * tel quel dans le formulaire) ou `null` si tout est valide. N'importe quel champ extra laissé vide
 * est ignoré (tous optionnels dans le formulaire) — seul un champ REMPLI est vérifié en format. */
export function validateEntryFields(values: ValidatableEntry): string | null {
  if (values.entryType === "card") {
    // Espaces/tirets autorisés à la SAISIE pour la lisibilité (ex: "4111 1111 1111 1111"), retirés
    // avant validation — mais aucune lettre ni autre caractère toléré.
    const digitsOnly = values.password.replace(/[\s-]/g, "");
    if (!/^\d+$/.test(digitsOnly)) {
      return "Numéro de carte : uniquement des chiffres (espaces autorisés pour la lisibilité).";
    }
    if (digitsOnly.length < 8 || digitsOnly.length > 19) {
      return "Numéro de carte : longueur invalide.";
    }

    const month = values.extraFields.expiryMonth?.trim() ?? "";
    if (month && !/^(0[1-9]|1[0-2])$/.test(month)) {
      return "Mois d'expiration : un nombre entre 01 et 12.";
    }

    const year = values.extraFields.expiryYear?.trim() ?? "";
    if (year) {
      if (!/^\d{4}$/.test(year)) {
        return "Année d'expiration : 4 chiffres (ex: 2028).";
      }
      const currentYear = new Date().getFullYear();
      const yearNum = Number(year);
      if (yearNum < currentYear - CARD_EXPIRY_YEAR_TOLERANCE_PAST || yearNum > currentYear + CARD_EXPIRY_YEAR_TOLERANCE_FUTURE) {
        return "Année d'expiration : semble incorrecte.";
      }
    }

    const cvv = values.extraFields.cvv?.trim() ?? "";
    if (cvv && !/^\d{3,4}$/.test(cvv)) {
      return "CVV : uniquement des chiffres (3 ou 4).";
    }
  }

  // Email de connexion (type "Mot de passe" uniquement — seul type qui a ce champ) : s'il est
  // rempli, doit ressembler à une adresse email. Retour utilisateur : "cette logique [validation
  // de format] s'applique partout, aussi au [formulaire de type] mot de passe."
  if (values.entryType === "login" && values.loginEmail.trim() && !EMAIL_PATTERN.test(values.loginEmail.trim())) {
    return "Email de connexion : format invalide.";
  }

  // Champ URL commun à tous les types (voir VaultEntryForm.tsx — pas réservé à "login") : doit
  // commencer par http:// ou https:// une fois normalisé, même liste blanche que openEntryUrl()
  // (voir lib/openExternalUrl.ts) — sans ce contrôle À LA SAISIE, une URL invalide/malveillante
  // n'était détectée qu'au moment de cliquer "Ouvrir le site", jamais avant.
  if (values.url.trim()) {
    const result = normalizeAndValidateUrl(values.url);
    if (!result.ok) return `URL du site : ${result.error}`;
  }

  return null;
}

/** URL normalisée (schéma https:// ajouté si absent) à stocker à la place de la saisie brute —
 * à appeler uniquement APRÈS validateEntryFields() ci-dessus (donc toujours valide ici si non
 * vide). Ainsi une entrée enregistrée porte toujours une URL avec schéma explicite, jamais
 * "github.com" tout court. */
export function normalizeEntryUrl(url: string): string {
  if (!url.trim()) return url;
  const result = normalizeAndValidateUrl(url);
  return result.ok ? result.normalized : url;
}
