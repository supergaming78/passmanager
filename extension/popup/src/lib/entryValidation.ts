// Validation des champs d'une entrée AVANT chiffrement — même principe et même code que
// frontend(app)/src/lib/entryValidation.ts côté app desktop (voir son commentaire pour le détail
// complet et le retour utilisateur à l'origine) : architecture Zero-Knowledge (voir
// lib/vaultCrypto.ts), le serveur ne voit jamais le contenu en clair d'une entrée, donc cette
// validation ne peut exister QUE côté client, ici.

import type { EntryType } from "./vaultCrypto";
import { normalizeAndValidateUrl } from "./openExternalUrl";

/** Sous-ensemble de VaultEntryFormValues effectivement nécessaire ici — évite un import depuis
 * components/VaultEntryForm.tsx (qui importe déjà ce module), donc toute dépendance circulaire. */
interface ValidatableEntry {
  entryType: EntryType;
  password: string;
  extraFields: Record<string, string>;
  url: string;
}

const CARD_EXPIRY_YEAR_TOLERANCE_PAST = 1; // années dans le passé encore tolérées (carte qui vient d'expirer)
const CARD_EXPIRY_YEAR_TOLERANCE_FUTURE = 30; // au-delà, presque certainement une faute de frappe

/** Valide les champs spécifiques au type d'entrée choisi. Retourne un message d'erreur (à afficher
 * tel quel dans le formulaire) ou `null` si tout est valide. Volontairement PAS de contrainte de
 * format sur le numéro de document d'identité (lettres+chiffres mélangés selon le pays) ni sur le
 * mot de passe lui-même — voir le commentaire complet côté app desktop. */
export function validateEntryFields(values: ValidatableEntry): string | null {
  if (values.entryType === "card") {
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

  if (values.url.trim()) {
    const result = normalizeAndValidateUrl(values.url);
    if (!result.ok) return `URL : ${result.error}`;
  }

  return null;
}

/** URL normalisée (schéma https:// ajouté si absent) à stocker à la place de la saisie brute — à
 * appeler uniquement APRÈS validateEntryFields() ci-dessus. */
export function normalizeEntryUrl(url: string): string {
  if (!url.trim()) return url;
  const result = normalizeAndValidateUrl(url);
  return result.ok ? result.normalized : url;
}
