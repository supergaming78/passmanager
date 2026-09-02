// Disposition du menu principal — retour utilisateur (2026-09-02), DESKTOP UNIQUEMENT (Windows/
// macOS/Linux, voir lib/platform.ts::isMobilePlatform()). Trois dispositions au choix pour la
// navigation persistante (voir components/AppShell.tsx) : "top" (bandeau horizontal, disposition
// actuelle, DÉFAUT), "sidebar" (barre latérale gauche persistante), "compact" (barre étroite à
// icônes seules, avec info-bulles). Purement local à cet appareil (localStorage, comme le thème),
// pas partagé entre appareils — un choix d'affichage n'a pas de raison de suivre le compte.
import { isMobilePlatform } from "./platform";

export type MenuLayout = "top" | "sidebar" | "compact";

const STORAGE_KEY = "passmanager.menuLayout";
const VALID_LAYOUTS: readonly MenuLayout[] = ["top", "sidebar", "compact"];

/** Lit la préférence brute — utilisée par le sélecteur dans Réglages (voir
 * components/MenuLayoutSettings.tsx). Ne tient PAS compte de la plateforme : voir
 * getEffectiveMenuLayout() ci-dessous pour la valeur RÉELLEMENT appliquée au rendu. */
export function getMenuLayout(): MenuLayout {
  const stored = localStorage.getItem(STORAGE_KEY);
  return (VALID_LAYOUTS as readonly string[]).includes(stored ?? "") ? (stored as MenuLayout) : "top";
}

export function setMenuLayout(layout: MenuLayout): void {
  localStorage.setItem(STORAGE_KEY, layout);
}

/** Valeur RÉELLEMENT appliquée au rendu (voir components/AppShell.tsx) — force "top" sur mobile
 * quelle que soit la valeur en localStorage (défensif : un ancien réglage resté en local après un
 * changement de plateforme, par exemple, ne doit jamais se retrouver appliqué sur téléphone). Le
 * sélecteur lui-même reste de toute façon masqué sur mobile (voir MenuLayoutSettings.tsx), cette
 * fonction est la seconde ligne de défense côté rendu. */
export function getEffectiveMenuLayout(): MenuLayout {
  if (isMobilePlatform()) return "top";
  return getMenuLayout();
}
