import { memo, useMemo, useState } from "react";
import { Link, NavLink, useNavigate } from "react-router-dom";
import type { MenuLayout } from "../lib/menuLayout";
import { isMobilePlatform } from "../lib/platform";
import EntryActionsMenu from "./EntryActionsMenu";

interface NavLinkItem {
  kind: "link";
  to: string;
  label: string;
  icon: string;
}
interface NavActionItem {
  kind: "action";
  label: string;
  icon: string;
  onClick: () => void;
  danger?: boolean;
}
type NavItem = NavLinkItem | NavActionItem;

interface Props {
  layout: MenuLayout;
  isModerator: boolean;
  email: string | null;
  onLogout: () => void;
  onReportBug: () => void;
  onSuggestFeature: () => void;
}

/** Liens communs à TOUTES les dispositions — un seul endroit pour la liste, chaque disposition
 * décide juste comment les DISPOSER (voir les trois rendus plus bas). "Déconnexion" volontairement
 * exclue d'ici : rendue à part dans chaque disposition (toujours la plus visible/isolée des
 * autres, jamais mélangée à la navigation courante — même parti pris que l'ancien header de
 * Vault.tsx, qui la sortait déjà de la liste des liens). "Suggérer une fonctionnalité" : retour
 * utilisateur (2026-09-02), "un peu comme le signalement de bug" mais réservée à l'app DESKTOP
 * (voir isMobilePlatform() — même garde-fou que MenuLayoutSettings.tsx dans Réglages), une
 * suggestion n'a pas de sens à proposer depuis un petit écran tactile où on tape peu de texte. */
function buildNavItems(isModerator: boolean, onReportBug: () => void, onSuggestFeature: () => void): NavItem[] {
  return [
    { kind: "link", to: "/vault", label: "Coffre", icon: "🔐" },
    ...(isModerator ? [{ kind: "link" as const, to: "/admin", label: "Administration", icon: "🛡️" }] : []),
    { kind: "link", to: "/shared-with-me", label: "Partagé avec moi", icon: "📥" },
    { kind: "link", to: "/shared-vaults", label: "Coffres partagés", icon: "👪" },
    { kind: "link", to: "/settings", label: "Réglages", icon: "⚙️" },
    ...(!isMobilePlatform() ? [{ kind: "action" as const, label: "Suggérer une fonctionnalité", icon: "💡", onClick: onSuggestFeature }] : []),
    { kind: "action", label: "Signaler un bug", icon: "🐞", onClick: onReportBug },
  ];
}

/** Navigation persistante de l'app — retour utilisateur (2026-09-02) : trois dispositions au
 * choix (voir Réglages → Apparence → Disposition du menu, DESKTOP uniquement), la disposition
 * "top" restant le défaut ET la SEULE utilisée sur mobile (voir lib/menuLayout.ts::
 * getEffectiveMenuLayout — imposé par le composant parent, AppShell.tsx, pas ici). "top" est un
 * PORT DIRECT de l'ancien header de pages/Vault.tsx (bandeau horizontal desktop + menu "⋮" replié
 * sur mobile), généralisé pour apparaître sur TOUTES les pages authentifiées au lieu de la seule
 * page Coffre. "sidebar"/"compact" sont nouvelles, jamais engagées sur mobile (voir plus haut). */
function AppNav({ layout, isModerator, email, onLogout, onReportBug, onSuggestFeature }: Props) {
  const [showMobileMenu, setShowMobileMenu] = useState(false);
  const navigate = useNavigate();
  // CORRECTIF PERF (retour utilisateur, 2026-09-02) : recalculé à chaque rendu auparavant (nouveau
  // tableau + nouveaux objets à chaque fois) alors que le résultat ne dépend que de isModerator/
  // onReportBug/onSuggestFeature — voir AppShell.tsx, qui mémorise maintenant ces callbacks pour
  // que ce useMemo profite réellement d'un cache d'un rendu à l'autre plutôt que de recalculer
  // systématiquement.
  const items = useMemo(
    () => buildNavItems(isModerator, onReportBug, onSuggestFeature),
    [isModerator, onReportBug, onSuggestFeature],
  );

  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `rounded-lg border px-3 py-1.5 text-sm font-medium transition ${
      isActive
        ? "border-indigo-300 bg-indigo-50 text-indigo-700 dark:border-indigo-800 dark:bg-indigo-950 dark:text-indigo-300"
        : "border-neutral-300 text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-900"
    }`;

  if (layout === "sidebar") {
    const sidebarLinkClass = ({ isActive }: { isActive: boolean }) =>
      `flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition ${
        isActive
          ? "bg-indigo-50 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300"
          : "text-neutral-700 hover:bg-neutral-100 dark:text-neutral-300 dark:hover:bg-neutral-900"
      }`;
    return (
      <nav className="flex h-full w-56 shrink-0 flex-col gap-1 overflow-y-auto border-r border-neutral-200 bg-white p-3 dark:border-neutral-800 dark:bg-neutral-950">
        <p className="truncate px-3 pb-2 text-xs text-neutral-500">{email}</p>
        {items.map((item) =>
          item.kind === "link" ? (
            <NavLink key={item.to} to={item.to} className={sidebarLinkClass}>
              <span aria-hidden="true">{item.icon}</span> {item.label}
            </NavLink>
          ) : (
            <button key={item.label} type="button" onClick={item.onClick} className={sidebarLinkClass({ isActive: false })}>
              <span aria-hidden="true">{item.icon}</span> {item.label}
            </button>
          ),
        )}
        <div className="mt-auto border-t border-neutral-200 pt-2 dark:border-neutral-800">
          <button
            type="button"
            onClick={onLogout}
            className="flex w-full items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:text-neutral-300 dark:hover:bg-neutral-900"
          >
            <span aria-hidden="true">🚪</span> Déconnexion
          </button>
        </div>
      </nav>
    );
  }

  if (layout === "compact") {
    const compactLinkClass = ({ isActive }: { isActive: boolean }) =>
      `flex h-10 w-10 items-center justify-center rounded-lg text-lg transition ${
        isActive
          ? "bg-indigo-50 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300"
          : "text-neutral-700 hover:bg-neutral-100 dark:text-neutral-300 dark:hover:bg-neutral-900"
      }`;
    return (
      <nav className="flex h-full w-14 shrink-0 flex-col items-center gap-1 overflow-y-auto border-r border-neutral-200 bg-white py-3 dark:border-neutral-800 dark:bg-neutral-950">
        {items.map((item) =>
          item.kind === "link" ? (
            <NavLink key={item.to} to={item.to} title={item.label} className={compactLinkClass}>
              <span aria-hidden="true">{item.icon}</span>
            </NavLink>
          ) : (
            <button key={item.label} type="button" onClick={item.onClick} title={item.label} className={compactLinkClass({ isActive: false })}>
              <span aria-hidden="true">{item.icon}</span>
            </button>
          ),
        )}
        <button
          type="button"
          onClick={onLogout}
          title="Déconnexion"
          className="mt-auto flex h-10 w-10 items-center justify-center rounded-lg text-lg text-neutral-700 hover:bg-neutral-100 dark:text-neutral-300 dark:hover:bg-neutral-900"
        >
          <span aria-hidden="true">🚪</span>
        </button>
      </nav>
    );
  }

  // "top" — voir le commentaire de la fonction : port direct de l'ancien header de Vault.tsx
  // (deux rangées : titre+email+menu mobile/déconnexion, puis nav sur sa PROPRE rangée en dessous
  // — PAS tout sur une seule rangée : le titre bloque de la place, la nav est en flex-wrap et peut
  // passer sur 2 lignes sur une fenêtre étroite, les deux se marchaient dessus/l'email se
  // retrouvait écrasé à largeur quasi nulle quand ils partageaient la même rangée, constaté à
  // l'écran lors de la conception).
  return (
    <header className="shrink-0 border-b border-neutral-200 bg-white px-4 py-3 dark:border-neutral-800 dark:bg-neutral-950">
      <div className="mx-auto flex max-w-4xl flex-col gap-3">
        <div className="flex items-center justify-between gap-3">
          <div className="min-w-0">
            <Link to="/vault" className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">
              🔐 PassManager
            </Link>
            <p className="truncate text-sm text-neutral-500">{email}</p>
          </div>

          {/* Menu ⋮ — MOBILE UNIQUEMENT (`sm:hidden`) — mêmes liens que la nav desktop ci-dessous,
           * repliés pour ne pas empiler une quinzaine de boutons sur un écran étroit (voir l'ancien
           * commentaire de pages/Vault.tsx, la même logique, juste généralisée à toutes les pages). */}
          <div className="shrink-0 sm:hidden">
            <EntryActionsMenu
              isOpen={showMobileMenu}
              onToggle={() => setShowMobileMenu((v) => !v)}
              onClose={() => setShowMobileMenu(false)}
              items={items.map((item) => ({
                label: item.label,
                onClick: item.kind === "link" ? () => navigate(item.to) : item.onClick,
              }))}
            />
          </div>

          <button
            type="button"
            onClick={onLogout}
            className="hidden shrink-0 rounded-lg border border-neutral-300 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-900 sm:block"
          >
            Déconnexion
          </button>
        </div>

        <nav className="hidden flex-wrap items-center gap-2 sm:flex">
          {items.map((item) =>
            item.kind === "link" ? (
              <NavLink key={item.to} to={item.to} className={linkClass}>
                {item.label}
              </NavLink>
            ) : (
              <button key={item.label} type="button" onClick={item.onClick} className={linkClass({ isActive: false })}>
                {item.label}
              </button>
            ),
          )}
        </nav>
      </div>
    </header>
  );
}

// CORRECTIF PERF (retour utilisateur, 2026-09-02) : AppNav se re-rendait avec le reste de
// AppShell.tsx même quand aucune de ses propres props n'avait changé (ex: `showBugReport` qui
// bascule pour afficher BugReportModal). `memo()` saute le rendu quand toutes les props sont
// identiques par égalité de référence — n'a d'effet réel que parce qu'AppShell.tsx mémorise
// maintenant onLogout/onReportBug (sinon de nouvelles fonctions à chaque rendu casseraient cette
// égalité de toute façon, rendant le memo() inutile).
export default memo(AppNav);
