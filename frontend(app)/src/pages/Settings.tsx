import { useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { useAuth } from "../state/AuthContext";
import ChangeEmailForm from "../components/ChangeEmailForm";
import ChangePasswordForm from "../components/ChangePasswordForm";
import DeviceList from "../components/DeviceList";
import AutoLockSettings from "../components/AutoLockSettings";
import RecoveryKitSettings from "../components/RecoveryKitSettings";
import AutoBackupSettings from "../components/AutoBackupSettings";
import EmergencyAccessSettings from "../components/EmergencyAccessSettings";
import SecurityHistorySettings from "../components/SecurityHistorySettings";
import AppUpdateSettings from "../components/AppUpdateSettings";
import ServerUrlForm from "../components/ServerUrlForm";
import ThemeSettings from "../components/ThemeSettings";
import MenuLayoutSettings from "../components/MenuLayoutSettings";
import ListLayoutSettings from "../components/ListLayoutSettings";
import { isMobilePlatform } from "../lib/platform";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-2xl border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-neutral-900">
      <h2 className="mb-3 text-base font-semibold text-neutral-900 dark:text-neutral-100">{title}</h2>
      {children}
    </section>
  );
}

export default function Settings() {
  const { email, isAdmin, canChooseServerInSettings } = useAuth();

  const [showChangeEmail, setShowChangeEmail] = useState(false);
  const [showChangePassword, setShowChangePassword] = useState(false);

  return (
    <main className="min-h-screen bg-neutral-50 px-4 py-8 dark:bg-neutral-950">
      {/* Largeur progressive tablette/desktop — voir le commentaire équivalent dans Vault.tsx.
       * Élargissement PLUS MODÉRÉ que les autres pages (2xl:max-w-5xl, pas 100rem) : cette page est
       * un simple formulaire à UNE colonne (des `<select>` pleine largeur, pas une grille de
       * cartes) — la laisser s'étirer autant que le Coffre donnerait des menus déroulants
       * absurdement larges plutôt que d'exploiter utilement l'espace. */}
      <div className="mx-auto flex max-w-2xl flex-col gap-4 md:max-w-3xl lg:max-w-4xl 2xl:max-w-5xl">
        {/* Plus de lien "← Retour au coffre" ici (retour utilisateur, 2026-09-02) : redondant
         * maintenant que la navigation vit dans components/AppShell.tsx, commune à toutes les
         * pages authentifiées — "Coffre" y est toujours accessible d'un clic. */}
        <header className="mb-2">
          <h1 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">Réglages</h1>
        </header>

        <Section title="Compte">
          <p className="mb-3 text-sm text-neutral-600 dark:text-neutral-400">{email}</p>
          {showChangeEmail ? (
            <ChangeEmailForm onDone={() => setShowChangeEmail(false)} />
          ) : (
            <button
              type="button"
              onClick={() => setShowChangeEmail(true)}
              className="rounded-lg border border-neutral-300 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              Changer d'email
            </button>
          )}
        </Section>

        <Section title="Mot de passe maître">
          {showChangePassword ? (
            <ChangePasswordForm onDone={() => setShowChangePassword(false)} />
          ) : (
            <button
              type="button"
              onClick={() => setShowChangePassword(true)}
              className="rounded-lg border border-neutral-300 px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              Changer le mot de passe maître
            </button>
          )}
        </Section>

        <Section title="Apparence">
          <div className="flex flex-col gap-4">
            <ThemeSettings />
            {/* Disposition du menu : DESKTOP uniquement (voir lib/platform.ts::isMobilePlatform) —
             * une barre latérale/compacte pensée pour un grand écran avec souris n'a pas vraiment
             * de sens sur téléphone/tablette, voir son propre commentaire pour le détail. */}
            {!isMobilePlatform() && <MenuLayoutSettings />}
            {/* CORRECTIF (retour utilisateur, 2026-09-02) : disposition des listes, DESKTOP
             * uniquement aussi désormais — revenu sur le choix d'origine ("a du sens aussi sur
             * mobile") : un téléphone a "beaucoup moins d'espace" pour qu'une grille de cartes ou
             * un mode compact apportent un vrai gain, voir lib/listLayout.ts::getEffectiveListLayout
             * (même mécanisme que la disposition du menu ci-dessus) pour la seconde ligne de
             * défense côté rendu, au cas où ce réglage serait resté en localStorage depuis un
             * changement de plateforme. */}
            {!isMobilePlatform() && <ListLayoutSettings />}
          </div>
        </Section>

        <Section title="Sécurité">
          <AutoLockSettings />
          <RecoveryKitSettings />
        </Section>

        <Section title="Appareils de confiance">
          <DeviceList />
        </Section>

        <Section title="Sauvegarde automatique">
          <AutoBackupSettings />
        </Section>

        <Section title="Historique de sécurité">
          <SecurityHistorySettings />
        </Section>

        <Section title="Accès d'urgence">
          <EmergencyAccessSettings />
        </Section>

        <Section title="Mises à jour">
          <AppUpdateSettings />
        </Section>

        {/* Réservé : l'Admin y a toujours accès, un compte normal seulement si l'Admin le lui a
            explicitement accordé (voir handlers/admin.rs::update_server_choice_in_settings() côté
            backend, panneau Administration côté app). isAdmin OU canChooseServerInSettings — voir
            state/AuthContext.tsx pour pourquoi ces deux valeurs restent distinctes. */}
        {(isAdmin || canChooseServerInSettings) && (
          <Section title="Serveur (cet appareil uniquement)">
            <ServerUrlForm />
          </Section>
        )}

        {/* Seule l'icône "openai" (voir lib/knownLogos.ts) vient de Font Awesome Free, sous licence
            CC BY 4.0, qui EXIGE une attribution — d'où cette mention. Simple Icons et CoreUI Brands
            (toutes les autres icônes) sont en CC0, aucune attribution requise, mais mentionnées ici
            aussi par souci de transparence. `<button onClick={openUrl}>` plutôt que `<a href>` :
            dans une app Tauri, un lien classique naviguerait la fenêtre de l'app elle-même au lieu
            d'ouvrir le navigateur système (voir lib/openExternalUrl.ts, même raison ailleurs dans
            l'app). */}
        <footer className="px-1 text-xs text-neutral-400 dark:text-neutral-600">
          Icônes de marques :{" "}
          <button type="button" onClick={() => void openUrl("https://simpleicons.org")} className="hover:underline">
            Simple Icons
          </button>{" "}
          et{" "}
          <button type="button" onClick={() => void openUrl("https://coreui.io/icons/")} className="hover:underline">
            CoreUI Brands
          </button>{" "}
          (CC0), icône OpenAI :{" "}
          <button type="button" onClick={() => void openUrl("https://fontawesome.com")} className="hover:underline">
            Font Awesome Free
          </button>{" "}
          (
          <button
            type="button"
            onClick={() => void openUrl("https://creativecommons.org/licenses/by/4.0/")}
            className="hover:underline"
          >
            CC BY 4.0
          </button>
          ).
        </footer>
      </div>
    </main>
  );
}
