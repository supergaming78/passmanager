import { useState } from "react";
import { Link } from "react-router-dom";
import { openUrl } from "@tauri-apps/plugin-opener";
import { useAuth } from "../state/AuthContext";
import ChangeEmailForm from "../components/ChangeEmailForm";
import ChangePasswordForm from "../components/ChangePasswordForm";
import DeviceList from "../components/DeviceList";
import AutoLockSettings from "../components/AutoLockSettings";
import AutoBackupSettings from "../components/AutoBackupSettings";
import EmergencyAccessSettings from "../components/EmergencyAccessSettings";
import SecurityHistorySettings from "../components/SecurityHistorySettings";
import AppUpdateSettings from "../components/AppUpdateSettings";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-2xl border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-neutral-900">
      <h2 className="mb-3 text-base font-semibold text-neutral-900 dark:text-neutral-100">{title}</h2>
      {children}
    </section>
  );
}

export default function Settings() {
  const { email } = useAuth();

  const [showChangeEmail, setShowChangeEmail] = useState(false);
  const [showChangePassword, setShowChangePassword] = useState(false);

  return (
    <main className="min-h-screen bg-neutral-50 px-4 py-8 dark:bg-neutral-950">
      <div className="mx-auto flex max-w-2xl flex-col gap-4">
        <header className="mb-2 flex items-center justify-between">
          <h1 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">Réglages</h1>
          <Link to="/vault" className="text-sm text-indigo-600 hover:underline dark:text-indigo-400">
            ← Retour au coffre
          </Link>
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

        <Section title="Sécurité">
          <AutoLockSettings />
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
