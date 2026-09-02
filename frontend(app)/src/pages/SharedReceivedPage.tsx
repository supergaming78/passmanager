import SharedWithMeSettings from "../components/SharedWithMeSettings";
import BlindSharesReceivedSettings from "../components/BlindSharesReceivedSettings";

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-2xl border border-neutral-200 bg-white p-5 dark:border-neutral-800 dark:bg-neutral-900">
      <h2 className="mb-3 text-base font-semibold text-neutral-900 dark:text-neutral-100">{title}</h2>
      {children}
    </section>
  );
}

/** Tout ce qui a été partagé AVEC l'utilisateur courant, les DEUX mécanismes de partage
 * "reçus" réunis sur un même écran accessible depuis le coffre (PAS dans Réglages, où ils
 * vivaient auparavant) — le coffre partagé familial reste sur sa propre page dédiée
 * (voir SharedVaultsPage.tsx), c'est une ressource commune à plusieurs membres, pas quelque
 * chose qu'on "reçoit" ponctuellement de la même façon que ces deux-là. */
export default function SharedReceivedPage() {
  return (
    <main className="min-h-screen bg-neutral-50 px-4 py-8 dark:bg-neutral-950">
      {/* Largeur progressive tablette/desktop — voir le commentaire équivalent dans Vault.tsx. */}
      <div className="mx-auto flex max-w-2xl flex-col gap-4 md:max-w-3xl lg:max-w-4xl xl:max-w-6xl 2xl:max-w-[100rem]">
        {/* Plus de lien "← Retour au coffre" ici (retour utilisateur, 2026-09-02) : redondant
         * maintenant que la navigation vit dans components/AppShell.tsx. */}
        <header className="mb-2">
          <h1 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">Partagé avec moi</h1>
        </header>

        <Section title="Partage classique">
          <SharedWithMeSettings />
        </Section>

        <Section title="Partage à usage limité">
          <BlindSharesReceivedSettings />
        </Section>
      </div>
    </main>
  );
}
