import type { ReactNode } from "react";

/** Mise en page partagée par tous les écrans d'authentification (register/login/2fa/...) —
 * carte centrée, cohérente sur les cinq écrans du flux plutôt que redéfinie à chaque fois.
 *
 * Le badge "Bêta" qui figurait ici a été retiré à la sortie de la version 1.0.0. Il avait été
 * conservé après la stabilisation du backend, parce que signaler la fin d'un déploiement n'est pas
 * la même chose que déclarer le logiciel lui-même terminé — cette seconde décision est désormais
 * prise. */
export default function AuthCard({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }) {
  return (
    <main className="flex min-h-screen items-center justify-center bg-neutral-50 px-4 dark:bg-neutral-950">
      <div className="w-full max-w-sm rounded-2xl border border-neutral-200 bg-white p-8 shadow-sm dark:border-neutral-800 dark:bg-neutral-900">
        <h1 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-neutral-500">{subtitle}</p>}
        <div className="mt-6">{children}</div>
      </div>
    </main>
  );
}
