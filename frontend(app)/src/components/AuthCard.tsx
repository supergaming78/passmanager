import type { ReactNode } from "react";

/** Mise en page partagée par tous les écrans d'authentification (register/login/2fa/...) —
 * carte centrée, cohérente sur les cinq écrans du flux plutôt que redéfinie à chaque fois.
 *
 * BADGE "Bêta" TEMPORAIRE (voir la conversation du 2026-08-31) : la période de test se fait avec
 * l'écran "Configurer le serveur" encore accessible (voir ServerSettingsRoute.tsx), avant que
 * l'adresse définitive du backend ne soit fixée en dur. Le badge ci-dessous marque cette période
 * de façon purement visuelle, sur les cinq écrans qui utilisent AuthCard (register/login/2fa/
 * forgot-password/reset-password) — RETIRER cette ligne (juste le <span> ci-dessous) quand
 * l'adresse définitive sera fixée et l'écran "Configurer le serveur" retiré. */
export default function AuthCard({ title, subtitle, children }: { title: string; subtitle?: string; children: ReactNode }) {
  return (
    <main className="flex min-h-screen items-center justify-center bg-neutral-50 px-4 dark:bg-neutral-950">
      <div className="w-full max-w-sm rounded-2xl border border-neutral-200 bg-white p-8 shadow-sm dark:border-neutral-800 dark:bg-neutral-900">
        <div className="flex items-center gap-2">
          <h1 className="text-xl font-semibold text-neutral-900 dark:text-neutral-100">{title}</h1>
          <span className="rounded-full bg-amber-100 px-2 py-0.5 text-[11px] font-medium text-amber-700 dark:bg-amber-950 dark:text-amber-400">
            Bêta
          </span>
        </div>
        {subtitle && <p className="mt-1 text-sm text-neutral-500">{subtitle}</p>}
        <div className="mt-6">{children}</div>
      </div>
    </main>
  );
}
