import { Component, type ErrorInfo, type ReactNode } from "react";
import BugReportModal from "./BugReportModal";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
  componentStack: string | null;
  showReportModal: boolean;
}

/**
 * Filet de sécurité contre un crash React non géré — SEUL composant CLASSE de tout ce projet
 * (React n'a pas d'équivalent en Hooks pour `componentDidCatch`/`getDerivedStateFromError`, c'est
 * la seule façon d'attraper une erreur de rendu levée par un composant enfant).
 *
 * POURQUOI CE COMPOSANT EXISTE : sans lui, une exception non gérée dans N'IMPORTE QUEL composant
 * fait disparaître TOUT l'arbre React, écran blanc — y compris le bouton "Signaler un bug"
 * lui-même, précisément au moment où on en aurait le plus besoin. Ce composant enveloppe donc
 * TOUTE l'app (voir main.tsx) et affiche, à la place de l'écran blanc, un écran de secours qui
 * garde ce bouton accessible, pré-rempli avec le message d'erreur ET la pile d'appels — jamais de
 * contenu du coffre (une pile d'appels React ne contient que des noms de composants/fichiers, pas
 * les valeurs manipulées).
 */
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, componentStack: null, showReportModal: false };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // console.error plutôt que silencieux : reste visible dans les outils de dev si jamais
    // quelqu'un les ouvre, en plus de l'écran de secours affiché à l'utilisateur.
    console.error("Erreur non gérée interceptée par ErrorBoundary :", error, errorInfo.componentStack);
    this.setState({ componentStack: errorInfo.componentStack ?? null });
  }

  render() {
    if (!this.state.error) return this.props.children;

    const description = `Erreur : ${this.state.error.message}\n\nPile d'appels :\n${this.state.componentStack ?? "(indisponible)"}`;

    return (
      <main className="flex min-h-screen items-center justify-center bg-neutral-50 px-4 dark:bg-neutral-950">
        <div className="w-full max-w-sm rounded-2xl border border-neutral-200 bg-white p-8 text-center shadow-sm dark:border-neutral-800 dark:bg-neutral-900">
          <h1 className="text-lg font-semibold text-neutral-900 dark:text-neutral-100">
            Une erreur est survenue
          </h1>
          <p className="mt-2 text-sm text-neutral-500">
            Désolé pour le désagrément — ton coffre reste protégé, rien n'a été perdu. Tu peux
            recharger l'app, ou nous signaler ce qui s'est passé pour qu'on puisse le corriger.
          </p>
          <div className="mt-5 flex flex-col gap-2">
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white hover:bg-indigo-700"
            >
              Recharger l'app
            </button>
            <button
              type="button"
              onClick={() => this.setState({ showReportModal: true })}
              className="rounded-lg border border-neutral-300 px-4 py-2 text-sm font-medium text-neutral-700 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-300 dark:hover:bg-neutral-800"
            >
              Signaler ce bug
            </button>
          </div>
        </div>
        {this.state.showReportModal && (
          <BugReportModal
            initialDescription={description}
            onClose={() => this.setState({ showReportModal: false })}
          />
        )}
      </main>
    );
  }
}
