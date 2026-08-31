import React from "react";
import ReactDOM from "react-dom/client";
import { HashRouter } from "react-router-dom";
import { AuthProvider } from "./state/AuthContext";
import ErrorBoundary from "./components/ErrorBoundary";
import { installDiagnosticLogCapture } from "./lib/diagnosticLog";
import App from "./App";

// AVANT tout le reste : pour que le journal de diagnostic (voir lib/diagnosticLog.ts, inclus
// automatiquement dans chaque signalement de bug) capture aussi les erreurs qui surviennent tôt,
// avant même le premier rendu.
installDiagnosticLogCapture();

// HashRouter plutôt que BrowserRouter : dans Tauri, l'app est servie comme un bundle statique
// (pas un vrai serveur HTTP avec routage côté serveur) — HashRouter garde toute la navigation
// côté client (URLs en "#/login") sans dépendre d'une configuration de fallback SPA côté Tauri.
//
// ErrorBoundary englobe TOUT, y compris AuthProvider — un crash à l'intérieur du contexte
// d'authentification lui-même (pas juste dans une page) doit aussi être attrapé, sinon
// ErrorBoundary passerait à côté exactement du genre de crash le plus grave.
ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <ErrorBoundary>
      <HashRouter>
        <AuthProvider>
          <App />
        </AuthProvider>
      </HashRouter>
    </ErrorBoundary>
  </React.StrictMode>,
);
