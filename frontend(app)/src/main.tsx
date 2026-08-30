import React from "react";
import ReactDOM from "react-dom/client";
import { HashRouter } from "react-router-dom";
import { AuthProvider } from "./state/AuthContext";
import App from "./App";

// HashRouter plutôt que BrowserRouter : dans Tauri, l'app est servie comme un bundle statique
// (pas un vrai serveur HTTP avec routage côté serveur) — HashRouter garde toute la navigation
// côté client (URLs en "#/login") sans dépendre d'une configuration de fallback SPA côté Tauri.
ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <HashRouter>
      <AuthProvider>
        <App />
      </AuthProvider>
    </HashRouter>
  </React.StrictMode>,
);
