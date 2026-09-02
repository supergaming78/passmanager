import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./App.css";
import { initTheme } from "./lib/theme";

// Le thème a déjà été appliqué une première fois par index.html::theme-init.js (anti-flash, voir
// son commentaire) — cet appel prend juste le relais pour le reste de la session (notamment le
// suivi en direct des changements de thème système si l'utilisateur a choisi "system").
initTheme();

// Pas de routeur ici (contrairement à frontend(app)/src/main.tsx) : cette phase n'a que deux
// écrans (connexion, coffre), gérés par un simple état local dans App.tsx — voir le plan pour le
// détail du périmètre réduit.
ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
