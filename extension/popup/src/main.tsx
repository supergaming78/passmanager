import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./App.css";

// Pas de routeur ici (contrairement à frontend(app)/src/main.tsx) : cette phase n'a que deux
// écrans (connexion, coffre), gérés par un simple état local dans App.tsx — voir le plan pour le
// détail du périmètre réduit.
ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
