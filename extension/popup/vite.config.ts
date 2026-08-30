import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// base: "./" — indispensable : une extension de navigateur est chargée depuis le disque
// (chrome-extension://<id>/popup/dist/...), pas depuis la racine "/" d'un serveur web comme
// l'app desktop (voir frontend(app)/vite.config.ts) ; des chemins d'assets absolus casseraient
// le chargement des scripts/CSS générés.
export default defineConfig({
  base: "./",
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "dist",
  },
  server: {
    // Le module WASM (voir lib/wasmCrypto.ts) vit dans extension/wasm-bindings/pkg-web, EN DEHORS
    // de la racine de ce projet (extension/popup) — sans ça, le serveur de dev refuserait de le
    // servir (restriction par défaut de Vite aux fichiers sous root). Sans effet sur `npm run
    // build` (Rollup lit directement sur disque, cette restriction ne s'applique qu'au serveur dev).
    fs: {
      allow: [".", "../wasm-bindings"],
    },
  },
});
