// Anti-flash : applique le thème AVANT le premier rendu, chargé comme script EXTERNE (PAS
// inline) — la CSP de cette app (Tauri, voir src-tauri/tauri.conf.json::csp, "script-src 'self'"
// sans 'unsafe-inline') bloquerait un <script> inline dans index.html. Duplique volontairement une
// petite partie de la logique de src/lib/theme.ts (qui prend le relais juste après, y compris pour
// suivre les changements de thème système en direct) : ce fichier doit rester totalement
// autonome, sans import, pour pouvoir s'exécuter avant même que le bundle JS ne soit chargé —
// c'est précisément ce qui évite le flash (le thème est déjà posé sur <html> avant que la
// feuille de style ne s'applique). Liste de thèmes tenue synchronisée à la main avec
// lib/theme.ts::Theme — voir son commentaire pour "midnight"/"ocean" (classes de palette
// supplémentaires, voir App.css).
(function () {
  try {
    var stored = localStorage.getItem("passmanager.theme");
    var valid = ["dark", "light", "system", "midnight", "ocean"];
    var theme = valid.indexOf(stored) !== -1 ? stored : "dark";
    var isDark = theme !== "light" && (theme !== "system" || window.matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.classList.toggle("dark", isDark);
    document.documentElement.style.colorScheme = isDark ? "dark" : "light";
    document.documentElement.classList.remove("theme-midnight", "theme-ocean");
    if (theme === "midnight" || theme === "ocean") {
      document.documentElement.classList.add("theme-" + theme);
    }
  } catch (e) {}
})();
