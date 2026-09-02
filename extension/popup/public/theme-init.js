// Anti-flash : applique le thème AVANT le premier rendu, chargé comme script EXTERNE (PAS
// inline) — la CSP de Manifest V3 (voir manifest.json::content_security_policy.extension_pages,
// "script-src 'self'") bloquerait un <script> inline dans index.html, imposée par le navigateur,
// aucun assouplissement possible ici. Duplique volontairement une petite partie de la logique de
// src/lib/theme.ts (qui prend le relais juste après) : ce fichier doit rester totalement autonome,
// sans import, pour pouvoir s'exécuter avant même que le bundle JS ne soit chargé — c'est
// précisément ce qui évite le flash. Liste de thèmes tenue synchronisée à la main avec
// lib/theme.ts::Theme — voir son commentaire pour la liste des classes de palette supplémentaires
// (voir App.css).
(function () {
  try {
    var stored = localStorage.getItem("passmanager.theme");
    var valid = ["dark", "light", "system", "midnight", "ocean", "forest", "sunset", "rose", "violet", "amber", "slate"];
    var paletteThemes = ["midnight", "ocean", "forest", "sunset", "rose", "violet", "amber", "slate"];
    var theme = valid.indexOf(stored) !== -1 ? stored : "dark";
    var isDark = theme !== "light" && (theme !== "system" || window.matchMedia("(prefers-color-scheme: dark)").matches);
    document.documentElement.classList.toggle("dark", isDark);
    document.documentElement.style.colorScheme = isDark ? "dark" : "light";
    for (var i = 0; i < paletteThemes.length; i++) {
      document.documentElement.classList.remove("theme-" + paletteThemes[i]);
    }
    if (paletteThemes.indexOf(theme) !== -1) {
      document.documentElement.classList.add("theme-" + theme);
    }
  } catch (e) {}
})();
