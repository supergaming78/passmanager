// Anti-flash : applique le thème AVANT le premier rendu, chargé comme script EXTERNE (PAS
// inline) — la CSP de cette app (Tauri, voir src-tauri/tauri.conf.json::csp, "script-src 'self'"
// sans 'unsafe-inline') bloquerait un <script> inline dans index.html. Duplique volontairement une
// petite partie de la logique de src/lib/theme.ts (qui prend le relais juste après, y compris pour
// suivre les changements de thème système en direct) : ce fichier doit rester totalement
// autonome, sans import, pour pouvoir s'exécuter avant même que le bundle JS ne soit chargé —
// c'est précisément ce qui évite le flash (le thème est déjà posé sur <html> avant que la
// feuille de style ne s'applique). Liste de thèmes tenue synchronisée à la main avec
// lib/theme.ts::Theme — voir son commentaire pour la liste des classes de palette supplémentaires
// (voir App.css).
//
// "custom" (retour utilisateur, 2026-09-03, affiné le même jour) duplique aussi, à la main, les
// tables L/C de lib/customTheme.ts — même raison (autonomie de ce fichier) — TENIR SYNCHRONISÉ si
// ces tables changent là-bas. Contrairement aux presets, "custom" pose des propriétés CSS INLINE
// (pas une classe) puisque teinte/luminosité choisies peuvent être n'importe quelle valeur ; le
// mode clair/sombre se DÉDUIT de la luminosité de fond choisie (pas une bascule séparée).
(function () {
  try {
    var stored = localStorage.getItem("passmanager.theme");
    var valid = ["dark", "light", "system", "midnight", "ocean", "forest", "sunset", "rose", "violet", "amber", "slate", "custom"];
    var paletteThemes = ["midnight", "ocean", "forest", "sunset", "rose", "violet", "amber", "slate"];
    var theme = valid.indexOf(stored) !== -1 ? stored : "dark";
    var html = document.documentElement;

    function clampL(l) {
      return Math.min(100, Math.max(0, l));
    }

    if (theme === "custom") {
      var cfg = {
        backgroundHue: 0, backgroundLightness: 12,
        accentHue: 277, accentLightness: 59,
        dangerHue: 27, dangerLightness: 64,
        successHue: 163, successLightness: 70,
        favoriteHue: 75, favoriteLightness: 77,
      };
      try {
        var storedCfg = localStorage.getItem("passmanager.customTheme");
        if (storedCfg) {
          var parsed = JSON.parse(storedCfg);
          for (var k in cfg) if (Object.prototype.hasOwnProperty.call(parsed, k)) cfg[k] = parsed[k];
        }
      } catch (e2) {}

      for (var j = 0; j < paletteThemes.length; j++) html.classList.remove("theme-" + paletteThemes[j]);

      // [luminosité native du palier, chroma native] par famille — voir lib/customTheme.ts pour
      // la source de ces valeurs et le raisonnement (ancrées sur le palier "500" natif).
      var INDIGO = { "50": [96.2, ".018"], "100": [93, ".034"], "200": [87, ".065"], "300": [78.5, ".115"], "400": [67.3, ".182"], "500": [58.5, ".233"], "600": [51.1, ".262"], "700": [45.7, ".24"], "800": [39.8, ".195"], "900": [35.9, ".144"], "950": [25.7, ".09"] };
      var RED = { "50": [97.1, ".013"], "100": [93.6, ".032"], "200": [88.5, ".062"], "300": [80.8, ".114"], "400": [70.4, ".191"], "500": [63.7, ".237"], "600": [57.7, ".245"], "700": [50.5, ".213"], "800": [44.4, ".177"], "900": [39.6, ".141"], "950": [25.8, ".092"] };
      var AMBER = { "50": [98.7, ".022"], "100": [96.2, ".059"], "300": [87.9, ".169"], "400": [82.8, ".189"], "500": [76.9, ".188"], "600": [66.6, ".179"], "700": [55.5, ".163"], "900": [41.4, ".112"], "950": [27.9, ".077"] };
      var EMERALD = { "100": [95, ".052"], "300": [84.5, ".143"], "400": [76.5, ".177"], "500": [69.6, ".17"], "600": [59.6, ".145"], "700": [50.8, ".118"], "950": [26.2, ".051"] };
      var GREEN = { "400": [79.2, ".209"], "600": [62.7, ".194"] };
      var INDIGO_ANCHOR = 58.5, RED_ANCHOR = 63.7, AMBER_ANCHOR = 76.9, EMERALD_ANCHOR = 69.6;

      function applyFamily(family, steps, hue, lightness, anchor) {
        var offset = lightness - anchor;
        for (var step in steps) {
          html.style.setProperty("--color-" + family + "-" + step, "oklch(" + clampL(steps[step][0] + offset).toFixed(1) + "% " + steps[step][1] + " " + hue + ")");
        }
      }
      applyFamily("indigo", INDIGO, cfg.accentHue, cfg.accentLightness, INDIGO_ANCHOR);
      applyFamily("red", RED, cfg.dangerHue, cfg.dangerLightness, RED_ANCHOR);
      applyFamily("amber", AMBER, cfg.favoriteHue, cfg.favoriteLightness, AMBER_ANCHOR);
      applyFamily("emerald", EMERALD, cfg.successHue, cfg.successLightness, EMERALD_ANCHOR);
      applyFamily("green", GREEN, cfg.successHue, cfg.successLightness, EMERALD_ANCHOR);

      var tintDark = ["--color-neutral-950", "--color-neutral-900", "--color-neutral-800"];
      var tintLight = ["--color-neutral-50", "--color-neutral-100", "--color-neutral-200"];
      for (var t = 0; t < tintDark.length; t++) html.style.removeProperty(tintDark[t]);
      for (var t2 = 0; t2 < tintLight.length; t2++) html.style.removeProperty(tintLight[t2]);

      var isDarkCustom = cfg.backgroundLightness < 50;
      if (isDarkCustom) {
        html.style.setProperty("--color-neutral-950", "oklch(" + clampL(cfg.backgroundLightness).toFixed(1) + "% .006 " + cfg.backgroundHue + ")");
        html.style.setProperty("--color-neutral-900", "oklch(" + clampL(cfg.backgroundLightness + 6).toFixed(1) + "% .008 " + cfg.backgroundHue + ")");
        html.style.setProperty("--color-neutral-800", "oklch(" + clampL(cfg.backgroundLightness + 12.4).toFixed(1) + "% .01 " + cfg.backgroundHue + ")");
      } else {
        html.style.setProperty("--color-neutral-50", "oklch(" + clampL(cfg.backgroundLightness).toFixed(1) + "% .008 " + cfg.backgroundHue + ")");
        html.style.setProperty("--color-neutral-100", "oklch(" + clampL(cfg.backgroundLightness - 1.5).toFixed(1) + "% .01 " + cfg.backgroundHue + ")");
        html.style.setProperty("--color-neutral-200", "oklch(" + clampL(cfg.backgroundLightness - 6.3).toFixed(1) + "% .015 " + cfg.backgroundHue + ")");
      }

      html.classList.toggle("dark", isDarkCustom);
      html.style.colorScheme = isDarkCustom ? "dark" : "light";
      return;
    }

    var isDark = theme !== "light" && (theme !== "system" || window.matchMedia("(prefers-color-scheme: dark)").matches);
    html.classList.toggle("dark", isDark);
    html.style.colorScheme = isDark ? "dark" : "light";
    for (var i = 0; i < paletteThemes.length; i++) {
      html.classList.remove("theme-" + paletteThemes[i]);
    }
    if (paletteThemes.indexOf(theme) !== -1) {
      html.classList.add("theme-" + theme);
    }
  } catch (e) {}
})();
