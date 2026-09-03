-- Retour utilisateur (2026-09-03, encore le même jour) : "contrôle de la saturation (pas que
-- teinte+luminosité)" — chaque couleur (fond compris) gagne un TROISIÈME réglage indépendant, la
-- saturation (0-100%, un multiplicateur de la chroma native par palier Tailwind — voir
-- lib/customTheme.ts). Remplace `background_style` (3 valeurs discrètes "neutral"/"subtle"/
-- "vivid") par un curseur continu `background_saturation`, cohérent avec les 4 autres couleurs
-- (qui, elles, n'avaient encore AUCUN contrôle de saturation — toujours la chroma native Tailwind,
-- 100% implicite).
ALTER TABLE theme_customization_profiles ADD COLUMN background_saturation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE theme_customization_profiles ADD COLUMN accent_saturation INTEGER NOT NULL DEFAULT 100;
ALTER TABLE theme_customization_profiles ADD COLUMN danger_saturation INTEGER NOT NULL DEFAULT 100;
ALTER TABLE theme_customization_profiles ADD COLUMN success_saturation INTEGER NOT NULL DEFAULT 100;
ALTER TABLE theme_customization_profiles ADD COLUMN favorite_saturation INTEGER NOT NULL DEFAULT 100;
ALTER TABLE theme_customization_profiles DROP COLUMN background_style;
