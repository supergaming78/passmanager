-- Retour utilisateur (2026-09-03, encore le même jour) : "background_neutral" (booléen, migration
-- précédente) ne permettait que DEUX choix — gris pur, ou coloré (chroma relevée, voir le
-- correctif du même jour sur applyBackground). L'utilisateur veut un TROISIÈME choix intermédiaire
-- : "par exemple lorsqu'on choisit noir, le fondu permettrait d'avoir un noir avec une légère
-- autre couleur" — c'est-à-dire la chroma FAIBLE ET FIXE (.006-.015) de la toute première version
-- de cette fonctionnalité, avant d'être relevée. Remplace le booléen par une énumération à trois
-- valeurs ("neutral" / "subtle" / "vivid"), validée côté application (voir
-- handlers/theme_customization.rs) — voir lib/customTheme.ts::applyBackground pour la chroma
-- exacte associée à chaque valeur.
ALTER TABLE theme_customization_profiles ADD COLUMN background_style TEXT NOT NULL DEFAULT 'neutral';
ALTER TABLE theme_customization_profiles DROP COLUMN background_neutral;
