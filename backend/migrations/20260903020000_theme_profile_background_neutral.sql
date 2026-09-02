-- Retour utilisateur (2026-09-03, encore le même jour) : la version précédente a fait disparaître
-- la possibilité d'un fond ENTIÈREMENT neutre (aucune teinte, chroma nulle) — la migration
-- précédente donnait toujours un soupçon de couleur au fond (chroma fixe .006-.01, jamais 0), alors
-- que la toute première version de cette fonctionnalité avait une case "teinté ou pas" qui,
-- décochée, donnait un fond parfaitement neutre. On la restaure, mais comme un choix EXPLICITE et
-- indépendant de la teinte/luminosité (voir lib/customTheme.ts côté client) plutôt qu'une bascule
-- séparée du mode clair/sombre.
ALTER TABLE theme_customization_profiles ADD COLUMN background_neutral INTEGER NOT NULL DEFAULT 1;
