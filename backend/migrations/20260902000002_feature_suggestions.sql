-- Suggestions de fonctionnalité envoyées depuis l'app desktop — voir handlers/feature_suggestion.rs.
-- Même raisonnement que bug_reports (migration 20260901000000) : DÉLIBÉRÉMENT EN CLAIR, pas
-- chiffré — un texte destiné à être lu par toi (l'Admin), rien à protéger en Zero-Knowledge ici.
--
-- Différence avec bug_reports : cette route EXIGE d'être connecté (contrairement au signalement de
-- bug, accessible même avant connexion pour signaler ce qui empêche justement de se connecter — une
-- suggestion de fonctionnalité n'a pas cette urgence). author_email est donc NOT NULL, toujours
-- l'email du compte réellement authentifié au moment de l'envoi — jamais une simple information de
-- contact facultative comme reporter_email dans bug_reports.
CREATE TABLE feature_suggestions (
    id TEXT PRIMARY KEY NOT NULL,
    author_email TEXT NOT NULL,
    description TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Le panneau Administration liste par défaut les plus récentes en premier.
CREATE INDEX idx_feature_suggestions_created_at ON feature_suggestions (created_at DESC);
