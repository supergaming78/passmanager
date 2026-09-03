PRAGMA foreign_keys = ON;

-- Audit sécurité/perf (retour utilisateur, 2026-09-03 : "cherche les bugs et failles de sécurité
-- [...] optimise tout ce qui est possible") — repéré par relecture, pas par un incident réel :
-- FeatureSuggestionRepository::create() (voir repository.rs) exécute
-- `SELECT COUNT(*) FROM feature_suggestions WHERE author_email = ?` à CHAQUE suggestion envoyée,
-- pour appliquer MAX_FEATURE_SUGGESTIONS_PER_USER — sans index sur `author_email`, cette requête
-- doit parcourir TOUTE la table à chaque appel (coût qui grandit avec le nombre total de
-- suggestions de TOUS les comptes, pas seulement celles de l'auteur). Aucun risque de sécurité
-- (la table reste petite dans l'usage visé), mais un index reste gratuit à l'écriture pour une
-- table de cette taille et évite que ce coût ne devienne perceptible si l'usage grandit.
CREATE INDEX idx_feature_suggestions_author ON feature_suggestions(author_email);
