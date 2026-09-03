-- OPTIMISATION : elargit idx_vault_user_deleted, l'index le plus sollicite de toute l'application.
--
-- Avant : (user_email, deleted_at) -- cree par 20240501000000_initial_schema.sql.
-- Apres : (user_email, deleted_at, is_favorite, updated_at)
--
-- Les deux colonnes ajoutees ne sont PAS la pour filtrer, mais pour eviter deux couts mesures avec
-- EXPLAIN QUERY PLAN sur le schema reel :
--
-- 1. `is_favorite` -- VaultRepository::get_all() (GET /vault, la requete la plus appelee de l'API)
--    se termine par `ORDER BY is_favorite DESC`. Avec l'ancien index, SQLite trouvait bien les
--    lignes de l'utilisateur, puis devait TOUTES les retrier dans une table temporaire :
--        SEARCH vault USING INDEX idx_vault_user_deleted (user_email=? AND deleted_at=?)
--        USE TEMP B-TREE FOR ORDER BY          <-- tri temporaire, a chaque appel
--    Avec `is_favorite` juste apres le prefixe filtre par egalite, les lignes sortent DEJA dans le
--    bon ordre (SQLite parcourt l'index a l'envers pour le DESC) et la ligne "USE TEMP B-TREE"
--    disparait completement du plan. Volontairement declaree ASC : SQLite sait parcourir un index
--    dans les deux sens, donc une seule definition sert aussi bien un futur tri ascendant.
--
-- 2. `updated_at` -- handlers/vault.rs::check_sync (GET /api/vault/sync, appele en boucle par
--    chaque appareil connecte pour detecter un changement) fait
--    `SELECT COUNT(*), MAX(updated_at) ... WHERE user_email = ? AND deleted_at IS NULL`.
--    Avec l'ancien index, SQLite devait ouvrir CHAQUE ligne de la table pour y lire `updated_at`.
--    En ajoutant cette colonne, l'index se suffit a lui-meme et le plan devient :
--        SEARCH vault USING COVERING INDEX idx_vault_user_deleted (...)
--    -- plus aucun acces a la table, sur la requete la plus repetee du produit.
--
-- Aucun impact sur la securite ni sur le modele Zero-Knowledge : `is_favorite` et `updated_at`
-- sont des metadonnees deja stockees en clair (voir le commentaire de la table `vault`), rien de
-- chiffre n'entre dans l'index. Le seul cout est un index legerement plus large a maintenir en
-- ecriture, negligeable devant le gain en lecture pour ce profil d'usage (beaucoup de lectures,
-- peu d'ecritures).
--
-- Non-regression verifiee sur le plan de get_trash() (`deleted_at IS NOT NULL ORDER BY deleted_at
-- DESC`), qui continue d'utiliser ce meme index exactement comme avant.

DROP INDEX IF EXISTS idx_vault_user_deleted;

CREATE INDEX IF NOT EXISTS idx_vault_user_deleted
    ON vault(user_email, deleted_at, is_favorite, updated_at);
