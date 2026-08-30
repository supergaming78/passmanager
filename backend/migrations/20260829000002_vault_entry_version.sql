-- DÉTECTION DE CONFLIT D'ÉDITION — voir VaultRepository::update(). `updated_at` (déjà existant)
-- s'est révélé insuffisant pour cet usage : CURRENT_TIMESTAMP en SQLite n'a qu'une précision à la
-- SECONDE, donc deux modifications de la même entrée survenant dans la MÊME seconde (deux appareils
-- qui enregistrent presque simultanément) produisent le même `updated_at` — le conflit ne serait
-- alors pas détecté. Un compteur entier dédié, incrémenté à CHAQUE modification, n'a pas ce
-- problème : deux écritures ne peuvent jamais partager la même valeur de version.
ALTER TABLE vault ADD COLUMN version INTEGER NOT NULL DEFAULT 1;
