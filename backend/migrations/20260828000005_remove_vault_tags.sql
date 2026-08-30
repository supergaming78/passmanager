-- Retrait des étiquettes multiples (encrypted_tags, voir 20260828000003_vault_tags.sql) — jugées
-- redondantes avec le dossier (encrypted_folder) à l'usage. Migration de retrait plutôt que
-- suppression de la migration d'origine : ne jamais modifier/supprimer une migration déjà
-- appliquée, sqlx en vérifie le checksum au démarrage.
ALTER TABLE vault DROP COLUMN encrypted_tags;
