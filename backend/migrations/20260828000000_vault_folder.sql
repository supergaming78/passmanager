-- Dossier d'organisation optionnel par entrée du coffre (ex: "Travail", "Perso", "Banque"),
-- CHIFFRÉ côté client comme les autres champs de contenu (voir models.rs::VaultEntryInput) — un
-- nom de dossier révèle une catégorisation sensible, pas question de le laisser en clair.
ALTER TABLE vault ADD COLUMN encrypted_folder TEXT DEFAULT NULL;
