-- TYPES D'ENTRÉE DÉDIÉS — voir VaultEntryInput/VaultEntry (models.rs). `entry_type` est une
-- métadonnée EN CLAIR (comme `is_favorite`) : "login" (défaut, comportement inchangé pour toutes
-- les entrées existantes), "card", "identity" ou "note". `encrypted_extra_fields` est UN SEUL blob
-- JSON chiffré côté client (comme n'importe quel autre champ `encrypted_*`) contenant les quelques
-- champs vraiment spécifiques à un type qui n'ont pas d'équivalent générique réutilisable (ex :
-- date d'expiration/CVV pour une carte) — le serveur ne le parse jamais, Zero-Knowledge oblige.
ALTER TABLE vault ADD COLUMN entry_type TEXT NOT NULL DEFAULT 'login';
ALTER TABLE vault ADD COLUMN encrypted_extra_fields TEXT DEFAULT NULL;
