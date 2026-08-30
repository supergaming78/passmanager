-- URL du site par entrée (ex: pour un bouton "Ouvrir le site" côté client) — CHIFFRÉE comme le
-- reste du contenu, une URL révèle autant qu'un nom de site.
ALTER TABLE vault ADD COLUMN encrypted_url TEXT DEFAULT NULL;
