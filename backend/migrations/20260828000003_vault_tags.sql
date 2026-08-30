-- Étiquettes multiples par entrée (ex: "Travail" ET "Facturation" sur la même entrée) — CHIFFRÉES
-- comme le reste du contenu, un tableau JSON de chaînes ("["Travail","Facturation"]") stocké dans
-- UN SEUL blob chiffré, comme encrypted_folder/encrypted_notes/encrypted_url. Complémentaire du
-- dossier existant (encrypted_folder, UN SEUL par entrée) — pas un remplacement : le dossier reste
-- la structure "un seul rangement", les tags permettent un classement croisé en plus.
ALTER TABLE vault ADD COLUMN encrypted_tags TEXT DEFAULT NULL;
