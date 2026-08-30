-- Il n'existe qu'UN SEUL "Admin" dans cette application (le compte configuré via ADMIN_EMAIL,
-- voir maintenance.rs::promote_configured_admin) — la colonne qui accordait jusqu'ici les mêmes
-- privilèges élevés à N'IMPORTE QUEL compte promu (voir handlers/admin.rs::update_user_role) est
-- renommée pour refléter ce que c'est réellement : un rôle de "Modérateur", attribuable par
-- l'Admin à qui il veut, mais jamais un second "admin".
ALTER TABLE users RENAME COLUMN is_admin TO is_moderator;
