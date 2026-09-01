-- Deux nouveaux leviers pour l'Admin (demandés explicitement, voir la conversation du 2026-09-01,
-- après le retrait complet puis la restriction de l'ancien écran public "Configurer le serveur") :
--
-- 1. can_choose_server_in_settings (PAR COMPTE, désactivé par défaut) : autorise ce compte précis
--    à changer l'adresse du backend depuis les Réglages, une fois connecté (voir
--    frontend(app)/src/components/ServerUrlForm.tsx) — même principe que
--    can_change_email_via_extension (20260831000001_extension_email_change_flag.sql), l'Admin
--    reste toujours autorisé indépendamment de cette colonne (voir handlers/admin.rs).
--
-- 2. server_choice_at_login_enabled (GLOBAL, une seule ligne, PAS par compte) : contrôle si le
--    lien "Configurer le serveur" est visible sur l'écran de connexion, AVANT toute
--    authentification (voir pages/Login.tsx). Par nature, ce réglage ne peut PAS être par compte
--    puisqu'aucun compte n'est encore identifié à ce stade — nouvelle table dédiée à un seul
--    réglage global plutôt qu'une colonne sur `users` (qui n'aurait aucun sens ici), lue via un
--    endpoint public non-authentifié (voir handlers/common.rs::get_public_config).
ALTER TABLE users ADD COLUMN can_choose_server_in_settings BOOLEAN NOT NULL DEFAULT 0;

CREATE TABLE app_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1), -- une seule ligne possible, forcée par ce CHECK
    server_choice_at_login_enabled BOOLEAN NOT NULL DEFAULT 0
);
INSERT INTO app_settings (id, server_choice_at_login_enabled) VALUES (1, 0);
