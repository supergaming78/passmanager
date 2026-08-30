PRAGMA foreign_keys = ON;

-- Permet de savoir si un access token JWT donné a été émis AVANT ou APRÈS le dernier
-- changement de mot de passe (voir middleware.rs::AuthUser et
-- handlers/auth.rs::update_password()/confirm_password_reset()). Sans cette colonne, changer
-- son mot de passe suite à une compromission détectée révoquait bien les refresh tokens, mais
-- un access token déjà émis restait valide jusqu'à ~10 minutes de plus (sa propre expiration)
-- malgré tout — l'attaquant gardait l'accès pendant cette fenêtre résiduelle.
--
-- Défaut '1970-01-01 00:00:00' (bien avant n'importe quel `iat` réel), volontairement PAS
-- CURRENT_TIMESTAMP : un défaut "maintenant" invaliderait immédiatement TOUTES les sessions
-- actives au moment de cette migration. Avec l'epoch comme sentinelle "jamais changé", le
-- contrôle dans AuthUser ne se déclenche jamais tant que le mot de passe n'a pas RÉELLEMENT
-- été changé depuis l'émission du jeton — correct aussi bien pour les comptes existants que
-- pour les nouvelles inscriptions (qui héritent du même défaut via le schéma).
ALTER TABLE users ADD COLUMN password_changed_at DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00';
