-- Protection anti-bruteforce PAR COMPTE (en plus du rate limiting par IP existant, voir
-- main.rs::build_router()) : sans ceci, un attaquant avec plusieurs IP (botnet, rotation VPN)
-- peut deviner indéfiniment le hash de mot de passe d'UN compte ciblé, le rate limiting par IP
-- ne s'appliquant qu'à chaque IP individuellement. Voir handlers/auth/session.rs::login() pour
-- la logique complète (fenêtre glissante, remise à zéro sur connexion réussie).
ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN last_failed_login_at DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00';
