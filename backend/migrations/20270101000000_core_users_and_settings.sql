-- =========================================================================
-- SOCLE — comptes utilisateurs, réglages globaux, journal d'audit, signalements de bug
-- =========================================================================
-- Base de départ propre : ce fichier (et les 4 suivants, regroupés par domaine) remplacent
-- l'historique complet des migrations précédentes, qui avait fini par accumuler plusieurs passes
-- successives sur les mêmes tables (ajouts puis retraits, contraintes ajoutées après coup...). Le
-- schéma qu'ils produisent est strictement identique à celui obtenu par l'ancien historique —
-- seule la façon d'y arriver est plus directe.
--
-- `users.id` (numérique, stable, immuable) est la clé primaire dont dépend la quasi-totalité du
-- reste du schéma. `users.email` reste UNIQUE NOT NULL : c'est du matériau CRYPTOGRAPHIQUE côté
-- client (crypto-core/src/crypto.rs dérive le sel Argon2id du coffre par SHA-256(email)), le JWT
-- (`sub`) continue de la porter, jamais l'id.
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_moderator BOOLEAN NOT NULL DEFAULT 0,
    email_verified BOOLEAN NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    password_changed_at DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00',
    max_trusted_devices INTEGER NOT NULL DEFAULT 10,
    sessions_revoked_at DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00',
    can_change_email_via_extension BOOLEAN NOT NULL DEFAULT 0,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    last_failed_login_at DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00',
    can_choose_server_in_settings BOOLEAN NOT NULL DEFAULT 0,
    recovery_sealed_vault_key TEXT,
    is_suspended BOOLEAN NOT NULL DEFAULT 0,
    preferred_theme TEXT NOT NULL DEFAULT 'dark',
    max_vault_entries INTEGER,
    max_attachments INTEGER
);
CREATE INDEX idx_users_unverified ON users(created_at) WHERE email_verified = 0;

-- Une seule ligne possible (CHECK id = 1) : réglages globaux du serveur, pas par compte. La ligne
-- elle-même DOIT être semée ici : contrairement aux autres tables de ce fichier (remplies par les
-- utilisateurs), une table à une seule ligne dont plus rien d'autre ne déclenche la création reste
-- vide pour toujours sans cet INSERT explicite — get_public_config()/l'Admin s'attendent tous deux
-- à ce qu'elle existe déjà.
CREATE TABLE app_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    server_choice_at_login_enabled BOOLEAN NOT NULL DEFAULT 0,
    registration_open BOOLEAN NOT NULL DEFAULT 1
);
INSERT INTO app_settings (id, server_choice_at_login_enabled, registration_open) VALUES (1, 0, 1);

-- Journal d'audit — délibérément SANS clé étrangère vers users(id) : une photo historique de "qui
-- a fait quoi" doit survivre à la suppression du compte concerné, donc reste un EMAIL EN TEXTE,
-- jamais une référence vivante. Purgé après 10 jours (voir maintenance.rs), pas de plafond ici.
CREATE TABLE audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT NOT NULL,
    action TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_audit_user_date ON audit_logs(user_email, created_at);
CREATE INDEX idx_audit_created_at ON audit_logs(created_at);

-- Signalements de bug — reporter_email nullable et SANS clé étrangère : simple info de contact
-- facultative, saisie avant toute connexion (voir handlers/bug_report.rs::create_bug_report, seule
-- route publique de ce domaine). category vérifiée par CHECK (choisie côté client uniquement sinon).
CREATE TABLE bug_reports (
    id TEXT PRIMARY KEY NOT NULL,
    reporter_email TEXT,
    description TEXT NOT NULL,
    app_version TEXT NOT NULL,
    platform TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    category TEXT NOT NULL DEFAULT 'Autre'
        CHECK (category IN ('Affichage', 'Synchronisation', 'Plantage', 'Autre'))
);
CREATE INDEX idx_bug_reports_created_at ON bug_reports(created_at DESC);
