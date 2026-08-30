PRAGMA foreign_keys = ON;

-- Table pour les compte 
CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin BOOLEAN NOT NULL DEFAULT 0
);


-- Table pour token
-- device_id : identifie l'appareil (app, extension, etc.) auquel ce token appartient,
-- pour permettre plusieurs sessions actives en parallèle pour un même utilisateur.
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token TEXT PRIMARY KEY NOT NULL,
    user_email TEXT NOT NULL,
    device_id TEXT NOT NULL DEFAULT '',
    expires_at DATETIME NOT NULL,
    is_persistent BOOLEAN NOT NULL DEFAULT 0,
    FOREIGN KEY (user_email) REFERENCES users(email) 
        ON UPDATE CASCADE 
        ON DELETE CASCADE
);

-- Table pour coffre
-- ZERO-KNOWLEDGE TOTAL : encrypted_site_name, encrypted_username, encrypted_login_email,
-- encrypted_preferred_login_type et encrypted_password sont TOUS chiffrés côté client. Le
-- serveur ne fait aucune hypothèse sur leur contenu (pas de recherche LIKE, pas de tri
-- alphabétique possible dessus — un texte chiffré ne préserve aucun motif exploitable).
-- deleted_at : suppression douce (corbeille). NULL = entrée active ; renseigné = passée à la
-- corbeille, récupérable pendant 30 jours (purge_old_trashed_vault_entries() dans main.rs)
-- avant d'être effacée définitivement.
CREATE TABLE IF NOT EXISTS vault (
    id TEXT PRIMARY KEY NOT NULL,
    encrypted_site_name TEXT NOT NULL,
    encrypted_username TEXT,
    encrypted_login_email TEXT,
    encrypted_password TEXT NOT NULL,
    encrypted_preferred_login_type TEXT NOT NULL,
    user_email TEXT NOT NULL,
    is_favorite BOOLEAN DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, -- Ajouté proprement ici !
    deleted_at DATETIME DEFAULT NULL,
    FOREIGN KEY (user_email) REFERENCES users(email) 
        ON UPDATE CASCADE 
        ON DELETE CASCADE
);

-- Table pour l'audit log
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT NOT NULL,
    action TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_email) REFERENCES users(email) 
        ON UPDATE CASCADE 
        ON DELETE CASCADE
);

-- device_id + user_email en clé composite : permet au même appareil physique d'être
-- associé à plusieurs comptes différents (poste partagé, tests) sans conflit.
-- last_used_at : mis à jour à chaque connexion réussie depuis cet appareil (voir login() et
-- verify_2fa_and_register_device() dans handlers/auth.rs) — permet à l'utilisateur de repérer
-- un appareil inactif depuis longtemps pour le révoquer en confiance (GET /devices).
CREATE TABLE IF NOT EXISTS trusted_devices (
    device_id TEXT NOT NULL,             -- UUID généré par l'app/extension
    user_email TEXT NOT NULL,
    device_name TEXT,                    -- ex: "Chrome Extension", "iPhone 15"
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (device_id, user_email),
    FOREIGN KEY(user_email) REFERENCES users(email) 
        ON UPDATE CASCADE 
        ON DELETE CASCADE
);

-- attempts : compteur de tentatives échouées, pour verrouiller (supprimer) le code
-- après un nombre d'essais trop élevé (protection anti-bruteforce sur un code à 6 chiffres).
CREATE TABLE IF NOT EXISTS tfa_codes (
    email TEXT PRIMARY KEY NOT NULL,
    code TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(email) REFERENCES users(email) 
        ON UPDATE CASCADE 
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_audit_user_date ON audit_logs(user_email, created_at);
-- Index séparé sur created_at SEUL : idx_audit_user_date ci-dessus ne sert à rien pour
-- get_audit_logs(), qui trie TOUTES les lignes par date sans filtrer par utilisateur (vue admin
-- globale) — un index composite (user_email, created_at) n'aide pas un tri non filtré à travers
-- tous les utilisateurs, seul un index sur created_at seul le permet.
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expiry ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_device ON refresh_tokens(user_email, device_id);
CREATE INDEX IF NOT EXISTS idx_vault_user_deleted ON vault(user_email, deleted_at);