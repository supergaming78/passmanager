-- =========================================================================
-- SESSIONS & APPAREILS — jetons, codes 2FA, tickets WebSocket, clés publiques, appareils de
-- confiance, historique des adresses IP
-- =========================================================================

CREATE TABLE refresh_tokens (
    token TEXT PRIMARY KEY NOT NULL,
    user_id INTEGER NOT NULL,
    device_id TEXT NOT NULL DEFAULT '',
    expires_at DATETIME NOT NULL,
    is_persistent BOOLEAN NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_refresh_tokens_expiry ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_user_device ON refresh_tokens(user_id, device_id);

-- Codes à usage unique (2FA de connexion, vérification d'email, réinitialisation de mot de passe) —
-- `purpose` distingue les 3 flux qui partagent cette table, clé composite (user_id, purpose) : un
-- code généré pour un flux ne doit jamais écraser un autre flux concurrent pour le même compte.
CREATE TABLE tfa_codes (
    user_id INTEGER NOT NULL,
    purpose TEXT NOT NULL,
    code TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, purpose),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_tfa_codes_expiry ON tfa_codes(expires_at);

-- Ticket à usage unique échangé contre l'accès à /ws (voir sync.rs) — l'access token Bearer
-- classique ne peut pas s'utiliser directement pour une connexion WebSocket.
CREATE TABLE ws_tickets (
    ticket_hash TEXT PRIMARY KEY NOT NULL,
    user_id INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_ws_tickets_expiry ON ws_tickets(expires_at);

-- Paire de clés asymétriques du compte (chiffrement des invitations à un coffre partagé/accès
-- d'urgence) — une seule paire par compte, PK simple sur user_id.
CREATE TABLE user_keys (
    user_id INTEGER PRIMARY KEY NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_private_key TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Appareils de confiance — DOIT être créée avant trusted_device_ips (clé composite référencée
-- ci-dessous), seule vraie dépendance d'ordre de ce fichier au-delà de `users`.
CREATE TABLE trusted_devices (
    device_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    device_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_ip_alert_at DATETIME NULL,
    PRIMARY KEY (device_id, user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_trusted_devices_user ON trusted_devices(user_id);

-- Fenêtre glissante des 5 IP les plus récentes vues par appareil de confiance (voir
-- record_device_ip_and_maybe_alert, handlers/auth/session.rs) — sert à détecter une connexion
-- depuis une IP jamais vue sur un appareil déjà approuvé.
CREATE TABLE trusted_device_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL,
    last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id, user_id) REFERENCES trusted_devices(device_id, user_id) ON DELETE CASCADE,
    UNIQUE (device_id, user_id, ip_address)
);
CREATE INDEX idx_trusted_device_ips_device ON trusted_device_ips(device_id, user_id);

-- Mémoire longue des adresses IP par compte (contrairement à audit_logs, purgé à 10 jours) — une
-- adresse revenant tous les quinze jours n'apparaît pas comme neuve à chaque fois.
CREATE TABLE account_ip_history (
    user_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL,
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, ip_address),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_account_ip_history_user ON account_ip_history(user_id, last_seen DESC);
CREATE INDEX idx_account_ip_history_ip ON account_ip_history(ip_address);
