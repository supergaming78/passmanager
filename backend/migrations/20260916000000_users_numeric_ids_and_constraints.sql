-- no-transaction
-- =========================================================================
-- COHÉRENCE DE LA BASE — identifiants numériques, contraintes manquantes, fusion des partages de
-- thème. Remplace 6 migrations écrites en plusieurs passes successives au fil d'une même relecture
-- (chacune reconstruisait parfois une table déjà reconstruite par la précédente, uniquement pour y
-- ajouter une contrainte de plus) : ce fichier unique reconstruit CHAQUE table UNE SEULE FOIS, dans
-- sa forme finale, pour que l'historique des migrations reste lisible plutôt que de rejouer le
-- brouillon.
--
-- 1) IDENTIFIANTS NUMÉRIQUES — `users.email` était la clé primaire, et ~21 autres tables
--    stockaient une colonne TEXT (user_email/owner_email/contact_email/shared_with_email/
--    created_by/author_email/member_email/from_email/to_email) comme clé étrangère vers
--    `users(email)`. Une clé primaire devrait être un identifiant STABLE et IMMUABLE, jamais une
--    donnée métier qui peut changer — `users` reçoit un `id INTEGER PRIMARY KEY AUTOINCREMENT`,
--    et toutes les tables dépendantes pointent désormais vers cet id plutôt que vers l'email.
--
--    CE QUI NE CHANGE PAS (volontairement) : `users.email` reste une colonne UNIQUE NOT NULL, avec
--    exactement les mêmes valeurs qu'avant — c'est du matériau CRYPTOGRAPHIQUE côté client
--    (crypto-core/src/crypto.rs dérive le sel Argon2id du coffre par SHA-256(email)), donc sa
--    valeur ne doit jamais être altérée par cette migration. Le JWT (`sub`) continue de porter
--    l'email, pas l'id — aucune app cliente (desktop, extension) ne voit quoi que ce soit changer.
--
--    CE QUI RESTE HORS MIGRATION (volontairement, décision déjà actée dans ce schéma) :
--      - audit_logs.user_email : délibérément sans FK depuis 20260829000001_audit_logs_survive_
--        account_deletion.sql — photo historique de "qui a fait quoi", doit survivre à la
--        suppression du compte, donc reste un EMAIL EN TEXTE, pas un id vivant.
--      - bug_reports.reporter_email : nullable, sans FK, saisie pré-connexion non vérifiée — sa
--        seule contrainte manquante (la catégorie) est traitée séparément, voir la migration
--        suivante (elle n'a aucune dépendance sur `users`, pas besoin du même dispositif).
--      - app_settings : aucune colonne utilisateur.
--
-- 2) CONTRAINTES MANQUANTES — plusieurs colonnes "enum" n'étaient validées que côté Rust, jamais
--    par la base : `entry_type` (vault/shared_vault_entries), `status` (emergency_contacts). Deux
--    garde-fous numériques ajoutés en plus : `vault_blind_shares.max_uses >= 1` et
--    `remaining_uses <= max_uses` (déjà garantis par le code applicatif, désormais impossibles à
--    violer même par un futur bug serveur). Une normalisation `CASE`/`COALESCE` protège les lignes
--    déjà en base qui pourraient être hors des valeurs attendues, plutôt que de faire échouer toute
--    la migration à cause d'une poignée de lignes isolées.
--
-- 3) FUSION shared_theme_profiles -> theme_customization_profiles — `shared_theme_profiles` était
--    un quasi-doublon (19 colonnes de couleurs identiques), qui n'existait que pour porter une
--    paire from_id/to_id supplémentaire. Un partage EN ATTENTE devient une ligne ORDINAIRE de
--    theme_customization_profiles, déjà possédée par le DESTINATAIRE (`user_id`), avec
--    `pending_from_user_id` renseigné tant qu'il n'est pas encore accepté (NULL = profil normal).
--    Accepter un partage devient un simple UPDATE qui efface cette colonne sur la ligne déjà là.
--    Un profil encore en attente ne peut jamais être actif (CHECK) : garanti par construction côté
--    code (voir repository.rs::ThemeShareRepository), rendu impossible à violer ici aussi.
--
-- `vault` est référencée par 4 tables en CASCADE (vault_password_history, vault_attachments,
-- vault_shares, vault_blind_shares) et `users` l'est par la QUASI-TOTALITÉ du schéma : reconstruire
-- l'une ou l'autre sous clés étrangères actives déclencherait un DELETE implicite en cascade sur
-- TOUT. D'où : `-- no-transaction` + PRAGMA foreign_keys OFF avant tout BEGIN (le PRAGMA est un
-- no-op à l'intérieur d'une transaction) + PRAGMA foreign_key_check juste avant COMMIT — procédure
-- officielle SQLite pour ce cas (https://www.sqlite.org/lang_altertable.html, section "Making
-- Other Kinds Of Table Schema Changes").
--
-- ORDRE : `users` doit être reconstruite EN PREMIER (chaque table suivante a besoin de son nouvel
-- `id` pour la jointure de reprise). Au-delà de `users`, la seule autre dépendance d'ordre réelle
-- est `trusted_device_ips`, qui référence la clé composite de `trusted_devices`. `ON UPDATE CASCADE`
-- est retiré de chaque FK reconstruite (un id numérique ne change jamais, la clause devenait sans
-- objet) ; `ON DELETE CASCADE` est conservé partout où il existait déjà.

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

-- =========================================================================
-- 1) users — la seule table dont la clé primaire elle-même change de forme
-- =========================================================================
CREATE TABLE users_new (
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
-- ORDER BY email : assignation déterministe des id, sans autre signification (aucun id
-- pré-existant à préserver, `users` n'en avait pas avant cette migration).
INSERT INTO users_new (
    email, password_hash, is_moderator, email_verified, created_at, password_changed_at,
    max_trusted_devices, sessions_revoked_at, can_change_email_via_extension,
    failed_login_attempts, last_failed_login_at, can_choose_server_in_settings,
    recovery_sealed_vault_key, is_suspended, preferred_theme, max_vault_entries, max_attachments
)
SELECT
    email, password_hash, is_moderator, email_verified, created_at, password_changed_at,
    max_trusted_devices, sessions_revoked_at, can_change_email_via_extension,
    failed_login_attempts, last_failed_login_at, can_choose_server_in_settings,
    recovery_sealed_vault_key, is_suspended, preferred_theme, max_vault_entries, max_attachments
FROM users
ORDER BY email;
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;
CREATE INDEX IF NOT EXISTS idx_users_unverified ON users(created_at) WHERE email_verified = 0;

-- =========================================================================
-- 2) vault — + CHECK entry_type, + NOT NULL is_favorite/updated_at (COALESCE de sécurité)
-- =========================================================================
CREATE TABLE vault_new (
    id TEXT PRIMARY KEY NOT NULL,
    encrypted_site_name TEXT NOT NULL,
    encrypted_username TEXT,
    encrypted_login_email TEXT,
    encrypted_password TEXT NOT NULL,
    encrypted_preferred_login_type TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    is_favorite BOOLEAN NOT NULL DEFAULT 0,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at DATETIME DEFAULT NULL,
    encrypted_folder TEXT DEFAULT NULL,
    encrypted_notes TEXT DEFAULT NULL,
    encrypted_url TEXT DEFAULT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    entry_type TEXT NOT NULL DEFAULT 'login' CHECK (entry_type IN ('login', 'card', 'identity', 'note')),
    encrypted_extra_fields TEXT DEFAULT NULL,
    use_count INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
INSERT INTO vault_new (
    id, encrypted_site_name, encrypted_username, encrypted_login_email, encrypted_password,
    encrypted_preferred_login_type, user_id, is_favorite, updated_at, deleted_at,
    encrypted_folder, encrypted_notes, encrypted_url, version, entry_type,
    encrypted_extra_fields, use_count
)
SELECT
    v.id, v.encrypted_site_name, v.encrypted_username, v.encrypted_login_email, v.encrypted_password,
    v.encrypted_preferred_login_type, u.id, COALESCE(v.is_favorite, 0),
    COALESCE(v.updated_at, CURRENT_TIMESTAMP), v.deleted_at,
    v.encrypted_folder, v.encrypted_notes, v.encrypted_url, v.version,
    CASE WHEN v.entry_type IN ('login', 'card', 'identity', 'note') THEN v.entry_type ELSE 'login' END,
    v.encrypted_extra_fields, v.use_count
FROM vault v JOIN users u ON u.email = v.user_email;
DROP TABLE vault;
ALTER TABLE vault_new RENAME TO vault;
CREATE INDEX IF NOT EXISTS idx_vault_user_deleted ON vault(user_id, deleted_at, is_favorite, updated_at);
CREATE INDEX IF NOT EXISTS idx_vault_deleted_at ON vault(deleted_at) WHERE deleted_at IS NOT NULL;

-- =========================================================================
-- 3) refresh_tokens
-- =========================================================================
CREATE TABLE refresh_tokens_new (
    token TEXT PRIMARY KEY NOT NULL,
    user_id INTEGER NOT NULL,
    device_id TEXT NOT NULL DEFAULT '',
    expires_at DATETIME NOT NULL,
    is_persistent BOOLEAN NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
INSERT INTO refresh_tokens_new (token, user_id, device_id, expires_at, is_persistent)
SELECT r.token, u.id, r.device_id, r.expires_at, r.is_persistent
FROM refresh_tokens r JOIN users u ON u.email = r.user_email;
DROP TABLE refresh_tokens;
ALTER TABLE refresh_tokens_new RENAME TO refresh_tokens;
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expiry ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_device ON refresh_tokens(user_id, device_id);

-- =========================================================================
-- 4) tfa_codes — PK composite (email, purpose) -> (user_id, purpose)
-- =========================================================================
CREATE TABLE tfa_codes_new (
    user_id INTEGER NOT NULL,
    purpose TEXT NOT NULL,
    code TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, purpose),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
INSERT INTO tfa_codes_new (user_id, purpose, code, expires_at, attempts)
SELECT u.id, t.purpose, t.code, t.expires_at, t.attempts
FROM tfa_codes t JOIN users u ON u.email = t.email;
DROP TABLE tfa_codes;
ALTER TABLE tfa_codes_new RENAME TO tfa_codes;
CREATE INDEX IF NOT EXISTS idx_tfa_codes_expiry ON tfa_codes(expires_at);

-- =========================================================================
-- 5) ws_tickets
-- =========================================================================
CREATE TABLE ws_tickets_new (
    ticket_hash TEXT PRIMARY KEY NOT NULL,
    user_id INTEGER NOT NULL,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
INSERT INTO ws_tickets_new (ticket_hash, user_id, expires_at)
SELECT w.ticket_hash, u.id, w.expires_at
FROM ws_tickets w JOIN users u ON u.email = w.user_email;
DROP TABLE ws_tickets;
ALTER TABLE ws_tickets_new RENAME TO ws_tickets;
CREATE INDEX IF NOT EXISTS idx_ws_tickets_expiry ON ws_tickets(expires_at);

-- =========================================================================
-- 6) user_keys — PK simple user_email -> PK simple user_id
-- =========================================================================
CREATE TABLE user_keys_new (
    user_id INTEGER PRIMARY KEY NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_private_key TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
INSERT INTO user_keys_new (user_id, public_key, encrypted_private_key, created_at)
SELECT u.id, k.public_key, k.encrypted_private_key, k.created_at
FROM user_keys k JOIN users u ON u.email = k.user_email;
DROP TABLE user_keys;
ALTER TABLE user_keys_new RENAME TO user_keys;

-- =========================================================================
-- 7) emergency_contacts — deux colonnes "qui" (owner/contact) + CHECK status
-- =========================================================================
CREATE TABLE emergency_contacts_new (
    id TEXT PRIMARY KEY NOT NULL,
    owner_id INTEGER NOT NULL,
    contact_id INTEGER NOT NULL,
    waiting_period_days INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'access_requested', 'access_granted')),
    sealed_vault_key TEXT,
    requested_at DATETIME,
    available_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (contact_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (owner_id, contact_id)
);
INSERT INTO emergency_contacts_new (
    id, owner_id, contact_id, waiting_period_days, status, sealed_vault_key,
    requested_at, available_at, created_at
)
SELECT e.id, uo.id, uc.id, e.waiting_period_days,
       CASE WHEN e.status IN ('pending', 'active', 'access_requested', 'access_granted') THEN e.status ELSE 'pending' END,
       e.sealed_vault_key, e.requested_at, e.available_at, e.created_at
FROM emergency_contacts e
JOIN users uo ON uo.email = e.owner_email
JOIN users uc ON uc.email = e.contact_email;
DROP TABLE emergency_contacts;
ALTER TABLE emergency_contacts_new RENAME TO emergency_contacts;
CREATE INDEX IF NOT EXISTS idx_emergency_contacts_owner ON emergency_contacts(owner_id);
CREATE INDEX IF NOT EXISTS idx_emergency_contacts_contact ON emergency_contacts(contact_id);

-- =========================================================================
-- 8) vault_shares — deux colonnes "qui" (owner/shared_with)
-- =========================================================================
CREATE TABLE vault_shares_new (
    id TEXT PRIMARY KEY NOT NULL,
    vault_id TEXT NOT NULL,
    owner_id INTEGER NOT NULL,
    shared_with_id INTEGER NOT NULL,
    sealed_entry TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vault_id) REFERENCES vault(id) ON DELETE CASCADE,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_with_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (vault_id, shared_with_id)
);
INSERT INTO vault_shares_new (id, vault_id, owner_id, shared_with_id, sealed_entry, created_at, updated_at)
SELECT s.id, s.vault_id, uo.id, uw.id, s.sealed_entry, s.created_at, s.updated_at
FROM vault_shares s
JOIN users uo ON uo.email = s.owner_email
JOIN users uw ON uw.email = s.shared_with_email;
DROP TABLE vault_shares;
ALTER TABLE vault_shares_new RENAME TO vault_shares;
CREATE INDEX IF NOT EXISTS idx_vault_shares_owner ON vault_shares(owner_id);
CREATE INDEX IF NOT EXISTS idx_vault_shares_recipient ON vault_shares(shared_with_id);

-- =========================================================================
-- 9) shared_vaults
-- =========================================================================
CREATE TABLE shared_vaults_new (
    id TEXT PRIMARY KEY NOT NULL,
    encrypted_name TEXT NOT NULL,
    created_by_id INTEGER NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by_id) REFERENCES users(id) ON DELETE CASCADE
);
INSERT INTO shared_vaults_new (id, encrypted_name, created_by_id, created_at)
SELECT sv.id, sv.encrypted_name, u.id, sv.created_at
FROM shared_vaults sv JOIN users u ON u.email = sv.created_by;
DROP TABLE shared_vaults;
ALTER TABLE shared_vaults_new RENAME TO shared_vaults;
CREATE INDEX IF NOT EXISTS idx_shared_vaults_created_by ON shared_vaults(created_by_id);

-- =========================================================================
-- 10) shared_vault_members — PK composite (shared_vault_id, member_email) -> (shared_vault_id, member_id)
-- =========================================================================
CREATE TABLE shared_vault_members_new (
    shared_vault_id TEXT NOT NULL,
    member_id INTEGER NOT NULL,
    sealed_vault_key TEXT NOT NULL,
    is_owner BOOLEAN NOT NULL DEFAULT 0,
    added_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (shared_vault_id, member_id),
    FOREIGN KEY (shared_vault_id) REFERENCES shared_vaults(id) ON DELETE CASCADE,
    FOREIGN KEY (member_id) REFERENCES users(id) ON DELETE CASCADE
);
INSERT INTO shared_vault_members_new (shared_vault_id, member_id, sealed_vault_key, is_owner, added_at)
SELECT m.shared_vault_id, u.id, m.sealed_vault_key, m.is_owner, m.added_at
FROM shared_vault_members m JOIN users u ON u.email = m.member_email;
DROP TABLE shared_vault_members;
ALTER TABLE shared_vault_members_new RENAME TO shared_vault_members;
CREATE INDEX IF NOT EXISTS idx_shared_vault_members_member ON shared_vault_members(member_id);

-- =========================================================================
-- 11) shared_vault_entries — + CHECK entry_type, + index couvrant (shared_vault_id, updated_at)
--     `shared_vault_entries` n'a AUCUN plafond par coffre (contrairement à toutes les autres
--     collections de ce fichier) : c'est la seule table où éviter le tri temporaire de
--     list_entries() (ORDER BY updated_at DESC) apporte un vrai bénéfice, d'où le critère de tri
--     en dernière colonne de l'index — même convention que vault/vault_password_history/
--     vault_attachments/account_ip_history.
-- =========================================================================
CREATE TABLE shared_vault_entries_new (
    id TEXT PRIMARY KEY NOT NULL,
    shared_vault_id TEXT NOT NULL,
    encrypted_site_name TEXT NOT NULL,
    encrypted_username TEXT,
    encrypted_login_email TEXT,
    encrypted_password TEXT NOT NULL,
    encrypted_preferred_login_type TEXT NOT NULL,
    encrypted_notes TEXT DEFAULT NULL,
    encrypted_url TEXT DEFAULT NULL,
    entry_type TEXT NOT NULL DEFAULT 'login' CHECK (entry_type IN ('login', 'card', 'identity', 'note')),
    encrypted_extra_fields TEXT DEFAULT NULL,
    created_by_id INTEGER NOT NULL,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (shared_vault_id) REFERENCES shared_vaults(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by_id) REFERENCES users(id) ON DELETE CASCADE
);
INSERT INTO shared_vault_entries_new (
    id, shared_vault_id, encrypted_site_name, encrypted_username, encrypted_login_email,
    encrypted_password, encrypted_preferred_login_type, encrypted_notes, encrypted_url,
    entry_type, encrypted_extra_fields, created_by_id, updated_at, version
)
SELECT
    e.id, e.shared_vault_id, e.encrypted_site_name, e.encrypted_username, e.encrypted_login_email,
    e.encrypted_password, e.encrypted_preferred_login_type, e.encrypted_notes, e.encrypted_url,
    CASE WHEN e.entry_type IN ('login', 'card', 'identity', 'note') THEN e.entry_type ELSE 'login' END,
    e.encrypted_extra_fields, u.id, e.updated_at, e.version
FROM shared_vault_entries e JOIN users u ON u.email = e.created_by;
DROP TABLE shared_vault_entries;
ALTER TABLE shared_vault_entries_new RENAME TO shared_vault_entries;
CREATE INDEX IF NOT EXISTS idx_shared_vault_entries_vault ON shared_vault_entries(shared_vault_id, updated_at DESC);

-- =========================================================================
-- 12) vault_blind_shares — deux colonnes "qui" (owner/shared_with) + CHECK max_uses/remaining_uses
-- =========================================================================
CREATE TABLE vault_blind_shares_new (
    id TEXT PRIMARY KEY NOT NULL,
    vault_id TEXT NOT NULL,
    owner_id INTEGER NOT NULL,
    shared_with_id INTEGER NOT NULL,
    sealed_site_name TEXT NOT NULL,
    sealed_credentials TEXT NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 1 CHECK (max_uses >= 1),
    remaining_uses INTEGER NOT NULL CHECK (remaining_uses >= 0 AND remaining_uses <= max_uses),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vault_id) REFERENCES vault(id) ON DELETE CASCADE,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (shared_with_id) REFERENCES users(id) ON DELETE CASCADE
);
INSERT INTO vault_blind_shares_new (
    id, vault_id, owner_id, shared_with_id, sealed_site_name, sealed_credentials,
    max_uses, remaining_uses, created_at
)
SELECT b.id, b.vault_id, uo.id, uw.id, b.sealed_site_name, b.sealed_credentials,
       b.max_uses, b.remaining_uses, b.created_at
FROM vault_blind_shares b
JOIN users uo ON uo.email = b.owner_email
JOIN users uw ON uw.email = b.shared_with_email;
DROP TABLE vault_blind_shares;
ALTER TABLE vault_blind_shares_new RENAME TO vault_blind_shares;
CREATE INDEX IF NOT EXISTS idx_vault_blind_shares_recipient ON vault_blind_shares(shared_with_id);
CREATE INDEX IF NOT EXISTS idx_vault_blind_shares_vault ON vault_blind_shares(vault_id);
CREATE INDEX IF NOT EXISTS idx_vault_blind_shares_owner ON vault_blind_shares(owner_id);

-- =========================================================================
-- 13) feature_suggestions
-- =========================================================================
CREATE TABLE feature_suggestions_new (
    id TEXT PRIMARY KEY NOT NULL,
    author_id INTEGER NOT NULL,
    description TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
);
INSERT INTO feature_suggestions_new (id, author_id, description, created_at)
SELECT f.id, u.id, f.description, f.created_at
FROM feature_suggestions f JOIN users u ON u.email = f.author_email;
DROP TABLE feature_suggestions;
ALTER TABLE feature_suggestions_new RENAME TO feature_suggestions;
CREATE INDEX IF NOT EXISTS idx_feature_suggestions_created_at ON feature_suggestions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_feature_suggestions_author ON feature_suggestions(author_id);

-- =========================================================================
-- 14) theme_customization_profiles — + fusion de shared_theme_profiles (voir l'en-tête de ce
--     fichier, point 3) : `pending_from_user_id` porte directement les partages en attente, plus
--     besoin d'une table séparée. Le CHECK interdit qu'une ligne soit À LA FOIS active et encore en
--     attente (garanti par construction côté code, rendu impossible à violer ici aussi).
-- =========================================================================
CREATE TABLE theme_customization_profiles_new (
    id TEXT PRIMARY KEY NOT NULL,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    background_hue INTEGER NOT NULL DEFAULT 0,
    background_lightness INTEGER NOT NULL DEFAULT 12,
    accent_hue INTEGER NOT NULL DEFAULT 277,
    accent_lightness INTEGER NOT NULL DEFAULT 59,
    danger_hue INTEGER NOT NULL DEFAULT 27,
    danger_lightness INTEGER NOT NULL DEFAULT 64,
    success_hue INTEGER NOT NULL DEFAULT 163,
    success_lightness INTEGER NOT NULL DEFAULT 70,
    favorite_hue INTEGER NOT NULL DEFAULT 75,
    favorite_lightness INTEGER NOT NULL DEFAULT 77,
    is_active INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    background_saturation INTEGER NOT NULL DEFAULT 0,
    accent_saturation INTEGER NOT NULL DEFAULT 100,
    danger_saturation INTEGER NOT NULL DEFAULT 100,
    success_saturation INTEGER NOT NULL DEFAULT 100,
    favorite_saturation INTEGER NOT NULL DEFAULT 100,
    pending_from_user_id INTEGER NULL REFERENCES users(id) ON DELETE CASCADE,
    CHECK (NOT (is_active = 1 AND pending_from_user_id IS NOT NULL)),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
-- Profils "normaux" existants (pending_from_user_id NULL).
INSERT INTO theme_customization_profiles_new (
    id, user_id, name, background_hue, background_lightness, accent_hue, accent_lightness,
    danger_hue, danger_lightness, success_hue, success_lightness, favorite_hue, favorite_lightness,
    is_active, created_at, background_saturation, accent_saturation, danger_saturation,
    success_saturation, favorite_saturation, pending_from_user_id
)
SELECT
    t.id, u.id, t.name, t.background_hue, t.background_lightness, t.accent_hue, t.accent_lightness,
    t.danger_hue, t.danger_lightness, t.success_hue, t.success_lightness, t.favorite_hue, t.favorite_lightness,
    t.is_active, t.created_at, t.background_saturation, t.accent_saturation, t.danger_saturation,
    t.success_saturation, t.favorite_saturation, NULL
FROM theme_customization_profiles t JOIN users u ON u.email = t.user_email;
-- Partages en attente (ex-shared_theme_profiles), fusionnés directement dans la même table :
-- possédés par le DESTINATAIRE (to -> user_id), avec pending_from_user_id = l'expéditeur (from).
INSERT INTO theme_customization_profiles_new (
    id, user_id, name, background_hue, background_lightness, background_saturation,
    accent_hue, accent_lightness, accent_saturation, danger_hue, danger_lightness, danger_saturation,
    success_hue, success_lightness, success_saturation, favorite_hue, favorite_lightness, favorite_saturation,
    is_active, created_at, pending_from_user_id
)
SELECT
    s.id, ut.id, s.name, s.background_hue, s.background_lightness, s.background_saturation,
    s.accent_hue, s.accent_lightness, s.accent_saturation, s.danger_hue, s.danger_lightness, s.danger_saturation,
    s.success_hue, s.success_lightness, s.success_saturation, s.favorite_hue, s.favorite_lightness, s.favorite_saturation,
    0, s.created_at, uf.id
FROM shared_theme_profiles s
JOIN users uf ON uf.email = s.from_email
JOIN users ut ON ut.email = s.to_email;
DROP TABLE theme_customization_profiles;
ALTER TABLE theme_customization_profiles_new RENAME TO theme_customization_profiles;
DROP TABLE shared_theme_profiles;
CREATE INDEX IF NOT EXISTS idx_theme_customization_profiles_user ON theme_customization_profiles(user_id);
CREATE INDEX IF NOT EXISTS idx_theme_customization_profiles_pending ON theme_customization_profiles(pending_from_user_id);

-- =========================================================================
-- 15) account_ip_history — PK composite (user_email, ip_address) -> (user_id, ip_address)
-- =========================================================================
CREATE TABLE account_ip_history_new (
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
INSERT INTO account_ip_history_new (user_id, ip_address, first_seen, last_seen, event_count, success_count, failure_count)
SELECT u.id, a.ip_address, a.first_seen, a.last_seen, a.event_count, a.success_count, a.failure_count
FROM account_ip_history a JOIN users u ON u.email = a.user_email;
DROP TABLE account_ip_history;
ALTER TABLE account_ip_history_new RENAME TO account_ip_history;
CREATE INDEX IF NOT EXISTS idx_account_ip_history_user ON account_ip_history(user_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_account_ip_history_ip ON account_ip_history(ip_address);

-- =========================================================================
-- 16) trusted_devices — PK composite (device_id, user_email) -> (device_id, user_id)
--     DOIT être reconstruite avant trusted_device_ips (étape 18), seule vraie dépendance d'ordre
--     au-delà de `users` dans toute cette migration.
-- =========================================================================
CREATE TABLE trusted_devices_new (
    device_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    device_name TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_ip_alert_at DATETIME NULL,
    PRIMARY KEY (device_id, user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
INSERT INTO trusted_devices_new (device_id, user_id, device_name, created_at, last_used_at, last_ip_alert_at)
SELECT d.device_id, u.id, d.device_name, d.created_at, d.last_used_at, d.last_ip_alert_at
FROM trusted_devices d JOIN users u ON u.email = d.user_email;
DROP TABLE trusted_devices;
ALTER TABLE trusted_devices_new RENAME TO trusted_devices;
CREATE INDEX IF NOT EXISTS idx_trusted_devices_user ON trusted_devices(user_id);

-- =========================================================================
-- 17) vault_password_history
-- =========================================================================
CREATE TABLE vault_password_history_new (
    id TEXT PRIMARY KEY NOT NULL,
    vault_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    encrypted_password TEXT NOT NULL,
    changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vault_id) REFERENCES vault(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
INSERT INTO vault_password_history_new (id, vault_id, user_id, encrypted_password, changed_at)
SELECT h.id, h.vault_id, u.id, h.encrypted_password, h.changed_at
FROM vault_password_history h JOIN users u ON u.email = h.user_email;
DROP TABLE vault_password_history;
ALTER TABLE vault_password_history_new RENAME TO vault_password_history;
CREATE INDEX IF NOT EXISTS idx_vault_password_history_vault_id ON vault_password_history(vault_id, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_vault_password_history_user_id ON vault_password_history(user_id);

-- =========================================================================
-- 18) vault_attachments
-- =========================================================================
CREATE TABLE vault_attachments_new (
    id TEXT PRIMARY KEY NOT NULL,
    vault_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    encrypted_filename TEXT NOT NULL,
    encrypted_content TEXT NOT NULL,
    content_size INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vault_id) REFERENCES vault(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
INSERT INTO vault_attachments_new (id, vault_id, user_id, encrypted_filename, encrypted_content, content_size, created_at)
SELECT a.id, a.vault_id, u.id, a.encrypted_filename, a.encrypted_content, a.content_size, a.created_at
FROM vault_attachments a JOIN users u ON u.email = a.user_email;
DROP TABLE vault_attachments;
ALTER TABLE vault_attachments_new RENAME TO vault_attachments;
CREATE INDEX IF NOT EXISTS idx_vault_attachments_vault_id ON vault_attachments(vault_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_vault_attachments_user_id ON vault_attachments(user_id);

-- =========================================================================
-- 19) trusted_device_ips — dépend de la NOUVELLE clé composite de trusted_devices (étape 16)
-- =========================================================================
CREATE TABLE trusted_device_ips_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    ip_address TEXT NOT NULL,
    last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id, user_id) REFERENCES trusted_devices(device_id, user_id) ON DELETE CASCADE,
    UNIQUE (device_id, user_id, ip_address)
);
INSERT INTO trusted_device_ips_new (id, device_id, user_id, ip_address, last_seen_at)
SELECT t.id, t.device_id, u.id, t.ip_address, t.last_seen_at
FROM trusted_device_ips t JOIN users u ON u.email = t.user_email;
DROP TABLE trusted_device_ips;
ALTER TABLE trusted_device_ips_new RENAME TO trusted_device_ips;
CREATE INDEX IF NOT EXISTS idx_trusted_device_ips_device ON trusted_device_ips(device_id, user_id);

-- Vérifie qu'aucune incohérence de clé étrangère n'a été introduite par les reconstructions
-- ci-dessus, avant de valider (résultat attendu : aucune ligne).
PRAGMA foreign_key_check;

COMMIT;

PRAGMA foreign_keys = ON;
