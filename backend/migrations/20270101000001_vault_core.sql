-- =========================================================================
-- COFFRE-FORT — entrées chiffrées, historique de mots de passe, pièces jointes, partages
-- =========================================================================
-- Zero-Knowledge total : le serveur ne déchiffre jamais rien, tous les champs `encrypted_*`/
-- `sealed_*` sont des blobs opaques produits côté client.

CREATE TABLE vault (
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
-- `deleted_at` (corbeille) fait partie de la clé de tri principale : c'est la requête la plus
-- fréquente de toute l'API (GET /vault, filtrée+triée). Index partiel séparé pour la purge
-- périodique (maintenance.rs), qui ne filtre QUE sur deleted_at.
CREATE INDEX idx_vault_user_deleted ON vault(user_id, deleted_at, is_favorite, updated_at);
CREATE INDEX idx_vault_deleted_at ON vault(deleted_at) WHERE deleted_at IS NOT NULL;

-- Historique des mots de passe précédents d'une entrée (purgé au-delà de MAX_HISTORY_PER_ENTRY,
-- voir repository.rs) — permet de revenir en arrière après un changement de mot de passe maître.
CREATE TABLE vault_password_history (
    id TEXT PRIMARY KEY NOT NULL,
    vault_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    encrypted_password TEXT NOT NULL,
    changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vault_id) REFERENCES vault(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_vault_password_history_vault_id ON vault_password_history(vault_id, changed_at DESC);
CREATE INDEX idx_vault_password_history_user_id ON vault_password_history(user_id);

-- Pièces jointes chiffrées (codes de secours, scans...) — quotas MAX_ATTACHMENTS_PER_ENTRY/_USER
-- appliqués côté handler (voir handlers/vault.rs).
CREATE TABLE vault_attachments (
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
CREATE INDEX idx_vault_attachments_vault_id ON vault_attachments(vault_id, created_at DESC);
CREATE INDEX idx_vault_attachments_user_id ON vault_attachments(user_id);

-- Partage direct d'une entrée avec UN AUTRE utilisateur (contrairement à vault_blind_shares plus
-- bas : ici le destinataire est un compte connu du serveur, pas un lien anonyme à usage limité).
CREATE TABLE vault_shares (
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
CREATE INDEX idx_vault_shares_owner ON vault_shares(owner_id);
CREATE INDEX idx_vault_shares_recipient ON vault_shares(shared_with_id);

-- Partage "à usage limité" (lien à usage compté, contrairement à vault_shares) — remaining_uses
-- décrémenté par un UPDATE atomique (`WHERE remaining_uses > 0`, voir BlindShareRepository::
-- use_blind_share) : la contrainte CHECK est une seconde ligne de défense, jamais violée en usage
-- normal.
CREATE TABLE vault_blind_shares (
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
CREATE INDEX idx_vault_blind_shares_recipient ON vault_blind_shares(shared_with_id);
CREATE INDEX idx_vault_blind_shares_vault ON vault_blind_shares(vault_id);
CREATE INDEX idx_vault_blind_shares_owner ON vault_blind_shares(owner_id);
