-- =========================================================================
-- PARTAGE ÉTENDU — coffres partagés familiaux, accès d'urgence
-- =========================================================================

-- Coffre partagé par plusieurs comptes (contrairement à vault_shares : ici une ENTRÉE n'appartient
-- à personne en particulier, elle appartient au coffre partagé lui-même).
CREATE TABLE shared_vaults (
    id TEXT PRIMARY KEY NOT NULL,
    encrypted_name TEXT NOT NULL,
    created_by_id INTEGER NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_shared_vaults_created_by ON shared_vaults(created_by_id);

-- Appartenance à un coffre partagé — la ligne du créateur (is_owner=1) est insérée dans la MÊME
-- transaction que la création du coffre (voir SharedVaultRepository::create) : un coffre partagé
-- sans aucun membre ne doit jamais pouvoir exister, même momentanément.
CREATE TABLE shared_vault_members (
    shared_vault_id TEXT NOT NULL,
    member_id INTEGER NOT NULL,
    sealed_vault_key TEXT NOT NULL,
    is_owner BOOLEAN NOT NULL DEFAULT 0,
    added_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (shared_vault_id, member_id),
    FOREIGN KEY (shared_vault_id) REFERENCES shared_vaults(id) ON DELETE CASCADE,
    FOREIGN KEY (member_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_shared_vault_members_member ON shared_vault_members(member_id);

-- Entrées d'un coffre partagé — éditables par N'IMPORTE QUEL membre, pas seulement le créateur
-- (voir SharedVaultRepository::update_entry). Index couvrant (shared_vault_id, updated_at) :
-- contrairement aux autres tables de ce fichier, AUCUN plafond n'existe sur le nombre d'entrées
-- d'un coffre partagé (voir add_entry) — la seule table de tout ce domaine où éviter le tri
-- temporaire de la liste apporte un vrai bénéfice.
CREATE TABLE shared_vault_entries (
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
CREATE INDEX idx_shared_vault_entries_vault ON shared_vault_entries(shared_vault_id, updated_at DESC);

-- Accès d'urgence : machine à états (pending -> active -> access_requested -> access_granted,
-- voir repository.rs::EmergencyRepository) imposée par CHECK, pas seulement documentée en
-- commentaire.
CREATE TABLE emergency_contacts (
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
CREATE INDEX idx_emergency_contacts_owner ON emergency_contacts(owner_id);
CREATE INDEX idx_emergency_contacts_contact ON emergency_contacts(contact_id);
