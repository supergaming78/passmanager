-- Accès d'urgence — voir src-tauri/src/emergency.rs (chiffrement) et handlers/emergency.rs
-- (flux complet : invitation, délai d'attente, approbation/refus) côté backend.

-- Paire de clés X25519 par utilisateur — la clé PRIVÉE est chiffrée côté client (avec la clé du
-- coffre), le serveur ne la voit jamais en clair, exactement comme les champs encrypted_* de
-- `vault`. La clé PUBLIQUE, elle, n'a pas besoin d'être protégée (c'est son rôle).
CREATE TABLE IF NOT EXISTS user_keys (
    user_email TEXT PRIMARY KEY NOT NULL,
    public_key TEXT NOT NULL,
    encrypted_private_key TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_email) REFERENCES users(email)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

-- Une ligne = "owner_email désigne contact_email comme contact de confiance".
-- status : 'pending' (invitation envoyée, pas encore acceptée) -> 'active' (acceptée, prête à
-- l'usage) -> 'access_requested' (le contact a demandé l'accès, en attente du délai ou d'une
-- décision du propriétaire) -> 'access_granted' (accès accordé, le contact peut consulter le
-- coffre en lecture seule).
-- sealed_vault_key : la clé du coffre du PROPRIÉTAIRE, scellée pour la clé publique du CONTACT
-- (voir emergency.rs::seal côté client) — NULL tant que le propriétaire ne l'a pas encore "semée"
-- (après acceptation par le contact, ou après un changement de mot de passe maître qui invalide
-- l'ancienne, tout comme le blob de déverrouillage rapide, voir quick_unlock.rs).
CREATE TABLE IF NOT EXISTS emergency_contacts (
    id TEXT PRIMARY KEY NOT NULL,
    owner_email TEXT NOT NULL,
    contact_email TEXT NOT NULL,
    waiting_period_days INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    sealed_vault_key TEXT,
    requested_at DATETIME,
    available_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_email) REFERENCES users(email)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    FOREIGN KEY (contact_email) REFERENCES users(email)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    UNIQUE (owner_email, contact_email)
);

CREATE INDEX IF NOT EXISTS idx_emergency_contacts_owner ON emergency_contacts(owner_email);
CREATE INDEX IF NOT EXISTS idx_emergency_contacts_contact ON emergency_contacts(contact_email);
