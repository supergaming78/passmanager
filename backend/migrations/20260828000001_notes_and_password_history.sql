-- Champ "Notes" optionnel par entrée du coffre — CHIFFRÉ comme le reste du contenu (voir
-- models.rs::VaultEntryInput), au même titre que encrypted_folder.
ALTER TABLE vault ADD COLUMN encrypted_notes TEXT DEFAULT NULL;

-- Historique des mots de passe : à chaque changement RÉEL de mot de passe (voir
-- VaultEntryInput::password_changed), l'ANCIENNE valeur chiffrée est archivée ici avant d'être
-- écrasée — permet à l'utilisateur de retrouver un ancien mot de passe après coup. user_email est
-- redondant avec une jointure via vault_id -> vault, mais évité volontairement : la ré-écriture de
-- TOUT l'historique d'un utilisateur (à chaque changement de mot de passe MAÎTRE, voir
-- ChangeMasterPasswordPayload) doit pouvoir se faire par une requête directe sur user_email, sans
-- jointure.
CREATE TABLE IF NOT EXISTS vault_password_history (
    id TEXT PRIMARY KEY NOT NULL,
    vault_id TEXT NOT NULL,
    user_email TEXT NOT NULL,
    encrypted_password TEXT NOT NULL,
    changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vault_id) REFERENCES vault(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    FOREIGN KEY (user_email) REFERENCES users(email)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_vault_password_history_vault_id ON vault_password_history(vault_id, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_vault_password_history_user_email ON vault_password_history(user_email);
