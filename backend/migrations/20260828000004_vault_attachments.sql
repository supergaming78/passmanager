-- Pièces jointes chiffrées par entrée (ex: codes de secours, scan de pièce d'identité) — le nom
-- du fichier ET son contenu sont CHIFFRÉS côté client comme le reste du coffre (voir
-- models.rs::VaultAttachmentInput), stockés ici en base64 TEXT (même convention que tous les
-- champs encrypted_* de `vault`). `content_size` est la SEULE métadonnée EN CLAIR : la taille en
-- octets du fichier ORIGINAL (avant chiffrement/base64), utile pour l'affichage et les quotas côté
-- serveur sans jamais avoir besoin de déchiffrer quoi que ce soit — une taille de fichier ne révèle
-- pas grand-chose en soi (contrairement au nom ou au contenu), le même arbitrage que `is_favorite`
-- ou `updated_at` ailleurs dans ce schéma.
--
-- user_email redondant avec une jointure via vault_id -> vault, gardé pour la même raison que
-- vault_password_history.user_email : permettre des requêtes de quota directes sans jointure.
CREATE TABLE IF NOT EXISTS vault_attachments (
    id TEXT PRIMARY KEY NOT NULL,
    vault_id TEXT NOT NULL,
    user_email TEXT NOT NULL,
    encrypted_filename TEXT NOT NULL,
    encrypted_content TEXT NOT NULL,
    content_size INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vault_id) REFERENCES vault(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    FOREIGN KEY (user_email) REFERENCES users(email)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_vault_attachments_vault_id ON vault_attachments(vault_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_vault_attachments_user_email ON vault_attachments(user_email);
