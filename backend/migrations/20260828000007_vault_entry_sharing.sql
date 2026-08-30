-- PARTAGE SÉCURISÉ D'UNE ENTRÉE — voir handlers/sharing.rs et src-tauri/src/sharing.rs pour la
-- crypto (X25519 sealed-box, même primitive que l'accès d'urgence mais avec un contexte HKDF
-- différent, voir INFO_SHARE_SEAL). Contrairement à emergency_contacts, PAS de colonne `status` :
-- ce partage est INSTANTANÉ (pas de délai d'attente), donc la présence de la ligne = accès actif ;
-- la révocation supprime simplement la ligne. `sealed_entry` contient le JSON scellé des champs en
-- clair de l'entrée (site/identifiants/mot de passe/notes/url) — le serveur ne le lit ni ne le
-- déchiffre jamais, Zero-Knowledge oblige, exactement comme `sealed_vault_key` dans
-- emergency_contacts.
CREATE TABLE IF NOT EXISTS vault_shares (
    id TEXT PRIMARY KEY NOT NULL,
    vault_id TEXT NOT NULL,
    owner_email TEXT NOT NULL,
    shared_with_email TEXT NOT NULL,
    sealed_entry TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    -- ON DELETE CASCADE sur vault_id : quand l'entrée source est purgée définitivement (voir
    -- VaultRepository::purge), tout partage actif de cette entrée disparaît automatiquement — un
    -- destinataire ne doit jamais pouvoir continuer à consulter le blob scellé d'une entrée qui
    -- n'existe plus côté propriétaire.
    FOREIGN KEY (vault_id) REFERENCES vault(id) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (owner_email) REFERENCES users(email) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (shared_with_email) REFERENCES users(email) ON UPDATE CASCADE ON DELETE CASCADE,
    -- Un seul partage actif par couple (entrée, destinataire) — repartager la même entrée avec la
    -- même personne doit mettre à jour la ligne existante, jamais en créer une seconde.
    UNIQUE (vault_id, shared_with_email)
);
CREATE INDEX IF NOT EXISTS idx_vault_shares_owner ON vault_shares(owner_email);
CREATE INDEX IF NOT EXISTS idx_vault_shares_recipient ON vault_shares(shared_with_email);
