-- Coffres partagés familiaux — plusieurs comptes voient et modifient le MÊME jeu d'entrées, mis à
-- jour EN DIRECT pour tout le monde (contrairement au partage 1-vers-1 existant, voir
-- `vault_shares`/handlers/sharing.rs, qui reste inchangé et continue d'exister EN PARALLÈLE : ce
-- nouveau système s'ajoute, ne remplace rien).
--
-- ZERO-KNOWLEDGE DE BOUT EN BOUT, même famille de primitives que le partage d'entrée et l'accès
-- d'urgence (X25519 sealed-box + HKDF-SHA256 + AES-256-GCM, voir crypto-core/src/shared_vault.rs) :
-- une clé symétrique AES-256 est générée UNE FOIS à la création du coffre partagé, puis scellée
-- INDIVIDUELLEMENT pour la clé publique X25519 de CHAQUE membre (réutilise le même trousseau par
-- utilisateur que l'accès d'urgence/le partage, table `user_keys`, avec un contexte HKDF encore
-- différent des deux autres usages). Toutes les entrées de ce coffre sont chiffrées UNE SEULE FOIS
-- avec cette clé symétrique partagée : n'importe quel membre peut la déchiffrer (il en détient sa
-- propre copie scellée), donc une modification par un membre est immédiatement visible par tous
-- les autres — pas de re-chiffrement par destinataire à chaque changement, contrairement au
-- partage d'entrée simple.
--
-- LIMITE ACCEPTÉE (documentée, comme toute construction à clé symétrique partagée de ce genre —
-- Bitwarden Organizations et 1Password Families ont la même limite) : retirer un membre révoque
-- son ACCÈS FUTUR (sa ligne dans shared_vault_members est supprimée, il ne peut plus lister ni
-- déchiffrer les entrées), mais ne protège PAS rétroactivement le contenu qu'il a déjà pu voir ou
-- exporter avant son retrait — la clé symétrique elle-même n'est pas changée. Une vraie protection
-- rétroactive demanderait de régénérer la clé ET de re-chiffrer TOUTES les entrées existantes pour
-- tous les membres restants à chaque retrait, un coût jugé disproportionné pour l'usage familial
-- visé (voir handlers/shared_vault.rs pour le détail de ce choix).

CREATE TABLE IF NOT EXISTS shared_vaults (
    id TEXT PRIMARY KEY NOT NULL,
    encrypted_name TEXT NOT NULL,  -- nom du coffre, chiffré avec SA PROPRE clé (comme les entrées)
    created_by TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(email)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

-- is_owner : uniquement le créateur à la création (voir handlers/shared_vault.rs) — seul un
-- propriétaire peut inviter/retirer des membres ou supprimer le coffre entier ; un membre simple
-- peut consulter/ajouter/modifier/supprimer des ENTRÉES, et quitter le coffre lui-même.
CREATE TABLE IF NOT EXISTS shared_vault_members (
    shared_vault_id TEXT NOT NULL,
    member_email TEXT NOT NULL,
    sealed_vault_key TEXT NOT NULL,
    is_owner BOOLEAN NOT NULL DEFAULT 0,
    added_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (shared_vault_id, member_email),
    FOREIGN KEY (shared_vault_id) REFERENCES shared_vaults(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    FOREIGN KEY (member_email) REFERENCES users(email)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

-- Structure des champs alignée sur la table `vault` (coffre personnel) pour la cohérence des
-- types d'entrée (login/carte/identité/note, voir entry_type/encrypted_extra_fields) — mais dans
-- sa PROPRE table, entièrement séparée : le coffre personnel de chacun n'est JAMAIS impacté par ce
-- nouveau système, zéro risque de régression sur son code déjà existant et testé. Volontairement
-- SANS pièces jointes, historique de mot de passe, corbeille, ni favoris pour cette première
-- version — suppression directe et définitive, périmètre volontairement réduit à l'essentiel
-- (liste d'identifiants partagés) plutôt que de dupliquer toute la richesse du coffre personnel.
CREATE TABLE IF NOT EXISTS shared_vault_entries (
    id TEXT PRIMARY KEY NOT NULL,
    shared_vault_id TEXT NOT NULL,
    encrypted_site_name TEXT NOT NULL,
    encrypted_username TEXT,
    encrypted_login_email TEXT,
    encrypted_password TEXT NOT NULL,
    encrypted_preferred_login_type TEXT NOT NULL,
    encrypted_notes TEXT DEFAULT NULL,
    encrypted_url TEXT DEFAULT NULL,
    entry_type TEXT NOT NULL DEFAULT 'login',
    encrypted_extra_fields TEXT DEFAULT NULL,
    created_by TEXT NOT NULL,       -- qui a ajouté cette entrée (affichage/audit uniquement)
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- Détection de conflit d'édition (même principe que `vault.version`, voir models.rs) — ENCORE
    -- plus pertinent ici que pour le coffre personnel : PLUSIEURS MEMBRES DIFFÉRENTS peuvent
    -- modifier la même entrée partagée à quelques instants d'écart, pas juste le même utilisateur
    -- depuis deux appareils.
    version INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY (shared_vault_id) REFERENCES shared_vaults(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_shared_vault_members_member ON shared_vault_members(member_email);
CREATE INDEX IF NOT EXISTS idx_shared_vault_entries_vault ON shared_vault_entries(shared_vault_id);
