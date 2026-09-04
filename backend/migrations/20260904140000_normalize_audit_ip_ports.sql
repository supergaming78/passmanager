-- REPARATION DES ADRESSES CONTENANT UN PORT SOURCE.
--
-- Les appelants du journal d'audit passaient `addr.to_string()` sur un SocketAddr, qui inclut le
-- PORT ("127.0.0.1:53144"). Ce port est ephemere : different a chaque connexion. Consequences
-- observees sur une vraie base avant correction — 102 "adresses distinctes" pour UNE seule
-- machine :
--   * le journal affichait des adresses bruitees ;
--   * l'historique par compte voyait une adresse NEUVE a chaque connexion, donc ne regroupait
--     rien et ne pouvait signaler aucun motif d'echecs-puis-reussite ;
--   * la geolocalisation echouait toujours, "127.0.0.1:53144" n'etant pas une adresse analysable.
--
-- La source est corrigee dans state.rs (normalize_ip, applique au point de passage commun des
-- 57 sites d'appel). Cette migration repare ce qui a deja ete ecrit.
--
-- Le decoupage ne peut pas simplement couper au premier ':' : une IPv6 nue en contient plusieurs
-- et serait detruite. Trois cas distingues :
--   1. la chaine contient ']'  -> forme "[ipv6]:port", on extrait entre crochets ;
--   2. elle contient EXACTEMENT un ':' -> forme "ipv4:port", on coupe avant ;
--   3. sinon -> deja nue (IPv4 seule, ou IPv6 seule qui a plusieurs ':'), on n'y touche pas.

-- 1) Le journal lui-meme.
UPDATE audit_logs
SET ip_address = CASE
    WHEN instr(ip_address, ']') > 0
        THEN substr(ip_address, 2, instr(ip_address, ']') - 2)
    WHEN length(ip_address) - length(replace(ip_address, ':', '')) = 1
        THEN substr(ip_address, 1, instr(ip_address, ':') - 1)
    ELSE ip_address
END
WHERE instr(ip_address, ':') > 0;

-- 2) L'historique par compte. Un simple UPDATE creerait des doublons sur la cle primaire
-- (user_email, ip_address) des que deux ports differents de la meme adresse s'y trouvent — ce qui
-- est precisement le cas ici. On reconstruit donc la table en fusionnant : les compteurs
-- s'additionnent, la premiere apparition est la plus ancienne, la derniere la plus recente.
CREATE TABLE account_ip_history_normalized (
    user_email TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_count INTEGER NOT NULL DEFAULT 0,
    success_count INTEGER NOT NULL DEFAULT 0,
    failure_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_email, ip_address),
    FOREIGN KEY (user_email) REFERENCES users(email)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

INSERT INTO account_ip_history_normalized
    (user_email, ip_address, first_seen, last_seen, event_count, success_count, failure_count)
SELECT
    user_email,
    CASE
        WHEN instr(ip_address, ']') > 0
            THEN substr(ip_address, 2, instr(ip_address, ']') - 2)
        WHEN length(ip_address) - length(replace(ip_address, ':', '')) = 1
            THEN substr(ip_address, 1, instr(ip_address, ':') - 1)
        ELSE ip_address
    END AS ip_nue,
    MIN(first_seen),
    MAX(last_seen),
    SUM(event_count),
    SUM(success_count),
    SUM(failure_count)
FROM account_ip_history
GROUP BY user_email, ip_nue;

DROP TABLE account_ip_history;
ALTER TABLE account_ip_history_normalized RENAME TO account_ip_history;

-- Les index suivaient l'ancienne table : a recreer sur la nouvelle.
CREATE INDEX IF NOT EXISTS idx_account_ip_history_user
    ON account_ip_history(user_email, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_account_ip_history_ip
    ON account_ip_history(ip_address);
