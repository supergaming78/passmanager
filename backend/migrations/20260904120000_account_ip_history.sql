-- HISTORIQUE DES IP PAR COMPTE, conserve au-dela de la purge du journal d'audit.
--
-- Pourquoi une table plutot que d'agreger audit_logs : le journal est purge a 10 jours
-- (AUDIT_LOG_RETENTION_DAYS), ce qui convient a des EVENEMENTS mais efface justement ce qu'on
-- veut garder ici — "cette adresse a deja ete vue sur ce compte, et depuis quand". Sans memoire
-- longue, une adresse revenant tous les quinze jours paraitrait NEUVE a chaque fois, exactement
-- le cas qu'on cherche a reperer.
--
-- Le cout reste minuscule parce qu'on stocke UNE ligne par (compte, adresse), pas une par
-- evenement : quelques dizaines de lignes pour un serveur familial, la ou audit_logs en accumule
-- des milliers. C'est ce qui rend la conservation longue acceptable ici alors qu'elle ne l'etait
-- pas pour le journal.
--
-- success_count / failure_count sont le vrai signal recherche : une adresse avec beaucoup d'echecs
-- PUIS une reussite est la signature d'une intrusion reussie par tatonnement. Une adresse avec
-- seulement des reussites est un usage normal. Une IP nue, sans ce decompte, ne distingue pas les
-- deux.
--
-- ON DELETE CASCADE (contrairement a audit_logs, volontairement conserve apres suppression d'un
-- compte) : cet historique n'a de sens que rattache a un compte vivant, et le garder apres coup
-- serait de la retention de donnees personnelles sans usage.

CREATE TABLE IF NOT EXISTS account_ip_history (
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

-- Sert le listage par compte (tri par derniere activite) sans balayer la table.
CREATE INDEX IF NOT EXISTS idx_account_ip_history_user
    ON account_ip_history(user_email, last_seen DESC);

-- Sert la question inverse : "quels AUTRES comptes ont utilise cette adresse ?", qui repond a
-- "quelqu'un s'est-il connecte au compte de quelqu'un d'autre".
CREATE INDEX IF NOT EXISTS idx_account_ip_history_ip
    ON account_ip_history(ip_address);

-- Amorcage depuis le journal encore present : sans cela l'ecran serait vide au demarrage et
-- donnerait a croire qu'aucune connexion n'a jamais eu lieu. Ne recupere que la fenetre non
-- purgee, c'est tout ce qui existe encore.
INSERT OR IGNORE INTO account_ip_history
    (user_email, ip_address, first_seen, last_seen, event_count, success_count, failure_count)
SELECT
    user_email,
    ip_address,
    MIN(created_at),
    MAX(created_at),
    COUNT(*),
    SUM(CASE WHEN action IN ('LOGIN', 'LOGIN_SUCCESS', 'LOGIN_SUCCESS_REMEMBER', 'LOGIN_SUCCESS_SESSION') THEN 1 ELSE 0 END),
    SUM(CASE WHEN action IN ('LOGIN_FAILED', 'LOGIN_BLOCKED_TOO_MANY_ATTEMPTS', 'LOGIN_BLOCKED_UNVERIFIED', 'LOGIN_BLOCKED_SUSPENDED') THEN 1 ELSE 0 END)
FROM audit_logs
WHERE user_email IN (SELECT email FROM users)
GROUP BY user_email, ip_address;
