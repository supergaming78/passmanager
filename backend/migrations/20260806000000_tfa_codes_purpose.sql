PRAGMA foreign_keys = ON;

-- BUG CORRIGE : `tfa_codes` avait `email` comme UNIQUE clef primaire, alors que la meme table
-- sert a TROIS flux differents (code 2FA de connexion, code de verification d'email a
-- l'inscription, code de reinitialisation de mot de passe). Consequence concrete : chaque
-- INSERT OR REPLACE ecrasait silencieusement le code d'un AUTRE flux en cours pour le meme
-- email, et n'importe quel endpoint de verification acceptait le code present en base peu
-- importe quel flux l'avait genere (un code de reset pouvait valider une verification d'email,
-- et inversement). Pas une faille exploitable par un tiers (il faut deja avoir acces a la boite
-- mail pour connaitre un code, quel que soit le flux), mais un vrai bug de robustesse entre deux
-- flux legitimes concurrents pour le meme utilisateur.
--
-- Correctif : cle composite (email, purpose) - chaque flux a desormais sa propre ligne,
-- independante des deux autres. SQLite ne permet pas de modifier une PRIMARY KEY existante via
-- ALTER TABLE : on recree la table (pattern standard pour ce type de migration SQLite).
--
-- Pas de tentative de recuperer un `purpose` historique pour les lignes existantes : ce sont des
-- codes ephemeres (5 a 30 minutes de duree de vie), quasi certainement deja expires au moment de
-- cette migration. On leur assigne 'login_2fa' par defaut, sans consequence reelle.
CREATE TABLE tfa_codes_new (
    email TEXT NOT NULL,
    purpose TEXT NOT NULL,
    code TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (email, purpose),
    FOREIGN KEY (email) REFERENCES users(email)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

INSERT INTO tfa_codes_new (email, purpose, code, expires_at, attempts)
SELECT email, 'login_2fa', code, expires_at, attempts FROM tfa_codes;

DROP TABLE tfa_codes;
ALTER TABLE tfa_codes_new RENAME TO tfa_codes;
