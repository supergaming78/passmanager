-- CORRECTIF SÉCURITÉ/FORENSIQUE : audit_logs avait `ON DELETE CASCADE` vers users(email) — supprimer
-- un compte (voir DELETE /admin/users/{email}, handlers/admin.rs, "voulu" pour un compte compromis
-- ou malveillant) effaçait donc AUSSI tout son historique d'audit (connexions, changements de mot
-- de passe, partages...), au moment précis où ce journal est le plus utile (enquête post-incident,
-- litige). Un journal d'audit sert à retracer CE QUI S'EST PASSÉ — sa valeur ne devrait jamais
-- dépendre du cycle de vie du compte qu'il documente.
--
-- SQLite ne permet pas de modifier une contrainte FOREIGN KEY existante via ALTER TABLE : on
-- recrée la table (schéma identique, sans la FK) selon le motif standard SQLite, en conservant
-- toutes les lignes existantes.
--
-- Effet de bord ACCEPTÉ : un changement d'email (PUT /auth/email) ne "réétiquette" plus
-- rétroactivement les anciennes lignes d'audit sous le nouvel email (elles gardaient auparavant
-- l'ancien via ON UPDATE CASCADE) — chaque ligne garde l'email TEL QU'IL ÉTAIT au moment de
-- l'action, ce qui est d'ailleurs plus fidèle à ce qu'un journal d'audit doit représenter.

PRAGMA foreign_keys = OFF;

CREATE TABLE audit_logs_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT NOT NULL,
    action TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO audit_logs_new (id, user_email, action, ip_address, user_agent, created_at)
    SELECT id, user_email, action, ip_address, user_agent, created_at FROM audit_logs;

DROP TABLE audit_logs;
ALTER TABLE audit_logs_new RENAME TO audit_logs;

-- Les deux index existants sur audit_logs portaient sur la table d'origine (supprimée avec elle) —
-- recréés ici à l'identique (idx_audit_user_date, idx_audit_created_at, voir schéma initial).
CREATE INDEX IF NOT EXISTS idx_audit_user_date ON audit_logs(user_email, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at);

PRAGMA foreign_keys = ON;
