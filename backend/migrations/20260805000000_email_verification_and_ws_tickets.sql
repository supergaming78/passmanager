PRAGMA foreign_keys = ON;

-- =========================================================================
-- VÉRIFICATION D'EMAIL À L'INSCRIPTION
-- =========================================================================
-- Avant cette migration, register() activait un compte immédiatement sans jamais confirmer
-- que l'utilisateur possède réellement l'email fourni — quelqu'un pouvait s'inscrire avec
-- l'email de quelqu'un d'autre et bloquer (Conflict) la vraie inscription de son propriétaire.
-- email_verified = 0 par défaut : register() insère désormais un compte NON vérifié, un code
-- est envoyé par email (même mécanisme que tfa_codes, voir handlers/auth.rs::verify_email),
-- et login() refuse les comptes non vérifiés.
ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT 0;

-- Nécessaire pour purger automatiquement les inscriptions jamais vérifiées (voir
-- cleanup_expired_tokens() dans main.rs) : sans ça, quelqu'un pourrait squatter indéfiniment
-- l'email d'un autre en s'inscrivant sans jamais confirmer.
ALTER TABLE users ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- RÉTROCOMPATIBILITÉ CRITIQUE : les comptes créés AVANT ce correctif n'ont jamais eu
-- l'occasion de suivre ce nouveau flux de vérification — sans cette ligne, TOUS les
-- utilisateurs existants seraient immédiatement bloqués à la connexion (email_verified = 0
-- par défaut sur la nouvelle colonne). On les considère donc vérifiés d'office ; seules les
-- NOUVELLES inscriptions, à partir de maintenant, devront confirmer leur email.
UPDATE users SET email_verified = 1;

-- =========================================================================
-- TICKETS WEBSOCKET À USAGE UNIQUE (voir handlers/sync.rs)
-- =========================================================================
-- Avant cette migration, /ws était authentifié directement avec l'access token JWT passé en
-- clair dans l'URL (contrainte de l'API WebSocket navigateur, qui ne permet pas d'en-tête
-- Authorization à l'ouverture) — un token réutilisable sur TOUTE l'API pouvait donc fuiter
-- dans des logs d'infrastructure intermédiaires (proxy, load balancer, APM).
-- Désormais, le client doit d'abord échanger son access token contre un ticket à usage
-- unique et très courte durée de vie (60s) via POST /ws/ticket (authentifié normalement par
-- en-tête Authorization), puis ouvrir la connexion WebSocket avec CE ticket. Un ticket qui
-- fuiterait dans des logs ne serait donc utilisable ni pour le REST, ni une seconde fois.
-- Seul le hash du ticket est stocké (même logique que refresh_tokens.token) : une fuite de la
-- BDD ne permettrait pas de rejouer un ticket déjà émis.
CREATE TABLE IF NOT EXISTS ws_tickets (
    ticket_hash TEXT PRIMARY KEY NOT NULL,
    user_email TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (user_email) REFERENCES users(email)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_ws_tickets_expiry ON ws_tickets(expires_at);
