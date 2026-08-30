-- Historique des IP RÉCEMMENT vues par appareil de confiance — permet de distinguer une connexion
-- normale (IP déjà connue pour CET appareil, même si elle a changé depuis la dernière fois — mobile,
-- FAI dynamique) d'une IP GENUINEMENT jamais vue pour cet appareil précis (signe possible d'un
-- device_id/refresh token volé et utilisé ailleurs). Volontairement une PETITE fenêtre glissante
-- (5 IP les plus récentes, comme MAX_HISTORY_PER_ENTRY pour l'historique de mots de passe) plutôt
-- qu'une liste illimitée : l'objectif est de limiter le bruit, pas de construire un profil complet.
--
-- LIMITE CONNUE : l'IP est capturée via ConnectInfo<SocketAddr> uniquement (voir session.rs), sans
-- lecture de X-Forwarded-For/X-Real-IP. Un utilisateur qui place lui-même un reverse-proxy devant
-- son instance auto-hébergée verrait systématiquement l'IP du proxy — l'alerte deviendrait alors
-- inutile (toujours la même IP) plutôt que dangereuse, ce n'est donc pas un problème de sécurité en
-- soi, juste une fonctionnalité qui perd de son intérêt dans ce cas de déploiement précis.
CREATE TABLE IF NOT EXISTS trusted_device_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    user_email TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id, user_email) REFERENCES trusted_devices(device_id, user_email) ON UPDATE CASCADE ON DELETE CASCADE,
    UNIQUE (device_id, user_email, ip_address)
);
CREATE INDEX IF NOT EXISTS idx_trusted_device_ips_device ON trusted_device_ips(device_id, user_email);
