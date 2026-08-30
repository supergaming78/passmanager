PRAGMA foreign_keys = ON;

-- Plafond du nombre d'appareils de confiance simultanés, CONFIGURABLE par l'utilisateur (à
-- l'inscription via AuthPayload.max_trusted_devices, puis modifiable via PUT /devices/limit,
-- voir handlers/auth.rs::verify_2fa_and_register_device() et handlers/devices.rs). Défaut 10,
-- même logique de protection anti-accumulation que MAX_VAULT_ENTRIES_PER_USER — ce n'est PAS une
-- vraie barrière de sécurité en soi, puisque chaque ajout d'appareil nécessite de toute façon un
-- code 2FA envoyé par email ; c'est surtout une protection contre l'accumulation silencieuse
-- d'appareils "de confiance" oubliés (donc de contournements de 2FA permanents) au fil du temps.
ALTER TABLE users ADD COLUMN max_trusted_devices INTEGER NOT NULL DEFAULT 10;

-- Horodatage d'une déconnexion globale volontaire, "déconnecter tous mes appareils" (voir
-- handlers/devices.rs::logout_all_devices()). Distincte de `password_changed_at` (ajoutée par la
-- migration précédente) : un changement de mot de passe ET une déconnexion globale volontaire
-- doivent TOUS LES DEUX invalider immédiatement les access tokens déjà émis, pas seulement les
-- refresh tokens — middleware.rs::AuthUser compare donc désormais contre le PLUS RÉCENT des deux
-- (MAX(password_changed_at, sessions_revoked_at)). Même sentinelle epoch que password_changed_at,
-- pour la même raison : ne rien invalider rétroactivement au moment de cette migration.
ALTER TABLE users ADD COLUMN sessions_revoked_at DATETIME NOT NULL DEFAULT '1970-01-01 00:00:00';
