-- CORRECTIF PERFORMANCE : trusted_devices a pour clé primaire (device_id, user_email) — device_id
-- EN TÊTE — mais GET /devices (handlers/devices.rs::list_devices) filtre uniquement sur
-- user_email, la colonne EN QUEUE de cette clé composée. SQLite ne peut utiliser l'index de la clé
-- primaire pour une requête qui ne fournit pas son PREMIER segment : chaque appel de cette route
-- fait donc un balayage complet de la table (full table scan), qui s'aggrave à mesure que le
-- nombre total d'appareils de confiance (tous utilisateurs confondus) grandit — contrairement à
-- `vault`/`audit_logs`/`refresh_tokens`, qui ont chacun déjà un index dédié `(user_email, ...)`.
CREATE INDEX IF NOT EXISTS idx_trusted_devices_user ON trusted_devices(user_email);
