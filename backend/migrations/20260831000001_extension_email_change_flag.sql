-- Autorise (ou non) un compte à changer son adresse email DEPUIS L'EXTENSION NAVIGATEUR
-- spécifiquement (voir handlers/auth/account.rs::update_email + common::is_extension_origin) —
-- désactivé par défaut pour tout le monde, y compris les comptes déjà existants. Un admin reste
-- toujours autorisé indépendamment de cette colonne (voir le handler), et peut l'activer pour un
-- compte précis (PUT /admin/users/{email}/extension-email-change) ou pour tous les comptes d'un
-- coup (PUT /admin/users/extension-email-change-all) — voir handlers/admin.rs.
ALTER TABLE users ADD COLUMN can_change_email_via_extension BOOLEAN NOT NULL DEFAULT 0;
