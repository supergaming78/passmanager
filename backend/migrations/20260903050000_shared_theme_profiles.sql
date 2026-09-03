PRAGMA foreign_keys = ON;

-- Partage d'un profil de personnalisation avec un AUTRE utilisateur (retour utilisateur,
-- 2026-09-03 : "au lieu de uniquement copier le code, il faudrait plutôt savoir le partager avec
-- d'autres utilisateurs" — remplace/complète le code copiable-collable, voir
-- lib/customTheme.ts::encodeThemeCode côté client, gardé pour un partage HORS de l'app).
--
-- PAS de chiffrement Zero-Knowledge (contrairement au partage d'entrées du coffre, voir
-- vault_shares) : une personnalisation de thème n'a rien à protéger, même raisonnement que
-- theme_customization_profiles. Un "partage" ici est donc une simple ligne EN CLAIR, en attente
-- d'acceptation par le destinataire — accepter la COPIE dans ses propres profils (voir
-- handlers/theme_customization.rs::accept_shared_theme_profile), jamais un lien live vers le
-- profil source (modifier le profil du partageur après coup n'affecte pas ce qui a déjà été
-- accepté, comme dupliquer un profil localement).
CREATE TABLE shared_theme_profiles (
    id TEXT PRIMARY KEY NOT NULL,
    from_email TEXT NOT NULL,
    to_email TEXT NOT NULL,
    name TEXT NOT NULL,
    background_hue INTEGER NOT NULL,
    background_lightness INTEGER NOT NULL,
    background_saturation INTEGER NOT NULL,
    accent_hue INTEGER NOT NULL,
    accent_lightness INTEGER NOT NULL,
    accent_saturation INTEGER NOT NULL,
    danger_hue INTEGER NOT NULL,
    danger_lightness INTEGER NOT NULL,
    danger_saturation INTEGER NOT NULL,
    success_hue INTEGER NOT NULL,
    success_lightness INTEGER NOT NULL,
    success_saturation INTEGER NOT NULL,
    favorite_hue INTEGER NOT NULL,
    favorite_lightness INTEGER NOT NULL,
    favorite_saturation INTEGER NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (from_email) REFERENCES users(email)
        ON UPDATE CASCADE
        ON DELETE CASCADE,
    FOREIGN KEY (to_email) REFERENCES users(email)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

-- Accélère GET /theme-profiles/shared (liste des partages EN ATTENTE reçus, voir
-- handlers/theme_customization.rs::list_shared_theme_profiles).
CREATE INDEX idx_shared_theme_profiles_to ON shared_theme_profiles(to_email);
