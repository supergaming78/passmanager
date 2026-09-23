-- =========================================================================
-- PERSONNALISATION & RETOURS — profils de thème (+ partages en attente), suggestions
-- =========================================================================

-- Un partage de profil de thème EN ATTENTE est une ligne ORDINAIRE de cette table, déjà possédée
-- par le DESTINATAIRE (`user_id`), avec `pending_from_user_id` renseigné tant qu'il n'est pas
-- encore accepté (NULL = profil normal). Accepter un partage efface simplement cette colonne sur
-- la ligne déjà là — pas de table séparée pour les partages en attente. Le CHECK interdit qu'une
-- ligne soit à la fois active et encore en attente (garanti par construction côté code, voir
-- repository.rs::ThemeShareRepository, rendu impossible à violer ici aussi).
CREATE TABLE theme_customization_profiles (
    id TEXT PRIMARY KEY NOT NULL,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    background_hue INTEGER NOT NULL DEFAULT 0,
    background_lightness INTEGER NOT NULL DEFAULT 12,
    accent_hue INTEGER NOT NULL DEFAULT 277,
    accent_lightness INTEGER NOT NULL DEFAULT 59,
    danger_hue INTEGER NOT NULL DEFAULT 27,
    danger_lightness INTEGER NOT NULL DEFAULT 64,
    success_hue INTEGER NOT NULL DEFAULT 163,
    success_lightness INTEGER NOT NULL DEFAULT 70,
    favorite_hue INTEGER NOT NULL DEFAULT 75,
    favorite_lightness INTEGER NOT NULL DEFAULT 77,
    is_active INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    background_saturation INTEGER NOT NULL DEFAULT 0,
    accent_saturation INTEGER NOT NULL DEFAULT 100,
    danger_saturation INTEGER NOT NULL DEFAULT 100,
    success_saturation INTEGER NOT NULL DEFAULT 100,
    favorite_saturation INTEGER NOT NULL DEFAULT 100,
    pending_from_user_id INTEGER NULL REFERENCES users(id) ON DELETE CASCADE,
    CHECK (NOT (is_active = 1 AND pending_from_user_id IS NOT NULL)),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_theme_customization_profiles_user ON theme_customization_profiles(user_id);
CREATE INDEX idx_theme_customization_profiles_pending ON theme_customization_profiles(pending_from_user_id);

-- Suggestions de fonctionnalité — plafonnées PAR AUTEUR (en attente) ET globalement (voir
-- repository.rs::FeatureSuggestionRepository), réservées au listage par l'Admin.
CREATE TABLE feature_suggestions (
    id TEXT PRIMARY KEY NOT NULL,
    author_id INTEGER NOT NULL,
    description TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX idx_feature_suggestions_created_at ON feature_suggestions(created_at DESC);
CREATE INDEX idx_feature_suggestions_author ON feature_suggestions(author_id);
