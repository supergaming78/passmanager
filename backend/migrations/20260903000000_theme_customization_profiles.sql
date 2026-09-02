PRAGMA foreign_keys = ON;

-- Personnalisation de thème SYNCHRONISÉE PAR COMPTE (retour utilisateur, 2026-09-03) —
-- contrairement à TOUS les autres réglages d'apparence (thème preset choisi dans
-- frontend(app)/src/lib/theme.ts, dispositions de menu/listes...), volontairement LOCAUX à chaque
-- appareil jusqu'ici (localStorage, jamais envoyés au serveur), celle-ci suit explicitement le
-- compte sur tous les appareils, à la demande explicite de l'utilisateur ("en profil"). PAS
-- chiffré Zero-Knowledge : une préférence d'affichage n'a rien à protéger, même raisonnement que
-- les autres colonnes de préférence déjà en clair sur `users` (can_choose_server_in_settings,
-- max_trusted_devices...).
--
-- PLUSIEURS profils nommés par compte (retour utilisateur, 2026-09-03, affiné le même jour :
-- "limiter le nombre de profil à part pour l'administrateur") — pas une seule ligne comme dans une
-- première version de cette fonctionnalité (jamais déployée, table recréée directement plutôt que
-- migrée : voir models.rs pour le détail du nouveau modèle). Le plafond par rôle (3 profils pour un
-- compte normal, illimité pour l'Admin) est appliqué CÔTÉ APPLICATION (voir
-- handlers/theme_customization.rs, repository.rs::ThemeProfileRepository::create) — pas en
-- contrainte SQL, puisqu'il dépend de qui appelle (AuthUser::is_admin), pas seulement des lignes
-- déjà présentes.
--
-- Teintes stockées en DEGRÉS OKLCH (0-359) et luminosités en POURCENTAGE (0-100, voir models.rs
-- pour la validation) — chaque couleur (fond/accent/danger/succès/favoris) a désormais SA PROPRE
-- teinte ET SA PROPRE luminosité, indépendantes des autres (plus de mode clair/sombre global : le
-- mode se déduit de la luminosité du fond choisi, voir lib/customTheme.ts côté client). Le calcul
-- de la palette complète (chroma sûr par palier Tailwind, déjà éprouvé pour chaque famille de
-- couleur) reste entièrement côté CLIENT, le serveur ne fait que stocker/valider des entiers,
-- jamais de logique de rendu.
CREATE TABLE theme_customization_profiles (
    id TEXT PRIMARY KEY NOT NULL,
    user_email TEXT NOT NULL,
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
    -- 0/1 (SQLite n'a pas de type booléen natif) — au plus UN profil actif à la fois par compte,
    -- appliqué côté application (voir ThemeProfileRepository::activate, transaction qui désactive
    -- tous les autres profils du compte avant d'activer celui-ci), pas une contrainte SQL.
    is_active INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_email) REFERENCES users(email)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);

-- Accélère GET /theme-profiles (liste par compte, voir ThemeProfileRepository::list) et le
-- décompte utilisé pour appliquer le plafond (ThemeProfileRepository::create).
CREATE INDEX idx_theme_customization_profiles_user ON theme_customization_profiles(user_email);
