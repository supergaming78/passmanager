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
-- Une ligne par compte au maximum (clé primaire = user_email, jamais plusieurs personnalisations
-- actives). N'existe QUE si l'utilisateur a explicitement configuré une personnalisation (voir
-- handlers/theme_customization.rs) — son absence (404) signifie simplement "thème preset actif,
-- pas de personnalisation", pas une erreur.
--
-- Teintes stockées en DEGRÉS OKLCH (0-360, voir models.rs pour la validation) — le calcul de la
-- palette complète (luminosité/chroma sûrs, déjà éprouvés pour chaque famille de couleur Tailwind)
-- reste entièrement côté CLIENT (voir lib/customTheme.ts), le serveur ne fait que stocker/valider
-- des entiers, jamais de logique de rendu.
CREATE TABLE user_theme_customization (
    user_email TEXT PRIMARY KEY NOT NULL,
    -- "dark"/"light" — base sur laquelle s'applique l'accent personnalisé (voir le commentaire de
    -- lib/customTheme.ts pour pourquoi seul l'accent est sûr à personnaliser en mode clair, pas le
    -- fond).
    mode TEXT NOT NULL DEFAULT 'dark',
    accent_hue INTEGER NOT NULL DEFAULT 277,
    -- 0/1 (SQLite n'a pas de type booléen natif) — si vrai ET mode='dark', le fond (cartes/page/
    -- bordures) reçoit une légère teinte de la même couleur que l'accent (voir le correctif du
    -- 2026-09-03 sur les thèmes preset, même principe ici).
    background_tinted INTEGER NOT NULL DEFAULT 0,
    danger_hue INTEGER NOT NULL DEFAULT 27,
    success_hue INTEGER NOT NULL DEFAULT 163,
    favorite_hue INTEGER NOT NULL DEFAULT 75,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_email) REFERENCES users(email)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);
