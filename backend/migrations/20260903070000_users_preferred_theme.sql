PRAGMA foreign_keys = ON;

-- Retour utilisateur, 2026-09-03 : "je veux que lorsqu'on choisit un thème ce soit pour partout
-- (aussi l'extension) que le thème soit appliqué partout" — jusqu'ici, SEUL le profil de
-- personnalisation ("Personnalisé…", voir theme_customization_profiles) était synchronisé par
-- compte ; le CHOIX du thème lui-même (Sombre/Clair/Minuit/Océan/.../Personnalisé) restait
-- volontairement local à chaque appareil (localStorage, voir lib/theme.ts côté app ET extension).
-- Cette colonne étend la synchronisation par compte à CE choix aussi — même raisonnement que
-- max_trusted_devices/can_change_email_via_extension/can_choose_server_in_settings déjà sur cette
-- table : une préférence d'affichage propre au compte, en clair (rien à protéger en Zero-Knowledge,
-- même argument que theme_customization_profiles), lue/écrite par le compte lui-même sans aucune
-- vérification de rôle.
--
-- Valeur par défaut 'dark' : identique au défaut déjà utilisé côté client (voir
-- lib/theme.ts::getTheme(), "nouveau défaut" du 2026-09-02) — un compte existant qui n'a jamais
-- touché ce réglage se retrouve avec la MÊME valeur qu'avant cette migration (comportement
-- inchangé), pas de bascule surprise vers autre chose.
ALTER TABLE users ADD COLUMN preferred_theme TEXT NOT NULL DEFAULT 'dark';
