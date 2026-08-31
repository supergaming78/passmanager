-- Signalements de bug envoyés depuis l'app desktop/Android — voir handlers/bug_report.rs.
--
-- DÉLIBÉRÉMENT EN CLAIR, pas chiffré : contrairement au coffre, un signalement de bug est un texte
-- TECHNIQUE écrit par l'utilisateur (description du problème rencontré), destiné à être lu par toi
-- (le modérateur/Admin) — il n'y a rien ici à protéger en Zero-Knowledge, exactement comme les
-- emails de compte ou les entrées d'audit_logs, déjà en clair pour la même raison.
--
-- reporter_email NULLABLE : le bouton "Signaler un bug" est accessible AVANT même la connexion
-- (voir la conversation qui a motivé cette fonctionnalité — un bug qui empêche justement de se
-- connecter doit pouvoir être signalé), donc aucun compte n'est garanti exister à ce moment-là.
-- Si l'app est connectée, son email est pré-rempli automatiquement mais reste éditable — jamais
-- vérifié/validé contre un vrai compte, c'est une simple information de contact facultative.
CREATE TABLE bug_reports (
    id TEXT PRIMARY KEY NOT NULL,
    reporter_email TEXT,
    description TEXT NOT NULL,
    app_version TEXT NOT NULL,
    platform TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Le panneau Administration liste par défaut les plus récents en premier.
CREATE INDEX idx_bug_reports_created_at ON bug_reports (created_at DESC);
