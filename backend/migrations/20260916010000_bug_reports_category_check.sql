-- =========================================================================
-- bug_reports.category — jamais validée par la base (choisie côté client uniquement, voir
-- components/BugReportModal.tsx). Séparée de la migration précédente : `bug_reports` n'a aucune
-- colonne référençant `users` (reporter_email est une simple info de contact facultative, sans FK,
-- voir 20260901000000_bug_reports.sql) et n'est référencée par aucune autre table — reconstruction
-- ordinaire, sans le dispositif `-- no-transaction` réservé aux tables imbriquées dans le CASCADE
-- de `users`/`vault`.
-- =========================================================================
CREATE TABLE bug_reports_new (
    id TEXT PRIMARY KEY NOT NULL,
    reporter_email TEXT,
    description TEXT NOT NULL,
    app_version TEXT NOT NULL,
    platform TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    category TEXT NOT NULL DEFAULT 'Autre'
        CHECK (category IN ('Affichage', 'Synchronisation', 'Plantage', 'Autre'))
);
INSERT INTO bug_reports_new (id, reporter_email, description, app_version, platform, created_at, category)
SELECT
    id, reporter_email, description, app_version, platform, created_at,
    CASE WHEN category IN ('Affichage', 'Synchronisation', 'Plantage', 'Autre') THEN category ELSE 'Autre' END
FROM bug_reports;
DROP TABLE bug_reports;
ALTER TABLE bug_reports_new RENAME TO bug_reports;
CREATE INDEX IF NOT EXISTS idx_bug_reports_created_at ON bug_reports(created_at DESC);
