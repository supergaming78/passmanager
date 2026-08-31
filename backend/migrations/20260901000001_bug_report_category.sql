-- Catégorie de bug (Affichage/Synchronisation/Plantage/Autre), choisie côté client avant l'envoi
-- (voir components/BugReportModal.tsx) — permet de trier dans Administration sans devoir ouvrir
-- chaque signalement. DEFAULT 'Autre' : cohérent avec la valeur par défaut côté client (voir
-- models.rs::CreateBugReportPayload), et sûr pour d'éventuelles lignes déjà en base avant cette
-- migration (aucune en pratique tant que ce projet n'a pas de vrai déploiement, mais la bonne
-- habitude à prendre).
ALTER TABLE bug_reports ADD COLUMN category TEXT NOT NULL DEFAULT 'Autre';
