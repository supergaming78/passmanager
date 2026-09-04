-- DEUX CONTROLES D'ADMINISTRATION ajoutes apres la 1.0.0.
--
-- 1. registration_open (GLOBAL) — l'inscription etait OUVERTE a quiconque atteignait le serveur.
--    Sur un deploiement familial expose sur Internet, cela permettait a un inconnu trouvant l'URL
--    de creer un compte, donc de consommer l'espace disque (voir MAX_VAULT_ENTRIES_PER_USER et le
--    plafond de pieces jointes, tous deux PAR COMPTE), de declencher des envois depuis le SMTP du
--    proprietaire — brulant son quota et la reputation de son domaine — et de remplir le journal
--    d'audit. Rejoint app_settings, ou vit deja le seul autre reglage reellement global.
--    Valeur initiale : 1 (ouvert), pour ne RIEN casser a la migration — un serveur qui se
--    fermerait tout seul apres une mise a jour serait une mauvaise surprise. A refermer depuis le
--    panneau Administration une fois les comptes crees.
--
-- 2. is_suspended (PAR COMPTE) — jusqu'ici, la seule sanction disponible etait la suppression
--    definitive du compte, qui cascade sur tout le coffre et ne se rattrape pas. La suspension
--    refuse la connexion et invalide les sessions en cours, mais CONSERVE les donnees : une marche
--    intermediaire, reversible, pour un doute ou un appareil perdu.

ALTER TABLE users ADD COLUMN is_suspended BOOLEAN NOT NULL DEFAULT 0;

ALTER TABLE app_settings ADD COLUMN registration_open BOOLEAN NOT NULL DEFAULT 1;
