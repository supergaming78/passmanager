-- TROIS CONTROLES D'ADMINISTRATION ajoutes apres la 1.0.0.
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
-- 2. beta_features_enabled (GLOBAL) + has_beta_access (PAR COMPTE) — acces aux fonctionnalites en
--    cours de rodage. Deux niveaux volontairement : le drapeau par compte designe QUI est
--    volontaire, l'interrupteur global permet de tout couper d'un coup si une fonctionnalite
--    derape, sans repasser sur chaque compte. Meme construction que
--    can_choose_server_in_settings (par compte) + server_choice_at_login_enabled (global).
--
--    ATTENTION, pour quiconque ajoutera une fonctionnalite derriere ce drapeau : il ouvre un
--    ACCES, il ne doit JAMAIS assouplir un garde-fou. Et toute route serveur concernee doit
--    verifier le drapeau ELLE AUSSI — GET /me ne fait qu'informer le client, s'y fier seul
--    laisserait contourner la restriction en appelant la route directement.
--
-- 3. is_suspended (PAR COMPTE) — jusqu'ici, la seule sanction disponible etait la suppression
--    definitive du compte, qui cascade sur tout le coffre et ne se rattrape pas. La suspension
--    refuse la connexion et invalide les sessions en cours, mais CONSERVE les donnees : une marche
--    intermediaire, reversible, pour un doute ou un appareil perdu.

ALTER TABLE users ADD COLUMN has_beta_access BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN is_suspended BOOLEAN NOT NULL DEFAULT 0;

ALTER TABLE app_settings ADD COLUMN registration_open BOOLEAN NOT NULL DEFAULT 1;
ALTER TABLE app_settings ADD COLUMN beta_features_enabled BOOLEAN NOT NULL DEFAULT 0;
