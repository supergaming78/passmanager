-- Partage à USAGE LIMITÉ, "aveugle" — le destinataire ne voit JAMAIS l'identifiant ni le mot de
-- passe : il ne voit que le nom du site, et peut déclencher un "usage" (remplissage automatique
-- côté extension, ou copie sans affichage côté desktop) un nombre de fois limité choisi par
-- l'expéditeur (1 par défaut). S'AJOUTE au partage d'entrée classique (vault_shares) ET aux
-- coffres partagés familiaux (shared_vault_entries), ne remplace ni l'un ni l'autre — trois
-- mécanismes de partage distincts qui coexistent, chacun pour un usage différent.
--
-- CONCEPTION — deux blobs scellés SÉPARÉS, pas un seul, et c'est le point important :
--   - `sealed_site_name` : librement consultable par le destinataire (liste des partages reçus),
--     NE CONSOMME JAMAIS d'usage — un destinataire doit pouvoir voir "il y a un partage en
--     attente pour tel site, X usages restants" sans que ça n'entame le compteur.
--   - `sealed_credentials` : identifiant + mot de passe scellés ENSEMBLE (JSON), accessible
--     UNIQUEMENT via POST /blind-shares/{id}/use (voir handlers/blind_share.rs), qui décrémente
--     `remaining_uses` de façon ATOMIQUE (un seul UPDATE avec la condition `remaining_uses > 0`
--     directement dans son WHERE, jamais un SELECT puis un UPDATE séparés) avant de renvoyer le
--     blob — sans ça, deux appels concurrents pourraient tous les deux réussir alors qu'il ne
--     restait qu'un seul usage disponible.
--
-- LIMITE ACCEPTÉE, HONNÊTE (documentée aussi côté handler et README) : empêcher le destinataire de
-- voir le mot de passe REND l'usage occasionnel/accidentel impossible (pas de bouton "voir"/
-- "copier" dans l'interface pour ce type de partage), et le nombre de FOIS où le blob scellé peut
-- même être demandé au serveur est strictement plafonné — mais un destinataire technique qui
-- inspecterait sa propre extension/application (outils de développement, mémoire du processus)
-- pourrait toujours extraire la valeur en clair PENDANT un usage autorisé. C'est une limite
-- inhérente à TOUT mécanisme de remplissage automatique côté client (le remplissage doit, à un
-- instant donné, disposer de la valeur en clair) — pas un défaut corrigible ici. Ce que cette
-- fonctionnalité garantit réellement : aucune exposition CASUELLE/accidentelle (rien à l'écran à
-- lire ou copier), et un nombre d'occasions d'y accéder strictement borné et compté.
CREATE TABLE IF NOT EXISTS vault_blind_shares (
    id TEXT PRIMARY KEY NOT NULL,
    vault_id TEXT NOT NULL,
    owner_email TEXT NOT NULL,
    shared_with_email TEXT NOT NULL,
    sealed_site_name TEXT NOT NULL,
    sealed_credentials TEXT NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 1,
    remaining_uses INTEGER NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (vault_id) REFERENCES vault(id) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (owner_email) REFERENCES users(email) ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (shared_with_email) REFERENCES users(email) ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_vault_blind_shares_recipient ON vault_blind_shares(shared_with_email);
CREATE INDEX IF NOT EXISTS idx_vault_blind_shares_vault ON vault_blind_shares(vault_id);
