-- QUOTAS PAR COMPTE, en surcharge des plafonds globaux.
--
-- Jusqu'ici les plafonds etaient des constantes Rust identiques pour tout le monde :
-- MAX_VAULT_ENTRIES_PER_USER (5000) et MAX_ATTACHMENTS_PER_USER (50), dans handlers/vault.rs.
-- Convenable par defaut, mais rigide des que les comptes ne se ressemblent pas — sur un serveur
-- familial, l'usage d'un adulte et celui d'un enfant n'ont aucune raison d'etre plafonnes pareil,
-- et l'espace disque est partage.
--
-- NULL = "utilise le plafond global". C'est le defaut, et c'est ce qui rend la migration sans
-- effet sur l'existant : aucun compte ne change de comportement tant que l'Admin n'a rien regle.
-- Un 0 explicite est donc distinct de NULL — il signifie reellement "aucune entree autorisee",
-- ce qui est un reglage legitime (geler un compte sans le suspendre).
--
-- Volontairement PAS de quota en octets sur les pieces jointes : la taille d'une piece jointe est
-- deja plafonnee a l'unite cote serveur, et un plafond en nombre est comprehensible d'un coup
-- d'oeil dans le panneau, la ou "42 Mo sur 50" demande une conversion mentale a chaque lecture.

ALTER TABLE users ADD COLUMN max_vault_entries INTEGER;
ALTER TABLE users ADD COLUMN max_attachments INTEGER;
