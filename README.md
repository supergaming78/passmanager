# PassManager — gestionnaire de mots de passe Zero-Knowledge

Gestionnaire de mots de passe auto-hébergé, en trois parties : un [backend](backend) (serveur),
une [app desktop/Android](frontend(app)) (Tauri), et une [extension navigateur](extension)
(Manifest V3). **Zero-Knowledge** : le serveur ne voit et ne stocke jamais le mot de passe maître,
ni la clé qui chiffre le coffre — toute la cryptographie a lieu côté client, en Rust natif ou
compilé en WebAssembly ([`crypto-core`](crypto-core), partagé entre les trois).

## Sommaire

- **Utilisateur final** (créer un compte, ajouter une entrée, partager un mot de passe...) : voir
  [`GUIDE_UTILISATEUR.md`](GUIDE_UTILISATEUR.md).
- **Développeur** : chaque projet a son propre README détaillé —
  [`backend/README.md`](backend/README.md),
  [`frontend(app)/README.md`](frontend(app)/README.md),
  [`extension/README.md`](extension/README.md) — architecture, configuration, développement,
  tests, déploiement.
- **API HTTP** consommée par les deux clients : [`backend/docs/API.md`](backend/docs/API.md).

## Fonctionnalités principales

- Coffre chiffré de bout en bout, synchronisé en temps réel entre appareils.
- Types d'entrée dédiés (identifiant, carte bancaire, identité, note sécurisée), pièces jointes
  chiffrées, historique des mots de passe, corbeille.
- Trois mécanismes de partage qui coexistent : partage classique (accès complet, instantané),
  coffres partagés familiaux (plusieurs membres, mis à jour en direct), partage à usage limité
  "aveugle" (le destinataire ne voit jamais l'identifiant ni le mot de passe).
- Accès d'urgence via un contact de confiance, générateur de mots de passe/phrases de passe,
  vérification de fuite (HIBP, opt-in), tableau de bord "Santé du coffre".
- Déverrouillage rapide par Windows Hello (desktop), mise à jour automatique de l'app desktop.

## Licence

[Tous droits réservés](LICENSE) — commune aux trois projets de ce dépôt. Code public à des fins de
consultation uniquement ; aucune réutilisation, redistribution ou modification n'est autorisée
sans permission écrite de l'auteur.
