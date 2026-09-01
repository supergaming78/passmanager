# Installer l'extension PassManager

Ce guide s'adresse à toi si quelqu'un t'a envoyé cette extension pour gérer tes mots de passe
directement depuis ton navigateur. Pas besoin de connaissances techniques pour la suite.

L'extension n'est PAS sur le Chrome Web Store ni sur addons.mozilla.org (les deux demandent un
paiement ou une revue longue) — l'installation se fait donc manuellement, une seule fois. Ça ne
change rien à la sécurité : le code est exactement le même que celui qui tournerait via un store.

## Chrome, Edge, Brave, Opera, Vivaldi (PC/Mac/Linux)

1. Dézippe le fichier téléchargé quelque part où tu ne le supprimeras pas par erreur (ex: dans tes
   Documents) — le dossier doit rester à cet endroit, l'extension le lit directement depuis là.
2. Ouvre ton navigateur, va sur `chrome://extensions` (Edge : `edge://extensions`, même page pour
   les autres).
3. Active le **Mode développeur** (interrupteur en haut à droite de la page).
4. Clique sur **Charger l'extension non empaquetée** (ou "Load unpacked").
5. Sélectionne le dossier dézippé (celui qui contient directement `manifest.json`).
6. L'icône PassManager apparaît dans la barre d'outils du navigateur — épingle-la (icône puzzle 🧩
   → épingle à côté de PassManager) pour l'avoir toujours sous la main.

**Mise à jour** : quand une nouvelle version sort, retélécharge le zip, dézippe-le au MÊME endroit
en écrasant l'ancien dossier, puis retourne sur `chrome://extensions` et clique sur l'icône
"Actualiser" (↻) sous PassManager. Pas besoin de tout réinstaller.

## Firefox (PC/Mac/Linux) — usage occasionnel

Firefox permet de charger l'extension sans la signer, mais seulement **temporairement** (jusqu'à
la fermeture de Firefox) :

1. Dézippe le fichier téléchargé.
2. Va sur `about:debugging#/runtime/this-firefox`.
3. Clique sur **Charger un module complémentaire temporaire**.
4. Sélectionne le fichier `manifest.json` à l'intérieur du dossier dézippé.

À refaire à chaque redémarrage de Firefox — pratique pour essayer, pas pour un usage quotidien.
Pour une installation permanente sur Firefox, une version signée par Mozilla (`.xpi`) est
nécessaire — pas encore disponible pour cette extension, demande à la personne qui te l'a envoyée
si tu en as besoin.

## Firefox pour Android

Chrome pour Android ne supporte aucune extension (restriction Google) — seul Firefox le permet,
et uniquement avec une version signée par Mozilla (`.xpi`), pas encore disponible pour cette
extension au moment de ce guide. Demande à la personne qui te l'a envoyée où en est cette version.

## iPhone/iPad (Safari)

Pas encore disponible — en cours de préparation.

## Après l'installation

Clique sur l'icône PassManager, connecte-toi avec le compte que tu as sur le serveur (même compte
que sur l'app desktop/Android si tu en as déjà un — le coffre est synchronisé entre tous tes
appareils). Voir aussi le guide général `GUIDE_UTILISATEUR.md` (si on te l'a transmis) pour tout ce
qui concerne l'usage au quotidien.
