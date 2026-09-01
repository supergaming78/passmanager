# Installer l'extension PassManager

Ce guide s'adresse à toi si quelqu'un t'a envoyé cette extension pour gérer tes mots de passe
directement depuis ton navigateur. Pas besoin de connaissances techniques pour la suite.

L'extension n'est PAS sur le Chrome Web Store (payant) ni listée publiquement sur
addons.mozilla.org — sur Chrome/Edge, l'installation se fait donc manuellement, une seule fois.
Sur Firefox, le fichier `.xpi` est bien signé par Mozilla (comme n'importe quelle extension du
store), juste pas mis en avant dans les résultats de recherche du store. Dans les deux cas, ça ne
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

## Firefox (PC/Mac/Linux) — installation permanente

Télécharge le fichier `.xpi` (PAS le zip, celui-ci est pour Chrome/Edge) depuis la même release,
puis :

1. Ouvre Firefox et fais glisser le fichier `.xpi` directement dans la fenêtre du navigateur —
   ou : menu ☰ → **Modules complémentaires et thèmes** → icône ⚙️ en haut → **Installer un module
   depuis un fichier** → sélectionne le `.xpi`.
2. Firefox demande confirmation d'installation → accepte.

C'est signé par Mozilla (comme n'importe quelle extension du store, juste non répertoriée
publiquement) : **installation permanente**, pas besoin de refaire quoi que ce soit au prochain
démarrage de Firefox.

## Firefox pour Android

Chrome pour Android ne supporte aucune extension (restriction Google) — seul Firefox le permet.

1. Télécharge le `.xpi` sur le téléphone (ou transfère-le depuis un ordinateur).
2. Ouvre l'app **Fichiers**, trouve le `.xpi` téléchargé, tape dessus → **Ouvrir avec** → **Firefox**.
3. Firefox l'installe directement — installation permanente, comme sur PC.

## iPhone/iPad (Safari)

Pas encore disponible — en cours de préparation.

## Après l'installation

Clique sur l'icône PassManager, connecte-toi avec le compte que tu as sur le serveur (même compte
que sur l'app desktop/Android si tu en as déjà un — le coffre est synchronisé entre tous tes
appareils). Voir aussi le guide général `GUIDE_UTILISATEUR.md` (si on te l'a transmis) pour tout ce
qui concerne l'usage au quotidien.
