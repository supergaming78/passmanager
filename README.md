# PassManager — gestionnaire de mots de passe Zero-Knowledge

Gestionnaire de mots de passe auto-hébergé, en trois parties : un [backend](backend) (serveur),
une [app desktop/Android](frontend(app)) (Tauri), et une [extension navigateur](extension)
(Manifest V3). **Zero-Knowledge** : le serveur ne voit et ne stocke jamais le mot de passe maître,
ni la clé qui chiffre le coffre — toute la cryptographie a lieu côté client, en Rust natif ou
compilé en WebAssembly ([`crypto-core`](crypto-core), partagé entre les trois).

## Sommaire

- **Utilisateur final** : guides ci-dessous (usage au quotidien, installation de l'extension).
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

## Guide d'utilisation

Ce guide s'adresse à toi si quelqu'un t'a invité à utiliser ce gestionnaire de mots de passe. Pas
besoin de connaissances techniques pour la suite.

### C'est quoi, ce truc ?

Un endroit unique et sécurisé où stocker tous tes mots de passe (et d'autres informations
sensibles : cartes bancaires, notes privées...). Au lieu de retenir 50 mots de passe différents,
tu n'en retiens qu'un seul — le **mot de passe maître** — et l'application se souvient de tout le
reste pour toi, de façon chiffrée.

**Particularité importante** : même la personne qui héberge le serveur (celle qui t'a invité) ne
peut PAS voir ton mot de passe maître, ni le contenu de ton coffre. Tout est chiffré directement
sur ton appareil, avant même d'être envoyé — le serveur ne stocke que des données déjà chiffrées,
qu'il ne sait pas lire. C'est ce qu'on appelle une architecture "Zero-Knowledge" (connaissance
nulle) : personne d'autre que toi ne peut ouvrir ton coffre.

### Règle d'or : ton mot de passe maître ne se récupère JAMAIS

C'est la conséquence directe du paragraphe précédent : puisque personne d'autre que toi ne connaît
ton mot de passe maître, **personne ne peut te le redonner si tu l'oublies**. Ni la personne qui
héberge le serveur, ni qui que ce soit.

Si tu l'oublies, la seule option est de créer un nouveau mot de passe maître via "Mot de passe
oublié" — mais ça **efface entièrement ton coffre actuel** (impossible de le déchiffrer sans
l'ancien mot de passe). Tu repars de zéro.

**Donc, avant toute chose** : choisis un mot de passe maître dont tu te souviendras vraiment (une
phrase plutôt qu'un mot, par exemple), et note-le quelque part en sécurité (papier rangé chez toi,
par exemple) au cas où.

### Premiers pas

1. **Crée ton compte** : ouvre l'application (desktop) ou l'extension de navigateur, renseigne ton
   email et choisis ton mot de passe maître (au moins 8 caractères — vise plus long si possible).
2. Un email de confirmation arrive : clique sur le lien/renseigne le code pour valider ton compte.
3. Connecte-toi une première fois — comme c'est un nouvel appareil, un code à 6 chiffres t'est
   envoyé par email pour confirmer que c'est bien toi. Une fois validé, cet appareil est retenu
   ("appareil de confiance") : tu n'auras plus ce code à saisir sur ce même appareil.

### Utiliser au quotidien

- **Ajouter une entrée** : bouton "+" ou "Ajouter" — renseigne le site, ton identifiant, le mot de
  passe (l'application peut en générer un fort à ta place), et éventuellement une note ou une
  pièce jointe.
- **Retrouver un mot de passe** : la barre de recherche en haut du coffre.
- **Copier un mot de passe** : bouton "Copier" sur l'entrée — il est automatiquement effacé du
  presse-papiers après quelques minutes (réglable dans Réglages), pour éviter qu'il traîne.
- **Remplissage automatique (extension navigateur)** : sur le site concerné, clique sur l'icône de
  l'extension puis "Remplir" sur la bonne entrée — le formulaire de connexion se remplit tout
  seul. Si tu es sur un site différent de celui enregistré pour cette entrée, une confirmation
  t'est demandée avant de remplir (protection contre les sites frauduleux qui imitent un vrai
  site).
- **Corbeille** : une entrée supprimée reste récupérable 30 jours avant suppression définitive.

### Partager un mot de passe avec quelqu'un

Depuis une entrée, "Partager" → renseigne l'email de la personne (elle doit déjà avoir un compte
sur ce même serveur). Elle verra apparaître cette entrée en lecture seule dans "Partagé avec moi".

**Limite actuelle** : le partage se fait entrée par entrée, à une personne à la fois — il n'y a pas
encore de "dossier partagé" qui mettrait tout le monde à jour automatiquement si tu changes le mot
de passe ensuite (ex: le WiFi de la maison). Si tu changes un mot de passe partagé, pense à le
repartager.

### Accès d'urgence — pour quelqu'un de confiance

Tu peux désigner une personne (famille proche, par exemple) qui pourra accéder à ton coffre en cas
d'imprévu (accident, décès...) — mais PAS immédiatement : après une demande explicite de sa part
et un délai d'attente pendant lequel TU peux refuser, si tu es en mesure de le faire. Configuré
dans Réglages → Accès d'urgence.

### Quel appareil, quelle application ?

- **Ordinateur (Windows)** : l'application desktop — icône sur le bureau une fois installée.
- **Navigateur (Chrome, Edge, Firefox...)** : l'extension navigateur, pour le remplissage
  automatique directement sur les sites visités.
- **Téléphone Android** : l'application, format identique au desktop.
- **iPhone/iPad** : l'application aussi, mais son installation est un peu différente — voir la
  section dédiée juste en dessous.

Ton coffre se synchronise automatiquement entre tous tes appareils connectés au même compte —
inutile de tout ressaisir sur chacun.

### Installer sur iPhone/iPad

L'application existe sur iPhone/iPad, mais n'est **pas sur l'App Store** (ça coûte 99$/an à Apple,
rien que pour avoir le droit d'y publier quoi que ce soit — pas justifié pour une app partagée
entre proches). Installer l'app se fait donc un peu différemment, via un outil gratuit appelé
**AltStore**, largement utilisé pour ce genre de cas.

**Ce qu'il te faut** : un ordinateur Windows (ou Mac) sur le même réseau WiFi que ton iPhone/iPad,
et un identifiant Apple (le même que celui que tu utilises déjà pour l'App Store — gratuit, pas
besoin d'un compte développeur payant).

1. **Sur l'ordinateur** : télécharge et installe AltServer depuis [altstore.io](https://altstore.io)
   (choisis la version Windows). Une fois installé, il tourne en arrière-plan (petite icône dans la
   zone de notification, en bas à droite de l'écran) — laisse-le allumé pour la suite.
2. **Branche ton iPhone/iPad en USB** à l'ordinateur (la première fois, c'est plus fiable qu'en
   WiFi seul).
3. Clique-droit sur l'icône AltServer → **Install AltStore** → choisis ton appareil dans la liste.
   Il te demande ton identifiant Apple + mot de passe : c'est normal, c'est ce qui sert à signer
   l'app localement (rien n'est envoyé à qui que ce soit d'autre qu'Apple, de la même façon que
   quand tu te connectes à l'App Store).
4. Sur ton iPhone/iPad, une app **AltStore** apparaît. Avant de l'ouvrir, va dans **Réglages →
   Général → VPN et gestion de l'appareil**, et fais confiance au profil qui porte ton identifiant
   Apple.
5. Télécharge le fichier `PassManager-unsigned.ipa` depuis la page des releases du projet
   (transfère-le sur ton iPhone/iPad — par AirDrop, iCloud Drive, ou en le téléchargeant
   directement dans Safari sur l'appareil).
6. Ouvre **AltStore** sur ton iPhone/iPad → onglet **My Apps** → bouton **+** en haut à gauche →
   sélectionne le fichier `.ipa`. L'installation démarre (peut prendre une minute).

**À savoir** : avec un identifiant Apple gratuit (pas de compte développeur payant), l'app doit être
re-signée tous les 7 jours, sinon elle s'arrête de fonctionner. AltServer s'en charge tout seul et
automatiquement — il suffit que l'ordinateur avec AltServer soit allumé et sur le même WiFi que ton
iPhone/iPad de temps en temps (ouvrir AltStore sur l'appareil de temps en temps aide aussi). Pas
besoin d'un Mac, ni de rebrancher en USB après la toute première installation.

### En cas de problème

- **Mot de passe maître oublié** : voir "Règle d'or" plus haut — récupération du COMPTE possible,
  mais le COFFRE actuel sera perdu.
- **Téléphone/ordinateur perdu ou volé** : va dans Réglages → Appareils depuis un autre appareil
  encore connecté, et révoque l'appareil perdu — il sera immédiatement déconnecté et devra
  repasser par le code de confirmation pour se reconnecter (donc inutile pour qui l'a trouvé, sans
  ton mot de passe maître de toute façon).
- **Email de connexion inhabituelle reçu, alors que ce n'était pas toi** : quelqu'un essaie
  peut-être d'accéder à ton compte. Change ton mot de passe maître par précaution (Réglages), et
  préviens la personne qui héberge le serveur.

### Questions fréquentes

**Est-ce que la personne qui héberge le serveur peut voir mes mots de passe ?** Non — voir
"C'est quoi, ce truc ?" plus haut. Elle héberge le service, mais ne peut techniquement pas lire le
contenu de ton coffre.

**Que se passe-t-il si je change mon adresse email ?** Ton coffre n'est pas affecté — seule
l'adresse liée à ton compte change (nécessite de reconfirmer ton mot de passe maître actuel).

**Puis-je utiliser l'application sur plusieurs appareils en même temps ?** Oui, sans limite
particulière (sauf un plafond du nombre d'appareils de confiance, ajustable dans Réglages).

## Installer l'extension navigateur

Ce guide s'adresse à toi si quelqu'un t'a envoyé cette extension pour gérer tes mots de passe
directement depuis ton navigateur. Pas besoin de connaissances techniques pour la suite.

L'extension n'est PAS sur le Chrome Web Store (payant) ni listée publiquement sur
addons.mozilla.org — sur Chrome/Edge, l'installation se fait donc manuellement, une seule fois.
Sur Firefox, le fichier `.xpi` est bien signé par Mozilla (comme n'importe quelle extension du
store), juste pas mis en avant dans les résultats de recherche du store. Dans les deux cas, ça ne
change rien à la sécurité : le code est exactement le même que celui qui tournerait via un store.

### Chrome, Edge, Brave, Opera, Vivaldi (PC/Mac/Linux)

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

### Firefox (PC/Mac/Linux) — installation permanente

Télécharge le fichier `.xpi` (PAS le zip, celui-ci est pour Chrome/Edge) depuis la même release,
puis :

1. Ouvre Firefox et fais glisser le fichier `.xpi` directement dans la fenêtre du navigateur —
   ou : menu ☰ → **Modules complémentaires et thèmes** → icône ⚙️ en haut → **Installer un module
   depuis un fichier** → sélectionne le `.xpi`.
2. Firefox demande confirmation d'installation → accepte.

C'est signé par Mozilla (comme n'importe quelle extension du store, juste non répertoriée
publiquement) : **installation permanente**, pas besoin de refaire quoi que ce soit au prochain
démarrage de Firefox.

**Mise à jour automatique** : contrairement à Chrome/Edge, Firefox vérifie tout seul (environ une
fois par jour) si une nouvelle version est disponible et l'installe automatiquement, sans rien à
faire de ton côté — comme n'importe quelle extension du store.

### Firefox pour Android

Chrome pour Android ne supporte aucune extension (restriction Google) — seul Firefox le permet.

1. Télécharge le `.xpi` sur le téléphone (ou transfère-le depuis un ordinateur).
2. Ouvre l'app **Fichiers**, trouve le `.xpi` téléchargé, tape dessus → **Ouvrir avec** → **Firefox**.
3. Firefox l'installe directement — installation permanente, comme sur PC.

### iPhone/iPad (Safari)

Pas encore disponible — en cours de préparation.

### Après l'installation

Clique sur l'icône PassManager, connecte-toi avec le compte que tu as sur le serveur (même compte
que sur l'app desktop/Android si tu en as déjà un — le coffre est synchronisé entre tous tes
appareils). Voir la section "Guide d'utilisation" plus haut pour tout ce qui concerne l'usage au
quotidien.

## Licence

[Tous droits réservés](LICENSE) — commune aux trois projets de ce dépôt. Code public à des fins de
consultation uniquement ; aucune réutilisation, redistribution ou modification n'est autorisée
sans permission écrite de l'auteur.
