# Guide d'utilisation — PassManager

Ce guide s'adresse à toi si quelqu'un t'a invité à utiliser ce gestionnaire de mots de passe. Pas
besoin de connaissances techniques pour la suite.

## C'est quoi, ce truc ?

Un endroit unique et sécurisé où stocker tous tes mots de passe (et d'autres informations
sensibles : cartes bancaires, notes privées...). Au lieu de retenir 50 mots de passe différents,
tu n'en retiens qu'un seul — le **mot de passe maître** — et l'application se souvient de tout le
reste pour toi, de façon chiffrée.

**Particularité importante** : même la personne qui héberge le serveur (celle qui t'a invité) ne
peut PAS voir ton mot de passe maître, ni le contenu de ton coffre. Tout est chiffré directement
sur ton appareil, avant même d'être envoyé — le serveur ne stocke que des données déjà chiffrées,
qu'il ne sait pas lire. C'est ce qu'on appelle une architecture "Zero-Knowledge" (connaissance
nulle) : personne d'autre que toi ne peut ouvrir ton coffre.

## Règle d'or : ton mot de passe maître ne se récupère JAMAIS

C'est la conséquence directe du paragraphe précédent : puisque personne d'autre que toi ne connaît
ton mot de passe maître, **personne ne peut te le redonner si tu l'oublies**. Ni la personne qui
héberge le serveur, ni qui que ce soit.

Si tu l'oublies, la seule option est de créer un nouveau mot de passe maître via "Mot de passe
oublié" — mais ça **efface entièrement ton coffre actuel** (impossible de le déchiffrer sans
l'ancien mot de passe). Tu repars de zéro.

**Donc, avant toute chose** : choisis un mot de passe maître dont tu te souviendras vraiment (une
phrase plutôt qu'un mot, par exemple), et note-le quelque part en sécurité (papier rangé chez toi,
par exemple) au cas où.

## Premiers pas

1. **Crée ton compte** : ouvre l'application (desktop) ou l'extension de navigateur, renseigne ton
   email et choisis ton mot de passe maître (au moins 8 caractères — vise plus long si possible).
2. Un email de confirmation arrive : clique sur le lien/renseigne le code pour valider ton compte.
3. Connecte-toi une première fois — comme c'est un nouvel appareil, un code à 6 chiffres t'est
   envoyé par email pour confirmer que c'est bien toi. Une fois validé, cet appareil est retenu
   ("appareil de confiance") : tu n'auras plus ce code à saisir sur ce même appareil.

## Utiliser au quotidien

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

## Partager un mot de passe avec quelqu'un

Depuis une entrée, "Partager" → renseigne l'email de la personne (elle doit déjà avoir un compte
sur ce même serveur). Elle verra apparaître cette entrée en lecture seule dans "Partagé avec moi".

**Limite actuelle** : le partage se fait entrée par entrée, à une personne à la fois — il n'y a pas
encore de "dossier partagé" qui mettrait tout le monde à jour automatiquement si tu changes le mot
de passe ensuite (ex: le WiFi de la maison). Si tu changes un mot de passe partagé, pense à le
repartager.

## Accès d'urgence — pour quelqu'un de confiance

Tu peux désigner une personne (famille proche, par exemple) qui pourra accéder à ton coffre en cas
d'imprévu (accident, décès...) — mais PAS immédiatement : après une demande explicite de sa part
et un délai d'attente pendant lequel TU peux refuser, si tu es en mesure de le faire. Configuré
dans Réglages → Accès d'urgence.

## Quel appareil, quelle application ?

- **Ordinateur (Windows)** : l'application desktop — icône sur le bureau une fois installée.
- **Navigateur (Chrome, Edge, Firefox...)** : l'extension navigateur, pour le remplissage
  automatique directement sur les sites visités.
- **Téléphone Android** : l'application, format identique au desktop.
- **iPhone/iPad** : l'application aussi, mais son installation est un peu différente — voir la
  section dédiée juste en dessous.

Ton coffre se synchronise automatiquement entre tous tes appareils connectés au même compte —
inutile de tout ressaisir sur chacun.

## Installer sur iPhone/iPad

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

## En cas de problème

- **Mot de passe maître oublié** : voir "Règle d'or" plus haut — récupération du COMPTE possible,
  mais le COFFRE actuel sera perdu.
- **Téléphone/ordinateur perdu ou volé** : va dans Réglages → Appareils depuis un autre appareil
  encore connecté, et révoque l'appareil perdu — il sera immédiatement déconnecté et devra
  repasser par le code de confirmation pour se reconnecter (donc inutile pour qui l'a trouvé, sans
  ton mot de passe maître de toute façon).
- **Email de connexion inhabituelle reçu, alors que ce n'était pas toi** : quelqu'un essaie
  peut-être d'accéder à ton compte. Change ton mot de passe maître par précaution (Réglages), et
  préviens la personne qui héberge le serveur.

## Questions fréquentes

**Est-ce que la personne qui héberge le serveur peut voir mes mots de passe ?** Non — voir
"C'est quoi, ce truc ?" plus haut. Elle héberge le service, mais ne peut techniquement pas lire le
contenu de ton coffre.

**Que se passe-t-il si je change mon adresse email ?** Ton coffre n'est pas affecté — seule
l'adresse liée à ton compte change (nécessite de reconfirmer ton mot de passe maître actuel).

**Puis-je utiliser l'application sur plusieurs appareils en même temps ?** Oui, sans limite
particulière (sauf un plafond du nombre d'appareils de confiance, ajustable dans Réglages).
