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

Ton coffre se synchronise automatiquement entre tous tes appareils connectés au même compte —
inutile de tout ressaisir sur chacun.

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
