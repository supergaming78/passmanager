# Changelog

Le plus récent en premier. Regroupé par composant : **Backend** (déployé en continu sur le
serveur, pas de version séparée — redéployer pour profiter des changements listés ici),
**App** (desktop Windows/macOS/Linux + mobile Android/iOS, versionnée `app-vX.Y.Z`) et
**Extension** (Chrome/Edge/Firefox, versionnée `ext-vX.Y.Z`).

## App v0.2.5 — 2026-09-02

### Performance
- Démarrage plus rapide et empreinte mémoire réduite : chaque écran (Coffre, Réglages,
  Administration...) ne se charge plus qu'au moment où on y navigue réellement, au lieu de tout
  charger d'un coup au lancement.
- La bibliothèque de vrais logos de marques (~5 Mo) ne se charge plus qu'à l'ouverture du coffre,
  plutôt que d'alourdir chaque démarrage de l'app.
- Chiffrement/déchiffrement du coffre nettement plus rapide en interne : une entrée qui déclenchait
  jusqu'à 9 opérations séparées n'en déclenche plus qu'une seule, et charger le coffre entier (à
  l'ouverture, à la sauvegarde automatique, à l'export/import) se fait maintenant en un seul bloc
  au lieu d'une opération par entrée — sensible surtout sur les gros coffres.

### Corrections
- Mobile (téléphone/tablette) : retrait de l'aide aux raccourcis clavier du menu, inutilisable sans
  clavier physique.
- Le guide d'utilisation est maintenant affiché directement sur la page de téléchargement de
  chaque nouvelle version, et joint en fichier à part (plus besoin d'installer pour le consulter).
- iOS : documentation de la marche à suivre AltStore pour installer sur iPhone/iPad sans compte
  développeur Apple payant.

## Extension v0.1.6 (rappel — déjà publiée, aucun changement depuis)

- Fenêtre séparée pendant la saisie du code de vérification (2FA), avec fermeture automatique une
  fois le code validé.
- Réglage à 3 choix pour cette fenêtre (toujours / seulement pour la 2FA / jamais), avec un défaut
  différent selon le navigateur (jamais sur Chrome/Edge, 2FA seulement sur Firefox).
- Mise à jour automatique sur Firefox (signature AMO automatisée, pas d'action manuelle à faire).
- Chrome/Edge : bandeau "mise à jour disponible" avec lien direct, faute de mise à jour 100%
  automatique possible sur ces navigateurs pour une extension auto-hébergée.
- Correctif de sécurité : le choix du serveur avant connexion a été retiré, l'URL est maintenant
  verrouillée par défaut (empêchait un détournement vers un faux serveur avant même l'écran de
  connexion).

## Backend — changements depuis le 2026-09-01 (déployés en continu)

### Performance
- Connexion quasi instantanée : le calcul de sécurité du mot de passe (Argon2) ne bloque plus le
  reste du serveur pendant la vérification.
- Emails (code 2FA, vérification de compte, réinitialisation, alertes de sécurité) envoyés en
  arrière-plan, sans ralentir la réponse au client — et avec une mise en page HTML propre.
- Réponses du serveur compressées avec Brotli en plus de gzip (pages/données plus légères à
  transférer).
- Import d'un coffre entier bien plus rapide (insertion groupée en base plutôt qu'entrée par
  entrée).
- Plafond de pagination du coffre relevé (100 → 500 entrées par page) : moins d'allers-retours
  réseau nécessaires pour charger un gros coffre.
- Requêtes base de données indépendantes lancées en parallèle plutôt qu'en séquence (changement de
  mot de passe, ajout de pièce jointe).
- Petit cache mémoire pour le réglage public le plus consulté par les clients avant même la
  connexion.

### Corrections
- Limiteur de débit anti-bruteforce assoupli : plusieurs appareils personnels derrière la même
  connexion internet ne se gênent plus entre eux.
- CORS : toute extension `moz-extension://` (Firefox) est acceptée, pas seulement un identifiant
  Chrome fixe.
- Repli du champ "identifiant" corrigé pour l'email sur 12 sites connus (desktop et extension).
- Correctif de build Docker : le binaire recompilé n'était pas toujours repris par l'image de
  production.
