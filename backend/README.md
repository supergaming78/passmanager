# Backend — Gestionnaire de mots de passe

Backend Rust (Axum + SQLite) pour un gestionnaire de mots de passe **Zero-Knowledge**, destiné à
être consommé par le client desktop Tauri (voir `../frontend(app)/README.md`) et par l'extension
navigateur (voir `../extension/README.md`) de ce même dépôt. Le serveur ne voit et ne stocke
jamais le mot de passe maître d'un utilisateur, ni la clé qui chiffre son coffre : toutes les
entrées du coffre lui arrivent déjà chiffrées côté client, et il ne fait que les stocker/servir
telles quelles.

Pour l'extension navigateur spécifiquement : son origine (`chrome-extension://<id>`) doit être
ajoutée à `ALLOWED_ORIGINS` ci-dessous pour que le CORS l'autorise — voir
`../extension/README.md#configuration-requise-côté-backend` pour la valeur exacte.

Ce qui suit est de la doc **développeur** (déploiement du serveur). Pour un guide destiné aux
utilisateurs finaux (comment créer un compte, ajouter une entrée, partager un mot de passe...),
voir [`../GUIDE_UTILISATEUR.md`](../GUIDE_UTILISATEUR.md).

## Sommaire

- [Architecture en bref](#architecture-en-bref)
- [Prérequis](#prérequis)
- [Configuration](#configuration)
- [Lancer en local](#lancer-en-local)
- [Lancer avec Docker](#lancer-avec-docker)
- [Sauvegarde de la base de données](#sauvegarde-de-la-base-de-données)
- [Espace disque](#espace-disque)
- [Exposer ce backend en HTTPS](#exposer-ce-backend-en-https)
- [Tests](#tests)
- [Documentation de l'API](#documentation-de-lapi)

## Architecture en bref

- **Web** : [Axum](https://github.com/tokio-rs/axum) sur [Tokio](https://tokio.rs/).
- **Base de données** : SQLite via [SQLx](https://github.com/launchbadge/sqlx) (mode WAL), migrations
  embarquées dans le binaire au moment de la compilation (`sqlx::migrate!`).
- **Mots de passe** : Argon2id (paramètres renforcés) + pepper serveur, appliqué à un hash
  d'authentification déjà dérivé côté client — jamais au mot de passe en clair.
- **Sessions** : access token JWT courte durée (HMAC-SHA256) + refresh token opaque à rotation,
  stocké hashé (SHA-256) en base. Un changement de mot de passe ou une déconnexion globale
  invalide immédiatement les access tokens déjà émis (voir `docs/API.md`).
- **2FA** : tout appareil non reconnu doit valider un code à 6 chiffres envoyé par email avant
  d'obtenir des tokens. Un login depuis un appareil déjà approuvé mais une IP jamais vue pour lui
  déclenche en plus une alerte email (voir `docs/API.md`, section `POST /auth/login`).
- **Accès d'urgence & partage d'entrée** : X25519 + HKDF-SHA256 + AES-256-GCM ("sealed box"), une
  seule paire de clés par utilisateur, séparée par domaine (`info` HKDF distinct) entre les deux
  usages — voir `docs/API.md`, sections "Accès d'urgence" et "Partage d'entrée". Le serveur ne voit
  jamais une clé privée en clair, ni le contenu scellé qu'il relaie.
- **Types d'entrée dédiés** : `entry_type` (login/carte/identité/note) est une métadonnée en clair,
  `encrypted_extra_fields` un blob chiffré côté client comme les autres champs — le serveur ne
  connaît ni n'impose la forme d'aucun des deux.

### Organisation du code (`src/`)

```
main.rs                  Bootstrap : config, DB, routing, démarrage/arrêt du serveur
state.rs                 AppState partagé entre tous les handlers
maintenance.rs           Tâches de fond périodiques (nettoyage) + bootstrap admin
config.rs                Chargement des variables d'environnement
crypto.rs                Hachage de mots de passe, JWT, tokens, comparaison temps constant
mailer.rs                Envoi des emails (2FA, vérification, alertes, reset)
middleware.rs            Extracteur `AuthUser` (validation du JWT à chaque requête)
models.rs                Structures de requête/réponse et modèles de base de données
repository.rs            Requêtes SQL du coffre-fort
error.rs                 Type d'erreur applicatif -> réponses HTTP
handlers/
  common.rs              Utilitaires partagés entre handlers (ex: extraction du User-Agent)
  auth.rs                Agrégateur du domaine authentification
  auth/register.rs       Inscription, vérification d'email, renvoi de code
  auth/session.rs        Connexion, 2FA, alerte de connexion inhabituelle, rafraîchissement, déconnexion
  auth/account.rs        Mot de passe (+ re-chiffrement), email, profil, historique de sécurité, réinitialisation de compte
  vault.rs               CRUD du coffre, corbeille, pièces jointes, export/import, synchronisation
  devices.rs             Appareils de confiance, plafond, déconnexion globale
  emergency.rs           Accès d'urgence (X25519 sealed-box) : contacts, clés, consultation en lecture seule
  sharing.rs             Partage sécurisé d'une entrée entre deux comptes (même primitive sealed-box)
  admin.rs               Gestion des comptes (rôles, révocation, suppression) + logs d'audit (tous comptes)
  sync.rs                Tickets WebSocket + synchronisation temps réel
```

## Prérequis

- Rust stable (édition 2021) + Cargo — **ou** Docker + Docker Compose.
- Un compte SMTP capable d'envoyer des emails (ex: un compte Gmail avec un
  [mot de passe d'application](https://support.google.com/accounts/answer/185833)) : requis pour
  les codes de vérification/2FA/réinitialisation, sans lequel l'inscription et la connexion ne
  peuvent pas aboutir.

## Configuration

Toutes les variables se chargent depuis l'environnement (ou un fichier `.env` à la racine, chargé
automatiquement au démarrage). Copie `.env.example` vers `.env` puis édite les valeurs :

```sh
cp .env.example .env
```

| Variable | Obligatoire | Défaut | Description |
|---|---|---|---|
| `DATABASE_URL` | oui | — | URL SQLite, ex: `sqlite:data/vault.db?mode=rwc` |
| `JWT_SECRET` | oui | — | Secret de signature JWT, **≥ 32 caractères** |
| `PASSWORD_PEPPER` | oui | — | Pepper ajouté avant le hachage Argon2, **≥ 32 caractères** |
| `SMTP_USER` | oui | — | Identifiant du compte SMTP |
| `SMTP_PASS` | oui | — | Mot de passe / jeton d'application SMTP |
| `APP_ENV` | non | `development` | `production` impose une vérification stricte de `JWT_SECRET` |
| `PORT` | non | `3000` | Port d'écoute HTTP **à l'intérieur du conteneur** — à ne pas confondre avec `HOST_PORT` ci-dessous |
| `HOST_PORT` *(Docker uniquement — pas une variable lue par l'appli elle-même)* | non | `13000` | Port exposé côté HÔTE (`docker-compose.yml`) — à changer si ce port est aussi déjà pris chez toi (ex: `HOST_PORT=13001`) ; le port interne (`PORT`) reste 3000 quoi qu'il arrive |
| `SMTP_HOST` | non | `smtp.gmail.com` | Hôte SMTP |
| `ACCESS_TOKEN_SECONDS` | non | `600` | Durée de vie de l'access token (secondes) |
| `REFRESH_TOKEN_HOURS` | non | `24` | Durée du refresh token avec "Se souvenir de moi" |
| `REFRESH_TOKEN_SHORT_SECONDS` | non | `5` | Durée du refresh token sans "Se souvenir de moi" |
| `ALLOWED_ORIGINS` | non | `http://localhost:5173` | Origines CORS autorisées, séparées par des virgules — voir l'avertissement ci-dessous, le défaut seul NE SUFFIT PAS pour l'app packagée |
| `ADMIN_EMAIL` | non | — | Email promu administrateur automatiquement (à l'inscription, ou immédiatement si le compte existe déjà) |
| `TRUST_PROXY_HEADERS` | non | `false` | Voir avertissement ci-dessous — ne concerne que le rate limiting |
| `GEOIP_DATABASE_PATH` | non | *(vide)* | Base MMDB locale pour l'origine des IP du panneau Administration — voir plus bas |

`PASSWORD_PEPPER` et `JWT_SECRET` font l'objet d'une vérification stricte au démarrage : le
programme refuse de démarrer si l'un des deux fait moins de 32 caractères.

**`ALLOWED_ORIGINS` — piège à connaître pour l'app desktop/Android** : l'app PACKAGÉE (le vrai
`.exe`/`.msi`/`.apk` installé, pas `npm run tauri dev`) ne se présente PAS avec une origine
`http://localhost:...` mais avec l'origine interne de Tauri — `http://tauri.localhost` sur Windows
et Android, `tauri://localhost` sur macOS/Linux (deux valeurs différentes selon la plateforme, une
contrainte de WebView2/Android WebView côté Tauri, pas un choix de ce projet). **Sans les DEUX
dans `ALLOWED_ORIGINS`, le CORS bloque silencieusement toutes les requêtes de l'app installée** —
elle semblerait "ne rien faire" au clic sur Connexion/Inscription, sans message d'erreur clair
(le navigateur/webview refuse la réponse avant même que le JS de l'app ne la voie). Déjà inclus
dans le défaut de `docker-compose.yml` (voir juste au-dessus) — à vérifier/ajouter manuellement
si tu configures `ALLOWED_ORIGINS` autrement (Portainer, `.env` local...), voir `.env.example`
pour la valeur complète recommandée.

### Géolocalisation des adresses IP (`GEOIP_DATABASE_PATH`)

Le panneau Administration peut afficher l'origine estimée des adresses IP d'un compte. **La
résolution se fait entièrement sur ton serveur, contre un fichier local** : aucune adresse de tes
utilisateurs n'est jamais envoyée à un service tiers.

C'est le point important. La méthode habituelle — interroger une API de géolocalisation — reviendrait
à transmettre à une entreprise inconnue la liste des adresses de ta famille, c'est-à-dire, dans le
temps, la carte de leurs déplacements. Dans un gestionnaire de mots de passe à divulgation nulle,
le chiffrement protégerait le contenu pendant qu'un canal annexe divulguerait le contexte.

**Optionnel** : sans ce réglage, la colonne « Origine » reste vide, rien n'est téléchargé, et le
reste fonctionne à l'identique.

#### Installer une base

DB-IP publie une base pays libre, sans compte à créer (~8 Mo) :

**En local, ou avec un `docker compose` que tu lances toi-même :**

```bash
cd backend/data
curl -L -o dbip-country.mmdb.gz \
  "https://download.db-ip.com/free/dbip-country-lite-$(date +%Y-%m).mmdb.gz"
gunzip dbip-country.mmdb.gz
```

**En Stack Portainer**, cette commande n'est pas praticable : `./data` vit dans le clone géré par
Portainer, dont le chemin sur l'hôte n'est pas évident à retrouver. Utilise le service
`geoip-init` prévu pour ça — il écrit au bon endroit sans avoir à le chercher :

1. Dans les variables d'environnement du Stack, ajoute `COMPOSE_PROFILES=geoip`.
2. Redéploie le Stack. Le conteneur `geoip-init` télécharge la base, la pose dans `./data`, puis
   s'arrête (il ne redémarre pas ; c'est normal qu'il apparaisse comme « exited »).
3. Ajoute `GEOIP_DATABASE_PATH=/app/data/dbip-country.mmdb`, puis redéploie une dernière fois.

Tu peux ensuite retirer `COMPOSE_PROFILES` : le fichier reste. S'il est toujours là et date de
moins de 60 jours, `geoip-init` ne le retélécharge pas.

`geoip-init` apparaît en **« exited (0) »** une fois son travail fini : c'est le résultat NORMAL.
C'est un conteneur à usage unique, pas un service — un code 0 signifie qu'il a réussi. Ses logs
disent laquelle des deux situations s'applique (« Base installee dans... » ou « deja presente »).
Un vrai échec sortirait avec le code 1.

**Les deux services démarrent en parallèle**, et `api` gagne souvent la course : au moment où il
démarre, la base n'est pas encore téléchargée. Ce n'est pas un problème — il retente d'ouvrir le
fichier au fil des consultations (au plus une fois par minute) et le prend en compte dès qu'il
apparaît, sans redémarrage. Le message d'avertissement au démarrage est donc attendu la première
fois ; c'est la ligne « Géolocalisation hors ligne active » qui fait foi, et elle peut arriver
plus tard.

Ce service est **inerte par défaut** — sans `COMPOSE_PROFILES=geoip`, il ne démarre jamais. Rien
n'est téléchargé à ton insu, même une base publique. Et ce téléchargement ne dit rien de tes
utilisateurs : il récupère une base complète, identique pour tout le monde. C'est l'inverse exact
d'une API de géolocalisation, à qui il faudrait envoyer les adresses à résoudre.

Dans les deux cas, `./data` est déjà monté sur `/app/data` : il n'y a aucun volume à ajouter. Au
démarrage, le backend journalise le type de base chargée et sa date de construction — c'est ainsi
que tu vérifies qu'elle est bien prise en compte.

MaxMind GeoLite2 fonctionne aussi (format identique) mais demande la création d'un compte. La
variante « City » ajoute les villes, au prix d'un fichier bien plus gros ; la base pays suffit
largement pour ce qu'on cherche ici.

Le fichier vieillit : les attributions d'adresses changent. Le rafraîchir tous les quelques mois
suffit — une base périmée donne des origines fausses, pas des erreurs.

#### Ce qu'il ne faut pas en conclure

Une géolocalisation d'IP est une **estimation**, jamais une position. Un VPN affiche le pays de son
serveur ; une connexion mobile est souvent rattachée à un équipement opérateur à des centaines de
kilomètres ; le CGNAT partage une même adresse entre des milliers d'abonnés. C'est utile pour
repérer un pays manifestement improbable, pas pour affirmer où quelqu'un se trouvait.

Si le serveur tourne derrière un reverse proxy sans `TRUST_PROXY_HEADERS=true`, toutes les adresses
enregistrées sont celles du proxy : la géolocalisation n'y changera rien, et le panneau te le
signalera.

**`TRUST_PROXY_HEADERS`** contrôle la façon dont le rate limiting identifie un client : par défaut
(`false`), il utilise l'IP du pair TCP direct — le seul choix sûr si ce backend est exposé
directement. Si tu le mets un jour derrière un reverse proxy (nginx, etc.), passe cette variable à
`true` **uniquement si ce proxy écrase lui-même** les en-têtes `X-Forwarded-For`/`X-Real-Ip`/
`Forwarded` avant de transmettre la requête — sinon n'importe quel client peut positionner ces
en-têtes lui-même pour obtenir un budget de rate limiting séparé à volonté et contourner
entièrement la protection.

## Lancer en local

```sh
cargo run
```

Les migrations SQL (`migrations/`) s'appliquent automatiquement au démarrage, sur la base pointée
par `DATABASE_URL`. Aucune étape manuelle n'est nécessaire.

## Lancer avec Docker

```sh
docker compose build
docker compose up -d
```

`docker-compose.yml` lit les secrets via des variables d'environnement (`${VAR}`, jamais gravées
dans l'image) — un fichier `.env` voisin (copié depuis `.env.example`, voir "Configuration"
ci-dessus) les fournit automatiquement pour cet usage en ligne de commande, aucune étape
supplémentaire nécessaire. La base SQLite persiste dans `./data` via un volume. Le conteneur
tourne en utilisateur non-root (UID 1000) : si le démarrage échoue avec une erreur de permission
sur `./data`, exécute une fois sur l'hôte :

```sh
mkdir -p ./data && sudo chown -R 1000:1000 ./data
```

Vérifier que le service répond (port hôte 13000 par défaut — voir `HOST_PORT` ci-dessous si un
autre service occupe déjà ce port sur ta machine) :

```sh
curl http://localhost:13000/health
```

### Déployer via Portainer (Stack)

`docker-compose.yml` fonctionne aussi tel quel comme Stack Portainer — méthode **Repository**,
pas besoin de copier/coller le fichier à la main :

1. **Stacks > Add stack**, nom au choix.
2. **Build method : Repository**.
3. **Repository URL** : `https://github.com/supergaming78/passmanager.git` (dépôt public, aucun
   identifiant à fournir).
4. **Compose path** : `backend/docker-compose.yml` (le fichier n'est PAS à la racine du dépôt).
5. **Environment variables** — Portainer clone ce dépôt directement, où `.env` n'existe PAS (il
   est volontairement exclu du dépôt, voir le `.gitignore` racine) : renseigne ici, un par un,
   les mêmes noms que le tableau de la section "Configuration" ci-dessus (`JWT_SECRET`,
   `PASSWORD_PEPPER`, `SMTP_USER`, `SMTP_PASS` au minimum — les autres ont un défaut raisonnable
   si laissés vides). Si le déploiement échoue avec `port is already allocated` (fréquent quand
   plusieurs stacks tournent déjà sur le même Docker) : ajoute `HOST_PORT` avec un port libre
   (ex: `HOST_PORT=13001`) — le port par défaut de ce projet (13000) peut lui aussi être déjà pris.
6. **Deploy the stack**.

Portainer construit l'image depuis le `Dockerfile` du dépôt cloné (comme `docker compose build`
en local) — le premier déploiement prend donc quelques minutes, les suivants (après un `git pull`
du Stack, bouton "Pull and redeploy" dans Portainer) ne reconstruisent que ce qui a changé.

**Mettre à jour** une fois du nouveau code poussé sur `main` : dans Portainer, ouvrir le Stack puis
**Pull and redeploy** — récupère le dernier commit du dépôt et reconstruit l'image, sans perdre les
volumes (`./data`/`./backups`, donc rien du coffre ni des sauvegardes).

#### Une mise à jour qui contient des migrations

Les migrations de base de données s'appliquent **automatiquement au démarrage** : il n'y a aucune
commande à lancer. Mais elles modifient la base, donc l'ordre compte.

1. **Vérifie que tu as une sauvegarde récente.** Le service `backup` en produit une toutes les 24 h
   dans `./backups` (voir la section Sauvegarde) — regarde la date du fichier le plus récent avant
   de continuer. Une migration ne se rejoue pas à l'envers.
2. **Pull and redeploy** dans Portainer. L'image est reconstruite depuis le dernier commit.
3. **Lis les logs du conteneur `api`** juste après. Les migrations appliquées y apparaissent, et un
   échec y serait visible immédiatement — un serveur qui démarre n'est pas la preuve qu'elles sont
   passées, c'est le journal qui l'est.
4. **Vérifie que le service répond** : `GET /health` doit renvoyer `200`, et le conteneur doit
   passer en `healthy` dans Portainer (le healthcheck met jusqu'à 30 s).

Si une migration échoue, le backend refuse de démarrer plutôt que de tourner sur un schéma
incohérent. Restaure alors la dernière sauvegarde et signale le problème — ne force pas.

**Attention à l'ordre avec l'app.** Une version de l'app plus récente que le backend appelle des
routes qui n'existent pas encore. Déploie toujours le backend **avant** (ou en même temps que) la
mise à jour de l'app.

## Sauvegarde de la base de données

> **Une sauvegarde par intervalle, pas une par redémarrage.** Le service sauvegarde au démarrage
> puis dort `BACKUP_INTERVAL_SECONDS`. Sans garde-fou, chaque redéploiement du stack produisait une
> sauvegarde de plus qui purgeait la plus ancienne : constaté sur un serveur réel, trois
> redéploiements dans la journée et les trois sauvegardes conservées dataient toutes de la même
> après-midi. C'est précisément le moment où l'historique compte — on redéploie parce qu'on change
> quelque chose, et si ce changement abîme les données, les seules sauvegardes restantes lui sont
> postérieures. Le service saute désormais son tour si une sauvegarde plus récente que l'intervalle
> existe déjà.


`docker-compose.yml` inclut un service `backup` (voir `scripts/backup.sh`) qui tourne en continu
à côté de `api` : toutes les 24h par défaut, il prend un instantané cohérent de la base SQLite
vivante (`sqlite3 <db> ".backup ..."` — sûr même en mode WAL, contrairement à un simple `cp`) et
l'écrit dans `./backups/`, en ne gardant que les 3 plus récents (configurable, voir les variables
`BACKUP_INTERVAL_SECONDS`/`BACKUP_KEEP_COUNT` dans `docker-compose.yml` — 3 par défaut désormais,
DÉLIBÉRÉMENT bas pour un serveur à l'espace disque limité, voir juste en dessous ; le défaut du
script lui-même, si cette variable était absente, resterait 14). Démarre automatiquement avec
`docker compose up -d`, rien à activer.

**Si l'espace disque est limité** (ex: 5-6 Go au total pour tout le service) : garder seulement 3
sauvegardes LOCALES suffit largement pour un filet de sécurité tout récent, à condition d'avoir une
VRAIE rétention plus longue ailleurs — voir "Ce que ce mécanisme ne fait PAS" ci-dessous, cette
partie-là reste indispensable, pas juste "conseillée", dans ce cas de figure.

**Ce que ça couvre** : comptes, coffres chiffrés, logs d'audit, relations d'accès d'urgence,
partages, appareils de confiance — tout ce qui vit UNIQUEMENT sur ce serveur. Sans cette
sauvegarde (ou en cas de perte simultanée de `./data` ET `./backups`, ex: disque entier détruit),
tout ça disparaît définitivement — la sauvegarde chiffrée automatique CÔTÉ CLIENT (voir
`../frontend(app)/README.md`) ne couvre que le contenu du coffre de chacun, pas les comptes/
logs/relations gérés par le serveur.

**Ce que ce mécanisme ne fait PAS** : il écrit sur le MÊME disque que `./data` par défaut — une
vraie protection contre une panne disque exige de copier `./backups` ailleurs (un autre disque,
un NAS, un stockage distant) à intervalle régulier ; ce n'est pas automatisé ici, à mettre en
place toi-même selon ton infrastructure (ex: `rsync`/`rclone` planifié vers une destination hors
de cette machine).

**Restaurer** une sauvegarde : arrêter `api` (`docker compose stop api`), remplacer
`./data/vault.db` (et ses fichiers `-wal`/`-shm` s'ils existent) par le fichier voulu dans
`./backups/`, puis relancer (`docker compose start api`).

## Espace disque

Pensé pour tourner sur un serveur à l'espace très limité (quelques Go au total). Ce qui consomme
réellement de l'espace, et comment c'est tenu sous contrôle :

- **Image Docker de `api`** : ~150-200 Mo (`debian:bookworm-slim` + un seul binaire Rust, voir le
  `Dockerfile` — SQLite lié statiquement, aucune dépendance système superflue).
- **`./data/vault.db`** : quelques Ko à quelques Mo pour du texte (comptes, coffres chiffrés), voir
  le plafond des pièces jointes (5 Mo/fichier, 50/utilisateur) pour le pire des cas par compte.
- **`./backups/`** : 3 sauvegardes complètes gardées par défaut (voir la section précédente) — pas
  14, délibérément réduit pour ce genre de déploiement. Si le coffre grossit un jour (beaucoup de
  pièces jointes), c'est CE nombre qu'il faut revoir en premier (chaque sauvegarde = une copie
  complète de `vault.db` à cet instant).
- **`./logs/`** : un fichier JSON par jour (`server.json.AAAA-MM-JJ`), **CORRECTIF** — jusqu'ici, ce
  dossier grossissait indéfiniment (aucune limite de rétention n'était réellement appliquée, malgré
  ce que le code semblait suggérir). Plafonné maintenant à 14 fichiers (~2 semaines) : le plus
  ancien est supprimé automatiquement dès qu'un 15e apparaît (voir `main.rs`, `RUST_LOG=info` par
  défaut dans `docker-compose.yml` — le niveau "debug" produirait des fichiers bien plus gros).
- **Docker lui-même** : les images/couches de build s'accumulent au fil des mises à jour
  (`docker compose build`/`pull`) si rien ne les nettoie — `docker system df` pour voir ce qui est
  utilisé, `docker system prune` (ou `-a` pour aussi les images non taguées) pour récupérer
  l'espace des anciennes images/couches devenues inutiles.

## Exposer ce backend en HTTPS

Par défaut, `docker-compose.yml` expose du HTTP en clair sur le port 3000 — suffisant pour un
usage strictement local (localhost, réseau domestique de confiance). Si tu exposes un jour ce
backend au-delà de ton LAN (accès depuis l'extérieur, nom de domaine), les jetons de session
(`Authorization: Bearer ...`) circuleraient alors en clair sur le réseau sans HTTPS — n'importe
qui en position d'interception (Wi-Fi public, FAI, etc.) pourrait les voler et usurper une session.

**Solution recommandée : [Caddy](https://caddyserver.com/) en reverse proxy devant `api`** — plus
simple qu'nginx + certbot pour un usage personnel : certificat Let's Encrypt obtenu et renouvelé
automatiquement, une seule ligne de configuration par domaine. Ajoute à `docker-compose.yml` :

```yaml
  caddy:
    image: caddy:2-alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
    depends_on:
      - api

volumes:
  caddy_data:
```

Et un fichier `Caddyfile` à côté de `docker-compose.yml` :

```
ton-domaine.exemple.com {
    reverse_proxy api:3000
}
```

(remplace par ton vrai nom de domaine, pointé vers l'IP publique de cette machine — Caddy a besoin
que ce domaine résolve correctement pour obtenir le certificat).

**Deux ajustements nécessaires côté configuration une fois Caddy en place** :

1. `ALLOWED_ORIGINS` (voir la table plus haut) doit inclure l'origine `https://` de chaque client
   web qui appellera désormais le backend via ce domaine plutôt qu'en direct.
2. Si tu veux aussi profiter de la protection par IP du rate limiting (voir `TRUST_PROXY_HEADERS`
   plus haut) plutôt que de voir TOUT le trafic passer pour une seule IP (celle de Caddy), passe
   `TRUST_PROXY_HEADERS=true` — Caddy positionne déjà correctement `X-Forwarded-For` par défaut,
   donc aucune configuration Caddy supplémentaire n'est nécessaire pour ça.

## Tests

```sh
cargo test
```

Chaque module de handler embarque ses propres tests d'intégration (appel direct des fonctions de
route, sur une base SQLite en mémoire avec les vraies migrations). En complément, `main.rs` inclut
des tests de bout en bout qui passent de vraies requêtes HTTP à travers le Router complet (rate
limiting, limites de taille par route, CORS...), pas seulement les handlers pris isolément. Aucune
infrastructure externe n'est nécessaire pour lancer la suite complète.

## Documentation de l'API

- [`docs/API.md`](docs/API.md) — référence lisible de toutes les routes (payloads, réponses,
  codes d'erreur, flux d'authentification, limites de débit).
- [`docs/openapi.yaml`](docs/openapi.yaml) — spécification [OpenAPI 3.0](https://swagger.io/specification/)
  équivalente, exploitable par des outils (Swagger UI, génération de client TypeScript pour
  l'app/l'extension, etc.).

## Licence

[Tous droits réservés](../LICENSE) — commune aux trois projets de ce dépôt (backend, app
desktop/Android, extension). Code public à des fins de consultation uniquement ; aucune
réutilisation, redistribution ou modification n'est autorisée sans permission écrite de l'auteur.
