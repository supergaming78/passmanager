# App — Gestionnaire de mots de passe (Tauri)

Client desktop [Tauri v2](https://v2.tauri.app/) (couche native Rust + interface web React/
TypeScript) pour un gestionnaire de mots de passe **Zero-Knowledge**, consommant l'API du
[backend](../backend). Le serveur ne voit et ne stocke jamais le mot de passe maître, ni la clé qui
chiffre le coffre : toute la cryptographie a lieu ici, côté client, en Rust natif.

Ce dépôt contient aussi une [extension navigateur](../extension) (Manifest V3 — Chrome, Edge,
Brave, Opera, Vivaldi, Firefox desktop et Android ; voir `../extension/README.md#compatibilité-navigateurs`
pour le détail par navigateur) qui réutilise la même cryptographie compilée en WebAssembly
(`crypto-core`, partagée avec ce client via `src-tauri/Cargo.toml`).

Ce qui suit est de la doc **développeur**. Pour un guide destiné aux utilisateurs finaux de cette
app (comment créer un compte, ajouter une entrée, partager un mot de passe...), voir
[`../GUIDE_UTILISATEUR.md`](../GUIDE_UTILISATEUR.md).

## Sommaire

- [Architecture en bref](#architecture-en-bref)
- [Prérequis](#prérequis)
- [Configuration](#configuration)
- [Lancer en développement](#lancer-en-développement)
- [Compiler pour la production](#compiler-pour-la-production)
- [Organisation du code](#organisation-du-code)
- [Fonctionnalités](#fonctionnalités)
- [Mises à jour automatiques](#mises-à-jour-automatiques)
- [Tests](#tests)
- [Documentation associée](#documentation-associée)
- [IDE recommandé](#ide-recommandé)

## Architecture en bref

- **Tauri v2** : une couche native Rust (`src-tauri/`, un vrai processus, pas un sandbox JS) pilote
  une webview système affichant l'interface React/TypeScript (`src/`). Les deux communiquent via des
  *commandes* (`invoke()` côté JS ↔ `#[tauri::command]` côté Rust).
- **Zero-Knowledge, une règle non négociable** : TOUTE la cryptographie (dérivation de clé,
  chiffrement/déchiffrement des champs, hachage) vit dans `src-tauri/src/crypto.rs` et les modules
  associés, **jamais en JavaScript**. Le code TypeScript n'appelle que des commandes Tauri déjà
  chiffrées/déchiffrées ; il ne voit jamais la clé du coffre en clair, ni ne manipule de primitive
  cryptographique lui-même.
- **Dérivation de clé** : Argon2id (mêmes paramètres renforcés que le serveur) puis HKDF-SHA256
  sépare la sortie unique en deux sous-clés indépendantes — l'une envoyée au serveur (hash
  d'authentification), l'autre gardée exclusivement en local (clé de chiffrement du coffre).
- **Chiffrement du contenu** : AES-256-GCM appliqué champ par champ (site, identifiant, mot de
  passe, notes, URL, champs additionnels des types dédiés...), nonce aléatoire à chaque appel,
  encodage base64 pour le transport.
- **Accès d'urgence & partage d'entrée** : une "boîte scellée" X25519 + HKDF-SHA256 + AES-256-GCM
  (chiffrement anonyme vers une clé publique) — une seule paire de clés par utilisateur, séparée
  par domaine HKDF entre les deux usages pour qu'ils restent cryptographiquement étanches l'un de
  l'autre (voir `src-tauri/src/emergency.rs`/`sharing.rs`).
- **Déverrouillage rapide (Windows uniquement)** : DPAPI (`dpapi.rs`) protège un blob contenant la
  clé du coffre, lié au compte Windows de la session ; Windows Hello (`quick_unlock.rs`,
  `UserConsentVerifier`) est le geste demandé à chaque déverrouillage. Le mot de passe maître reste
  toujours utilisable en repli, sur toutes les plateformes.
- **Android** : même code React/TS et même crypto Rust que le desktop (`crypto-core` partagé,
  aucune divergence) — voir `src-tauri/gen/android/`. Pas de déverrouillage rapide (Windows Hello
  uniquement, voir ci-dessus) : toujours le mot de passe maître sur Android. Durcissement
  spécifique à la plateforme : `FLAG_SECURE` activé (`MainActivity.kt`) pour empêcher toute capture
  d'écran/vignette "Applications récentes" pendant que le coffre est déverrouillé.
- **Aucune URL de backend figée** : configurable directement dans l'app (écran "Serveur", voir
  `src/lib/settings.ts::getBackendUrl`/`setBackendUrl`) — ce client peut pointer vers n'importe
  quelle instance du backend auto-hébergée par l'utilisateur, pas une seule adresse fixe au build.

## Prérequis

- Node.js 18+ et npm.
- Rust stable + Cargo (même toolchain que le [backend](../backend)).
- La [CLI Tauri](https://v2.tauri.app/reference/cli/) (déjà en devDependency, invoquée via
  `npm run tauri`).
- **Windows** : dépendances système Tauri habituelles (WebView2, déjà présent sur Windows 10/11 à
  jour).
- **macOS/Linux** : voir les [prérequis officiels Tauri](https://v2.tauri.app/start/prerequisites/)
  (Xcode / webkit2gtk selon la plateforme) — le déverrouillage rapide (Windows Hello) est alors
  simplement indisponible, l'app retombe sur la saisie du mot de passe maître.
- **Android** : Android Studio + le SDK/NDK Android, plus les cibles Rust correspondantes
  (`rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
  i686-linux-android`) — voir les [prérequis mobile officiels Tauri](https://v2.tauri.app/start/prerequisites/#android).
  `src-tauri/gen/android/` est déjà généré (`tauri android init` n'est pas à refaire).

## Configuration

Pas de fichier `.env` pour ce client : l'URL du backend se configure **dans l'app elle-même**
(écran "Serveur", premier lancement ou Réglages), stockée en local, modifiable à tout moment — voir
`src/lib/settings.ts`. Aucune adresse n'est codée en dur au build.

## Lancer en développement

```sh
npm install
npm run tauri dev
```

Ouvre la fenêtre native de l'app avec rechargement à chaud, aussi bien côté interface (Vite) que
côté couche native Rust. `npm run dev` seul ne lance que le serveur Vite (utile pour itérer
rapidement sur l'UI dans un navigateur classique), mais dans ce mode les commandes Tauri — donc
toute la cryptographie — ne sont pas disponibles.

Pour Android (émulateur ou appareil connecté via ADB) :

```sh
npm run tauri android dev
```

## Compiler pour la production

```sh
npm run tauri build
```

Produit un installeur natif pour la plateforme courante (l'emplacement exact du binaire/installeur
est indiqué dans la sortie de la commande). Pour Android :

```sh
npm run tauri android build
```

Produit un `.apk`/`.aab` dans `src-tauri/gen/android/app/build/outputs/` — nécessite une identité
de signature (keystore) pour un build `release` installable/distribuable ; voir la
[doc officielle de signature Android de Tauri](https://v2.tauri.app/distribute/sign/android/).

## Organisation du code

### `src/` — interface web (React/TypeScript)

```
api/
  client.ts               Appels HTTP vers le backend (un wrapper par route)
  tauri.ts                Wrappers fins autour des commandes Tauri (invoke()) — jamais de crypto ici
  types.ts                Types miroir des modèles backend (snake_case, alignés sur backend/src/models.rs)
state/
  AuthContext.tsx          Session, tokens, verrouillage du coffre, synchronisation temps réel
lib/                        Logique métier pure (aucun JSX), un fichier par domaine, notamment :
  vaultCrypto.ts             Conversion forme chiffrée <-> PlainVaultEntry (délègue tout à api/tauri.ts)
  vaultFile.ts               Import/export de fichier (JSON/CSV/TXT), sauvegarde chiffrée automatique
  entrySharing.ts            Partage sécurisé d'une entrée entre deux comptes
  sharedVault.ts              Coffres partagés familiaux (clé symétrique, mise à jour en direct)
  blindShare.ts                Partage à usage limité ("aveugle" — jamais l'identifiant/le mot de passe)
  emergencyAccess.ts         Accès d'urgence (contact de confiance)
  passwordChangeCrypto.ts    Re-chiffrement en masse lors d'un changement de mot de passe maître
  breachCheck.ts             Vérification de fuite (HIBP, k-anonymat, strictement opt-in)
  fuzzyMatch.ts               Tolérance aux fautes de frappe pour la recherche du coffre
  siteAvatar.ts, knownLogos*.ts   Reconnaissance de marque pour l'icône affichée par entrée
components/                  Composants React réutilisables (formulaires, modales, panneaux de réglages)
pages/                       Un composant par route (voir App.tsx pour le routing)
```

### `src-tauri/src/` — couche native (Rust)

```
lib.rs             Déclare toutes les commandes Tauri (invoke()) exposées au frontend
crypto.rs           Dérivation de clé, chiffrement/déchiffrement AES-256-GCM, SHA-1 (voir breachCheck.ts)
emergency.rs         Boîte scellée X25519 pour l'accès d'urgence
sharing.rs           Même primitive, domaine HKDF séparé, pour le partage d'entrée
dpapi.rs            Protection DPAPI du blob de clé (déverrouillage rapide, Windows)
quick_unlock.rs      Windows Hello (UserConsentVerifier)
state.rs            État partagé du processus (clé du coffre actuellement déverrouillée, le cas échéant)
```

## Fonctionnalités

- Coffre chiffré de bout en bout, synchronisé en temps réel entre appareils (WebSocket).
- Types d'entrée dédiés : identifiant, carte bancaire, identité, note sécurisée.
- Pièces jointes chiffrées, historique des mots de passe, corbeille.
- Trois mécanismes de partage distincts, qui coexistent : partage classique d'une entrée entre
  deux comptes (accès complet, instantané) ; coffres partagés familiaux (plusieurs membres, mis à
  jour en direct pour tous) ; partage à usage limité "aveugle" (le destinataire ne voit jamais
  l'identifiant ni le mot de passe, seulement le nom du site, et ne peut l'utiliser qu'un nombre de
  fois choisi par l'expéditeur — 1 par défaut). Le partage classique reçu ET le partage à usage
  limité reçu vivent sur un seul écran commun "Partagé avec moi" (`pages/SharedReceivedPage.tsx`),
  accessible directement depuis le coffre — pas dans Réglages. Accès d'urgence via un contact de
  confiance.
- Import (Chrome/Firefox/LastPass/KeePass/Bitwarden/1Password, ancien format maison) et export
  JSON/CSV/TXT (avec chiffrement optionnel par un mot de passe séparé) ; sauvegarde chiffrée
  automatique (désactivée par défaut, à activer explicitement dans Réglages).
- Générateur de mots de passe/phrases de passe, indicateur de force, vérification de fuite (HIBP,
  action explicite uniquement — jamais automatique).
- Tableau de bord "Santé du coffre" (faibles, réutilisés, anciens, compromis, score, répartition).
- Recherche tolérante aux fautes de frappe, filtres rapides, dossiers, favoris.
- Déverrouillage rapide par Windows Hello, avec repli toujours possible sur le mot de passe maître.
- Historique de sécurité consultable (connexions, changements, partages) et alerte email sur
  connexion depuis une adresse IP inhabituelle.
- Icônes de marque reconnues automatiquement pour la plupart des sites courants.
- Signalement de bug (`components/BugReportModal.tsx`) — accessible même sans être connecté (un
  bug qui empêche justement la connexion doit pouvoir être signalé), consultable par un modérateur
  dans Administration.

## Mises à jour automatiques

### Desktop (Windows/macOS/Linux) — installation 100% automatique

Aucune action requise : `components/DesktopAutoUpdater.tsx` vérifie une fois au lancement de l'app,
puis télécharge, installe et relance automatiquement si une version plus récente existe — un simple
bandeau informatif s'affiche pendant le téléchargement (pour ne pas surprendre par un redémarrage
sans prévenir), aucun bouton à cliquer. Un bouton "Vérifier les mises à jour" reste disponible dans
Réglages (`components/AppUpdateSettings.tsx`) pour forcer une vérification immédiate, mais ce n'est
plus le chemin normal.

- Le client interroge le manifeste `latest.json` publié sur les GitHub Releases de ce dépôt (URL
  exacte dans `src-tauri/tauri.conf.json::plugins.updater.endpoints` — **à ajuster** si le dépôt
  GitHub réel n'est pas `supergaming78/passmanager`, un nom deviné en l'absence du dépôt réel au
  moment où ce code a été écrit).
- Chaque installeur est signé (voir `src-tauri/tauri.conf.json::plugins.updater.pubkey`, la clé
  publique correspondant à `src-tauri/tauri-updater.key` — clé privée générée localement,
  **jamais commitée**, voir le `.gitignore` racine) : l'app refuse d'installer un `latest.json`/
  installeur qui ne serait pas signé par cette clé, ce qui empêche un GitHub compromis (ou un
  miroir/CDN intermédiaire) de pousser une mise à jour falsifiée.
- **Si la clé privée de signature est perdue**, il est impossible de signer une future mise à jour
  reconnue par les installations déjà en circulation : en garder une copie de sauvegarde hors du
  dépôt (gestionnaire de mots de passe/coffre séparé, par exemple) est fortement recommandé.

### Android — bandeau d'invitation, PAS d'installation automatique

Techniquement impossible de faire plus sans passer par le Play Store (décliné pour l'instant, coût
et revue) : Android exige TOUJOURS une confirmation système avant d'installer un APK, même signé —
aucun code, même sur cet appareil, ne peut contourner ça pour une app installée hors store.

À la place : `components/MobileUpdateBanner.tsx` compare, à chaque ouverture de l'app, le numéro de
version courant au même `latest.json` que le desktop (même version applicative pour les deux, un
seul tag `app-v*` couvre les deux à la fois) — si une version plus récente existe, un bandeau
apparaît avec un lien direct vers la page de release GitHub, où l'utilisateur télécharge et installe
l'APK lui-même (une seule confirmation système à valider). Le bandeau réapparaît à chaque ouverture
tant que la version n'a pas été mise à jour (le "×" ne le masque que pour la session en cours).

### Publier une nouvelle version (desktop + Android ensemble)

Bump `version` dans `src-tauri/tauri.conf.json` + `src-tauri/Cargo.toml` + `package.json` +
`versionName`/`versionCode` dans `src-tauri/gen/android/app/build.gradle.kts` (ou via
`tauri.properties`), puis pousser un tag `app-vX.Y.Z` — le workflow
[`.github/workflows/release-app.yml`](../.github/workflows/release-app.yml) (basé sur
[`tauri-apps/tauri-action`](https://github.com/tauri-apps/tauri-action) pour le desktop, appel
direct à la CLI Tauri pour Android) compile desktop (3 OS) ET un APK Android signé, publie le tout
comme **une seule release GitHub en brouillon** (`releaseDraft: true` — relecture manuelle avant que
les utilisateurs existants ne la voient). **⚠️ Ce workflow n'a pas encore été exécuté pour de vrai**
(pas de dépôt GitHub créé au moment de son écriture) — à déboguer au premier tag poussé, comme tout
nouveau pipeline CI.

Secrets à configurer une seule fois (Settings > Secrets and variables > Actions du dépôt GitHub) :
- `TAURI_SIGNING_PRIVATE_KEY` / `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` (desktop, voir ci-dessus).
- `ANDROID_KEYSTORE_BASE64` (contenu de `src-tauri/gen/android/passmanager-release.keystore`,
  généré localement via `keytool`, encodé en base64 — **jamais commité**, voir
  `src-tauri/gen/android/.gitignore`), `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`. **Même
  mise en garde que pour la clé desktop** : sans ce keystore, impossible de publier une mise à jour
  qu'Android accepterait d'installer par-dessus une version déjà installée (Android refuse une
  APK signée par une clé différente de celle déjà en place) — à sauvegarder précieusement.

L'extension navigateur, elle, se met à jour via le mécanisme natif du navigateur une fois publiée
(Chrome Web Store ou signature AMO pour Firefox) — voir `../extension/README.md`, aucun code de
mise à jour custom nécessaire côté extension.

## Tests

```sh
cd src-tauri
cargo test
cargo clippy --tests -- -D warnings
```

Il n'y a pas de suite de tests JS dans ce projet — la vérification côté interface passe par une
compilation stricte :

```sh
npm run build
```

(exécute `tsc` en mode strict puis le build Vite ; toute erreur de type fait échouer la commande.)

## Documentation associée

- [`backend/README.md`](../backend/README.md) — serveur : architecture, configuration, déploiement.
- [`backend/docs/API.md`](../backend/docs/API.md) — référence complète de l'API HTTP consommée par
  ce client.

## IDE recommandé

[VS Code](https://code.visualstudio.com/) avec les extensions
[Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) et
[rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer).

## Licence

[Tous droits réservés](../LICENSE) — commune aux trois projets de ce dépôt (backend, app
desktop/Android, extension). Code public à des fins de consultation uniquement ; aucune
réutilisation, redistribution ou modification n'est autorisée sans permission écrite de l'auteur.
