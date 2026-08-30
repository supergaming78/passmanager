# Extension navigateur PassManager

Extension Manifest V3 : popup de connexion + consultation du coffre. Réutilise la même
cryptographie que l'app desktop (`crypto-core`, compilé en WebAssembly ici — voir
`wasm-bindings/`), jamais de crypto réimplémentée en JS.

Ce qui suit est de la doc **développeur**. Pour un guide destiné aux utilisateurs finaux (comment
créer un compte, ajouter une entrée, partager un mot de passe...), voir
[`../GUIDE_UTILISATEUR.md`](../GUIDE_UTILISATEUR.md).

**Périmètre actuel (Phase 4 + coffres partagés familiaux + partage à usage limité)** : connexion
(avec 2FA si nécessaire), liste du coffre, recherche, copie du mot de passe, ouverture du site,
remplissage automatique (voir ci-dessous), ajout/modification/suppression d'entrée, favoris,
corbeille (restauration/purge), et **trois mécanismes de partage distincts qui coexistent** :
- partage classique d'une entrée entre deux comptes (accès complet, instantané) ;
- **coffres partagés familiaux** (création, invitation/retrait de membres, entrées visibles et
  modifiables EN DIRECT par tous les membres, avec remplissage automatique comme pour le coffre
  personnel — voir `components/SharedVaultDetailView.tsx`/`lib/sharedVault.ts`) ;
- **partage à usage limité "aveugle"** (le destinataire ne voit JAMAIS l'identifiant ni le mot de
  passe, seulement le nom du site, et ne peut le "Remplir" qu'un nombre de fois choisi par
  l'expéditeur, 1 par défaut — voir `components/BlindShareView.tsx`/`lib/blindShare.ts`).

Le partage classique reçu ET le partage à usage limité reçu vivent sur un seul écran commun,
"Partagé avec moi" (`components/SharedReceivedView.tsx`), accessible directement depuis la barre
du coffre — PAS deux boutons séparés, et PAS dans Réglages. Le coffre partagé familial reste sur
son propre écran dédié (ressource commune à plusieurs membres, pas quelque chose qu'on "reçoit"
ponctuellement de la même façon).

Plus : accès d'urgence (contacts de confiance, consultation en lecture seule d'un coffre accordé),
réglages (URL du serveur, délai de verrouillage, effacement du presse-papiers, changement d'email,
gestion des appareils de confiance).

**Volontairement exclu** : le changement de MOT DE PASSE MAÎTRE reste une opération DESKTOP
uniquement — c'est l'opération la plus à risque de toute l'app (export complet du coffre +
historique + pièces jointes, re-chiffrement de tout, ré-envoi atomique, puis rescellement de tous
les partages/accès d'urgence) ; une erreur y corromprait le coffre, et ce chemin ne peut pas être
testé aussi rigoureusement qu'un changement de code habituel. La popup explique ça et renvoie vers
l'app desktop. Également exclus par impossibilité technique (pas par choix) : sauvegarde
automatique (accès disque arbitraire, aucune API équivalente en extension de navigateur) et
déverrouillage rapide Windows Hello (Tauri/Windows uniquement).

## Compatibilité navigateurs

Vérifiée contre la documentation officielle Chrome/Mozilla/Apple (pas supposée) — voir "Firefox
pour Android", "Safari (macOS/iOS)" et "Configuration requise côté backend" plus bas pour le
détail de chaque cas.

| Navigateur | Desktop | Android | Remarque |
|---|---|---|---|
| Chrome, Edge, Brave, Opera, Vivaldi | ✅ | — (voir ci-dessous) | Même moteur d'extensions, même ID (`chrome-extension://hcggmibfhgjcamfehjjdmagbecbkljdj`) partout |
| Firefox | ✅ | ✅ | Nécessite une signature Mozilla même en usage privé (voir "Firefox pour Android") ; origine `moz-extension://<uuid>` différente par profil |
| Quetta (Chromium, Android) | — | ✅ probable, non testé | Seul navigateur Android connu à ce jour supportant le chargement d'extensions Manifest V3 "à la Chrome" ; même ID que Chrome desktop attendu, à confirmer en pratique |
| Chrome/tout navigateur Chromium standard sur Android | — | ❌ | Restriction volontaire de Google — aucune extension installable, quel que soit le code |
| Safari (macOS/iOS) | ⚠️ code prêt, conversion à faire sur Mac | ⚠️ idem (iOS) | Voir "Safari (macOS/iOS)" plus bas — le code de cette extension est déjà compatible (vérifié), mais la conversion en app Xcode nécessite un Mac, que cet outil ne peut pas fournir |

## Remplissage automatique

Le bouton "Remplir" sur une entrée insère l'identifiant/email et le mot de passe dans le
formulaire de connexion de l'onglet actif — premier champ `input[type="password"]` trouvé sur la
page, puis le champ identifiant le plus proche AVANT lui dans le DOM (limitation connue : un
formulaire de CHANGEMENT de mot de passe, avec plusieurs champs "password", remplira le premier).

Avant de remplir, le domaine de l'onglet actif est comparé au domaine enregistré pour l'entrée
(voir `lib/autofill.ts::domainsLikelyMatch`, tolérant aux sous-domaines dans les deux sens) — en
cas de désaccord, une confirmation est demandée plutôt que de remplir silencieusement (protection
contre un remplissage sur un domaine de phishing visuellement identique).

**Modèle de permission volontairement minimal** : `activeTab` + `scripting`, PAS de
`host_permissions`, PAS de script tournant en permanence sur les pages visitées. L'extension n'a
accès à l'onglet actif QUE parce que l'utilisateur vient d'ouvrir la popup (le clic sur l'icône de
l'extension EST le geste qui accorde `activeTab`) — aucune détection automatique de formulaire en
arrière-plan, aucune icône injectée dans les pages. Sur une page où Chrome refuse toute injection
par principe (`chrome://`, Chrome Web Store, visionneuse PDF intégrée...), le bouton affiche
"Impossible de remplir sur cette page." plutôt que d'échouer silencieusement.

## Structure

```
extension/
  manifest.json          Manifest V3 — popup uniquement, pas de background/content_scripts
  extension-key.pem       Clé privée fixe (voir "ID d'extension stable" ci-dessous) — NE PAS PUBLIER
  icons/                  16/32/48/128 px, générées depuis frontend(app)/public/icon.png
  wasm-bindings/          Crate Rust exposant crypto-core en WASM (voir Phase 1)
    pkg-nodejs/             build --target nodejs, utilisé UNIQUEMENT par test-node.js
    pkg-web/                build --target web, utilisé par la popup (voir plus bas)
  popup/                  App React/TS (Vite) — le contenu réel de la popup
    dist/                   build de production, référencé par manifest.json
```

## Construire

```bash
# 1. Rebuild du module WASM si crypto-core ou wasm-bindings/src a changé
cd wasm-bindings
wasm-pack build --target web --out-dir pkg-web

# 2. Build de la popup
cd ../popup
npm install   # une seule fois
npm run build # -> popup/dist/
```

## Charger dans Chrome (développement)

1. `chrome://extensions`
2. Activer le "Mode développeur" (en haut à droite)
3. "Charger l'extension non empaquetée" → sélectionner le dossier `extension/` (celui qui contient
   `manifest.json`, pas `popup/`)

## ID d'extension stable

`manifest.json` embarque une clé publique fixe (`"key"`) dérivée de `extension-key.pem` — sans
ça, Chrome générerait un ID différent à chaque rechargement de l'extension, ce qui casserait la
configuration CORS du backend entre deux essais (voir plus bas). Avec cette clé, l'ID reste
toujours :

```
hcggmibfhgjcamfehjjdmagbecbkljdj
```

Donc l'origine de l'extension est toujours `chrome-extension://hcggmibfhgjcamfehjjdmagbecbkljdj`.
`extension-key.pem` n'a pas besoin d'être secrète comme un mot de passe, mais ne devrait pas être
perdue (l'ID changerait) ni publiée n'importe où sans réflexion (n'importe qui la possédant
pourrait publier une extension avec ce même ID sur le Web Store) — `.gitignore` l'exclut déjà
explicitement pour qu'un futur `git init` + `git add .` ne l'embarque pas par erreur.

## CSP et WebAssembly

`manifest.json` déclare `"content_security_policy": { "extension_pages": "script-src 'self'
'wasm-unsafe-eval'; object-src 'self'" }` — sans `'wasm-unsafe-eval'`, Chrome bloque la
compilation du module WASM par défaut (CSP MV3 standard, rien de spécifique à cette app) avec
l'erreur `neither 'wasm-eval' nor 'unsafe-eval' is an allowed source`. `'wasm-unsafe-eval'` est le
seul mot-clé de ce type accepté par le validateur de manifest MV3 (contrairement à `'unsafe-eval'`,
qui autoriserait aussi `eval()`/`new Function()` — interdit en MV3) : il n'autorise QUE
l'instanciation WebAssembly, rien de plus.

## Firefox pour Android

**Chrome pour Android ne supporte AUCUNE extension** — pas de `chrome://extensions`, pas de
chargement "non empaquetée", pas d'installation depuis le Web Store sur mobile. C'est une
restriction volontaire de Google, rien à voir avec le code de cette extension : elle ne peut donc
tourner que sur Firefox pour Android côté mobile.

`manifest.json` déclare `browser_specific_settings` (`gecko.id` + `gecko_android`) pour être
reconnue par Firefox — obligatoire pour la signature MV3, sinon Firefox refuse l'extension. Version
minimale fixée à 115 (première version supportant `storage.session`, utilisé pour les jetons de
session — voir lib/session.ts) ; le CSP `'wasm-unsafe-eval'` ci-dessus est supporté depuis Firefox
103, donc déjà couvert. Ces deux exigences sont vérifiées contre la doc MDN/Mozilla, pas supposées.

**Contrairement à Chrome, Firefox exige que TOUTE extension soit signée par Mozilla pour
s'installer** — y compris en usage privé, pas seulement pour publication sur addons.mozilla.org
(AMO). Il n'y a pas d'équivalent de "charger l'extension non empaquetée" sur Firefox Android pour
un usage permanent. Deux chemins possibles :

1. **Test/développement (temporaire)** : `web-ext run -t firefox-android --adb-device <id> --firefox-apk <package>`
   (nécessite `web-ext` ≥ 7.12.0, Android Platform Tools/`adb` dans le PATH, débogage USB activé
   sur le téléphone, câble USB). L'extension se charge dans le profil principal du téléphone mais
   se décharge à la fin de la session `web-ext run` — pratique pour vérifier que tout fonctionne,
   pas pour un usage quotidien.
2. **Usage permanent** : créer un compte développeur gratuit sur
   [addons.mozilla.org](https://addons.mozilla.org), puis signer l'extension en mode **non répertorié**
   (`web-ext sign --channel=unlisted`, avec les identifiants API AMO) — ça ne la publie PAS
   publiquement, ça produit juste un `.xpi` signé par Mozilla. Transférer ce `.xpi` sur le
   téléphone, puis (Android 10+) : dans Firefox, taper plusieurs fois sur le logo Firefox dans
   `about:firefox` pour activer le menu de débogage caché, puis Réglages → Extensions →
   "Installer une extension depuis un fichier".

Aucune de ces deux étapes n'est automatisable depuis cet outil (nécessite un appareil Android
physique connecté et/ou un compte Mozilla personnel) — le code est prêt, mais l'installation reste
à faire manuellement en suivant l'un des deux chemins ci-dessus.

## Safari (macOS/iOS)

**Blocage dur, différent des cas Chrome/Firefox ci-dessus** : convertir en Safari Web Extension
nécessite `xcrun safari-web-extension-converter`, un outil livré avec Xcode — **Xcode ne tourne
que sur macOS**, aucun contournement possible depuis Windows/Linux. Cette conversion ne peut donc
pas être terminée depuis cet environnement, contrairement à tout le reste de cet audit. Ce qui
suit est le travail de préparation fait à l'avance (vérifié contre la doc Apple/MDN, pas supposé)
plus la procédure exacte à suivre sur un Mac.

**Compatibilité du code déjà vérifiée** — aucun changement de code nécessaire avant la conversion :
- Safari expose `chrome.*` comme un ALIAS de `browser.*` (comme Firefox) — le code de cette
  extension utilise déjà exclusivement `chrome.*`, donc pas de portage vers `browser.*` à faire.
- `chrome.storage.session` (utilisé pour les jetons de session, voir lib/session.ts) : supporté
  depuis Safari/iOS 16.4 (2023) — largement couvert par toute version de Safari encore maintenue
  aujourd'hui.
- `chrome.scripting.executeScript` (remplissage automatique, voir lib/autofill.ts) : supporté par
  Safari aussi bien en Manifest V2 qu'en V3.
- Le CSP `'wasm-unsafe-eval'` (voir "CSP et WebAssembly" ci-dessus) : nécessaire au chargement du
  module WASM, supporté par le modèle CSP MV3 standard qu'Apple a adopté avec le reste de
  l'écosystème.

**Procédure à suivre sur un Mac avec Xcode installé** (commande vérifiée contre la doc Apple) :

```sh
cd popup && npm run build && cd ..   # build à jour avant conversion, comme pour Chrome/Firefox
xcrun safari-web-extension-converter . \
  --app-name PassManager \
  --bundle-identifier com.julie.passmanager.safari \
  --swift \
  --copy-resources
```

Ouvre le projet Xcode généré, choisis ton identifiant de signature (compte Apple, gratuit pour un
usage personnel sur ton propre appareil — un compte développeur payant n'est requis que pour
distribuer publiquement sur l'App Store), puis build & run. Sur iOS, il faut en plus activer
l'extension dans Réglages → Safari → Extensions une fois l'app installée sur l'appareil.

Comme pour Firefox, je ne peux pas te garantir que la conversion se déroule sans accroc que je
n'aurais pas anticipé (icônes, entitlements, quirks spécifiques à une version de Safari) sans
pouvoir l'exécuter moi-même — seul un vrai test sur Mac le confirmera.

## Configuration requise côté backend

La popup appelle l'API backend directement en `fetch()` depuis son origine. Le backend doit
l'autoriser dans sa configuration CORS — ajouter cette origine à `ALLOWED_ORIGINS` (voir
`backend/.env`, déjà une liste séparée par des virgules). **L'origine change selon le NAVIGATEUR
(pas juste l'OS)**, un même appareil peut donc avoir besoin de PLUSIEURS origines dans la liste :

- **Chrome, Edge, Brave, Opera, Vivaldi (desktop) et tout navigateur Chromium sur Android
  (ex: Quetta)** : tous dérivent l'ID d'extension de la MÊME façon (déterministe, à partir de la
  clé publique `"key"` du manifest — voir "ID d'extension stable" plus haut) — une SEULE origine
  couvre donc tous ces navigateurs à la fois, chargée dans lequel qu'ils soient :
  ```
  chrome-extension://hcggmibfhgjcamfehjjdmagbecbkljdj
  ```
- **Firefox (desktop ET Android)** : origine `moz-extension://<uuid>` — CET UUID N'EST PAS
  PRÉVISIBLE À L'AVANCE, contrairement à Chrome. Même avec `browser_specific_settings.gecko.id`
  fixé dans le manifest (voir "Firefox pour Android" plus haut), Firefox génère un UUID aléatoire
  à la PREMIÈRE installation sur un profil donné, puis le garde stable ensuite sur CE profil —
  donc à découvrir une fois l'extension installée, PAS à deviner avant. Pour le trouver :
  `about:debugging#/runtime/this-firefox` (colonne "Internal UUID" de l'extension) sur desktop,
  ou `about:addons` → détails de l'extension sur Android. Cet UUID sera DIFFÉRENT sur chaque
  profil Firefox distinct (desktop et Android comptent comme deux profils séparés) — donc
  potentiellement DEUX origines `moz-extension://` à ajouter si tu utilises Firefox sur les deux.

Exemple complet avec les trois familles :
```
ALLOWED_ORIGINS=http://localhost:1420,http://localhost:5173,chrome-extension://hcggmibfhgjcamfehjjdmagbecbkljdj,moz-extension://<uuid-desktop>,moz-extension://<uuid-android>
```

Puis redémarrer le backend. Sans l'origine correspondante, la popup affichera une erreur réseau à
la connexion — le serveur reçoit bien la requête, mais le navigateur bloque la LECTURE de la
réponse (politique CORS standard, rien de spécifique à cette app ni à un navigateur en particulier).

## Garde de la clé du coffre

Contrairement à l'app desktop (clé jamais transmise au JS, toujours gardée côté Rust), le module
WASM renvoie la `vault_key` brute au JS — inévitable pour que la popup puisse déchiffrer. Voir
`popup/src/lib/session.ts` pour le compromis retenu : la clé est gardée en mémoire navigateur
(`chrome.storage.session`, jamais écrite sur disque, effacée à la fermeture du navigateur) pendant
5 minutes glissantes à partir de la dernière ouverture de la popup (réglable dans "Réglages") ;
passé ce délai, le mot de passe maître doit être ressaisi.

L'accès d'urgence et le partage d'entrée (voir `popup/src/lib/emergencyAccess.ts` et
`popup/src/lib/entrySharing.ts`) recomposent en TypeScript les mêmes 8 commandes Tauri que le
desktop, à partir des fonctions WASM déjà exportées (`generate_keypair`, `seal`, `unseal`,
`seal_for_share`, `unseal_share`) — aucun nouveau code Rust n'a été nécessaire. La clé du coffre
d'un propriétaire ayant accordé un accès d'urgence est déverrouillée en mémoire JS locale au
composant qui l'affiche (jamais dans `chrome.storage.session`, un accès occasionnel/lecture seule
n'a pas besoin de survivre à une fermeture de popup) — même modèle déjà accepté pour la clé de
coffre principale, appliqué une seconde fois.

## Licence

[Tous droits réservés](../LICENSE) — commune aux trois projets de ce dépôt (backend, app
desktop/Android, extension). Code public à des fins de consultation uniquement ; aucune
réutilisation, redistribution ou modification n'est autorisée sans permission écrite de l'auteur.
