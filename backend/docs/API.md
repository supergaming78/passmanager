# Référence API

Documentation de toutes les routes exposées par le backend. Pour un contrat machine-readable
(génération de client, Swagger UI...), voir [`openapi.yaml`](openapi.yaml).

## Sommaire

- [Conventions générales](#conventions-générales)
- [Modèle d'authentification](#modèle-dauthentification)
- [Limitation de débit (rate limiting)](#limitation-de-débit-rate-limiting)
- [Format des erreurs](#format-des-erreurs)
- [Authentification](#endpoints--authentification)
- [Coffre-fort](#endpoints--coffre-fort-vault)
- [Appareils de confiance](#endpoints--appareils-de-confiance)
- [Accès d'urgence](#endpoints--accès-durgence)
- [Partage d'entrée](#endpoints--partage-dentrée)
- [Coffres partagés familiaux](#endpoints--coffres-partagés-familiaux)
- [Partage à usage limité](#endpoints--partage-à-usage-limité)
- [Synchronisation temps réel](#endpoints--synchronisation-temps-réel)
- [Administration](#endpoints--administration)
- [Divers](#endpoints--divers)

## Conventions générales

- Toutes les requêtes et réponses avec un corps utilisent `Content-Type: application/json`,
  **sauf** `POST /auth/register` qui répond en texte brut (`"OK"`) — historique, à garder en tête
  côté client si tu ne veux pas faire échouer un `response.json()`.
- Une réponse sans corps (`204 No Content`, ou certains `200`/`202` volontairement vides) ne
  contient aucun JSON à parser.
- Les champs préfixés `encrypted_` sont des blobs **déjà chiffrés côté client** (Zero-Knowledge) :
  le serveur les stocke et les renvoie tels quels, sans jamais les déchiffrer, les comparer ou les
  trier par contenu. Aucune recherche côté serveur n'est possible sur ces champs — le filtrage/tri
  doit se faire côté client après déchiffrement.
- `master_password_hash` (et ses variantes `old_`/`new_`) n'est **jamais** le mot de passe maître
  en clair : c'est un hash d'authentification dérivé localement par le client (Argon2id/PBKDF2) à
  partir du mot de passe maître. Le serveur ne doit jamais recevoir le mot de passe maître lui-même.

## Modèle d'authentification

1. **Inscription** (`POST /auth/register`) crée un compte **non vérifié** et envoie un code à 6
   chiffres par email. Le compte est inutilisable pour se connecter tant que ce code n'a pas été
   confirmé via `POST /auth/verify-email`.
2. **Connexion** (`POST /auth/login`) :
   - Si l'appareil (`device_id`) est déjà "de confiance" pour ce compte : renvoie directement un
     `access_token` (JWT) et un `refresh_token`.
   - Sinon : renvoie `202 { "status": "2FA_REQUIRED" }` et envoie un code à 6 chiffres par email.
     Le client doit ensuite appeler `POST /auth/verify-device` avec ce code pour enregistrer
     l'appareil comme "de confiance", **puis rappeler `/auth/login`** pour obtenir les tokens.
3. **Access token** : JWT signé HMAC-SHA256, durée de vie courte (`ACCESS_TOKEN_SECONDS`, 600s par
   défaut). À envoyer dans l'en-tête `Authorization: Bearer <access_token>` sur toutes les routes
   authentifiées.
4. **Refresh token** : chaîne opaque aléatoire (jamais un JWT), à durée de vie plus longue
   (`REFRESH_TOKEN_HOURS` si "se souvenir de moi", sinon `REFRESH_TOKEN_SHORT_SECONDS`). Consommé
   à **usage unique** : chaque appel à `POST /auth/refresh` le fait tourner (rotation) — l'ancien
   refresh token ne fonctionne plus après coup, même s'il n'a pas expiré.
5. **Invalidation immédiate de session** : un access token déjà émis est rejeté (même s'il n'a pas
   encore expiré) dès que l'un de ces événements survient sur le compte :
   - changement de mot de passe volontaire (`PUT /auth/password`) ;
   - réinitialisation de mot de passe oublié (`POST /auth/reset-password`) ;
   - déconnexion globale volontaire (`POST /devices/logout-all`).
   Dans ces trois cas, toutes les requêtes authentifiées suivantes avec l'ancien access token
   renvoient `401`, obligeant le client à se reconnecter.
6. **WebSocket** : `GET /ws` ne s'authentifie **pas** avec l'access token directement (l'API
   WebSocket des navigateurs ne permet pas d'en-tête `Authorization` à l'ouverture). Le client doit
   d'abord échanger son access token contre un ticket à usage unique via `POST /ws/ticket`, puis
   ouvrir la connexion avec `GET /ws?ticket=<ticket>`. `POST /devices/logout-all` ferme
   activement toute connexion `/ws` déjà ouverte pour ce compte (pas seulement les futures
   requêtes REST) : le serveur diffuse un événement interne que le client reçoit juste avant la
   fermeture du socket.

## Limitation de débit (rate limiting)

Trois paliers, par adresse IP (voir `TRUST_PROXY_HEADERS` dans `../README.md` — désactivé par
défaut, l'identification reste sur l'IP du pair TCP direct tant que ce backend n'est pas
explicitement déclaré derrière un reverse proxy de confiance) :

| Palier | Routes concernées | Limite |
|---|---|---|
| Sensible | `POST /auth/register`, `/login`, `/verify-email`, `/resend-verification`, `/forgot-password`, `/reset-password`, `/verify-device` ; `PUT /auth/email`, `/auth/password` ; `PUT /admin/users/{email}/role`, `/admin/users/{email}/email`, `/admin/users/{email}/extension-email-change`, `/admin/users/extension-email-change-all`, `/admin/users/{email}/server-choice`, `/admin/users/server-choice-all`, `/admin/server-choice-at-login`, `/admin/registration-open`, `/admin/users/{email}/suspended` ; `POST /admin/users/{email}/revoke-sessions` ; `DELETE /admin/users/{email}` | 10 req/s, rafale de 30 |
| Signalement de bug | `POST /bug-reports` | 8 req/s, rafale de 16 — palier dédié, plus permissif que "Sensible" (pas de risque de brute-force ici, juste éviter qu'une famille derrière la même IP se bloque mutuellement) mais toujours en deçà du palier Global |
| Auth (reste) | `POST /auth/logout`, `/refresh` | 60 req/s, rafale de 150 |
| Global | Toutes les autres routes (`/vault/*`, `/devices/*`, `/ws/*`, `/me`, `/audit`, `GET /admin/users`, `/theme-profiles*`, `/theme-preference`...) | 200 req/s, rafale de 500 |

Un dépassement renvoie `429 Too Many Requests` avec un en-tête `Retry-After` (secondes avant que
la rafale se recharge — voir la crate `governor`, ce n'est PAS un blocage permanent : il n'y a
jamais besoin de redémarrer le serveur pour qu'il se résorbe). Les routes `/auth/*` sensibles
cumulent le palier "Sensible" **et** le palier "Auth" (le plus strict des deux s'applique de
fait) ; les 6 routes `/admin/users/*` mutantes ci-dessus sont hors du groupe `/auth`, donc
uniquement sur le palier "Sensible" (pas de cumul avec "Auth").

Toute requête dépassant **30 secondes** (ex: un envoi SMTP qui traîne) est coupée avec
`408 Request Timeout` et `{ "error": "La requête a pris trop de temps" }`.

## Format des erreurs

Toute erreur applicative renvoie `{ "error": "<message>" }` avec un code HTTP parmi :

| Code | Cas |
|---|---|
| `400` | Validation du payload échouée, ou message spécifique (ex: email pas encore vérifié, re-chiffrement incomplet, plafond d'appareils atteint) |
| `401` | Identifiants incorrects, session/token expiré ou invalidé, compte introuvable |
| `403` | Droits insuffisants (ex: `/audit` par un non-admin) |
| `404` | Ressource introuvable ou n'appartenant pas à l'appelant |
| `408` | Requête trop longue (timeout global de 30s) |
| `409` | Conflit (ex: doublon en base) |
| `429` | Limite de débit dépassée |
| `500` | Erreur interne (hachage, jeton, base de données) — message volontairement générique, jamais de détail technique exposé au client |

## Endpoints — Authentification

Toutes les routes ci-dessous sont préfixées par `/auth`.

### `POST /auth/register`

Crée un compte. **Aucune authentification requise.**

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `email` | string | oui | format email valide |
| `master_password_hash` | string | oui | 6-128 caractères |
| `device_id` | string | oui | identifiant stable de l'appareil (ignoré ici, seulement utile au login) |
| `remember_me` | bool | non | ignoré à l'inscription |
| `max_trusted_devices` | number | non | 1-50, défaut 10 — plafond d'appareils de confiance pour ce compte |

**Réponse** : `201 Created`, corps texte brut `"OK"` (pas de JSON).
**Erreurs** : `400` validation, `409` email déjà utilisé.
**Effet de bord** : envoie un code de vérification à 6 chiffres par email (expire en 30 min).


### `POST /auth/verify-email`

Confirme le code reçu à l'inscription.

| Champ | Type | Requis |
|---|---|---|
| `email` | string | oui |
| `code` | string | oui |

**Réponse** : `200 OK`, corps vide.
**Erreurs** : `400` code incorrect/expiré/aucun code en attente, ou trop de tentatives (5 max, le
code est alors définitivement invalidé — il faut se réinscrire).

### `POST /auth/resend-verification`

Renvoie un nouveau code de vérification (le précédent expire ou a été perdu).

| Champ | Type | Requis |
|---|---|---|
| `email` | string | oui |

**Réponse** : `202 Accepted`, corps vide, **dans tous les cas** — email inconnu ou déjà vérifié
inclus (anti-énumération de comptes). Aucun nouveau code n'est généré si le compte n'existe pas ou
est déjà vérifié.

**Cooldown anti-email-bombing (60 s par adresse)** : si un code de vérification a déjà été émis
pour cette adresse il y a moins de 60 secondes, la requête répond le même `202` mais **aucun email
n'est envoyé et le code en cours reste inchangé**. Le rate limiting par IP ne suffisait pas ici :
cette route expédie un email vers une adresse choisie par l'appelant, donc une adresse ciblée
restait inondable depuis plusieurs IP. Le code déjà reçu par l'utilisateur légitime reste valide.

### `POST /auth/login`

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `email` | string | oui | format email valide |
| `master_password_hash` | string | oui | 6-128 caractères |
| `device_id` | string | oui | |
| `remember_me` | bool | non | détermine la durée du refresh token |
| `max_trusted_devices` | number | non | ignoré au login |

**Réponses possibles** :
- `200 OK` — appareil de confiance :
  ```json
  { "access_token": "...", "refresh_token": "...", "expires_in": 600 }
  ```
- `202 Accepted` — appareil inconnu, 2FA requis :
  ```json
  { "status": "2FA_REQUIRED" }
  ```
- `400` — email pas encore vérifié (voir `/auth/verify-email`), OU compte temporairement bloqué
  pour trop d'échecs récents (voir ci-dessous) — message distinct dans ce dernier cas.
- `401` — email ou mot de passe incorrect (même message pour les deux cas).

**Effet de bord (appareil de confiance uniquement)** : si l'adresse IP appelante n'a jamais été vue
pour CET appareil précis (fenêtre glissante des 5 IP les plus récentes), envoie une alerte de
sécurité par email et journalise `LOGIN_NEW_IP_DETECTED` (voir `GET /audit/me`) — jamais bloquant,
purement informatif (une IP seule n'est pas un signal fiable pour refuser une connexion : VPN,
itinérance mobile...). Aucune alerte lors du tout premier login d'un appareil qui vient d'être
approuvé (déjà couvert par l'alerte "nouvel appareil" de `POST /auth/verify-device`).

**Anti-bruteforce par compte** : en plus du rate limiting par IP (voir plus haut), chaque compte
suit ses échecs de mot de passe consécutifs. Après 5 échecs, le compte est bloqué (`400`, message
dédié) pendant 15 minutes glissantes à partir du DERNIER échec — même avec le bon mot de passe.
Une connexion réussie remet immédiatement ce compteur à zéro. Complète (ne remplace pas) le rate
limiting par IP : celui-ci seul ne protège pas un compte ciblé par un attaquant changeant d'IP.

### `POST /auth/verify-device`

Valide le code 2FA reçu suite à un `login()` sur un appareil inconnu, et l'enregistre comme
appareil de confiance.

| Champ | Type | Requis |
|---|---|---|
| `email` | string | oui |
| `code` | string | oui |
| `device_id` | string | oui |
| `device_name` | string | non — nom convivial (ex: "iPhone de Jean") |

**Réponse** : `200 OK`, corps vide. **Rappeler `/auth/login` ensuite** pour obtenir les tokens.
**Erreurs** : `400` code incorrect/expiré, trop de tentatives, ou plafond d'appareils de confiance
atteint (l'utilisateur doit d'abord révoquer un appareil existant via `DELETE /devices/{id}`).
**Effet de bord** : envoie une alerte de sécurité par email ("nouvel appareil approuvé").

### `POST /auth/refresh`

| Champ | Type | Requis |
|---|---|---|
| `refresh_token` | string | oui |

**Réponse** : `200 OK` :
```json
{ "access_token": "...", "refresh_token": "..." }
```
(pas de champ `expires_in` ici, contrairement à `/auth/login`.)

**Erreurs** : `401 SessionExpired` — token invalide, expiré, ou déjà utilisé (rotation à usage
unique : rejouer un ancien refresh token échoue toujours, même s'il n'a pas expiré).

### `POST /auth/logout`

Révoque **un seul** refresh token (un seul appareil). **Aucune authentification requise** — la
connaissance du refresh token suffit à prouver la légitimité de la déconnexion.

| Champ | Type | Requis |
|---|---|---|
| `refresh_token` | string | oui |

**Réponse** : `204 No Content`, idempotent (succès même si le token n'existait déjà plus).

### `PUT /auth/password`

*Authentification requise.* Change volontairement le mot de passe maître. **Doit obligatoirement
inclure la ré-encryption de la totalité du coffre actif** (architecture Zero-Knowledge : la clé de
chiffrement du coffre dérive du mot de passe maître).

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `old_master_password_hash` | string | oui | 6-128 caractères |
| `new_master_password_hash` | string | oui | 6-128 caractères |
| `reencrypted_entries` | array | oui | voir ci-dessous — **doit contenir EXACTEMENT toutes les entrées actives du coffre** |
| `reencrypted_history` | array | non (défaut `[]`) | voir ci-dessous — **doit contenir EXACTEMENT toutes les lignes de `vault_password_history` de l'utilisateur** |
| `reencrypted_attachments` | array | non (défaut `[]`) | voir ci-dessous — **doit contenir EXACTEMENT toutes les pièces jointes de l'utilisateur** |

Chaque élément de `reencrypted_entries` :

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `id` | string | oui | id d'une entrée existante |
| `encrypted_site_name` | string | oui | 1-8192 caractères |
| `encrypted_username` | string | non | max 8192 caractères |
| `encrypted_login_email` | string | non | max 8192 caractères |
| `encrypted_password` | string | oui | 1-8192 caractères |
| `encrypted_preferred_login_type` | string | oui | 1-8192 caractères |
| `encrypted_folder` | string | non | max 8192 caractères |
| `encrypted_notes` | string | non | max 8192 caractères |
| `encrypted_url` | string | non | max 8192 caractères |
| `encrypted_extra_fields` | string | non | max 8192 caractères — champs additionnels des types dédiés (carte/identité), voir `POST /vault` |

Chaque élément de `reencrypted_history` :

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `id` | string | oui | id d'une ligne d'historique existante (voir `GET /vault/{id}/history`) |
| `encrypted_password` | string | oui | 1-8192 caractères |

Chaque élément de `reencrypted_attachments` :

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `id` | string | oui | id d'une pièce jointe existante (voir `GET /vault/{id}/attachments`) |
| `encrypted_filename` | string | oui | 1-8192 caractères |
| `encrypted_content` | string | oui | 1-10 000 000 caractères |

**Réponse** : `200 OK`, corps vide.
**Erreurs** : `401` ancien mot de passe incorrect ; `400` si le nombre d'entrées re-chiffrées, de
lignes d'historique re-chiffrées, ou de pièces jointes re-chiffrées, ne correspond pas exactement à
ce qui existe en base (opération annulée dans son ensemble, rien n'est modifié).
**Effets de bord** : invalide **toutes** les sessions actives (tous appareils) ; envoie une alerte
de sécurité par email ; ferme aussi immédiatement les access tokens déjà émis (voir
[Modèle d'authentification](#modèle-dauthentification)).
**Note** : cette route accepte des requêtes jusqu'à 512 Mo (un coffre de 5000 entrées et 50 pièces
jointes re-chiffrées peut être volumineux). Comme `POST /vault/import`, elle est limitée à
**2 requêtes traitées simultanément** sur tout le serveur : au-delà, les requêtes attendent leur
tour (et reçoivent un `408` si l'attente dépasse le délai global de 30 s). Sans ce plafond, Axum
bufferisant tout le corps en mémoire avant désérialisation, quelques requêtes concurrentes de cette
taille suffisaient à épuiser la RAM du serveur.

**Le re-chiffrement doit être EXHAUSTIF et SANS DOUBLON** : `reencrypted_entries`,
`reencrypted_history` et `reencrypted_attachments` doivent contenir **exactement** les
identifiants présents en base — ni manquant, ni inconnu, ni répété. La vérification porte sur
l'ensemble des identifiants (pas seulement leur nombre) et s'effectue à l'intérieur de la
transaction, donc une entrée ajoutée par un autre appareil pendant l'opération fait échouer le
changement au lieu de rester chiffrée avec l'ancienne clé. En cas d'écart : `400` avec un message
détaillant la catégorie concernée, et **rien n'est modifié**.

### `PUT /auth/email`

*Authentification requise.* Change l'adresse email du compte.

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `new_email` | string | oui | format email valide |
| `master_password_hash` | string | oui | confirmation d'identité |

**Réponse** : `200 OK`, corps vide.
**Erreurs** : `401` mot de passe incorrect ; `403` si l'appelant vient d'une extension navigateur
(en-tête `Origin` commençant par `chrome-extension://`/`moz-extension://`) et n'est ni admin ni
explicitement autorisé (voir `can_change_email_via_extension` sous `GET /me` et
`PUT /admin/users/{email}/extension-email-change` plus bas — l'app desktop n'est JAMAIS concernée
par cette restriction, quelle que soit la valeur de ce réglage).
**Effets de bord** : invalide toutes les sessions actives ; envoie une alerte de sécurité à
**l'ancienne** adresse (pas la nouvelle) ; propage automatiquement le changement à toutes les
données liées (coffre, appareils de confiance, logs d'audit...).

### `GET /me`

*Authentification requise.*

**Réponse** : `200 OK` :
```json
{
  "email": "utilisateur@example.com",
  "is_moderator": false,
  "max_trusted_devices": 10,
  "can_change_email_via_extension": false,
  "can_choose_server_in_settings": false,
  "is_admin": false,
  "preferred_theme": "dark",
  "has_recovery_kit": false
}
```
`has_recovery_kit` : indique seulement si un kit de récupération est configuré (voir
`PUT /auth/recovery-kit`), afin que le client propose « générer un kit » ou « kit déjà en place ».
Le blob scellé lui-même n'est JAMAIS exposé ici — il ne sort qu'au terme du flux de récupération.
`is_moderator` : seule source fiable pour qu'un client sache s'il doit afficher une interface
d'administration — jamais déduit du JWT lui-même (qui ne porte pas ce champ, voir la section
Authentification plus haut). `max_trusted_devices` : le plafond d'appareils de confiance
actuellement en vigueur (seul moyen pour un client de le connaître avant de le modifier via
`PUT /devices/limit`, qui ne renvoie que 200 vide). `can_change_email_via_extension` : voir
`PUT /auth/email` ci-dessus — permet à un client (la popup de l'extension) de savoir s'il doit
afficher son formulaire de changement d'email plutôt que d'attendre un 403 pour le découvrir.
`can_choose_server_in_settings` : voir `PUT /admin/users/{email}/server-choice` plus bas — permet à
l'app (desktop/Android) de savoir si elle doit afficher la section "Serveur" dans les Réglages.
Valeur BRUTE de la colonne, PAS combinée avec `is_admin` : c'est au client de faire
`is_admin || can_choose_server_in_settings` (l'Admin y a toujours accès indépendamment de cette
valeur). `is_admin` : vrai UNIQUEMENT pour le compte configuré via `ADMIN_EMAIL` — seul compte
autorisé à appeler `PUT /admin/users/{email}/role` (voir plus bas) ; permet à l'écran
Administration de masquer les boutons promouvoir/rétrograder pour tout le monde d'autre.
`preferred_theme` : le thème actuellement choisi (preset ou `"custom"`), synchronisé par compte —
voir `PUT /theme-preference` plus bas.

### `GET /audit/me`

*Authentification requise.* Historique de sécurité SELF-SERVICE — contrairement à `GET /audit`
(section Administration plus bas, réservé aux admins, tous comptes confondus), ne renvoie que les
100 entrées les plus récentes du compte APPELANT (`WHERE user_email = ?`), triées du plus récent
au plus ancien. Même forme de réponse que `GET /audit`. Aucun contenu du coffre là-dedans — juste
action/IP/user-agent/date en clair.

**Rétention : 10 jours.** Une tâche de maintenance purge les entrées plus anciennes de la base
(voir `maintenance.rs::AUDIT_LOG_RETENTION_DAYS`) — sans quoi la table grossirait indéfiniment, une
ligne par action et à vie. La trace elle-même n'est pas perdue pour autant : chaque entrée est
aussi émise dans le journal structuré du serveur (fichiers de log, avec leur propre rotation), qui
reste consultable pour une investigation au-delà de cette fenêtre. Seul l'historique affiché par
l'API est donc limité à 10 jours.

### `POST /auth/forgot-password`

Initie une réinitialisation de mot de passe oublié.

| Champ | Type | Requis |
|---|---|---|
| `email` | string | oui |

**Réponse** : `202 Accepted`, corps vide, **dans tous les cas** (anti-énumération de comptes —
même réponse que l'email existe ou non).

**Cooldown anti-email-bombing (60 s par adresse)** : même mécanisme que
`POST /auth/resend-verification` — si un code de réinitialisation a déjà été émis pour cette
adresse il y a moins de 60 secondes, la réponse reste un `202` identique mais aucun email n'est
envoyé et le code en cours reste valide.

### `POST /auth/reset-password`

Confirme le code reçu et applique le nouveau mot de passe.

⚠️ **Purge intégrale du coffre** : contrairement à `PUT /auth/password` (changement volontaire),
il n'y a ici aucune clé de l'ancien mot de passe pour re-chiffrer quoi que ce soit — toutes les
entrées du coffre sont **définitivement supprimées**.

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `email` | string | oui | |
| `code` | string | oui | |
| `new_master_password_hash` | string | oui | 6-128 caractères |

**Réponse** : `200 OK`, corps vide.
**Erreurs** : `400` code invalide/expiré, ou trop de tentatives.
**Effets de bord** : purge tout le coffre, invalide toutes les sessions, ferme les access tokens
déjà émis.

## Endpoints — Coffre-fort (vault)

Toutes les routes ci-dessous nécessitent une authentification.


## Kit de récupération

Sans kit, oublier son mot de passe maître **condamne le coffre** : `POST /auth/reset-password`
ci-dessus ne peut que le vider, faute de la moindre clé pour re-chiffrer quoi que ce soit.

Le kit stocke la clé du coffre **scellée par un code de récupération** que l'utilisateur imprime et
range physiquement (voir `crypto-core/src/recovery.rs`). Le serveur ne voit jamais ce code : il ne
détient qu'un blob qu'il ne peut pas ouvrir — le modèle Zero-Knowledge est intact.

⚠️ **Ce n'est pas une porte dérobée.** Si le code est perdu **en même temps** que le mot de passe
maître, le coffre reste définitivement irrécupérable.

### `PUT /auth/recovery-kit`

*Authentification requise.* Enregistre (ou remplace) le kit. Le client scelle lui-même la clé de son
coffre — le serveur ne reçoit que le résultat.

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `sealed_vault_key` | string | oui | 1 à 8192 caractères |

**Réponse** : `204 No Content`. Une alerte de sécurité est envoyée par email au titulaire.

⚠️ **Le kit est automatiquement invalidé** dès que la clé du coffre change : changement volontaire
de mot de passe (`PUT /auth/password`), réinitialisation (`POST /auth/reset-password`) et
récupération elle-même. Il scelle en effet l'ANCIENNE clé et ne déchiffrerait plus rien — le
laisser en place donnerait un kit silencieusement inopérant, pire qu'aucun kit puisqu'on se croirait
couvert. Ni le serveur ni le client ne peuvent le re-sceller (le code n'est affiché qu'une fois et
n'est stocké nulle part) : **il faut en générer un nouveau après chaque changement de mot de passe**.

### `DELETE /auth/recovery-kit`

*Authentification requise.* Supprime le kit ; le code imprimé devient inopérant (feuille égarée,
code peut-être vu par quelqu'un).

**Réponse** : `204 No Content`.

### `POST /auth/recovery/data`

Étape **1** de la récupération. Le code reçu par email (via `POST /auth/forgot-password`) prouve la
possession de l'adresse, et donne le blob scellé **ainsi que le contenu chiffré du coffre** à
re-chiffrer.

Le code n'est **pas consommé** ici : l'étape 2 en a encore besoin pour s'autoriser. Il reste soumis
au même verrouillage anti-bruteforce que la réinitialisation (5 tentatives).

Pourquoi joindre le coffre plutôt que laisser le client le récupérer ensuite : les routes d'export
(`POST /vault/export`, `POST /vault/history/export`) exigent le hash du mot de passe maître —
précisément ce que l'utilisateur a oublié. Les renvoyer ici évite au passage d'avoir à délivrer une
session, donc d'élargir ce que ce code autorise. Ces octets restent chiffrés de bout en bout : sans
le code de récupération, ils ne servent à rien.

| Champ | Type | Requis |
|---|---|---|
| `email` | string | oui |
| `code` | string | oui |
| `device_id` | string | oui |

**Réponse** : `200 OK` avec `sealed_vault_key`, `entries`, `history` et `attachments`.
`400` si aucun kit n'est configuré pour ce compte — la réinitialisation classique reste alors
possible, mais elle videra le coffre.

### `POST /auth/recovery/complete`

Étape **2**. Le client a descellé la clé avec son code, tout re-chiffré avec la clé dérivée du
**nouveau** mot de passe maître, et renvoie le résultat. Contrairement à `reset-password`, **le
coffre est conservé**.

Le code est cette fois **consommé**. Toutes les sessions tombent, y compris celle délivrée à
l'étape 1, et le kit qui vient de servir est **invalidé** : il scelle la clé de l'ancien mot de
passe et ne déchiffre plus rien. Le laisser en place donnerait un kit silencieusement inopérant —
pire qu'aucun kit, puisqu'on se croirait couvert. L'utilisateur en régénère un après coup.

| Champ | Type | Requis |
|---|---|---|
| `email` | string | oui |
| `code` | string | oui |
| `new_master_password_hash` | string | oui |
| `reencrypted_entries` | tableau | oui |
| `reencrypted_history` | tableau | oui |
| `reencrypted_attachments` | tableau | oui |

**Le re-chiffrement doit être exhaustif et sans doublon** — mêmes règles et même vérification par
ensemble d'identifiants que `PUT /auth/password` (voir sa section). En cas d'écart : `400`, et
**rien n'est modifié**. Mêmes plafonds de taille (512 Mo) et de concurrence (2 requêtes
simultanées) que `PUT /auth/password`, pour la même raison.

### `GET /vault?limit=&offset=`

Liste les entrées actives du coffre de l'utilisateur (favoris en premier).

| Paramètre | Type | Défaut | Notes |
|---|---|---|---|
| `limit` | number | 50 | plafonné à 100 quoi que le client demande |
| `offset` | number | 0 | |

**Réponse** : `200 OK`, tableau de `VaultEntry` :
```json
[{
  "id": "uuid",
  "encrypted_site_name": "...",
  "encrypted_username": "...",
  "encrypted_login_email": "...",
  "encrypted_password": "...",
  "encrypted_preferred_login_type": "...",
  "user_email": "...",
  "is_favorite": false,
  "encrypted_folder": null,
  "encrypted_notes": null,
  "encrypted_url": null,
  "entry_type": "login",
  "encrypted_extra_fields": null,
  "updated_at": "2026-08-05T12:00:00",
  "version": 1,
  "has_attachments": false,
  "use_count": 0
}]
```
`version` : compteur entier incrémenté à chaque modification — à renvoyer dans `expected_version`
lors d'un `PUT /vault/{id}` pour détecter un conflit d'édition (voir plus bas).
`has_attachments` : vrai si cette entrée a au moins une pièce jointe (calculé à la volée, pas une
colonne stockée) — évite au client d'interroger `GET /vault/{id}/attachments` pour chaque entrée
juste pour savoir s'il faut afficher un indicateur.
`use_count` : nombre de fois où cette entrée a été utilisée (copie du mot de passe ou remplissage
automatique — voir `PATCH /vault/{id}/use`) — pour un tri "le plus utilisé" côté client. Ne
reflète jamais une modification de contenu : n'affecte ni `updated_at` ni `version`.
`entry_type` : type d'entrée dédié (`"login"` par défaut, ou `"card"`/`"identity"`/`"note"`) —
métadonnée EN CLAIR, comme `is_favorite`. `encrypted_extra_fields` : blob JSON chiffré côté client
contenant les champs spécifiques au type (ex: date d'expiration/CVV pour une carte) — jamais
interprété par le serveur, purement une convention côté client (voir `POST /vault`).

### `POST /vault`

Ajoute une entrée.

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `encrypted_site_name` | string | oui | 1-8192 caractères |
| `encrypted_username` | string | non | max 8192 caractères |
| `encrypted_login_email` | string | non | max 8192 caractères |
| `encrypted_password` | string | oui | 1-8192 caractères |
| `encrypted_preferred_login_type` | string | oui | 1-8192 caractères |
| `is_favorite` | bool | oui | |
| `encrypted_folder` | string | non | max 8192 caractères |
| `encrypted_notes` | string | non | max 8192 caractères |
| `encrypted_url` | string | non | max 8192 caractères |
| `entry_type` | string | non (défaut `"login"`) | métadonnée EN CLAIR — `"login"`/`"card"`/`"identity"`/`"note"`, aucune valeur imposée côté serveur |
| `encrypted_extra_fields` | string | non | max 8192 caractères — voir `GET /vault` |
| `password_changed` | bool | non (défaut `false`) | voir `PUT /vault/{id}` |

**Réponse** : `201 Created`, corps vide.
**Erreurs** : `400` validation, ou plafond de 5000 entrées actives atteint.

### `PUT /vault/{id}`

Modifie une entrée existante (mêmes champs que `POST /vault`). `password_changed` doit être `true`
UNIQUEMENT si le CLIENT a réellement changé le mot de passe dans ce formulaire (pas à chaque
simple modification de site/dossier/notes/url, qui repasse pourtant par cette même route) : dans ce
cas, l'ANCIENNE valeur chiffrée de `encrypted_password` est archivée dans l'historique (voir
`GET /vault/{id}/history`) avant d'être écrasée. Le serveur ne peut pas déduire ce changement
lui-même en comparant les blobs chiffrés (AES-GCM est randomisé, `encrypted_password` diffère
toujours d'un appel à l'autre même à mot de passe inchangé).

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `expected_version` | number | non | voir DÉTECTION DE CONFLIT ci-dessous |

**DÉTECTION DE CONFLIT** : si `expected_version` est fourni, il doit correspondre à `version` tel
qu'il est actuellement en base au moment de cet appel — sinon la modification est refusée (`409`)
plutôt que d'écraser silencieusement une modification faite entre-temps depuis un AUTRE appareil.
Omettre ce champ désactive le contrôle (compatible avec un client plus ancien).

**Réponse** : `200 OK`, corps vide.
**Erreurs** : `404` si l'entrée n'existe pas, n'appartient pas à l'appelant, ou est dans la
corbeille (il faut d'abord la restaurer) ; `409` en cas de conflit de version (voir ci-dessus).

### `GET /vault/{id}/history`

Historique des mots de passe d'une entrée, du plus récent au plus ancien (archivé automatiquement
par `PUT /vault/{id}` quand `password_changed: true` — voir ci-dessus). Plafonné à 20 versions par
entrée (les plus anciennes sont purgées automatiquement au-delà).

**Réponse** : `200 OK`, tableau de `PasswordHistoryEntry` :
```json
[{ "id": "uuid", "vault_id": "uuid", "encrypted_password": "...", "changed_at": "2026-08-05T12:00:00" }]
```
**Erreurs** : aucune erreur spécifique — une entrée sans historique renvoie simplement `[]`.

### `POST /vault/history/export`

Exporte l'intégralité de l'historique de mots de passe de l'utilisateur (tous dossiers/entrées
confondus) — à récupérer, re-chiffrer côté client, puis renvoyer dans `reencrypted_history` lors
d'un changement de mot de passe maître (voir `PUT /auth/password`). Même exigence de
reconfirmation du mot de passe maître que `POST /vault/export`, pour la même raison.

| Champ | Type | Requis |
|---|---|---|
| `master_password_hash` | string | oui — reconfirmation obligatoire |

**Réponse** : `200 OK`, tableau de `PasswordHistoryEntry` (même forme que `GET /vault/{id}/history`,
tous dossiers confondus, sans plafond).
**Erreurs** : `401` mot de passe incorrect.

### `POST /vault/{id}/attachments`

Ajoute une pièce jointe chiffrée à une entrée (nom de fichier ET contenu CHIFFRÉS côté client —
voir `src-tauri/src/crypto.rs::encrypt_field` — le serveur ne les lit ni ne les valide jamais).

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `encrypted_filename` | string | oui | 1-8192 caractères |
| `encrypted_content` | string | oui | 1-10 000 000 caractères (~5 Mo de fichier original, une fois chiffré et doublement encodé en base64) |
| `content_size` | number | oui | 1-5 242 880 (taille EN CLAIR du fichier original, en octets — SEULE métadonnée non chiffrée, fournie par le client, non vérifiable par le serveur) |

**Réponse** : `201 Created` : `{ "id": "uuid" }`.
**Erreurs** : `400` validation, ou plafond atteint (5 pièces jointes par entrée, 50 au total par
utilisateur) ; `404` si l'entrée n'existe pas, n'appartient pas à l'appelant, ou est dans la
corbeille.
**Note** : cette route accepte des requêtes jusqu'à 16 Mo.

### `GET /vault/{id}/attachments`

Liste les pièces jointes d'une entrée, **sans leur contenu** (évite de transférer plusieurs Mo par
fichier juste pour en afficher le nom).

**Réponse** : `200 OK`, tableau de `VaultAttachmentMeta` :
```json
[{ "id": "uuid", "encrypted_filename": "...", "content_size": 1234, "created_at": "2026-08-05T12:00:00" }]
```

### `GET /vault/{id}/attachments/{attachment_id}`

Récupère UNE pièce jointe complète (avec son contenu chiffré) — pour le téléchargement.

**Réponse** : `200 OK`, un `VaultAttachment` :
```json
{ "id": "uuid", "vault_id": "uuid", "encrypted_filename": "...", "encrypted_content": "...", "content_size": 1234, "created_at": "2026-08-05T12:00:00" }
```
**Erreurs** : `404`.

### `DELETE /vault/{id}/attachments/{attachment_id}`

Supprime définitivement une pièce jointe (pas de corbeille pour les pièces jointes).

**Réponse** : `204 No Content`.
**Erreurs** : `404`.

### `DELETE /vault/{id}`

Suppression **douce** (déplace vers la corbeille, récupérable 30 jours).

**Réponse** : `204 No Content`.
**Erreurs** : `404`.

### `PATCH /vault/{id}/favorite`

Bascule le statut favori (`true` <-> `false`).

**Réponse** : `200 OK`, corps vide.
**Erreurs** : `404` (y compris si l'entrée est dans la corbeille).

### `PATCH /vault/{id}/use`

Incrémente le compteur d'utilisation (`use_count`, voir `GET /vault`) — à appeler à chaque copie du
mot de passe ou remplissage automatique. N'affecte ni `updated_at` ni `version` : pas une
modification de contenu, jamais de conflit d'édition possible dessus. Appel best-effort côté
client, recommandé de ne pas attendre sa réponse avant de continuer l'action réelle
(copier/remplir). Ne déclenche PAS de notification de synchronisation vers les autres appareils
(voir `GET /api/vault/sync`) — volontairement, pour ne pas provoquer un rechargement complet du
coffre à chaque copie de mot de passe ; les autres appareils voient la valeur à jour à leur
prochain rechargement naturel du coffre.

**Réponse** : `200 OK`, corps vide.
**Erreurs** : `404` (y compris si l'entrée est dans la corbeille, ou n'appartient pas à l'appelant).

### `GET /vault/trash`

Liste les entrées dans la corbeille (les plus récemment supprimées en premier).

**Réponse** : `200 OK`, tableau de `TrashedVaultEntry` :
```json
[{
  "id": "uuid",
  "encrypted_site_name": "...",
  "encrypted_username": "...",
  "encrypted_login_email": "...",
  "encrypted_preferred_login_type": "...",
  "is_favorite": false,
  "deleted_at": "2026-08-05T12:00:00",
  "encrypted_folder": null
}]
```
(pas de `encrypted_password` ni `user_email` dans cette réponse allégée.)

### `POST /vault/{id}/restore`

Restaure une entrée de la corbeille.

**Réponse** : `200 OK`, corps vide. **Erreurs** : `404`.

### `DELETE /vault/{id}/permanent`

Supprime **définitivement** une entrée déjà dans la corbeille (aucun retour en arrière). Échoue
sur une entrée active (doit d'abord passer par `DELETE /vault/{id}`).

**Réponse** : `204 No Content`. **Erreurs** : `404`.

### `POST /vault/import`

Importe en bloc un ensemble d'entrées (ex: restauration d'un backup obtenu via `/vault/export`).
Chaque entrée devient une **nouvelle** ligne — jamais de fusion/écrasement de l'existant.

| Champ | Type | Requis |
|---|---|---|
| `entries` | array de `VaultEntryInput` (mêmes champs que `POST /vault`) | oui |

**Réponse** : `201 Created` :
```json
{ "imported": 3 }
```
**Erreurs** : `400` si une seule entrée du lot est invalide, ou si l'import dépasse le plafond de
5000 entrées actives — dans les deux cas, **rien n'est importé** (tout ou rien).
**Note** : accepte des requêtes jusqu'à 256 Mo, et est limitée à **2 requêtes traitées
simultanément** sur tout le serveur (même plafond que `PUT /auth/password`, voir sa note pour le
raisonnement) : au-delà, les requêtes attendent leur tour.

### `POST /vault/export`

Exporte l'intégralité du coffre actif (pas de pagination). Reste chiffré (Zero-Knowledge).

| Champ | Type | Requis |
|---|---|---|
| `master_password_hash` | string | oui — reconfirmation obligatoire |

**Réponse** : `200 OK`, tableau de `VaultEntry` (même forme que `GET /vault`, sans pagination).
**Erreurs** : `401` mot de passe incorrect.

### `GET /api/vault/sync` (alias `GET /api/vault/sync-check`)

Endpoint léger pour savoir si le client doit re-télécharger le coffre, sans le récupérer en
entier.

**Réponse** : `200 OK` :
```json
{ "sync_token": "3_2026-08-05 12:00:00", "total_entries": 3, "last_modified": "2026-08-05 12:00:00" }
```
`sync_token` change dès qu'une entrée est ajoutée, modifiée, ou que son statut favori change (les
entrées dans la corbeille ne comptent pas dans `total_entries`).

## Endpoints — Appareils de confiance

Toutes les routes ci-dessous nécessitent une authentification.

### `GET /devices`

**Réponse** : `200 OK`, tableau de `TrustedDevice` :
```json
[{ "device_id": "...", "device_name": "iPhone de Jean", "created_at": "...", "last_used_at": "...", "last_ip": "203.0.113.4" }]
```
`last_ip` : dernière adresse IP connue pour cet appareil, `null` si aucune n'a encore été enregistrée
(appareil approuvé avant l'ajout de ce suivi).

### `DELETE /devices/{device_id}`

Révoque un appareil de confiance : il devra repasser par le 2FA à sa prochaine connexion, et sa
session active (s'il en a une) est immédiatement coupée.

**Réponse** : `204 No Content`. **Erreurs** : `404`.

### `PUT /devices/limit`

Modifie le plafond d'appareils de confiance (choisi initialement à l'inscription via
`max_trusted_devices`).

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `new_limit` | number | oui | 1-50 |
| `master_password_hash` | string | oui | reconfirmation obligatoire |

**Réponse** : `200 OK`, corps vide. **Erreurs** : `401` mot de passe incorrect.

### `POST /devices/logout-all`

Déconnexion totale volontaire : révoque **toutes** les sessions actives, sur **tous** les
appareils — y compris celui qui appelle cette route. Aucune reconfirmation de mot de passe
requise (action purement défensive, ne peut rien exposer). Ferme également toute connexion
WebSocket (`GET /ws`) déjà ouverte pour ce compte (voir point 6 plus haut).

**Réponse** : `204 No Content`.
**Effet de bord** : ferme aussi immédiatement les access tokens déjà émis (voir
[Modèle d'authentification](#modèle-dauthentification)).

## Endpoints — Accès d'urgence

Toutes les routes ci-dessous nécessitent une authentification. Zero-Knowledge de bout en bout : le
serveur ne relaie que des clés publiques et des blobs déjà chiffrés côté client (voir
`src-tauri/src/emergency.rs` pour la construction cryptographique — une "boîte scellée" X25519).

Machine à états d'une relation (`status`) : `pending` (invitation envoyée) → `active` (acceptée) →
`access_requested` (le contact a demandé l'accès, délai d'attente en cours) → `access_granted`
(accès accordé, définitivement ou automatiquement après le délai).

### `PUT /emergency/keys`

Enregistre ou remplace sa propre paire de clés X25519 (générée côté client).

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `public_key` | string | oui | 1-8192 caractères |
| `encrypted_private_key` | string | oui | 1-8192 caractères — CHIFFRÉE côté client avec la clé du coffre |

**Réponse** : `200 OK`, corps vide.

### `GET /emergency/keys/me`

Récupère ses propres clés (publique **et** privée chiffrée) — nécessaire pour desceller la clé
d'un coffre distant une fois l'accès accordé.

**Réponse** : `200 OK`, `{ "public_key": "...", "encrypted_private_key": "..." }`.

### `GET /emergency/keys/{email}`

Récupère **uniquement** la clé publique d'un autre utilisateur (jamais sa clé privée, même
chiffrée) — ce qu'il faut pour lui sceller quelque chose.

**Réponse** : `200 OK`, `{ "public_key": "..." }`.
**Erreurs** : `404` si cet utilisateur n'a jamais configuré l'accès d'urgence.

### `POST /emergency/contacts`

Désigne un nouveau contact de confiance — envoie une invitation par email, sans effet tant qu'elle
n'est pas acceptée.

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `contact_email` | string | oui | email valide, différent du sien |
| `waiting_period_days` | number | oui | 0-90 |

**Réponse** : `201 Created`, `{ "id": "uuid" }`.
**Erreurs** : `400` validation, ou tentative de s'ajouter soi-même ; `409` ce contact est déjà désigné.

### `GET /emergency/contacts`

Liste les contacts désignés par l'utilisateur connecté ("les gens en qui j'ai confiance").

**Réponse** : `200 OK`, tableau de `EmergencyContact` (id, owner_email, contact_email,
waiting_period_days, status, requested_at, available_at, created_at — **jamais**
`sealed_vault_key`, qui ne transite que via `GET /emergency/contacts/{id}/vault`).

### `GET /emergency/granted-to-me`

Liste les relations où l'utilisateur connecté est le **contact** désigné ("les comptes où on m'a
fait confiance"). Même forme que `GET /emergency/contacts`.

### `POST /emergency/contacts/{id}/accept`

Le contact accepte l'invitation.

**Réponse** : `200 OK`, corps vide. **Erreurs** : `404` (invitation inconnue, déjà traitée, ou vous
n'êtes pas le contact désigné — réponse volontairement identique dans les trois cas).

### `POST /emergency/contacts/{id}/decline`

Le contact refuse l'invitation (supprime la relation).

**Réponse** : `204 No Content`. **Erreurs** : `404`.

### `PUT /emergency/contacts/{id}/seed`

Le propriétaire chiffre (scelle) sa clé de coffre pour ce contact précis — peut être rappelé à
tout moment pour rafraîchir le blob (ex: après un changement de mot de passe maître).

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `sealed_vault_key` | string | oui | 1-8192 caractères |

**Réponse** : `200 OK`, corps vide. **Erreurs** : `404`.

### `POST /emergency/contacts/{id}/request-access`

Le contact demande l'accès d'urgence — démarre le délai d'attente configuré par le propriétaire.
Refusé si l'invitation n'a pas été acceptée, ou si le propriétaire n'a pas encore scellé sa clé.

**Réponse** : `200 OK`, corps vide. **Erreurs** : `404`.
**Effet de bord** : notifie le propriétaire par email.

### `POST /emergency/contacts/{id}/approve`

Le propriétaire approuve immédiatement une demande en cours, sans attendre la fin du délai.

**Réponse** : `200 OK`, corps vide. **Erreurs** : `404`.

### `POST /emergency/contacts/{id}/reject`

Le propriétaire refuse une demande en cours (retour à `active` — la relation elle-même n'est pas
supprimée, seule cette demande précise est annulée).

**Réponse** : `200 OK`, corps vide. **Erreurs** : `404`.

### `GET /emergency/contacts/{id}/vault`

Le contact consulte le coffre du propriétaire, en lecture seule — uniquement si `status` vaut déjà
`access_granted`, ou si le délai d'attente est écoulé (promotion automatique à cet instant).

**Réponse** : `200 OK`, `{ "sealed_vault_key": "...", "entries": [VaultEntry, ...] }` (même forme
que `GET /vault`, sans pagination).
**Erreurs** : `404` si l'accès n'est pas (encore) accordé.
**Effet de bord** : notifie le propriétaire par email à **chaque** consultation effective.

### `DELETE /emergency/contacts/{id}`

Révoque une relation — le propriétaire ou le contact peuvent y mettre fin à tout moment.

**Réponse** : `204 No Content`. **Erreurs** : `404` (y compris pour un tiers étranger à la relation).

## Endpoints — Partage d'entrée

Toutes les routes ci-dessous nécessitent une authentification. Même construction Zero-Knowledge que
l'accès d'urgence ci-dessus (boîte scellée X25519, réutilise `/emergency/keys/*` pour les clés
publiques), mais **instantané** : pas de délai d'attente ni de machine à états — un partage existe
ou n'existe pas.

### `POST /vault/{id}/shares`

Partage (ou re-partage, après une modification de l'entrée) l'entrée `{id}` avec un autre
utilisateur. Le client résout d'abord la clé publique du destinataire (`GET
/emergency/keys/{email}`) et scelle le contenu en clair de l'entrée AVANT d'appeler cette route.

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `shared_with_email` | string | oui | email valide, différent du sien |
| `sealed_entry` | string | oui | 1-32768 caractères — JSON scellé des champs en clair de l'entrée |

**Réponse** : `201 Created`, `{ "id": "uuid" }`. Re-partager avec le **même** destinataire réutilise
le même `id` et remplace le blob existant (jamais de doublon).
**Erreurs** : `400` validation, ou tentative de partage avec soi-même ; `404` si `{id}` n'existe pas
ou n'appartient pas à l'appelant.
**Effet de bord** : notifie le destinataire par email.

### `GET /vault/{id}/shares`

Liste les partages actifs de l'entrée `{id}`, vus par son propriétaire.

**Réponse** : `200 OK`, tableau de `VaultShare` (id, shared_with_email, created_at — **jamais**
`sealed_entry`, qui ne transite que via `GET /shares/{id}`).

### `GET /shares/shared-with-me`

Liste tout ce qui a été partagé avec l'utilisateur connecté, tous propriétaires confondus.

**Réponse** : `200 OK`, tableau de `SharedWithMeEntry` (id, vault_id, owner_email, created_at —
jamais `sealed_entry`).

### `GET /shares/{id}`

Récupère le blob scellé d'un partage précis, à desceller côté client — réservé au **destinataire**
désigné (ni le propriétaire lui-même via cette route, ni évidemment un tiers).

**Réponse** : `200 OK`, `{ "owner_email": "...", "sealed_entry": "..." }`.
**Erreurs** : `404` si le partage n'existe pas, si l'appelant n'en est pas le destinataire, ou si
l'entrée source a depuis été mise à la corbeille.

### `DELETE /shares/{id}`

Révoque un partage — le propriétaire ou le destinataire peuvent y mettre fin à tout moment.

**Réponse** : `204 No Content`. **Erreurs** : `404` (y compris pour un tiers étranger au partage).

## Endpoints — Coffres partagés familiaux

Toutes les routes ci-dessous nécessitent une authentification. **S'AJOUTE** au partage d'entrée
1-vers-1 ci-dessus, ne le remplace pas — les deux systèmes coexistent pour deux usages différents.
Même construction Zero-Knowledge (boîte scellée X25519, réutilise `/emergency/keys/*` pour les
clés publiques), mais avec une **clé symétrique partagée par tous les membres** (générée une seule
fois à la création, scellée individuellement pour chacun) plutôt qu'un blob par destinataire : une
modification par un membre est visible **en direct** par tous les autres (notifiés via WebSocket,
`event_type: "SHARED_VAULT_UPDATE"`), sans avoir besoin de re-partager après chaque changement.

**Rôles** : exactement UN propriétaire par coffre (le créateur, immuable — pas de transfert de
propriété dans cette version) ; tout autre membre est un membre simple. Un membre simple peut
consulter/ajouter/modifier/supprimer des **entrées**, et quitter le coffre lui-même. Seul le
propriétaire peut inviter/retirer un AUTRE membre, ou supprimer le coffre entier — et ne peut PAS
quitter son propre coffre (doit le supprimer entièrement à la place, voir `DELETE /shared-vaults/{id}`).

**Limite acceptée** (documentée, comme toute construction à clé symétrique partagée de ce type) :
retirer un membre révoque son accès **futur**, mais ne protège pas rétroactivement ce qu'il a déjà
pu voir/exporter avant son retrait — la clé n'est pas changée à chaque retrait (coût jugé
disproportionné pour l'usage familial visé).

**Périmètre volontairement réduit** par rapport au coffre personnel dans cette première version :
pas de pièces jointes, d'historique de mot de passe, de corbeille (suppression directe et
définitive), ni de favoris/dossiers pour les entrées partagées.

### `POST /shared-vaults`

Crée un nouveau coffre partagé — l'appelant en devient automatiquement le propriétaire et premier
membre. Le client a déjà généré une clé symétrique fraîche pour ce coffre, chiffré `encrypted_name`
avec elle, et scellé cette même clé pour sa propre clé publique.

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `encrypted_name` | string | oui | 1-8192 caractères |
| `sealed_vault_key` | string | oui | 1-4096 caractères — clé du coffre scellée pour l'appelant |

**Réponse** : `201 Created`, `{ "id": "uuid" }`.

### `GET /shared-vaults`

Liste les coffres partagés dont l'appelant est membre.

**Réponse** : `200 OK`, tableau de `SharedVaultView` (id, encrypted_name, created_by, created_at,
`sealed_vault_key` — **toujours la copie de l'appelant**, jamais celle d'un autre membre —, is_owner).

### `DELETE /shared-vaults/{id}`

Supprime **définitivement** le coffre entier (membres et entrées inclus) — réservé au propriétaire.

**Réponse** : `204 No Content`. **Erreurs** : `404` si `{id}` n'existe pas ou que l'appelant n'en
est pas le propriétaire.

### `POST /shared-vaults/{id}/members`

Invite un nouveau membre — réservé au propriétaire. Le client a déjà résolu la clé publique du
futur membre (`GET /emergency/keys/{email}`) et scellé la clé du coffre pour lui.

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `member_email` | string | oui | email valide, différent de l'appelant |
| `sealed_vault_key` | string | oui | 1-4096 caractères |

**Réponse** : `201 Created`. **Erreurs** : `400` validation, tentative de s'inviter soi-même, ou
déjà membre ; `403` si l'appelant n'est pas le propriétaire.
**Effet de bord** : notifie le nouveau membre par email.

### `GET /shared-vaults/{id}/members`

Liste les membres d'un coffre partagé — n'importe quel membre peut la consulter.

**Réponse** : `200 OK`, tableau de `SharedVaultMemberView` (member_email, is_owner, added_at —
**jamais** `sealed_vault_key`, propre à chaque membre). **Erreurs** : `404` si l'appelant n'est pas
membre.

### `DELETE /shared-vaults/{id}/members/{email}`

Retire un membre. Si `{email}` est celui de l'appelant : il quitte le coffre de lui-même (interdit
pour le propriétaire — voir plus haut). Sinon : réservé au propriétaire, qui retire quelqu'un
d'autre.

**Réponse** : `204 No Content`. **Erreurs** : `404` (membre introuvable, ou tentative du propriétaire
de se retirer lui-même) ; `403` (tentative par un non-propriétaire de retirer quelqu'un d'autre).

### `GET /shared-vaults/{id}/entries`

Liste les entrées d'un coffre partagé — réservé à ses membres.

**Réponse** : `200 OK`, tableau de `SharedVaultEntry` (mêmes champs `encrypted_*`/`entry_type` que
le coffre personnel, plus `created_by` et `version`). **Erreurs** : `404` si l'appelant n'est pas
membre.

### `POST /shared-vaults/{id}/entries`

Ajoute une entrée — réservé aux membres (n'importe lequel).

| Champ | Type | Requis |
|---|---|---|
| `encrypted_site_name` | string | oui |
| `encrypted_username`, `encrypted_login_email`, `encrypted_notes`, `encrypted_url`, `encrypted_extra_fields` | string | non |
| `encrypted_password`, `encrypted_preferred_login_type` | string | oui |
| `entry_type` | string | non (défaut `"login"`) |

**Réponse** : `201 Created`, `{ "id": "uuid" }`.
**Effet de bord** : notifie TOUS les membres via WebSocket (`SHARED_VAULT_UPDATE`).

### `PUT /shared-vaults/{id}/entries/{entry_id}`

Modifie une entrée — mêmes champs que la création, plus `expected_version` (voir [Coffre-fort](#endpoints--coffre-fort-vault)
pour le principe de détection de conflit — **encore plus pertinent ici**, plusieurs membres
différents pouvant modifier la même entrée à quelques instants d'écart).

**Réponse** : `200 OK`. **Erreurs** : `404` (entrée introuvable ou appelant non-membre) ; `409` si
`expected_version` ne correspond plus à la version actuelle.
**Effet de bord** : notifie tous les membres via WebSocket.

### `DELETE /shared-vaults/{id}/entries/{entry_id}`

Supprime **définitivement** une entrée (pas de corbeille) — réservé aux membres.

**Réponse** : `204 No Content`. **Erreurs** : `404`.
**Effet de bord** : notifie tous les membres via WebSocket.

## Endpoints — Partage à usage limité

Toutes les routes ci-dessous nécessitent une authentification. **S'AJOUTE** au partage d'entrée
classique ET aux coffres partagés familiaux ci-dessus, ne remplace ni l'un ni l'autre — trois
mécanismes de partage distincts qui coexistent, chacun pour un usage différent.

Le destinataire **ne voit jamais** l'identifiant ni le mot de passe — seulement le nom du site —
et ne peut déclencher un "usage" (remplissage automatique côté extension, copie sans affichage
côté desktop) qu'un nombre de fois limité choisi par l'expéditeur (**1 par défaut**). Deux blobs
scellés distincts côté client : le nom du site (librement consultable, ne consomme jamais
d'usage) et les identifiants (accessibles uniquement via `POST /blind-shares/{id}/use`, qui
décrémente le compteur de façon **atomique** — une seule requête SQL avec la condition
`remaining_uses > 0` directement dans son `WHERE`, jamais un `SELECT` puis un `UPDATE` séparés,
pour qu'aucune course entre deux appels concurrents ne puisse jamais dépasser le nombre d'usages
autorisé).

**Limite honnêtement documentée** : empêcher l'affichage du mot de passe rend son exposition
CASUELLE/accidentelle impossible (aucun bouton "voir"/"copier" pour ce type de partage) et borne
strictement le nombre d'OCCASIONS d'y accéder — mais un destinataire techniquement outillé
(inspection de sa propre extension/application) pourrait toujours extraire la valeur en clair
PENDANT un usage autorisé. C'est une limite inhérente à tout mécanisme de remplissage automatique
côté client, pas un défaut corrigible côté serveur.

### `POST /vault/{id}/blind-shares`

Crée un partage à usage limité pour l'entrée `{id}`. Le client résout d'abord la clé publique du
destinataire (`GET /emergency/keys/{email}`) et scelle **séparément** le nom du site et les
identifiants avant d'appeler cette route.

| Champ | Type | Requis | Contraintes |
|---|---|---|---|
| `shared_with_email` | string | oui | email valide, différent du sien |
| `sealed_site_name` | string | oui | 1-8192 caractères |
| `sealed_credentials` | string | oui | 1-32768 caractères — JSON scellé (identifiant + mot de passe) |
| `max_uses` | number | non | 1-1000, défaut 1 |

**Réponse** : `201 Created`, `{ "id": "uuid" }`.
**Erreurs** : `400` validation, ou tentative de partage avec soi-même ; `404` si `{id}` n'existe pas
ou n'appartient pas à l'appelant.
**Effet de bord** : notifie le destinataire par email.

### `GET /vault/{id}/blind-shares`

Liste les partages à usage limité actifs de l'entrée `{id}`, vus par son propriétaire.

**Réponse** : `200 OK`, tableau de `VaultBlindShare` (id, shared_with_email, max_uses,
remaining_uses, created_at — **jamais** les blobs scellés).

### `GET /blind-shares/shared-with-me`

Liste tout ce qui a été partagé en usage limité avec l'utilisateur connecté.

**Réponse** : `200 OK`, tableau de `BlindShareReceivedView` (id, owner_email, `sealed_site_name`
**inclus** — librement consultable, ne consomme jamais d'usage —, max_uses, remaining_uses,
created_at — jamais `sealed_credentials`).

### `POST /blind-shares/{id}/use`

Le **destinataire** consomme UN usage : décrémente `remaining_uses` de façon atomique et renvoie
les identifiants scellés, à desceller et utiliser **immédiatement** côté client (jamais mis en
cache ni ré-affiché ensuite).

**Réponse** : `200 OK`, `{ "sealed_credentials": "...", "remaining_uses": N }`.
**Erreurs** : `400` (message dédié) si plus aucun usage disponible ; `404` si le partage n'existe
pas, si l'appelant n'en est pas le destinataire désigné, ou si l'entrée source a depuis été
supprimée (mise à la corbeille ou purgée).

### `DELETE /blind-shares/{id}`

Révoque un partage à usage limité — le propriétaire ou le destinataire peuvent y mettre fin à tout
moment, indépendamment du nombre d'usages restants.

**Réponse** : `204 No Content`. **Erreurs** : `404`.

## Endpoints — Synchronisation temps réel

### `POST /ws/ticket`

*Authentification requise.* Échange l'access token contre un ticket à usage unique, destiné
exclusivement à l'ouverture de `/ws` (voir [Modèle d'authentification](#modèle-dauthentification)).

**Réponse** : `200 OK` :
```json
{ "ticket": "...", "expires_in": 60 }
```

### `GET /ws?ticket=<ticket>`

Bascule la connexion en WebSocket. Le `ticket` (obtenu via `POST /ws/ticket`) est à usage unique
et expire après 60 secondes.

Une fois connecté, le client reçoit des messages texte JSON à chaque modification du coffre
effectuée depuis un **autre** appareil du même compte :
```json
{ "event_type": "VAULT_ADD" }
```
Valeurs possibles : `VAULT_ADD`, `VAULT_DELETE`, `VAULT_UPDATE`, `VAULT_TOGGLE_FAVORITE`,
`VAULT_RESTORE`, `VAULT_PURGE`, `VAULT_IMPORT`. Ce canal ne transporte **jamais** de contenu
chiffré — c'est uniquement un signal de réveil, le client doit rappeler les routes REST
habituelles (`GET /vault`, `/api/vault/sync`) pour connaître l'état réel.

**Erreurs** : `401 SessionExpired` si le ticket est invalide, déjà consommé, ou expiré. Un
plafond de 10 connexions simultanées par utilisateur s'applique (`409 Conflict` au-delà).

## Endpoints — Administration

**Terminologie** : il n'existe qu'un seul **Admin** — le compte configuré via `ADMIN_EMAIL`
(`is_admin = true`, voir `GET /me` et `GET /admin/users`). Tout autre compte promu
(`is_moderator = true` mais `is_admin = false`) est un **Modérateur** : il peut gérer les
comptes non-admin, mais jamais un autre modérateur ni l'Admin — voir la section "Hiérarchie entre
admins" de chaque endpoint ci-dessous.

### `GET /audit`

*Authentification requise, réservé aux administrateurs.*

**Rétention : 10 jours** — même purge que `GET /audit/me` (voir sa section pour le détail et
pourquoi la trace reste disponible dans les fichiers de log au-delà).

**Réponse** : `200 OK`, les 100 derniers logs d'audit du système (tous utilisateurs confondus),
triés du plus récent au plus ancien :
```json
[{
  "id": 1,
  "user_email": "...",
  "action": "LOGIN_SUCCESS_SESSION",
  "ip_address": "...",
  "user_agent": "...",
  "created_at": "..."
}]
```
**Erreurs** : `403` si l'appelant n'est pas administrateur.

### `GET /admin/users`

*Authentification requise, réservé aux administrateurs.*

Liste tous les comptes de l'application. **Ne contient jamais `password_hash`**, même haché.

**Réponse** : `200 OK` :
```json
[{
  "email": "...",
  "is_moderator": false,
  "email_verified": true,
  "created_at": "...",
  "max_trusted_devices": 10,
  "can_change_email_via_extension": false,
  "can_choose_server_in_settings": false,
  "is_admin": false,
  "is_suspended": false,
  "entry_count": 42,
  "attachment_bytes": 1048576
}]
```
`is_admin` : voir la note de terminologie en tête de cette section — vrai UNIQUEMENT sur
la ligne du compte `ADMIN_EMAIL` (l'"Admin"), jamais sur un simple "Modérateur".

`is_suspended` : voir `PUT /admin/users/{email}/suspended` plus bas.

`entry_count` (entrées de coffre non supprimées) et `attachment_bytes` (somme des pièces jointes)
donnent l'espace occupé par chaque compte — sur un serveur auto-hébergé, voir qui approche des
plafonds évite de découvrir le problème par un disque plein. Ils sont calculés par deux agrégats
GROUP BY distincts recroisés en mémoire, et non par des sous-requêtes corrélées par ligne : le coût
reste le même que le serveur ait 3 comptes ou 300. Un compte sans aucune entrée n'apparaît dans
aucun des deux agrégats et reçoit donc `0`, pas une absence de champ.
**Erreurs** : `403` si l'appelant n'est pas administrateur.

### `PUT /admin/users/{email}/role`

*Authentification requise, réservé au PREMIER admin uniquement (voir plus bas).* Promeut ou
rétrograde un compte administrateur. **SEUL le compte configuré via `ADMIN_EMAIL` (le "premier
admin", propriétaire de l'instance) peut appeler cet endpoint** — un AUTRE admin, même avec
`is_moderator = true` en base, ne peut ni promouvoir ni rétrograder personne (`403`). Le premier admin
**ne peut pas modifier son propre rôle** via cet endpoint (évite un verrouillage accidentel).
Si `ADMIN_EMAIL` n'est pas configuré, personne ne peut plus changer de rôle via cet endpoint.

| Champ | Type | Obligatoire |
|---|---|---|
| `is_moderator` | boolean | oui |

**Réponse** : `200 OK`, corps vide.
**Erreurs** : `403` appelant autre que le premier admin. `400` tentative d'auto-modification.
`404` email inconnu.

### `PUT /admin/users/{email}/email`

*Authentification requise, réservé aux administrateurs.* Change l'email d'un AUTRE compte —
utile si un utilisateur a perdu l'accès à sa boîte mail ou a fait une faute de frappe à
l'inscription. **Ne touche JAMAIS au mot de passe maître ni à la clé du coffre** (l'email n'est
pas une donnée cryptographique — le Zero-Knowledge reste intact, l'admin ne peut toujours pas
accéder au contenu du coffre de la cible). Un admin **ne peut pas** l'utiliser sur son propre
compte (utiliser `PUT /auth/email`, avec sa propre reconfirmation par mot de passe).

| Champ | Type | Obligatoire |
|---|---|---|
| `new_email` | string (email) | oui |

**Hiérarchie entre admins** (même règle que les endpoints ci-dessous) : le premier admin
(`ADMIN_EMAIL`) ne peut JAMAIS être ciblé, par personne. Un admin "normal" ne peut cibler QUE des
comptes non-admin — cibler un AUTRE admin reste réservé au premier admin.

**Réponse** : `200 OK`, corps vide.
**Erreurs** : `403` non-admin, ou tentative de cibler un admin sans être le premier admin. `400`
validation, ou tentative d'auto-modification. `404` email inconnu.
**Effets de bord** : invalide toutes les sessions du compte ; envoie une alerte de sécurité à
**l'ancienne** adresse (seul moyen pour le vrai propriétaire de s'apercevoir du changement s'il
n'en est pas à l'origine) ; tracé dans l'audit sous le **nouvel** email.

### `PUT /admin/users/{email}/extension-email-change`

*Authentification requise.* Autorise ou interdit à CE compte de changer son adresse email depuis
l'extension navigateur (sans effet sur l'app desktop, jamais concernée par cette restriction —
voir `PUT /auth/email` ci-dessus). Désactivé par défaut pour tout le monde ; un admin reste
toujours autorisé indépendamment de ce réglage pour son propre compte.
**Hiérarchie entre admins** (voir aussi `DELETE /admin/users/{email}` et
`POST /admin/users/{email}/revoke-sessions` ci-dessous, même règle) : le premier admin
(`ADMIN_EMAIL`) ne peut JAMAIS être la cible, par personne. Un admin "normal" ne peut cibler QUE
des comptes non-admin — cibler un AUTRE admin reste réservé au premier admin.

| Champ | Type | Obligatoire |
|---|---|---|
| `enabled` | boolean | oui |

**Réponse** : `200 OK`, corps vide.
**Erreurs** : `403` non-admin, ou tentative de cibler un admin sans être le premier admin. `404` email inconnu.

### `PUT /admin/users/extension-email-change-all`

*Authentification requise, réservé au PREMIER admin uniquement.* Même réglage que ci-dessus, mais
appliqué à TOUS les comptes d'un coup — comme cette variante touche aussi les comptes admin (sans
pouvoir les exclure proprement), elle est réservée exclusivement à `ADMIN_EMAIL`.

| Champ | Type | Obligatoire |
|---|---|---|
| `enabled` | boolean | oui |

**Réponse** : `200 OK`, corps vide.
**Erreurs** : `403` appelant autre que le premier admin.

### `PUT /admin/users/{email}/server-choice`

*Authentification requise, réservé à l'Admin (`ADMIN_EMAIL`) — PAS un simple modérateur.* Autorise
ou interdit à CE compte de changer l'adresse du backend depuis les Réglages de l'app
(desktop/Android). Désactivé par défaut pour tout le monde ; l'Admin reste toujours autorisé
indépendamment de ce réglage, pour son propre compte. Garde-fou volontairement plus strict que
`PUT /admin/users/{email}/extension-email-change` ci-dessus (réservé aux modérateurs) : rediriger
l'app de quelqu'un vers un autre backend est un vecteur d'hameçonnage bien plus sensible — un faux
backend pourrait capter le hash du mot de passe maître envoyé à la connexion.

| Champ | Type | Obligatoire |
|---|---|---|
| `enabled` | boolean | oui |

**Réponse** : `200 OK`, corps vide.
**Erreurs** : `403` appelant non-Admin, ou tentative de cibler l'Admin lui-même. `404` email inconnu.

### `PUT /admin/users/server-choice-all`

*Authentification requise, réservé à l'Admin.* Même réglage que ci-dessus, mais appliqué à TOUS
les comptes d'un coup (modérateurs compris, sans clause d'exclusion possible).

| Champ | Type | Obligatoire |
|---|---|---|
| `enabled` | boolean | oui |

**Réponse** : `200 OK`, corps vide.
**Erreurs** : `403` appelant non-Admin.

### `PUT /admin/server-choice-at-login`

*Authentification requise, réservé à l'Admin.* Réglage **GLOBAL** (pas par compte) : contrôle si
le lien "Configurer le serveur" est visible sur l'écran de connexion de l'app, **avant toute
authentification** — voir `GET /public-config` ci-dessous, qui expose cette valeur sans
authentification (aucun compte n'est encore identifié à ce stade).

| Champ | Type | Obligatoire |
|---|---|---|
| `enabled` | boolean | oui |

**Réponse** : `200 OK`, corps vide.
**Erreurs** : `403` appelant non-Admin.

### `POST /admin/users/{email}/revoke-sessions`

*Authentification requise.* Révoque immédiatement toutes les
sessions actives du compte ciblé (tous appareils, access tokens déjà émis inclus) et ferme ses
connexions WebSocket actives — équivalent de `POST /devices/logout-all`, déclenché par un admin
sur un compte tiers (ex: compte signalé compromis). **Hiérarchie entre admins** : le premier admin
(`ADMIN_EMAIL`) ne peut jamais être ciblé (même par lui-même — utiliser
`POST /devices/logout-all` pour ses propres sessions) ; un admin "normal" ne peut cibler que des
comptes non-admin.

**Réponse** : `204 No Content`.
**Erreurs** : `403` non-admin, ou tentative de cibler un admin sans être le premier admin. `404` email inconnu.

### `DELETE /admin/users/{email}`

*Authentification requise.* Supprime **définitivement** un compte et
tout ce qui lui est rattaché (coffre, appareils de confiance, sessions, codes en attente — voir
`ON DELETE CASCADE`). Aucun retour en arrière possible. Un admin **ne peut pas supprimer son
propre compte** via cet endpoint. **Hiérarchie entre admins** : même règle que
`POST /admin/users/{email}/revoke-sessions` ci-dessus — le premier admin ne peut jamais être
supprimé, un admin "normal" ne peut supprimer que des comptes non-admin.

**Réponse** : `204 No Content`.
**Erreurs** : `403` non-admin, ou tentative de cibler un admin sans être le premier admin. `400`
tentative d'auto-suppression. `404` email inconnu.

## Endpoints — Signalement de bug

Envoyé depuis l'app desktop/Android (voir `components/BugReportModal.tsx`), **jamais chiffré** :
un texte technique destiné à être lu directement par un modérateur, pas une donnée du coffre.

### `POST /bug-reports`

**Route PUBLIQUE — aucune authentification requise.** Accessible même sans compte/connexion,
volontairement : un bug qui empêche justement de se connecter doit pouvoir être signalé depuis
l'app elle-même. Rate-limitée (voir `bug_report_governor`, 8 req/s par IP — palier dédié, plus
permissif que le palier "Sensible" réservé au brute-force sur l'authentification) et plafonnée à
500 signalements en attente au total via une insertion SQL atomique (au-delà, `400` — protège
contre un remplissage de la table par une route anonyme, sans fenêtre de course exploitable).

| Champ | Type | Obligatoire |
|---|---|---|
| `description` | string (1-4000) | oui |
| `reporter_email` | string (email) | non — simple info de contact, jamais vérifiée contre un compte, sert aussi à prévenir la personne quand le signalement est marqué traité (voir `DELETE /admin/bug-reports/{id}`) |
| `app_version` | string (1-50) | oui |
| `platform` | string (1-50) | oui |
| `category` | string (1-30) | non — "Autre" par défaut si absent, n'importe quelle chaîne est acceptée (liste fermée uniquement côté client, voir `BugReportModal.tsx`) |

**Réponse** : `201 Created` :
```json
{ "id": "..." }
```
**Erreurs** : `400` validation, ou plafond global atteint. `429` si le taux de requêtes est dépassé.

### `GET /admin/bug-reports`

*Authentification requise, réservé au SEUL Admin (`ADMIN_EMAIL`) — PAS aux modérateurs*,
contrairement au reste de ce panneau (demande explicite : les signalements peuvent contenir des
détails techniques que le propriétaire de l'instance préfère garder pour lui seul). Liste tous les
signalements, du plus récent au plus ancien.

**Réponse** : `200 OK` :
```json
[{
  "id": "...",
  "reporter_email": "...",
  "description": "...",
  "app_version": "0.1.0",
  "platform": "Windows",
  "category": "Plantage",
  "created_at": "..."
}]
```
**Erreurs** : `403` si l'appelant n'est pas l'Admin (même un modérateur reçoit `403`).

### `DELETE /admin/bug-reports/{id}`

*Authentification requise, réservé au SEUL Admin — même restriction que `GET /admin/bug-reports`
ci-dessus.* Supprime un signalement — pas de statut "résolu" séparé, la suppression EST la façon de
le marquer traité.

**Effets de bord** : si un `reporter_email` avait été laissé, un email de courtoisie lui est envoyé
("ton signalement a été traité") — best-effort, un échec d'envoi ne fait jamais échouer la
suppression elle-même.

**Réponse** : `204 No Content`.
**Erreurs** : `403` si l'appelant n'est pas l'Admin (même un modérateur reçoit `403`). `404`
signalement inconnu.

## Endpoints — Suggestion de fonctionnalité

Envoyé depuis l'app desktop uniquement (voir `components/FeatureSuggestionModal.tsx`), **jamais
chiffré** — même raisonnement que les signalements de bug ci-dessus, mais toutes les routes
exigent un compte connecté (contrairement à `POST /bug-reports`) : une suggestion n'a pas
l'urgence d'un bug qui empêche de se connecter.

### `POST /feature-suggestions`

*Authentification requise — n'importe quel compte connecté peut suggérer une fonctionnalité.*
`author_email` vient toujours du compte authentifié (`AuthUser`), jamais d'un champ du payload.
Pas de palier dédié (sur le palier Global comme le reste de l'API authentifiée) — plafonnée à 20
suggestions en attente PAR AUTEUR (pas global, contrairement aux signalements de bug : cette route
exige un compte, chaque abus reste imputable).

| Champ | Type | Obligatoire |
|---|---|---|
| `description` | string (1-4000) | oui |

**Réponse** : `201 Created` :
```json
{ "id": "..." }
```
**Erreurs** : `400` validation, ou plafond par auteur atteint. `401` non connecté.

### `GET /admin/feature-suggestions`

*Authentification requise, réservé au SEUL Admin (`ADMIN_EMAIL`) — PAS aux modérateurs*, même
restriction que `GET /admin/bug-reports`. Liste toutes les suggestions, de la plus récente à la
plus ancienne.

**Réponse** : `200 OK` :
```json
[{
  "id": "...",
  "author_email": "...",
  "description": "...",
  "created_at": "..."
}]
```
**Erreurs** : `403` si l'appelant n'est pas l'Admin (même un modérateur reçoit `403`).

### `DELETE /admin/feature-suggestions/{id}`

*Authentification requise, réservé au SEUL Admin — même restriction que ci-dessus.* Supprime une
suggestion — pas de statut "examinée" séparé, la suppression EST la façon de la marquer traitée.

**Effets de bord** : un email de courtoisie est envoyé à l'auteur ("ta suggestion a été
examinée") — best-effort, un échec d'envoi ne fait jamais échouer la suppression elle-même.
Contrairement aux signalements de bug, cet email part TOUJOURS (`author_email` n'est jamais vide).

**Réponse** : `204 No Content`.
**Erreurs** : `403` si l'appelant n'est pas l'Admin (même un modérateur reçoit `403`). `404`
suggestion inconnue.

## Endpoints — Personnalisation de thème (profils)

Retour utilisateur (2026-09-03, affiné le même jour) : contrairement au thème preset choisi côté
client et aux dispositions de menu/listes (tous locaux à chaque appareil, jamais envoyés au
serveur), cette personnalisation SUIT LE COMPTE sur tous les appareils, sous forme de PLUSIEURS
profils nommés (pas un réglage unique). Jamais chiffrée Zero-Knowledge — une préférence d'affichage
n'a rien à protéger. Chaque route agit UNIQUEMENT sur les profils du compte APPELANT (email tiré du
token, jamais d'un paramètre) — aucune restriction de rôle au-delà d'être connecté, SAUF la
création, plafonnée à **3 profils par compte non-admin** (illimité pour le compte `ADMIN_EMAIL`).

Chaque couleur (fond/accent/danger/succès/favoris) a sa propre teinte OKLCH (`*_hue`, 0-359°), sa
propre luminosité (`*_lightness`, 0-100%) ET sa propre saturation (`*_saturation`, 0-100% — un
multiplicateur de la chroma native Tailwind de chaque palier) — pas de mode clair/sombre séparé :
le client déduit s'il doit afficher en clair ou en sombre à partir de la luminosité du fond choisi
(voir `lib/customTheme.ts` côté client). Le calcul de la palette complète reste entièrement côté
client, le serveur ne stocke/valide que des entiers.

### `GET /theme-profiles`

*Authentification requise.* Liste tous les profils du compte connecté, du plus ancien au plus
récent.

**Réponse** : `200 OK`, tableau (vide si le compte n'a jamais rien créé) :
```json
[
  {
    "id": "b6b5...",
    "name": "Mon thème",
    "background_hue": 220, "background_lightness": 12, "background_saturation": 80,
    "accent_hue": 180, "accent_lightness": 55, "accent_saturation": 100,
    "danger_hue": 20, "danger_lightness": 60, "danger_saturation": 100,
    "success_hue": 150, "success_lightness": 65, "success_saturation": 100,
    "favorite_hue": 60, "favorite_lightness": 75, "favorite_saturation": 100,
    "is_active": true
  }
]
```
`is_active` : au plus UN profil actif à la fois par compte (voir `POST .../activate` ci-dessous).

### `POST /theme-profiles`

*Authentification requise.* Crée un nouveau profil (jamais actif à la création — voir `activate`
ci-dessous pour ça). Corps identique aux champs de la vue ci-dessus, `name` en plus (1-60
caractères), sans `id`/`is_active`.

| Champ | Type | Contrainte |
|---|---|---|
| `name` | string | 1-60 caractères |
| `background_hue`, `accent_hue`, `danger_hue`, `success_hue`, `favorite_hue` | entier | 0-359 |
| `background_lightness`, `accent_lightness`, `danger_lightness`, `success_lightness`, `favorite_lightness` | entier | 0-100 |
| `background_saturation`, `accent_saturation`, `danger_saturation`, `success_saturation`, `favorite_saturation` | entier | 0-100 (0 = gris pur pour le fond, chroma nulle pour les autres ; 100 = chroma native Tailwind) |

**Réponse** : `201 Created`, le profil créé (même forme que GET, `is_active: false`).
**Erreurs** : `400` validation (nom/teinte/luminosité hors plage, OU plafond de 3 profils atteint
pour un compte non-admin).

### `PUT /theme-profiles/{id}`

*Authentification requise.* Modifie un profil existant du compte connecté (nom + toutes les
teintes/luminosités) — n'affecte jamais `is_active` (voir `activate` ci-dessous). Mêmes champs que
`POST` ci-dessus.

**Réponse** : `204 No Content`.
**Erreurs** : `400` validation. `404` si `id` n'existe pas ou n'appartient pas au compte connecté.

### `DELETE /theme-profiles/{id}`

*Authentification requise.* Supprime un profil du compte connecté. Si le profil supprimé était
actif, plus AUCUN profil n'est actif ensuite (le client retombe sur un thème preset) — jamais
réactivé automatiquement un autre profil à sa place.

**Réponse** : `204 No Content`.
**Erreurs** : `404` si `id` n'existe pas ou n'appartient pas au compte connecté.

### `POST /theme-profiles/{id}/activate`

*Authentification requise.* Active ce profil et désactive tous les autres profils du compte
connecté, de façon atomique (jamais deux profils actifs en même temps).

**Réponse** : `204 No Content`.
**Erreurs** : `404` si `id` n'existe pas ou n'appartient pas au compte connecté.

### Partage d'un profil avec un autre utilisateur

Retour utilisateur (2026-09-03) : "savoir le partager avec d'autres utilisateurs" plutôt qu'un
simple code copiable-collable (toujours disponible côté client, voir
`lib/customTheme.ts::encodeThemeCode`). PAS de chiffrement — une personnalisation de thème n'a
rien à protéger, contrairement au partage d'entrées du coffre.

### `POST /theme-profiles/{id}/share`

*Authentification requise.* Partage UN des profils du compte connecté avec un autre utilisateur de
ce serveur — copie ses valeurs telles quelles au moment du partage (pas un lien live : modifier le
profil source ensuite n'affecte pas ce qui a été partagé).

| Champ | Type | Contrainte |
|---|---|---|
| `shared_with_email` | string | email valide, différent du compte appelant |

**Réponse** : `201 Created { "id": "..." }`.
**Erreurs** : `400` si l'email est invalide ou identique au compte appelant. `404` si `id`
n'appartient pas au compte connecté, OU si `shared_with_email` ne correspond à aucun compte de ce
serveur.

### `GET /theme-profiles/shared`

*Authentification requise.* Liste tous les partages EN ATTENTE reçus par le compte connecté (pas
encore acceptés/déclinés), du plus récent au plus ancien.

**Réponse** : `200 OK`, tableau (vide si personne n'a rien partagé) — chaque élément a la même
forme qu'un profil (voir `GET /theme-profiles`), plus `from_email` (l'expéditeur), sans `id` de
profil ni `is_active` (ce n'est pas encore un profil).

### `POST /theme-profiles/shared/{id}/accept`

*Authentification requise.* Accepte un partage reçu — le copie dans les PROPRES profils du compte
connecté (soumis au même plafond de 3 profils que `POST /theme-profiles`) puis retire le partage
de la liste d'attente.

**Réponse** : `201 Created`, le nouveau profil créé (même forme que `POST /theme-profiles`).
**Erreurs** : `400` si le plafond de profils est atteint — le partage reste alors EN ATTENTE
(non supprimé), réessayable après avoir supprimé un profil existant. `404` si `id` n'existe pas ou
n'est pas adressé au compte connecté.

### `DELETE /theme-profiles/shared/{id}`

*Authentification requise.* Refuse/retire un partage — l'expéditeur peut annuler avant
acceptation, le destinataire peut décliner (les deux côtés acceptés, comme la révocation d'un
partage d'entrée du coffre).

**Réponse** : `204 No Content`.
**Erreurs** : `404` si `id` n'existe pas ou n'implique le compte connecté ni comme expéditeur ni
comme destinataire.

### Choix du thème lui-même (preset ou "custom")

Retour utilisateur : *"je veux que lorsqu'on choisit un thème ce soit pour partout (aussi
l'extension) que le thème soit appliqué partout"* — distinct de tout ce qui précède, qui gère les
COULEURS d'un profil "Personnalisé…". Ce champ dit simplement LEQUEL des thèmes disponibles est
actuellement choisi sur le compte, y compris un simple preset (`dark`/`light`/`system`/`midnight`/
`ocean`/`forest`/`sunset`/`rose`/`violet`/`amber`/`slate`/`custom`) qui restait jusqu'ici purement
local à chaque appareil. Exposé en lecture via `preferred_theme` sur `GET /me`.

### `PUT /theme-preference`

*Authentification requise.* Met à jour le thème actuellement choisi par le compte connecté.

**Corps** :
```json
{ "theme": "midnight" }
```

**Réponse** : `204 No Content`.
**Erreurs** : `400` si `theme` ne fait pas partie des valeurs reconnues côté serveur.

## Endpoints — Divers

### `GET /health`

*Aucune authentification requise.* Vérifie que le serveur répond ET que la base de données est
joignable.

**Réponse** : `200 OK { "status": "ok" }`, ou `503 Service Unavailable { "status": "db_unreachable" }`.

### `GET /admin/users/{email}/ip-history`

*Authentification requise, modérateur.* Toutes les adresses IP vues pour UN compte, avec ce
qu'elles ont produit.

Lit `account_ip_history` (migration `20260904120000`), **pas** `audit_logs` : l'historique n'est
donc plus tronqué à la purge de 10 jours du journal. C'était la limite de la première version — une
adresse revenant tous les quinze jours y paraissait neuve à chaque fois, précisément le cas qu'on
cherche à repérer.

**Pourquoi une table séparée plutôt qu'un agrégat du journal.** Le journal garde des ÉVÉNEMENTS
récents en détail ; cette table garde une mémoire longue et compacte des ADRESSES. Le coût reste
minuscule parce qu'on stocke une ligne par (compte, adresse) et non par événement : quelques
dizaines de lignes pour un serveur familial, là où `audit_logs` en accumule des milliers. C'est ce
qui rend la conservation longue acceptable ici alors qu'elle ne l'était pas pour le journal.

Alimentée par `AppState::record_ip_seen()`, appelée depuis `log_audit()` — donc par tout événement
audité, best-effort : un échec d'écriture n'interrompt jamais l'action de l'utilisateur.

**Les trois chiffres, et pourquoi ils sont là.** Une IP nue ne dit rien :

- `success_count` / `failure_count` — beaucoup d'échecs **puis** une réussite depuis la même
  adresse est la signature d'une intrusion aboutie par tâtonnement. Sans ce couple, impossible de
  distinguer cette situation d'un usage normal. Comptés comme échec : `LOGIN_FAILED`,
  `LOGIN_BLOCKED_TOO_MANY_ATTEMPTS`, `LOGIN_BLOCKED_UNVERIFIED`, `LOGIN_BLOCKED_SUSPENDED`. Comme
  succès : `LOGIN`, `LOGIN_SUCCESS`, `LOGIN_SUCCESS_REMEMBER`, `LOGIN_SUCCESS_SESSION`. Les autres
  actions n'incrémentent que `event_count`.
- `other_accounts` — combien d'AUTRES comptes ont utilisé la même adresse. **À lire avec prudence
  sur un serveur familial** : tout le monde y partage l'IP publique de la maison, donc une adresse
  commune est la norme et non une anomalie. Le signal utile est le croisement — une adresse
  partagée qui porte AUSSI des échecs.

**Rétention.** Pas de limite de temps, volontairement : c'est tout l'intérêt de la table. La borne
est en nombre — `MAX_IPS_PER_ACCOUNT = 500` adresses par compte, élaguées par
`maintenance::prune_account_ip_history()` sur les moins récemment vues. L'élagage a lieu dans le
cycle de maintenance et non à l'écriture, qui est sur le chemin critique de chaque connexion.
`ON DELETE CASCADE` : l'historique disparaît avec le compte, contrairement à `audit_logs`
volontairement conservé — le garder serait de la rétention de données personnelles sans usage.

**Réponse** : `200 OK`, trié par dernière activité décroissante, 500 lignes au maximum :
```json
[{
  "ip_address": "203.0.113.7",
  "first_seen": "2026-09-01 08:00:00",
  "last_seen": "2026-09-03 11:00:00",
  "event_count": 12,
  "success_count": 4,
  "failure_count": 8,
  "other_accounts": 1
}]
```
Horodatages en UTC au format SQLite (`YYYY-MM-DD HH:MM:SS`), pas ISO 8601.

**Erreurs** : `403` si l'appelant n'est pas modérateur. Un compte inconnu ou sans activité renvoie
une liste vide, pas `404` — l'absence d'activité n'est pas une erreur.

**Pas de géolocalisation côté serveur, délibérément.** Localiser une adresse demande d'interroger
un service tiers, donc de lui transmettre les adresses des utilisateurs — dans un gestionnaire de
mots de passe à divulgation nulle, faire fuiter par un canal annexe ce que le chiffrement protège
serait contradictoire. Le client propose à la place un lien « Localiser » que l'administrateur
ouvre lui-même dans son navigateur, et le dit explicitement à l'écran.

**Piège de déploiement** : derrière un reverse proxy sans `TRUST_PROXY_HEADERS=true`, le serveur
enregistre l'IP du **proxy**, identique pour tous les comptes. La route ne peut pas le détecter ;
le client prévient quand il ne voit qu'une seule adresse et qu'elle est privée.

### `PUT /admin/registration-open`

*Authentification requise, réservé à l'Admin (`ADMIN_EMAIL`) — PAS un simple modérateur.* Ouvre ou
ferme les inscriptions sur tout le serveur.

Ouvert par défaut, et la migration laisse volontairement cette valeur pour ne rien casser sur un
serveur existant — un serveur qui se fermerait tout seul après une mise à jour serait une mauvaise
surprise. Sur un déploiement familial exposé sur Internet, laisser ouvert permet à quiconque trouve
l'URL de créer un compte, donc de consommer l'espace disque, de déclencher des envois depuis ton
SMTP (brûlant ton quota et la réputation de ton domaine) et de remplir le journal d'audit : à
refermer une fois tes comptes créés.

Le refus est appliqué **avant** le hachage Argon2id de `POST /auth/register`, pour qu'un serveur
fermé ne serve pas d'amplificateur de charge. Le compte `ADMIN_EMAIL` reste **toujours** autorisé à
s'inscrire, même fermé : sans cette exception, un serveur neuf livré fermé n'aurait aucun
administrateur possible.

| Champ | Type | Obligatoire |
|---|---|---|
| `enabled` | boolean | oui |

**Réponse** : `200 OK`, corps vide.
**Erreurs** : `403` appelant autre que l'Admin.
**Audit** : `REGISTRATION_OPENED` / `REGISTRATION_CLOSED`.

### `PUT /admin/users/{email}/suspended`

*Authentification requise, modérateur.* Suspend ou réactive un compte — marche intermédiaire entre
"ne rien faire" et `DELETE /admin/users/{email}`, qui cascade sur tout le coffre et ne se rattrape
pas. Les données sont **conservées** : l'opération est réversible.

Une suspension **coupe aussi les sessions en cours** (suppression des `refresh_tokens` dans la même
transaction que la mise à jour du drapeau) ; sans cela, le compte resterait utilisable jusqu'à
l'expiration de son jeton d'accès. Le middleware d'authentification refuse par ailleurs tout jeton
d'un compte suspendu, avec `401 Ce compte est suspendu.`

Même hiérarchie que les autres actions sur un compte tiers (`check_can_act_on_target`) : l'Admin ne
peut jamais être la cible, et un modérateur ne peut pas suspendre un autre modérateur.

| Champ | Type | Obligatoire |
|---|---|---|
| `is_suspended` | boolean | oui |

**Réponse** : `200 OK`, corps vide.
**Erreurs** : `403` non-modérateur, ou cible protégée par la hiérarchie. `404` email inconnu.
**Audit** : `ACCOUNT_SUSPENDED` / `ACCOUNT_UNSUSPENDED`.

### `GET /public-config`

*Aucune authentification requise* — volontairement séparé de `GET /health` ci-dessus (rôles
différents : orchestrateur/load balancer d'un côté, config produit de l'autre). Petits réglages
GLOBAUX (pas par compte) lisibles avant toute connexion — utilisé par l'écran de connexion de l'app
pour savoir s'il doit afficher le lien "Configurer le serveur" (voir
`PUT /admin/server-choice-at-login` plus haut, réservé à l'Admin).

**Réponse** : `200 OK` :
```json
{ "server_choice_at_login_enabled": false, "registration_open": true }
```

`registration_open` est lu **frais à chaque appel**, contrairement à
`server_choice_at_login_enabled` qui est mis en cache : l'écran Administration affiche cette valeur
comme l'état réel du serveur, et un cache la rendrait trompeuse juste après un basculement.
L'écran d'inscription s'en sert pour prévenir avant que le formulaire ne soit rempli — mais c'est
un pur confort d'affichage, `POST /auth/register` reste la seule autorité.
