use serde::{Deserialize, Serialize};
use validator::Validate;
use regex::Regex;
use std::sync::LazyLock;

// SyncResponse est utilisée à la fois par /api/vault/sync et son alias /api/vault/sync-check.
#[derive(Serialize)]
pub struct SyncResponse {
    /// Un token unique (souvent un hash ou un timestamp) représentant l'état du coffre
    pub sync_token: String,
    /// Le nombre d'éléments actuellement dans le coffre (utile pour une vérification rapide)
    pub total_entries: i64,
    /// La date de dernière modification globale du coffre pour cet utilisateur
    pub last_modified: String,
}

/// Événement interne diffusé via `AppState::sync_tx` (canal broadcast en mémoire, PAS en BDD)
/// à chaque fois qu'un utilisateur modifie son coffre depuis un appareil. Chaque connexion
/// WebSocket ouverte par un autre appareil du MÊME utilisateur reçoit cet événement et sait
/// qu'il doit re-synchroniser (en rappelant les routes REST habituelles — ce canal ne transporte
/// jamais le contenu chiffré lui-même, juste un signal "quelque chose a changé").
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncEvent {
    /// Sert à filtrer côté serveur : seules les connexions WebSocket de CET utilisateur doivent
    /// recevoir l'événement (le canal broadcast est partagé par tous les utilisateurs connectés).
    #[serde(skip)] // Jamais renvoyé au client : c'est un détail de routage interne, pas une donnée utile
    pub user_email: String,
    /// Action qui a déclenché l'événement (ex: "VAULT_ADD", "VAULT_DELETE"...) — informatif
    /// seulement, le client doit de toute façon rappeler GET /vault pour connaître l'état réel.
    pub event_type: String,
}

// =========================================================================
// 1. EXPRESSIONS RÉGULIÈRES (VALIDATION GLOBALE)
// =========================================================================

/// Valide la LONGUEUR d'un hash d'authentification dérivé côté client (Zero-Knowledge total —
/// voir crypto.rs et le commentaire sur AuthPayload). Ce n'est PLUS un mot de passe lisible :
/// c'est la sortie d'une KDF (Argon2id/PBKDF2) calculée par le client, encodée en base64/hex.
/// La plage 6-128 reste volontairement large pour couvrir les encodages usuels (ex: base64 d'un
/// hash SHA-256 ≈ 44 caractères, hex d'un hash 512 bits ≈ 128 caractères).
pub static RE_PASSWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^.{6,128}$").unwrap()
});


// =========================================================================
// 2. MODÈLES DE BASE DE DONNÉES (ENTITÉS)
// =========================================================================

/// Représente un appareil de confiance dans la réponse de listage (GET /devices).
#[derive(Serialize, sqlx::FromRow)]
pub struct TrustedDevice {
    pub device_id: String,
    pub device_name: Option<String>,
    pub created_at: chrono::NaiveDateTime,
    pub last_used_at: chrono::NaiveDateTime, // Dernière connexion réussie depuis cet appareil
    /// Dernière adresse IP vue pour cet appareil (voir trusted_device_ips) — `None` pour un
    /// appareil approuvé avant l'existence de cette table (migration 20260831000000), jamais
    /// rétroactivement rempli. Retour utilisateur (2026-09-02) : demandé pour l'écran "Appareils
    /// de confiance", pour repérer un appareil suspect sans attendre une alerte email.
    pub last_ip: Option<String>,
}

/// Représente un utilisateur dans la base de données.
/// `password_hash` : ATTENTION, depuis le passage au Zero-Knowledge total, ceci est le hachage
/// (Argon2 + pepper serveur) d'un hash d'authentification déjà dérivé côté CLIENT à partir du
/// mot de passe maître — le serveur ne voit et ne stocke jamais le mot de passe maître lui-même,
/// ni la clé qui chiffre le coffre (voir crypto.rs).
/// `sqlx::FromRow` permet à SQLx de mapper automatiquement les colonnes d'une ligne SQL vers cette structure.
#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub email: String,
    pub password_hash: String,
    pub is_moderator: bool,    // Indicateur de rôle pour les privilèges de modérateur
    // Faux tant que le code envoyé à l'inscription n'a pas été confirmé via /auth/verify-email
    // (voir handlers/auth.rs::register()/verify_email()) — login() refuse les comptes non
    // vérifiés, pour empêcher quelqu'un de s'inscrire avec l'email de quelqu'un d'autre.
    pub email_verified: bool,
    // Anti-bruteforce PAR COMPTE (voir handlers/auth/session.rs::login()) : nombre d'échecs de
    // mot de passe consécutifs depuis la dernière connexion réussie, et horodatage du dernier
    // échec. Remis à zéro sur connexion réussie. Complète le rate limiting par IP (main.rs), qui
    // seul ne protège pas un compte ciblé par un attaquant changeant d'IP.
    pub failed_login_attempts: i64,
    pub last_failed_login_at: chrono::NaiveDateTime,
}

/// Vue "administrateur" d'un compte (voir handlers/admin.rs::list_users()) — délibérément
/// séparée de `User` : ne contient JAMAIS `password_hash`, même haché. Un endpoint réservé aux
/// modérateurs n'a aucune raison de faire transiter ce champ, quand bien même il ne serait jamais
/// affiché côté client — défense en profondeur contre une future erreur de sérialisation.
#[derive(Serialize, sqlx::FromRow)]
pub struct AdminUserView {
    pub email: String,
    pub is_moderator: bool,
    pub email_verified: bool,
    pub created_at: chrono::NaiveDateTime,
    pub max_trusted_devices: i64,
    /// Autorisation à changer son email DEPUIS L'EXTENSION NAVIGATEUR — voir
    /// handlers/auth/account.rs::update_email(). Sans rapport avec is_moderator/email_verified :
    /// l'Admin reste toujours autorisé indépendamment de cette colonne.
    pub can_change_email_via_extension: bool,
    /// Autorisation à changer l'adresse du backend DEPUIS LES RÉGLAGES, une fois connecté (voir
    /// frontend(app)/src/components/ServerUrlForm.tsx) — même principe que le champ ci-dessus,
    /// l'Admin reste toujours autorisé indépendamment de cette colonne. Voir aussi
    /// server_choice_at_login_enabled (table app_settings) : réglage GLOBAL distinct, pour la
    /// visibilité du même choix AVANT connexion (aucun compte identifié à ce stade).
    pub can_choose_server_in_settings: bool,
    /// Vrai UNIQUEMENT pour le compte configuré via ADMIN_EMAIL — il n'existe qu'UN SEUL "Admin"
    /// (ce compte) ; tout autre compte avec `is_moderator = true` est un "Modérateur" (voir
    /// handlers/admin.rs::list_users(), qui remplit ce champ après coup via
    /// AuthUser::is_admin() — PAS sélectionné en SQL, `#[sqlx(default)]` évite d'exiger une
    /// colonne de ce nom dans la ligne).
    #[sqlx(default)]
    pub is_admin: bool,
}

/// Représente une entrée de journal d'audit en base de données pour l'historique de sécurité.
#[derive(Serialize, sqlx::FromRow)]
pub struct AuditLog {
    pub id: i64,
    pub user_email: String,
    pub action: String,             // L'action effectuée (ex: "CONNEXION", "MODIF_MDP")
    pub ip_address: String,         // Adresse IP de l'appelant
    pub user_agent: Option<String>, // Navigateur ou outil utilisé (Optionnel car non garanti)
    pub created_at: chrono::NaiveDateTime, // Horodatage précis de l'action
}

/// Représente un code de double authentification (2FA / TFA) stocké temporairement en BDD.
/// `purpose` distingue les TROIS flux qui partagent cette même table ("login_2fa",
/// "email_verification", "password_reset" — voir les constantes PURPOSE_* dans handlers/auth.rs) :
/// sans ce champ, un code généré pour un flux pouvait écraser et valider un autre flux concurrent
/// pour le même email (voir la migration 20260806000000_tfa_codes_purpose.sql).
#[allow(dead_code)]
#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct TfaCode {
    pub email: String,
    pub purpose: String,
    pub code: String,
    pub expires_at: String,         // Date de fin de validité sous forme de chaîne de caractères
    pub attempts: i64,              // Nombre de tentatives échouées (verrouillage après un seuil)
}


// =========================================================================
// 3. ENTRÉES DU COFFRE-FORT (VAULT POOL) — ZERO-KNOWLEDGE TOTAL
// =========================================================================
// TOUS les champs de contenu (encrypted_site_name, encrypted_username, encrypted_login_email,
// encrypted_preferred_login_type, encrypted_password) sont des blobs chiffrés côté CLIENT.
// Le serveur les stocke tels quels, sans jamais tenter de les lire, comparer, ou trier par
// contenu (impossible et trompeur sur du texte chiffré). Seuls `id`, `is_favorite`,
// `updated_at`/`deleted_at` restent des métadonnées en clair, nécessaires au fonctionnement
// du service (identifier une ligne, trier les favoris, gérer la corbeille/sync).

/// Données envoyées PAR LE CLIENT pour créer ou modifier une entrée du coffre-fort.
/// Volontairement séparée de `VaultEntry` (la réponse serveur) : `id` et `user_email` ne sont
/// jamais fournis par le client ici — `id` est généré côté serveur à la création, et `user_email`
/// est toujours celui extrait du JWT (jamais celui que le client prétendrait envoyer), donc ces
/// deux champs n'ont simplement pas leur place dans ce que le client peut soumettre.
/// Valeur par défaut de `VaultEntryInput::entry_type`/pour une entrée créée avant l'existence de
/// ce champ — voir la migration 20260830000000_vault_entry_types.sql, qui applique le même défaut
/// côté colonne SQL.
fn default_entry_type() -> String {
    "login".to_string()
}

#[derive(Deserialize, Validate, Clone)]
pub struct VaultEntryInput {
    // max = 8192 : généreux pour couvrir le surcoût du chiffrement + encodage base64 (~33%),
    // même pour un contenu long, tout en empêchant un client malveillant/buggé de soumettre un
    // blob disproportionné (protection contre l'épuisement de stockage — voir repository.rs).
    #[validate(length(min = 1, max = 8192))] 
    pub encrypted_site_name: String,          // Nom du site/appli, CHIFFRÉ côté client

    #[validate(length(max = 8192))]
    pub encrypted_username: Option<String>,   // Identifiant de connexion, CHIFFRÉ côté client
    #[validate(length(max = 8192))]
    pub encrypted_login_email: Option<String>,// Email de connexion, CHIFFRÉ côté client

    #[validate(length(min = 1, max = 8192))]
    pub encrypted_password: String, // Le mot de passe chiffré côté client - Au moins 1 caractère

    #[validate(length(min = 1, max = 8192))]
    pub encrypted_preferred_login_type: String, // Méthode de connexion favorite, CHIFFRÉE
    pub is_favorite: bool,          // Statut de mise en favori (métadonnée EN CLAIR, pas du contenu)

    // Dossier d'organisation (ex: "Travail", "Perso") — CHIFFRÉ comme tout le reste : même un nom
    // de dossier révèle une catégorisation sensible ("Banque", "Professionnel"...), pas question
    // de le laisser en clair. Optionnel : NULL = pas de dossier assigné.
    #[validate(length(max = 8192))]
    pub encrypted_folder: Option<String>,

    // Notes libres (ex: réponses aux questions de sécurité) — CHIFFRÉES comme le reste. Optionnel.
    #[validate(length(max = 8192))]
    pub encrypted_notes: Option<String>,

    // URL du site (ex: pour un bouton "Ouvrir le site" côté client) — CHIFFRÉE comme le reste,
    // une URL révèle autant qu'un nom de site. Optionnel.
    #[validate(length(max = 8192))]
    pub encrypted_url: Option<String>,

    // Type d'entrée dédié ("login"/"card"/"identity"/"note") — métadonnée EN CLAIR, comme
    // `is_favorite` (voir la migration 20260830000000_vault_entry_types.sql). `#[serde(default)]`
    // avec la valeur "login" : un CLIENT PLUS ANCIEN qui ignore cette notion continue de créer des
    // entrées "login" exactement comme avant ce champ. Volontairement pas de validation de
    // contenu ici (ex: liste blanche des valeurs) — un type inconnu doit être accepté et stocké
    // tel quel, seul le CLIENT décide comment l'afficher (voir PlainVaultEntry côté frontend, qui
    // retombe sur un affichage générique pour un type qu'il ne reconnaît pas).
    #[serde(default = "default_entry_type")]
    pub entry_type: String,

    // Blob JSON chiffré côté client contenant les champs spécifiques au type (ex: date
    // d'expiration/CVV pour une carte) — voir le commentaire de la migration. Le serveur ne le
    // parse ni ne le valide jamais au-delà de sa longueur, comme tout autre champ `encrypted_*`.
    #[validate(length(max = 8192))]
    #[serde(default)]
    pub encrypted_extra_fields: Option<String>,

    // Vrai UNIQUEMENT si le CLIENT a réellement modifié le mot de passe dans ce formulaire (pas à
    // chaque simple modification de site/dossier/notes, qui repasse pourtant par le même endpoint
    // PUT /vault/{id} — voir handlers/vault.rs::update_vault_entry()). Sert à décider si l'ANCIEN
    // mot de passe chiffré doit être archivé dans l'historique avant d'être écrasé. Le serveur ne
    // peut pas le déduire lui-même en comparant les blobs chiffrés : AES-GCM est randomisé (nonce
    // unique à chaque chiffrement), donc `encrypted_password` diffère TOUJOURS bit à bit d'un appel
    // à l'autre, même si le mot de passe en clair sous-jacent n'a pas changé — cette comparaison ne
    // dirait donc jamais rien d'utile côté serveur.
    #[serde(default)]
    pub password_changed: bool,

    // DÉTECTION DE CONFLIT (voir VaultRepository::update) : le `version` (voir VaultEntry) que le
    // client avait reçu la dernière fois qu'il a chargé cette entrée. S'il ne correspond plus à
    // `version` TEL QU'IL EST ACTUELLEMENT en base au moment de ce PUT, la modification est
    // refusée (AppError::Conflict, 409) plutôt que d'écraser silencieusement une modification
    // faite entre-temps depuis un AUTRE appareil. Un compteur entier dédié plutôt que comparer
    // `updated_at` : CURRENT_TIMESTAMP n'a qu'une précision à la SECONDE en SQLite, deux
    // modifications survenant dans la même seconde auraient le même horodatage et le conflit
    // serait manqué. `#[serde(default)]` : `None` pour un ajout/import (où ce champ n'a pas de
    // sens, VaultEntryInput est partagé entre les trois usages) OU un client plus ancien qui
    // ignore cette notion — dans les deux cas, le contrôle est simplement désactivé, comportement
    // identique à avant ce correctif.
    #[serde(default)]
    pub expected_version: Option<i64>,
}

/// Représente une donnée sensible du coffre-fort telle que RENVOYÉE PAR LE SERVEUR
/// (mappée directement depuis une ligne de la table `vault`, `id` et `user_email` toujours présents).
#[derive(Serialize, sqlx::FromRow)]
pub struct VaultEntry {
    pub id: String,
    pub encrypted_site_name: String,
    pub encrypted_username: Option<String>,
    pub encrypted_login_email: Option<String>,
    pub encrypted_password: String,
    pub encrypted_preferred_login_type: String,
    pub user_email: String,
    pub is_favorite: bool,
    pub encrypted_folder: Option<String>,
    pub encrypted_notes: Option<String>,
    pub encrypted_url: Option<String>,
    // Type d'entrée dédié + ses champs additionnels chiffrés — voir VaultEntryInput ci-dessus pour
    // le détail complet.
    pub entry_type: String,
    pub encrypted_extra_fields: Option<String>,
    // Dernière modification (métadonnée EN CLAIR, comme is_favorite) — sert au client à afficher
    // "modifié il y a X" et à repérer les mots de passe anciens (voir docs/API.md).
    pub updated_at: chrono::NaiveDateTime,
    // Compteur de version (métadonnée EN CLAIR) — incrémenté à CHAQUE modification (voir
    // VaultRepository::update). Le client renvoie la valeur qu'il avait au moment où il a chargé
    // l'entrée dans `VaultEntryInput::expected_version` ; si elle ne correspond plus à celle
    // actuellement en base, la modification est refusée (conflit d'édition, voir plus bas) plutôt
    // que d'écraser silencieusement un changement fait entre-temps depuis un autre appareil.
    pub version: i64,
    // Vrai si cette entrée a au moins une pièce jointe (voir vault_attachments) — métadonnée EN
    // CLAIR calculée à la volée (pas une colonne stockée), utile pour un filtre "avec pièce
    // jointe" côté client sans devoir interroger GET /vault/{id}/attachments pour CHAQUE entrée.
    pub has_attachments: bool,
}

/// Représente une entrée dans la CORBEILLE (supprimée en douceur, pas encore purgée).
/// Volontairement plus léger que `VaultEntry` : pas besoin de renvoyer `encrypted_password` ni
/// `user_email` pour un écran "Corbeille" (juste de quoi identifier l'entrée et décider de la
/// restaurer ou de la purger) — `deleted_at` en plus, pour afficher "supprimé il y a 3 jours".
/// Le client doit déchiffrer `encrypted_site_name` localement pour afficher un nom lisible.
#[derive(Serialize, sqlx::FromRow)]
pub struct TrashedVaultEntry {
    pub id: String,
    pub encrypted_site_name: String,
    pub encrypted_username: Option<String>,
    pub encrypted_login_email: Option<String>,
    pub encrypted_preferred_login_type: String,
    pub is_favorite: bool,
    pub deleted_at: chrono::NaiveDateTime,
    pub encrypted_folder: Option<String>,
}

/// Une entrée du coffre déjà RE-CHIFFRÉE par le client avec la nouvelle clé dérivée du NOUVEAU
/// mot de passe maître (voir ChangeMasterPasswordPayload). Le serveur ne peut absolument pas
/// vérifier que le re-chiffrement est correct (Zero-Knowledge oblige) — c'est entièrement la
/// responsabilité du client de ne pas se tromper. `id` identifie l'entrée EXISTANTE à mettre à
/// jour (ceci ne crée jamais de nouvelle entrée). Le serveur ne vérifie QUE le NOMBRE d'entrées
/// re-chiffrées reçues (voir ChangeMasterPasswordPayload et update_password() dans
/// handlers/auth/account.rs), jamais que chaque champ optionnel individuel (`encrypted_folder`,
/// `encrypted_notes`, `encrypted_url`, `encrypted_extra_fields`...) est cohérent avec ce que
/// l'entrée avait avant — un client buggé qui renverrait `None` pour un champ qui avait
/// pourtant une valeur écraserait silencieusement cette valeur (comportement délibéré, cohérent
/// pour TOUS les champs `encrypted_*` optionnels, pas spécifique à un seul d'entre eux : le
/// contrôle de complétude possible côté serveur s'arrête au comptage, le reste appartient
/// entièrement au client par nature du Zero-Knowledge).
#[derive(Deserialize, Validate, Clone)]
pub struct ReencryptedVaultEntry {
    pub id: String,
    #[validate(length(min = 1, max = 8192))]
    pub encrypted_site_name: String,
    #[validate(length(max = 8192))]
    pub encrypted_username: Option<String>,
    #[validate(length(max = 8192))]
    pub encrypted_login_email: Option<String>,
    #[validate(length(min = 1, max = 8192))]
    pub encrypted_password: String,
    #[validate(length(min = 1, max = 8192))]
    pub encrypted_preferred_login_type: String,
    #[validate(length(max = 8192))]
    pub encrypted_folder: Option<String>,
    #[validate(length(max = 8192))]
    pub encrypted_notes: Option<String>,
    #[validate(length(max = 8192))]
    pub encrypted_url: Option<String>,
    // `entry_type` n'a pas besoin d'être re-chiffré (c'est déjà en clair) et ne change jamais lors
    // d'un changement de mot de passe maître — seul `encrypted_extra_fields` doit l'être, comme
    // les autres champs `encrypted_*` ci-dessus. `None` si l'entrée n'en avait pas.
    #[validate(length(max = 8192))]
    pub encrypted_extra_fields: Option<String>,
}

/// Une entrée d'historique de mot de passe (voir vault_password_history en base) : l'ANCIENNE
/// valeur d'un mot de passe, archivée automatiquement quand le client signale un changement réel
/// (voir VaultEntryInput::password_changed). `vault_id` identifie l'entrée du coffre concernée —
/// utile pour GET /vault/{id}/history (où il est redondant avec l'URL, mais garder une forme
/// unique simplifie aussi son usage lors du re-chiffrement en masse à un changement de mot de
/// passe MAÎTRE, voir ChangeMasterPasswordPayload).
#[derive(Serialize, sqlx::FromRow)]
pub struct PasswordHistoryEntry {
    pub id: String,
    pub vault_id: String,
    pub encrypted_password: String,
    pub changed_at: chrono::NaiveDateTime,
}

/// Une entrée d'historique déjà RE-CHIFFRÉE par le client avec la nouvelle clé — même principe que
/// `ReencryptedVaultEntry`, mais pour `vault_password_history` plutôt que `vault`. `id` identifie
/// la ligne d'historique EXISTANTE à mettre à jour.
#[derive(Deserialize, Validate, Clone)]
pub struct ReencryptedHistoryEntry {
    pub id: String,
    #[validate(length(min = 1, max = 8192))]
    pub encrypted_password: String,
}

/// Une pièce jointe déjà RE-CHIFFRÉE par le client avec la nouvelle clé — même principe que
/// `ReencryptedVaultEntry`/`ReencryptedHistoryEntry`, mais pour `vault_attachments`. `id`
/// identifie la pièce jointe EXISTANTE à mettre à jour (jamais de création ici). Les deux champs
/// chiffrés (nom de fichier ET contenu) doivent être re-chiffrés ensemble, comme lors de l'ajout
/// initial (voir VaultAttachmentInput) — un contenu re-chiffré avec un nom resté sous l'ancienne
/// clé (ou l'inverse) laisserait la pièce jointe partiellement indéchiffrable.
#[derive(Deserialize, Validate, Clone)]
pub struct ReencryptedVaultAttachment {
    pub id: String,
    #[validate(length(min = 1, max = 8192))]
    pub encrypted_filename: String,
    #[validate(length(min = 1, max = 10_000_000))]
    pub encrypted_content: String,
}

/// Une pièce jointe soumise par le client (POST /vault/{id}/attachments) — nom de fichier ET
/// contenu CHIFFRÉS côté client (voir crypto.rs::encrypt_field), stockés tels quels par le
/// serveur : Zero-Knowledge oblige, il ne les lit, ne les déchiffre et ne les valide jamais en
/// tant que fichier. `content_size` est fourni par le client (taille du fichier ORIGINAL, avant
/// chiffrement) — SEULE métadonnée en clair, utile pour l'affichage/les quotas sans déchiffrer
/// quoi que ce soit ; le client peut mentir dessus sans que ça n'affecte personne d'autre que
/// lui-même (aucune conséquence de sécurité, juste un affichage éventuellement trompeur).
#[derive(Deserialize, Validate, Clone)]
pub struct VaultAttachmentInput {
    #[validate(length(min = 1, max = 8192))]
    pub encrypted_filename: String,

    // 10_000_000 : généreux pour couvrir le double encodage base64 + le surcoût du chiffrement
    // d'un fichier jusqu'à MAX_ATTACHMENT_BYTES (5 Mo, voir handlers/vault.rs) — fichier -> base64
    // (~4/3) -> chiffré -> base64 (~4/3) à nouveau, soit un facteur ~1.78 dans le pire cas.
    #[validate(length(min = 1, max = 10_000_000))]
    pub encrypted_content: String,

    #[validate(range(min = 1, max = 5_242_880, message = "Fichier trop volumineux (5 Mo maximum)"))]
    pub content_size: i64,
}

/// Métadonnées d'une pièce jointe SANS son contenu (GET /vault/{id}/attachments, listing) — évite
/// de transférer potentiellement plusieurs Mo par fichier juste pour en afficher le nom. Voir
/// `VaultAttachment` ci-dessous pour la forme complète, renvoyée uniquement au téléchargement
/// d'UNE pièce jointe précise.
#[derive(Serialize, sqlx::FromRow)]
pub struct VaultAttachmentMeta {
    pub id: String,
    pub encrypted_filename: String,
    pub content_size: i64,
    pub created_at: chrono::NaiveDateTime,
}

/// Une pièce jointe complète, AVEC son contenu chiffré — renvoyée uniquement par
/// GET /vault/{id}/attachments/{attachment_id} (téléchargement explicite d'un fichier précis).
#[derive(Serialize, sqlx::FromRow)]
pub struct VaultAttachment {
    pub id: String,
    pub vault_id: String,
    pub encrypted_filename: String,
    pub encrypted_content: String,
    pub content_size: i64,
    pub created_at: chrono::NaiveDateTime,
}


// =========================================================================
// 4. PAYLOADS DE REQUÊTES (AUTHENTIFICATION & SÉCURITÉ)
// =========================================================================
// Ces structures servent à réceptionner, désérialiser et valider le contenu des requêtes HTTP POST/PUT.

/// Données requises lors de la soumission du formulaire d'authentification principal.
/// `master_password_hash` : ATTENTION, ce n'est PAS le mot de passe maître en clair. Le client
/// doit calculer LOCALEMENT (Argon2id/PBKDF2) une clé maîtresse à partir du mot de passe + email,
/// PUIS dériver de cette clé un hash d'authentification distinct — c'est CE hash qui est envoyé
/// ici. Le serveur ne doit JAMAIS recevoir le mot de passe maître lui-même (Zero-Knowledge total).
#[derive(Deserialize, Validate)]
pub struct AuthPayload {
    #[validate(email(message = "Format d'email invalide"))] 
    pub email: String,

    #[validate(
        length(min = 6, max = 128, message = "Hash d'authentification invalide"),
        regex(path = *crate::models::RE_PASSWORD)
    )]
    pub master_password_hash: String, // Hash d'authentification dérivé CÔTÉ CLIENT (jamais le mot de passe)
    pub device_id: String,         // Identifiant matériel unique de l'appareil émetteur
    pub remember_me: Option<bool>, // Case à cocher "Se souvenir de moi"

    // Uniquement pertinent à l'INSCRIPTION (ignoré par login(), qui réutilise cette même
    // structure — comme `remember_me` n'est lui pertinent qu'au login). Permet à l'utilisateur
    // de choisir son propre plafond d'appareils de confiance dès la création du compte plutôt
    // que de subir uniquement la valeur par défaut. La plage 1-50 EST le plafond serveur absolu,
    // non contournable : ce n'est pas qu'une suggestion, `validate()` la fait respecter avant
    // que la valeur n'atteigne la moindre requête SQL.
    #[validate(range(min = 1, max = 50, message = "La limite d'appareils de confiance doit être comprise entre 1 et 50"))]
    pub max_trusted_devices: Option<u32>,
}

/// Données pour vérifier le code de double authentification (TFA).
#[derive(Deserialize, Validate)]
pub struct VerifyTfaPayload {
    #[validate(email)] 
    pub email: String,
    pub code: String,              // Le code reçu par email (ex: à 6 chiffres)
    pub device_id: String,
    pub device_name: Option<String>, // Nom convivial de l'appareil (ex: "iPhone de Jean")
}

/// Données pour initier une demande de réinitialisation de mot de passe oublié.
#[derive(Deserialize, Validate)]
pub struct ForgotPasswordPayload {
    #[validate(email(message = "Format d'email invalide"))] 
    pub email: String,
}

/// Données finales pour confirmer la réinitialisation suite à la saisie du code reçu.
/// RAPPEL IMPORTANT (Zero-Knowledge) : une réinitialisation (mot de passe oublié) purge
/// TOUJOURS le coffre — contrairement à un changement de mot de passe volontaire
/// (ChangeMasterPasswordPayload), il n'y a ici aucune clé de l'ancien mot de passe pour
/// re-chiffrer quoi que ce soit, donc les données existantes sont irrécupérables par nature.
#[derive(Deserialize, Validate)]
pub struct ConfirmResetPayload {
    #[validate(email(message = "Format d'email invalide"))] 
    pub email: String,
    pub code: String,              // Code de validation du reset envoyé par mail

    #[validate(
        length(min = 6, max = 128, message = "Hash d'authentification invalide"),
        regex(path = *crate::models::RE_PASSWORD)
    )]
    pub new_master_password_hash: String, // Nouveau hash d'authentification, dérivé côté client
}

/// Données pour confirmer l'email fourni à l'inscription (voir handlers/auth.rs::verify_email()).
/// Même mécanisme de code à 6 chiffres que VerifyTfaPayload/ConfirmResetPayload, réutilisant la
/// table `tfa_codes` et son verrouillage anti-bruteforce (MAX_CODE_ATTEMPTS).
#[derive(Deserialize, Validate)]
pub struct VerifyEmailPayload {
    #[validate(email(message = "Format d'email invalide"))]
    pub email: String,
    pub code: String, // Code reçu par email à l'inscription
}

/// Données pour rafraîchir un token d'accès expiré.
#[derive(serde::Deserialize)]
pub struct RefreshPayload {
    pub refresh_token: String,     // Le token de rafraîchissement stocké côté client
}


// =========================================================================
// 5. PAYLOADS DE REQUÊTES (MISES À JOUR DU PROFIL)
// =========================================================================

/// Données permettant à un utilisateur connecté de changer VOLONTAIREMENT son mot de passe
/// maître (à ne pas confondre avec ConfirmResetPayload, qui gère l'oubli de mot de passe).
/// Contrairement à un changement "classique", ceci DOIT s'accompagner du re-chiffrement de
/// TOUTES les entrées actives du coffre par le client — ET de TOUT son historique de mots de passe
/// (voir vault_password_history) : la clé de chiffrement du coffre dérive du mot de passe maître,
/// donc la changer sans tout re-chiffrer rendrait les données existantes définitivement
/// indéchiffrables. `reencrypted_entries`/`reencrypted_history`/`reencrypted_attachments` doivent
/// donc chacun contenir EXACTEMENT tout ce que l'utilisateur possède (le serveur vérifiera
/// qu'aucune ligne n'est oubliée, dans les trois cas).
#[derive(Deserialize, Validate)]
pub struct ChangeMasterPasswordPayload {
    #[validate(
        length(min = 6, max = 128, message = "Hash d'authentification invalide"),
        regex(path = *crate::models::RE_PASSWORD)
    )]
    pub old_master_password_hash: String,

    #[validate(
        length(min = 6, max = 128, message = "Hash d'authentification invalide"),
        regex(path = *crate::models::RE_PASSWORD)
    )]
    pub new_master_password_hash: String,

    pub reencrypted_entries: Vec<ReencryptedVaultEntry>,

    // #[serde(default)] : rétrocompatible avec un client qui n'aurait pas encore cette notion
    // d'historique — dans ce cas, aucune ligne d'historique n'existe encore côté serveur non plus
    // (fonctionnalité nouvelle), donc une liste vide est de toute façon la valeur correcte.
    #[serde(default)]
    pub reencrypted_history: Vec<ReencryptedHistoryEntry>,

    // #[serde(default)] : rétrocompatible avec un client d'avant ce correctif, qui ignore tout
    // simplement l'existence des pièces jointes ici. SANS DANGER : si l'utilisateur possède déjà
    // des pièces jointes en BDD, le garde-fou de comptage (voir update_password()) rejettera quand
    // même la requête plutôt que de les laisser silencieusement indéchiffrables — un client trop
    // ancien sera donc bloqué avec un message clair plutôt que de corrompre des données.
    #[serde(default)]
    pub reencrypted_attachments: Vec<ReencryptedVaultAttachment>,
}

/// Données permettant à un utilisateur connecté de changer son adresse e-mail.
/// `master_password_hash` : même hash d'authentification que pour le login (jamais le mot de
/// passe en clair) — sert à reconfirmer l'identité avant un changement sensible.
#[derive(Deserialize, Validate)]
pub struct UpdateEmailPayload {
    #[validate(email(message = "Format d'email invalide"))]
    pub new_email: String,         // Nouvelle adresse e-mail ciblée
    pub master_password_hash: String, // Confirmation obligatoire par le hash d'authentification actuel
}

/// Données permettant à un MODÉRATEUR (ou l'Admin) de changer l'email d'un AUTRE compte (voir
/// handlers/admin.rs::admin_update_user_email()) — PAS de `master_password_hash` ici : l'appelant
/// ne connaît pas (et ne peut pas connaître, Zero-Knowledge oblige) le mot de passe maître de la
/// cible, seul son propre rôle (modérateur au minimum) compte (même raison que UpdateUserRolePayload).
/// Ne touche JAMAIS au mot de passe maître ni à la clé du coffre — seulement l'identifiant email.
#[derive(Deserialize, Validate)]
pub struct AdminUpdateEmailPayload {
    #[validate(email(message = "Format d'email invalide"))]
    pub new_email: String,
}

/// Données pour modifier APRÈS COUP le plafond d'appareils de confiance choisi à l'inscription
/// (voir AuthPayload.max_trusted_devices et handlers/devices.rs::update_device_limit()).
/// `master_password_hash` : même logique de reconfirmation que pour UpdateEmailPayload — un
/// paramètre qui affecte la posture de sécurité du compte ne doit pas être modifiable par la
/// seule connaissance d'un access token, même volé.
#[derive(Deserialize, Validate)]
pub struct UpdateDeviceLimitPayload {
    #[validate(range(min = 1, max = 50, message = "La limite d'appareils de confiance doit être comprise entre 1 et 50"))]
    pub new_limit: u32,
    pub master_password_hash: String,
}

/// Données pour changer le rôle MODÉRATEUR d'un compte (voir handlers/admin.rs::update_user_role()) —
/// on ne "promeut" jamais personne au rang "Admin" (il n'y en a qu'un, voir ADMIN_EMAIL), seulement
/// au rang "Modérateur". Pas de `master_password_hash` ici, contrairement aux payloads ci-dessus :
/// ce n'est pas l'utilisateur qui modifie SON PROPRE compte (auto-confirmation par mot de passe),
/// mais l'Admin qui agit sur le compte d'un AUTRE utilisateur — le fait d'être l'Admin (déjà
/// vérifié par le handler via `AuthUser::is_admin()`) est la seule barrière pertinente ici.
#[derive(Deserialize)]
pub struct UpdateUserRolePayload {
    pub is_moderator: bool,
}

/// Payload admin pour autoriser/interdire le changement d'email DEPUIS L'EXTENSION à UN compte
/// précis (voir handlers/admin.rs::update_extension_email_change_setting()). Même raison que
/// UpdateUserRolePayload ci-dessus : pas de master_password_hash, seul le rôle (modérateur au
/// minimum) de l'appelant compte ici.
#[derive(Deserialize)]
pub struct UpdateExtensionEmailChangePayload {
    pub enabled: bool,
}

/// Voir handlers/admin.rs::update_server_choice_in_settings() (par compte) /
/// update_server_choice_in_settings_all() (tous les comptes).
#[derive(Deserialize)]
pub struct UpdateServerChoiceInSettingsPayload {
    pub enabled: bool,
}

/// Voir handlers/admin.rs::update_server_choice_at_login() — réglage GLOBAL (pas par compte).
#[derive(Deserialize)]
pub struct UpdateServerChoiceAtLoginPayload {
    pub enabled: bool,
}

/// Données pour exporter l'intégralité du coffre (voir handlers/vault.rs::export_vault()).
/// `master_password_hash` : reconfirmation obligatoire — sans ça, un access token volé (courte
/// durée de vie, mais suffisant) permettrait d'exfiltrer TOUT le coffre en un seul appel, plutôt
/// que d'être limité à ce que les routes normales exposent déjà de toute façon (get_vault()).
/// Le coffre exporté reste chiffré (Zero-Knowledge) : le serveur ne déchiffre jamais rien, cette
/// vérification sert uniquement de défense en profondeur contre le vol de session.
#[derive(Deserialize, Validate)]
pub struct ExportVaultPayload {
    pub master_password_hash: String,
}

/// Données pour importer en bloc un ensemble d'entrées déjà chiffrées côté client (typiquement
/// un backup obtenu via POST /vault/export). Chaque entrée devient une NOUVELLE ligne du coffre —
/// jamais de fusion ni d'écrasement de l'existant (voir handlers/vault.rs::import_vault()) :
/// c'est la sémantique la plus simple et la plus sûre, aucune donnée existante ne peut jamais
/// être perdue ou modifiée par un import, il ne peut qu'en ajouter.
/// Pas de `Validate` ici : chaque `VaultEntryInput` est validée individuellement dans le handler
/// (même raison que `ChangeMasterPasswordPayload::reencrypted_entries` — la macro dérivée de
/// `validator` sur un `Vec<T>` n'est pas fiable).
#[derive(Deserialize)]
pub struct ImportVaultPayload {
    pub entries: Vec<VaultEntryInput>,
}


// =========================================================================
// 5BIS. ACCÈS D'URGENCE — voir src-tauri/src/emergency.rs pour le chiffrement (boîte scellée
// X25519) et handlers/emergency.rs pour le flux complet (invitation, délai d'attente,
// approbation/refus). Le serveur ne voit et ne déchiffre JAMAIS rien ici : il relaie des clés
// publiques et des blobs déjà scellés, exactement comme il relaie des blobs `encrypted_*` pour le
// reste du coffre.
// =========================================================================

/// Paire de clés X25519 soumise par le client — la clé PUBLIQUE est en clair (c'est son rôle),
/// la clé PRIVÉE est CHIFFRÉE côté client (avec la clé du coffre) avant d'arriver ici : le
/// serveur ne la voit jamais en clair, comme n'importe quel champ `encrypted_*` de `vault`.
/// `sqlx::FromRow`/`Serialize` en plus de `Deserialize` : ce même type sert AUSSI à relire ses
/// propres clés depuis `user_keys` et à les renvoyer telles quelles (voir
/// EmergencyRepository::get_own_keys, handlers::get_own_keys) — les champs correspondent
/// exactement aux colonnes de la table, pas besoin d'une structure séparée juste pour la lecture.
#[derive(Deserialize, Serialize, Validate, Clone, sqlx::FromRow)]
pub struct UserKeysInput {
    #[validate(length(min = 1, max = 8192))]
    pub public_key: String,
    #[validate(length(min = 1, max = 8192))]
    pub encrypted_private_key: String,
}

/// Réponse de GET /emergency/keys/{email} — UNIQUEMENT la clé publique de cet utilisateur (jamais
/// sa clé privée chiffrée, qui n'a de sens que pour son propre propriétaire).
#[derive(Serialize, sqlx::FromRow)]
pub struct UserPublicKey {
    pub public_key: String,
}

/// Une relation d'accès d'urgence (voir handlers/emergency.rs pour la machine à états complète
/// derrière `status`).
#[derive(Serialize, sqlx::FromRow)]
pub struct EmergencyContact {
    pub id: String,
    pub owner_email: String,
    pub contact_email: String,
    pub waiting_period_days: i64,
    pub status: String,
    pub requested_at: Option<chrono::NaiveDateTime>,
    pub available_at: Option<chrono::NaiveDateTime>,
    pub created_at: chrono::NaiveDateTime,
}

/// Données pour POST /emergency/contacts (désigner un nouveau contact de confiance).
#[derive(Deserialize, Validate)]
pub struct AddEmergencyContactPayload {
    #[validate(email(message = "Format d'email invalide"))]
    pub contact_email: String,
    #[validate(range(min = 0, max = 90, message = "Le délai d'attente doit être compris entre 0 et 90 jours"))]
    pub waiting_period_days: i64,
}

/// Données pour PUT /emergency/contacts/{id}/seed (le propriétaire chiffre sa clé de coffre pour
/// ce contact précis, voir emergency.rs::seal côté client).
#[derive(Deserialize, Validate)]
pub struct SeedEmergencyKeyPayload {
    #[validate(length(min = 1, max = 8192))]
    pub sealed_vault_key: String,
}

/// Réponse de GET /emergency/contacts/{id}/vault — le coffre COMPLET (lecture seule) d'un
/// propriétaire ayant accordé l'accès d'urgence, accompagné du blob scellé nécessaire pour en
/// retrouver la clé de déchiffrement (voir emergency.rs::unseal côté client).
#[derive(Serialize)]
pub struct EmergencyVaultView {
    pub sealed_vault_key: String,
    pub entries: Vec<VaultEntry>,
}


// =========================================================================
// 5TER. PARTAGE SÉCURISÉ D'UNE ENTRÉE — voir src-tauri/src/sharing.rs pour le chiffrement (même
// boîte scellée X25519 que l'accès d'urgence ci-dessus, réutilise `user_keys`, mais avec un
// contexte HKDF différent) et handlers/sharing.rs pour le flux complet. Contrairement à l'accès
// d'urgence : INSTANTANÉ (pas de machine à états, pas de délai d'attente) — un partage existe ou
// n'existe pas. Le serveur ne voit et ne déchiffre JAMAIS `sealed_entry`.
// =========================================================================

/// Données pour POST /vault/{id}/shares (partager une entrée avec un autre utilisateur).
/// `sealed_entry` : JSON des champs en clair de l'entrée (site/identifiants/mot de passe/notes/
/// url), scellé côté client pour la clé publique de `shared_with_email` — voir
/// src-tauri/src/sharing.rs::seal_for_share. 32768 : généreux pour un JSON de tous les champs d'une
/// entrée (chacun jusqu'à ~2000 caractères en clair réaliste) plus le surcoût du scellement
/// (clé éphémère 32 octets + nonce 12 octets + tag GCM 16 octets, negligeable ici) et le
/// base64 (~4/3) — bien en-deçà du cas des pièces jointes, une entrée n'a pas de contenu de fichier.
#[derive(Deserialize, Validate)]
pub struct ShareEntryPayload {
    #[validate(email(message = "Format d'email invalide"))]
    pub shared_with_email: String,
    #[validate(length(min = 1, max = 32768))]
    pub sealed_entry: String,
}

/// Un partage vu par le PROPRIÉTAIRE (GET /vault/{id}/shares) — jamais `sealed_entry` : inutile
/// pour lister/révoquer, et une fuite ici permettrait de reconstituer un blob qui ne devrait être
/// lisible que par son destinataire (même principe que `EmergencyContact`, qui omet
/// `sealed_vault_key`).
#[derive(Serialize, sqlx::FromRow)]
pub struct VaultShare {
    pub id: String,
    pub shared_with_email: String,
    pub created_at: chrono::NaiveDateTime,
}

/// Un partage vu par le DESTINATAIRE (GET /shares/shared-with-me) — même raison, jamais
/// `sealed_entry` ici non plus (voir get_shared_entry côté repository pour l'unique endpoint qui
/// l'expose, avec l'autorisation encodée directement dans le SQL).
#[derive(Serialize, sqlx::FromRow)]
pub struct SharedWithMeEntry {
    pub id: String,
    pub vault_id: String,
    pub owner_email: String,
    pub created_at: chrono::NaiveDateTime,
}

/// Réponse de GET /shares/{id} — LE seul endpoint à exposer `sealed_entry`, réservé au
/// destinataire du partage (voir SharingRepository::get_shared_entry, autorisation en SQL).
#[derive(Serialize, sqlx::FromRow)]
pub struct SharedEntryView {
    pub owner_email: String,
    pub sealed_entry: String,
}


// =========================================================================
// 5bis. COFFRES PARTAGÉS FAMILIAUX (voir migration 20260831000004_shared_vaults.sql et
// crypto-core/src/shared_vault.rs pour le schéma cryptographique complet) — S'AJOUTE au partage
// d'entrée 1-vers-1 ci-dessus, ne le remplace pas : les deux systèmes coexistent, chacun pour un
// usage différent (partager UNE entrée ponctuellement VS un ensemble d'entrées qui reste à jour
// EN DIRECT pour plusieurs membres).
// =========================================================================

/// Données pour POST /shared-vaults (créer un nouveau coffre partagé). `encrypted_name` : nom du
/// coffre, chiffré côté client avec la clé symétrique FRAÎCHEMENT GÉNÉRÉE pour ce coffre (voir
/// crypto-core::shared_vault::generate_vault_key), comme n'importe quelle entrée. `sealed_vault_key`
/// : cette MÊME clé, scellée par le créateur pour SA PROPRE clé publique (il doit lui aussi
/// détenir une copie scellée pour pouvoir déchiffrer les entrées qu'il ajoute ensuite — pas de
/// traitement spécial pour le créateur au-delà de "premier membre, is_owner=true").
#[derive(Deserialize, Validate)]
pub struct CreateSharedVaultPayload {
    #[validate(length(min = 1, max = 8192))]
    pub encrypted_name: String,
    #[validate(length(min = 1, max = 4096))]
    pub sealed_vault_key: String,
}

/// Un coffre partagé vu par UN de ses membres (GET /shared-vaults) — `sealed_vault_key` est
/// TOUJOURS la copie scellée pour L'APPELANT spécifiquement (jamais celle d'un autre membre, voir
/// SharedVaultRepository::list_for_member — l'autorisation ET la sélection de la bonne clé sont
/// encodées directement dans la requête SQL, via une jointure sur `member_email = <appelant>`).
#[derive(Serialize, sqlx::FromRow)]
pub struct SharedVaultView {
    pub id: String,
    pub encrypted_name: String,
    pub created_by: String,
    pub created_at: chrono::NaiveDateTime,
    pub sealed_vault_key: String,
    pub is_owner: bool,
}

/// Données pour POST /shared-vaults/{id}/members (inviter un membre). Le CLIENT a déjà résolu la
/// clé publique du futur membre (GET /emergency/keys/{email}, même endpoint déjà réutilisé par le
/// partage d'entrée classique) et scellé la clé du coffre partagé pour lui AVANT cet appel — le
/// serveur ne fait que stocker le blob déjà scellé, comme pour ShareEntryPayload.
#[derive(Deserialize, Validate)]
pub struct InviteSharedVaultMemberPayload {
    #[validate(email(message = "Format d'email invalide"))]
    pub member_email: String,
    #[validate(length(min = 1, max = 4096))]
    pub sealed_vault_key: String,
}

/// Un membre d'un coffre partagé, vu par n'importe quel AUTRE membre (GET
/// /shared-vaults/{id}/members) — jamais `sealed_vault_key` ici : la clé scellée d'un membre
/// n'est déchiffrable QUE par lui (chiffrée pour sa clé publique à lui), l'exposer aux autres
/// membres ne leur serait d'aucune utilité mais resterait une fuite de principe inutile (même
/// logique que VaultShare, qui omet déjà `sealed_entry` pour la liste des destinataires).
#[derive(Serialize, sqlx::FromRow)]
pub struct SharedVaultMemberView {
    pub member_email: String,
    pub is_owner: bool,
    pub added_at: chrono::NaiveDateTime,
}

fn default_shared_entry_type() -> String {
    "login".to_string()
}

/// Données pour créer/modifier une entrée dans un coffre partagé (POST/PUT
/// /shared-vaults/{id}/entries) — tous les champs `encrypted_*` chiffrés côté client avec la clé
/// SYMÉTRIQUE du coffre partagé (voir crypto::encrypt_field, la MÊME primitive que pour le coffre
/// personnel — seule la clé utilisée diffère). Volontairement plus réduit que `VaultEntryInput` :
/// pas de dossier/favori/pièces jointes/historique pour cette première version (voir la migration
/// pour le détail du choix de périmètre).
#[derive(Deserialize, Validate, Clone)]
pub struct SharedVaultEntryInput {
    #[validate(length(min = 1, max = 8192))]
    pub encrypted_site_name: String,
    #[validate(length(max = 8192))]
    pub encrypted_username: Option<String>,
    #[validate(length(max = 8192))]
    pub encrypted_login_email: Option<String>,
    #[validate(length(min = 1, max = 8192))]
    pub encrypted_password: String,
    #[validate(length(min = 1, max = 8192))]
    pub encrypted_preferred_login_type: String,
    #[validate(length(max = 8192))]
    pub encrypted_notes: Option<String>,
    #[validate(length(max = 8192))]
    pub encrypted_url: Option<String>,
    #[serde(default = "default_shared_entry_type")]
    pub entry_type: String,
    #[validate(length(max = 8192))]
    #[serde(default)]
    pub encrypted_extra_fields: Option<String>,
    // Détection de conflit d'édition — voir le commentaire sur la colonne `version` dans la
    // migration : encore plus pertinent ici que pour le coffre personnel, plusieurs membres
    // DIFFÉRENTS pouvant modifier la même entrée à quelques instants d'écart.
    #[serde(default)]
    pub expected_version: Option<i64>,
}

/// Une entrée de coffre partagé telle que renvoyée par le serveur.
#[derive(Serialize, sqlx::FromRow)]
pub struct SharedVaultEntry {
    pub id: String,
    pub shared_vault_id: String,
    pub encrypted_site_name: String,
    pub encrypted_username: Option<String>,
    pub encrypted_login_email: Option<String>,
    pub encrypted_password: String,
    pub encrypted_preferred_login_type: String,
    pub encrypted_notes: Option<String>,
    pub encrypted_url: Option<String>,
    pub entry_type: String,
    pub encrypted_extra_fields: Option<String>,
    pub created_by: String,
    pub updated_at: chrono::NaiveDateTime,
    pub version: i64,
}


// =========================================================================
// 5ter. PARTAGE À USAGE LIMITÉ ("AVEUGLE") — voir migration 20260831000005_vault_blind_shares.sql
// et crypto-core/src/blind_share.rs. S'AJOUTE au partage d'entrée classique ET aux coffres
// partagés familiaux ci-dessus, ne remplace ni l'un ni l'autre. Le destinataire ne voit JAMAIS
// l'identifiant ni le mot de passe — seulement le nom du site — et ne peut déclencher un "usage"
// qu'un nombre de fois limité (par défaut 1). Voir handlers/blind_share.rs pour le détail complet
// du modèle de menace et ses limites honnêtement documentées.
// =========================================================================

/// Données pour POST /vault/{id}/blind-shares. DEUX blobs scellés séparément côté client (voir le
/// commentaire en tête de la migration pour le pourquoi) : `sealed_site_name` (librement
/// consultable, ne consomme jamais d'usage) et `sealed_credentials` (JSON identifiant+mot de
/// passe, gardé derrière le compteur d'usages). `max_uses` : optionnel, défaut 1 côté client comme
/// côté serveur (voir Default ci-dessous) — plafonné à 1000, une valeur absurde ne protégeant plus
/// rien tout en consommant du stockage inutilement.
fn default_max_uses() -> i64 {
    1
}

#[derive(Deserialize, Validate)]
pub struct CreateBlindSharePayload {
    #[validate(email(message = "Format d'email invalide"))]
    pub shared_with_email: String,
    #[validate(length(min = 1, max = 8192))]
    pub sealed_site_name: String,
    #[validate(length(min = 1, max = 32768))]
    pub sealed_credentials: String,
    #[serde(default = "default_max_uses")]
    #[validate(range(min = 1, max = 1000, message = "Le nombre d'usages doit être compris entre 1 et 1000"))]
    pub max_uses: i64,
}

/// Un partage à usage limité vu par le PROPRIÉTAIRE (GET /vault/{id}/blind-shares) — jamais les
/// blobs scellés : inutiles pour lister/révoquer, une fuite ici permettrait de reconstituer un
/// blob qui ne devrait être lisible que par son destinataire.
#[derive(Serialize, sqlx::FromRow)]
pub struct VaultBlindShare {
    pub id: String,
    pub shared_with_email: String,
    pub max_uses: i64,
    pub remaining_uses: i64,
    pub created_at: chrono::NaiveDateTime,
}

/// Un partage à usage limité vu par le DESTINATAIRE (GET /blind-shares/shared-with-me) —
/// `sealed_site_name` EST inclus ici (librement consultable, voir le commentaire de la migration),
/// mais JAMAIS `sealed_credentials` : ce blob ne transite QUE via POST /blind-shares/{id}/use, qui
/// décrémente le compteur.
#[derive(Serialize, sqlx::FromRow)]
pub struct BlindShareReceivedView {
    pub id: String,
    pub owner_email: String,
    pub sealed_site_name: String,
    pub max_uses: i64,
    pub remaining_uses: i64,
    pub created_at: chrono::NaiveDateTime,
}

/// Réponse de POST /blind-shares/{id}/use — LE seul endpoint à exposer `sealed_credentials`,
/// réservé au destinataire, et UNIQUEMENT si `remaining_uses > 0` au moment de l'appel (décrémenté
/// atomiquement dans la même requête SQL, voir BlindShareRepository::consume_use).
#[derive(Serialize, sqlx::FromRow)]
pub struct BlindShareCredentialsView {
    pub sealed_credentials: String,
    pub remaining_uses: i64,
}


// =========================================================================
// 5quater. SIGNALEMENT DE BUG — voir migration 20260901000000_bug_reports.sql et
// handlers/bug_report.rs. PAS chiffré (contrairement au coffre) : un texte technique écrit par
// l'utilisateur, destiné à être lu directement par un modérateur, pas une donnée du coffre.
// Accessible SANS connexion (voir POST /bug-reports, route publique mais fortement rate-limitée) :
// un bug qui empêche justement de se connecter doit pouvoir être signalé depuis l'app elle-même.
// =========================================================================

/// "Autre" si le client n'envoie rien — jamais bloquant, cette catégorie n'est qu'un aide au tri
/// côté Administration, pas une donnée qui doit faire échouer l'envoi si absente.
fn default_bug_category() -> String {
    "Autre".to_string()
}

#[derive(Deserialize, Validate)]
pub struct CreateBugReportPayload {
    #[validate(length(min = 1, max = 4000, message = "La description doit faire entre 1 et 4000 caractères"))]
    pub description: String,
    /// Facultatif — pré-rempli côté client avec l'email du compte connecté s'il y en a un
    /// (éditable), mais JAMAIS vérifié contre un vrai compte : une simple information de contact.
    /// Sert aussi à prévenir la personne quand le modérateur marque le signalement traité (voir
    /// BugReportRepository::delete/mailer::send_bug_report_resolved).
    #[validate(email(message = "Format d'email invalide"))]
    pub reporter_email: Option<String>,
    #[validate(length(min = 1, max = 50))]
    pub app_version: String,
    #[validate(length(min = 1, max = 50))]
    pub platform: String,
    /// Choisie dans une liste fermée côté client (voir BugReportModal.tsx) mais volontairement
    /// PAS un enum ici — une valeur imprévue ne doit jamais faire échouer tout l'envoi, juste
    /// atterrir telle quelle dans la colonne (Administration l'affiche brute).
    #[serde(default = "default_bug_category")]
    #[validate(length(min = 1, max = 30))]
    pub category: String,
}

/// Un signalement de bug vu par un modérateur (GET /admin/bug-reports).
#[derive(Serialize, sqlx::FromRow)]
pub struct BugReportView {
    pub id: String,
    pub reporter_email: Option<String>,
    pub description: String,
    pub app_version: String,
    pub platform: String,
    pub category: String,
    pub created_at: chrono::NaiveDateTime,
}

// =========================================================================
// 6. STRUCTURES DIVERSES (PAGINATION & RÉPONSES API)
// =========================================================================

/// Paramètres optionnels passés dans l'URL (Query Parameters) pour les requêtes de listage (GET).
/// PAS de champ `search` : impossible de rechercher côté serveur sur du contenu chiffré (voir
/// le commentaire en tête de section 3). La recherche doit se faire CÔTÉ CLIENT, après avoir
/// récupéré et déchiffré les entrées.
#[derive(Deserialize)]
pub struct PaginationParams { 
    pub limit: Option<u32>,        // Nombre maximum de résultats par page
    pub offset: Option<u32>,       // Index de départ du segment de résultats
}

impl PaginationParams {
    /// Limite plafonnée à MAX_LIMIT, quoi que le client demande (ex: `?limit=999999999`),
    /// pour éviter qu'une requête mal formée ou malveillante ne fasse remonter toute la table.
    /// Valeur par défaut de 50 si le client ne précise rien.
    ///
    /// CORRECTIF PERF (retour utilisateur, 2026-09-02) : 100 -> 500. `api/client.ts::getFullVault()`
    /// pagine de façon SÉQUENTIELLE (chaque page dépend de savoir si la précédente était la
    /// dernière, impossible à paralléliser sans changer la forme de la réponse) — pour un coffre
    /// de plusieurs centaines/milliers d'entrées (plafond MAX_VAULT_ENTRIES_PER_USER = 5000, voir
    /// handlers/vault.rs), ça pouvait représenter des dizaines d'allers-retours réseau l'un après
    /// l'autre. Le volume TOTAL de données transféré ne change pas avec la taille de page (mêmes
    /// entrées, juste groupées différemment) — augmenter cette limite réduit donc uniquement le
    /// nombre d'allers-retours, sans changement client. 500 reste raisonnable en pire cas de taille
    /// de réponse (500 entrées × 5 champs chiffrés × 8192 caractères max ≈ 19,5 Mo, très généreux
    /// par rapport à un usage réel — voir le calcul équivalent pour /auth/password dans main.rs).
    pub fn effective_limit(&self) -> i64 {
        const MAX_LIMIT: u32 = 500;
        self.limit.unwrap_or(50).min(MAX_LIMIT) as i64
    }
}

/// Modèle de réponse JSON renvoyé au client lors d'une authentification réussie.
#[allow(dead_code)]
#[derive(serde::Serialize)]
pub struct AuthResponse {
    pub access_token: String,      // Jeton JWT d'accès de courte durée
    pub refresh_token: String,     // Jeton opaque de rafraîchissement de longue durée
}

// =========================================================================
// TESTS SUR LES FONCTIONS PURES DE CE FICHIER
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_effective_limit_defaults_to_50_when_unspecified() {
        let p = PaginationParams { limit: None, offset: None };
        assert_eq!(p.effective_limit(), 50);
    }

    #[test]
    fn test_effective_limit_respects_a_reasonable_client_value() {
        let p = PaginationParams { limit: Some(10), offset: None };
        assert_eq!(p.effective_limit(), 10);
    }

    #[test]
    fn test_effective_limit_clamps_excessive_client_value() {
        // Un client demandant un limit absurde ne doit jamais dépasser MAX_LIMIT (500, voir
        // effective_limit() — relevé à 500 le 2026-09-02, anciennement 100)
        let p = PaginationParams { limit: Some(999_999_999), offset: None };
        assert_eq!(p.effective_limit(), 500);
    }

    #[test]
    fn test_re_password_accepts_valid_lengths() {
        assert!(RE_PASSWORD.is_match("123456")); // 6 caractères : limite basse acceptée
        assert!(RE_PASSWORD.is_match(&"a".repeat(128))); // 128 caractères : limite haute acceptée
        assert!(RE_PASSWORD.is_match("un_hash_dauthentification_derive"));
    }

    #[test]
    fn test_re_password_rejects_invalid_lengths() {
        assert!(!RE_PASSWORD.is_match("12345")); // 5 caractères : trop court
        assert!(!RE_PASSWORD.is_match(&"a".repeat(129))); // 129 caractères : trop long
        assert!(!RE_PASSWORD.is_match("")); // vide
    }

    #[test]
    fn test_vault_entry_input_accepts_reasonable_encrypted_content() {
        let entry = VaultEntryInput {
            encrypted_site_name: "a".repeat(8192),
            encrypted_username: Some("b".repeat(8192)),
            encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "c".repeat(8192),
            encrypted_preferred_login_type: "email".to_string(),
            is_favorite: false,
        };
        assert!(entry.validate().is_ok(), "un contenu chiffré à la limite haute (8192) doit être accepté");
    }

    #[test]
    fn test_vault_entry_input_rejects_oversized_encrypted_content() {
        let entry = VaultEntryInput {
            encrypted_site_name: "a".repeat(8193), // 1 caractère de trop
            encrypted_username: None,
            encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(),
            encrypted_preferred_login_type: "email".to_string(),
            is_favorite: false,
        };
        assert!(entry.validate().is_err(), "un blob chiffré au-delà de 8192 caractères doit être rejeté");
    }

    #[test]
    fn test_vault_entry_input_rejects_empty_required_fields() {
        let entry = VaultEntryInput {
            encrypted_site_name: "Site".to_string(),
            encrypted_username: None,
            encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "login".to_string(), encrypted_extra_fields: None,
            encrypted_password: "chiffre".to_string(),
            encrypted_preferred_login_type: "".to_string(), // vide, désormais rejeté aussi
            is_favorite: false,
        };
        assert!(entry.validate().is_err(), "encrypted_preferred_login_type vide doit être rejeté");
    }

    /// `encrypted_extra_fields` (types d'entrée dédiés — carte/identité) partage la même limite de
    /// 8192 caractères que les autres champs `encrypted_*`, mais n'avait aucun test dédié jusqu'ici.
    #[test]
    fn test_vault_entry_input_rejects_oversized_encrypted_extra_fields() {
        let entry = VaultEntryInput {
            encrypted_site_name: "MaCarte".to_string(),
            encrypted_username: None,
            encrypted_login_email: None, encrypted_folder: None, encrypted_notes: None, encrypted_url: None, password_changed: false, expected_version: None,
            entry_type: "card".to_string(), encrypted_extra_fields: Some("a".repeat(8193)), // 1 caractère de trop
            encrypted_password: "chiffre".to_string(),
            encrypted_preferred_login_type: "email".to_string(),
            is_favorite: false,
        };
        assert!(entry.validate().is_err(), "encrypted_extra_fields au-delà de 8192 caractères doit être rejeté");

        let mut within_limit = entry;
        within_limit.encrypted_extra_fields = Some("a".repeat(8192));
        assert!(within_limit.validate().is_ok(), "encrypted_extra_fields à la limite haute (8192) doit être accepté");
    }
}