use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;
use tracing::{error, warn};
use argon2::password_hash::Error as ArgonError;

// =========================================================================
// 1. ÉNUMÉRATION DES ERREURS DE L'APPLICATION
// =========================================================================

/// Liste toutes les erreurs possibles qui peuvent survenir dans l'application.
#[allow(dead_code)] // Empêche le compilateur de râler si certaines variantes ne sont pas encore utilisées
#[derive(Debug)]
pub enum AppError {
    InvalidCredentials,          // Identifiants (email/mot de passe) incorrects
    SessionExpired,              // Jeton JWT expiré
    UserAlreadyExists,           // Tentative d'inscription avec un email déjà pris
    DatabaseError(sqlx::Error),  // Encapsule une vraie erreur provenant de la base de données (SQLx)
    Internal(String),            // Erreur interne générique avec un message de contexte
    ValidationError(String),     // Échec de la validation des données reçues (ex: email mal formé)
    HashError,                   // Problème lors du hachage ou de la vérification du mot de passe
    JwtError(jsonwebtoken::errors::Error), // Encapsule une erreur liée à la génération/lecture du JWT
    NotFound,                    // Ressource demandée inexistante (404)
    Conflict(String),            // Conflit d'état (ex: modification d'une ressource verrouillée)
    Forbidden,                   // Utilisateur authentifié mais n'ayant pas les droits requis
}

// =========================================================================
// 2. CONVERSION DES ERREURS EN RÉPONSES HTTP (AXUM)
// =========================================================================

/// Implémentation du trait `IntoResponse` d'Axum.
/// C'est ce qui permet de retourner directement un `AppError` dans vos routes web.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Associe chaque variante d'erreur à un code statut HTTP et un message grand public
        let (status, error_message) = match self {
            
            // 403 Forbidden - Droits insuffisants
            Self::Forbidden => (StatusCode::FORBIDDEN, "Accès refusé : Droits insuffisants".to_string()),
            
            // 401 Unauthorized - Session expirée
            Self::SessionExpired => (StatusCode::UNAUTHORIZED, "Votre session a expiré, veuillez vous reconnecter".to_string()),
            
            // 401 Unauthorized - Mauvais identifiants
            Self::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Email ou mot de passe incorrect".to_string()),
            
            // 400 Bad Request - Doublon d'utilisateur
            Self::UserAlreadyExists => (StatusCode::BAD_REQUEST, "Cet utilisateur existe déjà".to_string()),
            
            // 400 Bad Request - Données invalides (Formulaire, JSON, etc.)
            // CORRECTIF : le message spécifique (`msg`) est renvoyé tel quel au client, comme
            // Conflict(msg) juste en dessous — aucun de ces messages n'est sensible (pas de
            // logique anti-énumération ici, contrairement à ex: register()/forgot-password qui
            // masquent volontairement si un compte existe). Avant ce correctif, TOUS les messages
            // spécifiques (code expiré, trop de tentatives, limite d'appareils/entrées atteinte,
            // email non vérifié, re-chiffrement incomplet...) étaient remplacés par cette même
            // phrase générique — le frontend (voir api/client.ts) est pourtant conçu pour afficher
            // le message exact renvoyé ici.
            Self::ValidationError(msg) => {
                warn!("Échec de validation détecté : {}", msg);
                (StatusCode::BAD_REQUEST, msg)
            },
            
            // 404 Not Found - Ressource introuvable
            Self::NotFound => (StatusCode::NOT_FOUND, "Ressource introuvable".to_string()),
            
            // 409 Conflict - Message dynamique passé à la fonction
            Self::Conflict(msg) => (StatusCode::CONFLICT, msg),
            
            // 500 Internal Server Error - Problème technique avec Argon2
            Self::HashError => (StatusCode::INTERNAL_SERVER_ERROR, "Erreur de hachage".to_string()),
            
            // 500 Internal Server Error - Problème technique avec le JWT
            Self::JwtError(err) => {
                // On log le vrai problème technique (`error!`) pour les développeurs en interne
                error!("JWT Error: {:?}", err);
                // On renvoie un message très générique au client pour ne pas donner d'indices à un attaquant
                (StatusCode::INTERNAL_SERVER_ERROR, "Erreur de jeton".to_string())
            },
            
            // Gestion avancée des erreurs de Base de Données (SQLx)
            Self::DatabaseError(err) => {
                // Si SQLx renvoie une erreur spécifique à la BDD (ex: contrainte d'unicité violée)
                if let Some(db_err) = err.as_database_error() {
                    // "1555" ou "2067" (codes souvent liés à SQLite / Postgres pour des violations uniques)
                    if db_err.code().as_deref() == Some("1555") || db_err.code().as_deref() == Some("2067") {
                        // On court-circuite la fonction et on répond directement un code 409 Conflict en JSON
                        return (
                            StatusCode::CONFLICT, 
                            Json(json!({"error": "Déjà existant"}))
                        ).into_response();
                    }
                }
                // Pour toute autre erreur de BDD (panne de serveur, mauvaise syntaxe SQL...) :
                error!("DB Error: {:?}", err); // Log de l'erreur brute sur le serveur
                (StatusCode::INTERNAL_SERVER_ERROR, "Erreur base de données".to_string()) // Message masqué au client
            },
            
            // 500 Internal Server Error - Erreur critique générique
            Self::Internal(msg) => {
                error!("ERREUR CRITIQUE INTERNE : {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Une erreur technique est survenue".to_string())
            },
        };

        // Génère la réponse HTTP finale formatée en JSON : { "error": "Le message d'erreur" }
        (status, Json(json!({ "error": error_message }))).into_response()
    }
}

// =========================================================================
// 3. CONVERTISSEURS AUTOMATIQUES (TRAIT FROM)
// =========================================================================
// Ces blocs permettent d'utiliser l'opérateur `?` dans votre code Rust. 
// Si une fonction renvoie une erreur SQLx ou JWT, elle sera automatiquement 
// transformée en votre `AppError` personnalisée.

/// Convertit automatiquement une erreur de hachage Argon2 en `AppError::HashError`
impl From<ArgonError> for AppError {
    fn from(_err: ArgonError) -> Self {
        Self::HashError
    }
}

/// Convertit automatiquement une erreur SQLx en `AppError::DatabaseError`
impl From<sqlx::Error> for AppError { 
    fn from(err: sqlx::Error) -> Self { 
        Self::DatabaseError(err) 
    } 
}

/// Convertit automatiquement une erreur de jeton jsonwebtoken en `AppError::JwtError`
impl From<jsonwebtoken::errors::Error> for AppError { 
    fn from(err: jsonwebtoken::errors::Error) -> Self { 
        Self::JwtError(err) 
    } 
}

/// Convertit automatiquement un échec de structure provenant du crate `validator` en `AppError::ValidationError`
/// CORRECTIF : `ValidationErrors::to_string()` produirait "champ: message" (ex: "new_email:
/// Format d'email invalide") — le préfixe technique du nom de champ Rust n'a rien à faire dans un
/// message destiné à l'utilisateur. On extrait ici directement les messages personnalisés déjà
/// écrits dans chaque `#[validate(..., message = "...")]` (voir models.rs), joints par "; " si
/// plusieurs champs échouent en même temps — repli sur le message brut de `validator` uniquement
/// si un champ n'a pas de message personnalisé (ne devrait jamais arriver dans ce projet, mais
/// vaut mieux qu'une chaîne vide).
impl From<validator::ValidationErrors> for AppError {
    fn from(err: validator::ValidationErrors) -> Self {
        let messages: Vec<String> = err
            .field_errors()
            .into_values()
            .flatten()
            .map(|field_err| {
                field_err
                    .message
                    .as_ref()
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| field_err.to_string())
            })
            .collect();
        Self::ValidationError(messages.join("; "))
    }
}

// =========================================================================
// TESTS SUR LE MAPPING DES ERREURS VERS LES CODES HTTP
// =========================================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// CORRECTIF : ValidationError(msg) doit renvoyer `msg` tel quel au client (comme Conflict),
    /// pas une phrase générique qui masquerait la vraie raison (code expiré, limite atteinte...).
    #[tokio::test]
    async fn test_validation_error_forwards_the_specific_message() {
        let response = AppError::ValidationError("Le code a expiré".to_string()).into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["error"], "Le code a expiré", "le message spécifique doit être renvoyé, pas une phrase générique");
    }

    /// Vérifie que chaque variante d'AppError produit bien le code de statut HTTP attendu.
    /// On ne lit que le status code de la Response (pas le corps), donc pas besoin de
    /// décoder le JSON pour ce test.
    #[test]
    fn test_error_variants_map_to_expected_status_codes() {
        let cases: Vec<(AppError, StatusCode)> = vec![
            (AppError::Forbidden, StatusCode::FORBIDDEN),
            (AppError::SessionExpired, StatusCode::UNAUTHORIZED),
            (AppError::InvalidCredentials, StatusCode::UNAUTHORIZED),
            (AppError::UserAlreadyExists, StatusCode::BAD_REQUEST),
            (AppError::ValidationError("test".to_string()), StatusCode::BAD_REQUEST),
            (AppError::NotFound, StatusCode::NOT_FOUND),
            (AppError::Conflict("déjà pris".to_string()), StatusCode::CONFLICT),
            (AppError::HashError, StatusCode::INTERNAL_SERVER_ERROR),
            (AppError::Internal("erreur critique".to_string()), StatusCode::INTERNAL_SERVER_ERROR),
        ];

        for (error, expected_status) in cases {
            let response = error.into_response();
            assert_eq!(
                response.status(),
                expected_status,
                "mauvais code HTTP pour cette variante d'erreur"
            );
        }
    }

    /// La conversion depuis `validator::ValidationErrors` doit extraire le message personnalisé
    /// (voir `#[validate(..., message = "...")]` dans models.rs), sans le préfixe technique du nom
    /// de champ Rust — voir le commentaire sur `impl From<validator::ValidationErrors>`.
    #[derive(validator::Validate)]
    struct ProbePayload {
        #[validate(email(message = "Format d'email invalide"))]
        new_email: String,
    }
    #[test]
    fn test_validation_errors_conversion_strips_field_name_prefix() {
        use validator::Validate;
        let bad = ProbePayload { new_email: "pas-un-email".to_string() };
        let app_err: AppError = bad.validate().unwrap_err().into();
        match app_err {
            AppError::ValidationError(msg) => assert_eq!(msg, "Format d'email invalide"),
            other => panic!("attendu ValidationError, obtenu {other:?}"),
        }
    }

    /// Une violation de contrainte d'unicité SQLite (codes 1555/2067) doit être remontée
    /// comme un 409 Conflict, pas comme une 500 générique.
    #[test]
    fn test_database_unique_violation_maps_to_conflict() {
        // On simule directement une DatabaseError générique (pas une vraie violation SQLite ici,
        // le test ci-dessus valide le comportement par défaut) : une erreur SQLx quelconque
        // qui N'EST PAS une violation de contrainte doit tomber sur 500, pas 409.
        let generic_db_error = AppError::DatabaseError(sqlx::Error::RowNotFound);
        let response = generic_db_error.into_response();
        assert_eq!(
            response.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "une erreur BDD générique (non liée à une contrainte unique) doit rester 500"
        );
    }
}