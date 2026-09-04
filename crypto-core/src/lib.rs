//! Cryptographie Zero-Knowledge partagée — voir le README à la racine du dépôt pour le contexte
//! d'ensemble. Extraite de `frontend(app)/src-tauri/src/{crypto,emergency,sharing}.rs` (mêmes
//! fichiers, contenu inchangé) pour être compilée à la fois pour le client desktop/Android
//! (`frontend(app)/src-tauri`, cible native) et pour la future extension navigateur
//! (`extension/wasm-bindings`, cible `wasm32-unknown-unknown`) — un seul et même code source pour
//! les deux, jamais deux implémentations séparées à maintenir en parallèle.
//!
//! Ces trois modules restent volontairement 100% des fonctions pures (aucun type spécifique à
//! Tauri ni à wasm-bindgen) : c'est ce qui les rend compilables tels quels vers n'importe quelle
//! cible. La couche d'intégration (commandes Tauri côté desktop, bindings wasm-bindgen côté
//! extension) reste entièrement dans les crates consommatrices.

pub mod crypto;
pub mod emergency;
pub mod sharing;
pub mod recovery;
pub mod shared_vault;
pub mod blind_share;
