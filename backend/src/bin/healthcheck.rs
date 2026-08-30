// Binaire de healthcheck minimal, utilisé UNIQUEMENT par Docker (voir Dockerfile HEALTHCHECK).
// Écrit en Rust pur (bibliothèque standard seulement, pas de crate externe) pour ne dépendre
// D'AUCUN paquet système supplémentaire dans l'image runtime — contrairement à `curl`, qui
// entraînait `openldap` en dépendance transitive et sa propre liste de CVE.
//
// Convention Cargo : tout fichier dans src/bin/*.rs est automatiquement compilé comme un
// binaire séparé du même package, sans rien à ajouter dans Cargo.toml. `cargo build --release`
// produit donc à la fois `target/release/backend` (le serveur) ET
// `target/release/healthcheck` (ce binaire), dans la même étape de build.
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::exit;
use std::time::Duration;

fn main() {
    // Doit correspondre au port réellement utilisé par le serveur (voir Config::get_addr()).
    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr = format!("127.0.0.1:{port}");

    let mut stream = match TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(_) => exit(1), // Le serveur ne répond même pas sur son port -> pas en bonne santé
    };

    // Timeouts courts : un healthcheck qui traîne ne doit jamais bloquer indéfiniment
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

    let request = "GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if stream.write_all(request.as_bytes()).is_err() {
        exit(1);
    }

    let mut response = String::new();
    if stream.read_to_string(&mut response).is_err() {
        exit(1);
    }

    // handlers::health_check() renvoie 200 OK si la BDD est joignable, 503 sinon.
    if response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200") {
        exit(0);
    } else {
        exit(1);
    }
}