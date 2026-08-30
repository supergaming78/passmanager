// Vérification Phase 1 (voir le plan) : le module WASM compilé depuis crypto-core (le MÊME code
// source que frontend(app)/src-tauri, voir crypto-core/src/lib.rs) doit se comporter de façon
// cryptographiquement identique au binaire natif desktop. Deux catégories de preuve ici :
//   1. Vecteur connu FIGÉ des deux côtés (voir crypto-core/src/crypto.rs::test_known_vector_matches_wasm_build)
//      — la preuve la plus forte, deux compilations totalement différentes doivent produire EXACTEMENT
//      les mêmes octets pour les mêmes entrées déterministes.
//   2. Propriétés générales (round-trip chiffrement/déchiffrement, boîte scellée, isolation
//      accès d'urgence/partage) — mêmes propriétés que la suite de tests Rust, vérifiées ici dans
//      l'environnement WASM/Node réel plutôt que supposées "pareilles parce que même code source".
//
// Lancer avec : node test-node.js (depuis extension/wasm-bindings/, après `wasm-pack build
// --target nodejs --out-dir pkg-nodejs`). Distinct de pkg-web/ (voir extension/popup/), construit
// avec `--target web` pour être chargeable dans une popup de navigateur (pas de require/fs/__dirname
// là-bas, contrairement à ce build-ci qui s'appuie sur eux et ne fonctionne donc que sous Node).

const wasm = require("./pkg-nodejs/wasm_bindings.js");

let failures = 0;
function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    failures++;
    console.error(`ÉCHEC: ${message}\n  attendu : ${expected}\n  obtenu  : ${actual}`);
  } else {
    console.log(`OK: ${message}`);
  }
}
function assertTrue(condition, message) {
  assertEqual(Boolean(condition), true, message);
}

// --- 1. Vecteur connu, identique à crypto-core/src/crypto.rs::test_known_vector_matches_wasm_build ---
{
  const keys = wasm.derive_keys("cross-target-test@example.com", "cross-target-test-password");
  const vaultKeyHex = Buffer.from(keys.vault_key).toString("hex");
  assertEqual(
    keys.auth_hash_hex,
    "4f7d8a8473865a465ece3c58a0da6bc1b24e84d3237d739789bfea540d55e84d",
    "derive_keys(WASM) produit le MÊME auth_hash_hex que le binaire natif (vecteur figé)",
  );
  assertEqual(
    vaultKeyHex,
    "a281ad7fe9b9d7e1a10f272f52bf8133addf206f9a5a74748083d9b0320a1ea6",
    "derive_keys(WASM) produit la MÊME vault_key que le binaire natif (vecteur figé)",
  );
}

// --- 2. SHA-1 (vérification de fuite HIBP) — même vecteur connu que côté Rust ---
{
  const hash = wasm.sha1_hex("password");
  assertEqual(hash, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", "sha1_hex(WASM) correspond au vecteur connu");
}

// --- 3. Round-trip chiffrement/déchiffrement d'un champ ---
{
  const keys = wasm.derive_keys("user@example.com", "mon_mot_de_passe");
  const plaintext = "https://example.com identifiant secret";
  const ciphertext = wasm.encrypt_field(keys.vault_key, plaintext);
  assertTrue(ciphertext !== plaintext, "le blob chiffré ne contient jamais le texte en clair tel quel");
  const decrypted = wasm.decrypt_field(keys.vault_key, ciphertext);
  assertEqual(decrypted, plaintext, "round-trip chiffrement/déchiffrement d'un champ");
}

// --- 4. Une mauvaise clé doit échouer, jamais renvoyer un contenu incorrect silencieusement ---
{
  const goodKeys = wasm.derive_keys("user@example.com", "bon_mot_de_passe");
  const badKeys = wasm.derive_keys("user@example.com", "mauvais_mot_de_passe");
  const ciphertext = wasm.encrypt_field(goodKeys.vault_key, "secret");
  let threw = false;
  try {
    wasm.decrypt_field(badKeys.vault_key, ciphertext);
  } catch {
    threw = true;
  }
  assertTrue(threw, "déchiffrer avec la mauvaise clé doit lever une exception JS, jamais réussir silencieusement");
}

// --- 5. Boîte scellée (accès d'urgence) — round-trip ---
{
  const pair = wasm.generate_keypair();
  const plaintext = "clé de coffre en base64, ou n'importe quel secret";
  const sealed = wasm.seal(plaintext, pair.public_key);
  assertTrue(sealed !== plaintext, "le blob scellé ne contient jamais le texte en clair tel quel");
  const recovered = wasm.unseal(sealed, pair.private_key);
  assertEqual(recovered, plaintext, "round-trip scellement/descellement (accès d'urgence)");
}

// --- 6. Isolation cryptographique accès d'urgence <-> partage d'entrée (même trousseau de clés) ---
{
  const pair = wasm.generate_keypair();
  const sealedForEmergency = wasm.seal("clé de coffre", pair.public_key);
  let threw = false;
  try {
    wasm.unseal_share(sealedForEmergency, pair.private_key);
  } catch {
    threw = true;
  }
  assertTrue(threw, "un blob scellé pour l'accès d'urgence ne doit jamais se desceller comme un partage d'entrée");

  const sealedForShare = wasm.seal_for_share("contenu d'entrée partagée", pair.public_key);
  let threw2 = false;
  try {
    wasm.unseal(sealedForShare, pair.private_key);
  } catch {
    threw2 = true;
  }
  assertTrue(threw2, "un blob scellé pour un partage d'entrée ne doit jamais se desceller comme un accès d'urgence");
}

console.log(failures === 0 ? "\nTous les tests d'interopérabilité desktop <-> WASM sont passés." : `\n${failures} échec(s).`);
process.exit(failures === 0 ? 0 : 1);
