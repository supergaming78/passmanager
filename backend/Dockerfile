# Étape 1 : Construction (Builder)
# Image de base pinnée à la branche majeure "1" sur Debian bookworm (au lieu de "slim" seul,
# qui suit silencieusement "latest") : reproductibilité des builds, et même base OS (bookworm)
# que l'image runtime ci-dessous, pour éviter des incompatibilités de libc entre les deux étapes.
FROM rust:1-slim-bookworm AS builder

WORKDIR /app
# NOTE : aucune dépendance système à installer ici. sqlx (feature "sqlite") compile SQLite depuis
# les sources et le lie STATIQUEMENT ("bundled"), et lettre utilise désormais `rustls` (TLS
# 100% Rust) au lieu de `native-tls`/OpenSSL — plus aucune bibliothèque C externe requise pour
# la compilation. `rust:slim` embarque déjà un compilateur C (gcc), suffisant pour les rares
# crates avec un build script (ex: la partie assembleur de `ring`, utilisée par rustls).

# --- Mise en cache de la compilation des dépendances (optimisation du temps de build) ---
# On compile d'abord un projet FACTICE avec uniquement Cargo.toml/Cargo.lock : Docker met en
# cache cette étape (toutes les dépendances déjà compilées) tant que ces deux fichiers ne
# changent pas. Résultat : modifier uniquement le code source (src/) ne déclenche PLUS la
# recompilation de toutes les dépendances à chaque build, seulement du code applicatif.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# --- Compilation du vrai code applicatif ---
# Le cache des dépendances ci-dessus reste valide (Cargo.toml/lock inchangés) : seul ce code
# est (re)compilé ici. `migrations/` doit être présent AVANT ce build : sqlx::migrate!() est une
# macro qui embarque le contenu des migrations DANS LE BINAIRE à la compilation (pas au runtime).
COPY src ./src
COPY migrations ./migrations
RUN cargo build --release

# Étape 2 : Exécution (Runtime)
FROM debian:bookworm-slim

WORKDIR /app
# Installation runtime minimale. PAS de `curl` : il tirait `openldap` en dépendance transitive
# (support LDAP intégré au paquet Debian curl), avec sa propre liste de CVE — remplacé par un
# petit binaire de healthcheck en Rust pur (voir src/bin/healthcheck.rs), sans dépendance système.
# Création d'un utilisateur applicatif NON-ROOT (bonne pratique : si le process est compromis,
# il n'a pas les privilèges root dans le conteneur).
# Purge de paquets présents dans l'image de base (`debian:bookworm-slim`) mais totalement
# inutiles à un binaire Rust compilé : `perl`/`tar` (relevés par le scan Docker Desktop), et
# `openssl` (le paquet CLI, PAS `libssl3` — ce dernier peut rester si un autre paquet en dépend
# encore ; on ne touche qu'à ce qui n'est plus nécessaire depuis le passage de lettre à `rustls`).
# `|| true` en garde-fou : si apt refuse d'en retirer un (paquet marqué "essential" ou requis par
# une dépendance restante), le build ne casse pas pour autant — il faudra juste regarder pourquoi.
# Installation runtime minimale. PAS de `curl` : il tirait `openldap` en dépendance transitive
# (support LDAP intégré au paquet Debian curl), avec sa propre liste de CVE — remplacé par un
# petit binaire de healthcheck en Rust pur (voir src/bin/healthcheck.rs), sans dépendance système.
# PAS de `ca-certificates` non plus : lettre utilise désormais `webpki-roots`, qui embarque les
# certificats racine DANS LE BINAIRE à la compilation. Or `ca-certificates` a une dépendance
# OBLIGATOIRE sur `openssl` côté Debian — en ne l'installant plus du tout, `openssl` n'est plus
# tiré dans l'image, là où le purger explicitement échouait silencieusement à cause de cette
# dépendance protégée.
# Création d'un utilisateur applicatif NON-ROOT (bonne pratique : si le process est compromis,
# il n'a pas les privilèges root dans le conteneur).
# Purge de perl/tar, présents dans l'image de base (`debian:bookworm-slim`) mais totalement
# inutiles à un binaire Rust compilé — c'est ce que relevait le scan Docker Desktop. `|| true`
# en garde-fou : si apt refuse d'en retirer un, le build ne casse pas pour autant.
RUN apt-get update \
    && useradd --system --uid 1000 --create-home --shell /usr/sbin/nologin appuser \
    && (apt-get purge -y --auto-remove perl perl-base perl-modules-5.36 tar || true) \
    && rm -rf /var/lib/apt/lists/*

# On ne récupère QUE les binaires compilés de l'étape précédente (serveur + healthcheck)
COPY --from=builder /app/target/release/backend /app/backend
COPY --from=builder /app/target/release/healthcheck /app/healthcheck

# PAS de `COPY .env` ici : les secrets (JWT_SECRET, PASSWORD_PEPPER, SMTP_PASS...) ne doivent
# JAMAIS être gravés dans l'image Docker (extractibles par quiconque a accès à l'image, même
# après suppression dans une étape ultérieure : ils restent dans l'historique des layers).
# Ils sont injectés au RUNTIME via `env_file` dans docker-compose.yml, jamais à la build.

# PAS de `COPY migrations` ici non plus : comme expliqué plus haut, sqlx::migrate!() les a déjà
# embarquées DANS LE BINAIRE à la compilation — les recopier au runtime ne servirait à rien.

# Prépare le dossier de données et donne la propriété à l'utilisateur non-root AVANT de basculer dessus
RUN mkdir -p /app/data && chown -R appuser:appuser /app
USER appuser

# Variables d'environnement par défaut
ENV PORT=3000
ENV APP_ENV=production

EXPOSE 3000

# Vérifie que le serveur répond ET que sa BDD est joignable (voir handlers::health_check).
# Permet à Docker/un orchestrateur de détecter un conteneur bloqué et d'agir en conséquence
# (redémarrage, retrait du load balancer...).
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/healthcheck"]

# Lancement de l'application
CMD ["./backend"]