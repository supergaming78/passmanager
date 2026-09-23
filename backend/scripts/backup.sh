#!/bin/sh
# Sauvegarde périodique de la base SQLite du serveur, lancée dans son PROPRE conteneur (voir le
# service "backup" dans docker-compose.yml) — jamais dans l'image applicative elle-même, pour ne
# pas y réintroduire une dépendance système (le binaire `sqlite3` CLI) que le Dockerfile a
# délibérément exclue (SQLite y est lié STATIQUEMENT dans le binaire Rust via sqlx, voir
# Dockerfile).
#
# Utilise `sqlite3 <db> ".backup <fichier>"` — PAS un simple `cp` : la base tourne en mode WAL
# (écritures en cours possibles à tout instant), une copie de fichier brute pourrait donc capturer
# un état incohérent à mi-écriture. La commande `.backup` de sqlite3 est l'API officielle conçue
# précisément pour produire un instantané cohérent d'une base WAL vivante, sans l'arrêter ni la
# verrouiller pour le reste de l'application.
#
# BACKUP_INTERVAL_SECONDS (défaut 86400 = 24h) et BACKUP_KEEP_COUNT (défaut 14, ~2 semaines à
# raison d'une sauvegarde par jour) sont surchargeables via l'environnement (voir
# docker-compose.yml, section "backup").
#
# BACKUP_ENCRYPTION_PASSPHRASE (optionnelle) : si définie, chaque sauvegarde est chiffrée
# symétriquement (GPG/AES-256) avant d'être écrite dans BACKUP_DIR, et la copie SQLite en clair
# n'existe jamais que le temps du chiffrement (fichier .tmp, supprimé juste après). Le fichier .db
# contient, en plus du coffre chiffré côté client, des métadonnées en clair (emails, IP de
# connexion, noms d'appareils, descriptions de bugs/suggestions) — ce chiffrement supplémentaire
# protège ces sauvegardes si BACKUP_DIR est ensuite synchronisé vers un stockage externe (NAS...).
# Sans cette variable, le comportement est inchangé (sauvegarde .db en clair, comme avant).
#
# Pour déchiffrer : `gpg --batch --yes --passphrase "$PASSPHRASE" --decrypt vault-XXXX.db.gpg > vault-XXXX.db`

set -eu

DB_PATH="${DB_PATH:-/data/vault.db}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
INTERVAL="${BACKUP_INTERVAL_SECONDS:-86400}"
KEEP_COUNT="${BACKUP_KEEP_COUNT:-14}"
PASSPHRASE="${BACKUP_ENCRYPTION_PASSPHRASE:-}"

if [ -n "$PASSPHRASE" ]; then
  echo "backup: demarrage (intervalle=${INTERVAL}s, retention=${KEEP_COUNT} sauvegardes, chiffrement GPG active)"
else
  echo "backup: demarrage (intervalle=${INTERVAL}s, retention=${KEEP_COUNT} sauvegardes, PAS de chiffrement - voir BACKUP_ENCRYPTION_PASSPHRASE)"
fi

while true; do
  if [ -f "$DB_PATH" ]; then
    # NE PAS RESAUVEGARDER si une sauvegarde plus recente que l'intervalle existe deja.
    #
    # Ce script sauvegarde au demarrage puis dort INTERVAL. Chaque redemarrage du conteneur —
    # donc chaque redeploiement du stack — produisait donc une sauvegarde de plus, qui purgeait
    # la plus ancienne. Constate sur un vrai serveur : trois redeploiements dans la journee, et
    # les trois sauvegardes conservees dataient toutes de la meme apres-midi.
    #
    # C'est exactement le moment ou l'historique compte le plus : on redeploie parce qu'on change
    # quelque chose, et si ce changement abime les donnees, les seules sauvegardes restantes sont
    # POSTERIEURES au probleme. La retention affichait "3 sauvegardes" en promettant trois jours,
    # et n'en couvrait plus qu'une heure.
    #
    # -mmin prend des MINUTES : l'intervalle est converti, avec un plancher a 1 pour qu'un
    # intervalle tres court reste testable.
    interval_min=$((INTERVAL / 60))
    [ "$interval_min" -lt 1 ] && interval_min=1
    # 'vault-*.db*' (et non 'vault-*.db') : couvre AUSSI les sauvegardes chiffrees .db.gpg, sans
    # quoi activer/desactiver BACKUP_ENCRYPTION_PASSPHRASE en cours de route ferait ignorer les
    # sauvegardes de l'autre format lors de cette verification.
    recente="$(find "$BACKUP_DIR" -maxdepth 1 -name 'vault-*.db*' -type f -mmin "-${interval_min}" 2>/dev/null | head -n 1)"
    if [ -n "$recente" ]; then
      echo "backup: une sauvegarde de moins de ${interval_min} min existe deja (${recente}) - passe ce tour"
      sleep "$INTERVAL"
      continue
    fi

    timestamp="$(date -u +%Y%m%d-%H%M%S)"
    base="${BACKUP_DIR}/vault-${timestamp}.db"
    tmp="${base}.tmp"
    dest=""

    # Ecrit d'abord sous un nom .tmp puis renomme/chiffre atomiquement à la fin : un arret/crash
    # du conteneur EN PLEIN milieu d'une sauvegarde ne doit jamais laisser un fichier .db partiel
    # qui se ferait ensuite passer pour une sauvegarde complete et valide.
    if sqlite3 "$DB_PATH" ".backup '${tmp}'"; then
      # Restreint la lecture au proprietaire AVANT toute autre operation : la base contient, en
      # plus du coffre chiffre cote client, des metadonnees en clair (emails, IP de connexion,
      # noms d'appareils, descriptions de bugs/suggestions...). Sans ce chmod, le fichier heritait
      # des permissions par defaut du conteneur (root, potentiellement lisible plus largement que
      # ./data ou tourne deja en UID 1000 avec un chown explicite - voir Dockerfile).
      chmod 600 "$tmp"

      if [ -n "$PASSPHRASE" ]; then
        dest="${base}.gpg"
        # --batch --yes : jamais de prompt interactif (ce script tourne sans terminal attache).
        # --pinentry-mode loopback : lit la passphrase fournie directement, sans tenter de
        # solliciter un agent gpg interactif (absent dans ce conteneur).
        if gpg --batch --yes --pinentry-mode loopback --passphrase "$PASSPHRASE" \
             --cipher-algo AES256 --symmetric --output "$dest" "$tmp"; then
          rm -f "$tmp"
          chmod 600 "$dest"
          echo "backup: OK -> ${dest} (chiffree)"
        else
          echo "backup: ECHEC du chiffrement GPG - sauvegarde en clair NON conservee par securite" >&2
          rm -f "$tmp"
          dest=""
        fi
      else
        dest="$base"
        mv "$tmp" "$dest"
        echo "backup: OK -> ${dest}"
      fi

      if [ -n "$dest" ]; then
        # Retention : ne garde que les N plus recentes, TOUS FORMATS CONFONDUS (meme principe que
        # frontend(app)/src/lib/vaultFile.ts::pruneOldBackups() cote client, applique ici cote
        # serveur) - une erreur sur un fichier individuel n'interrompt pas le nettoyage des autres.
        count=$(find "$BACKUP_DIR" -maxdepth 1 -name 'vault-*.db*' -type f | wc -l)
        if [ "$count" -gt "$KEEP_COUNT" ]; then
          find "$BACKUP_DIR" -maxdepth 1 -name 'vault-*.db*' -type f | sort | head -n "$((count - KEEP_COUNT))" | while IFS= read -r old; do
            rm -f "$old" && echo "backup: purge de ${old}"
          done
        fi
      fi
    else
      echo "backup: ECHEC de la sauvegarde (voir sortie sqlite3 ci-dessus)" >&2
      rm -f "$tmp"
    fi
  else
    echo "backup: ${DB_PATH} introuvable pour l'instant (le serveur n'a peut-etre pas encore demarre) - nouvelle tentative au prochain cycle" >&2
  fi

  sleep "$INTERVAL"
done
