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

set -eu

DB_PATH="${DB_PATH:-/data/vault.db}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
INTERVAL="${BACKUP_INTERVAL_SECONDS:-86400}"
KEEP_COUNT="${BACKUP_KEEP_COUNT:-14}"

echo "backup: demarrage (intervalle=${INTERVAL}s, retention=${KEEP_COUNT} sauvegardes)"

while true; do
  if [ -f "$DB_PATH" ]; then
    timestamp="$(date -u +%Y%m%d-%H%M%S)"
    dest="${BACKUP_DIR}/vault-${timestamp}.db"
    tmp="${dest}.tmp"

    # Ecrit d'abord sous un nom .tmp puis renomme atomiquement à la fin : un arret/crash du
    # conteneur EN PLEIN milieu d'une sauvegarde ne doit jamais laisser un fichier .db partiel
    # qui se ferait ensuite passer pour une sauvegarde complete et valide.
    if sqlite3 "$DB_PATH" ".backup '${tmp}'"; then
      mv "$tmp" "$dest"
      echo "backup: OK -> ${dest}"

      # Retention : ne garde que les N plus recentes (meme principe que
      # frontend(app)/src/lib/vaultFile.ts::pruneOldBackups() cote client, applique ici cote
      # serveur) - une erreur sur un fichier individuel n'interrompt pas le nettoyage des autres.
      count=$(find "$BACKUP_DIR" -maxdepth 1 -name 'vault-*.db' -type f | wc -l)
      if [ "$count" -gt "$KEEP_COUNT" ]; then
        find "$BACKUP_DIR" -maxdepth 1 -name 'vault-*.db' -type f | sort | head -n "$((count - KEEP_COUNT))" | while IFS= read -r old; do
          rm -f "$old" && echo "backup: purge de ${old}"
        done
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
