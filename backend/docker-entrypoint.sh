#!/bin/sh
# Point d'entrée du conteneur — CORRECTIF trouvé face à un vrai déploiement Portainer bloqué :
# "unable to open database file" (SQLite code 14) au démarrage, malgré `chown -R appuser:appuser
# /app` fait au moment du BUILD de l'image (voir Dockerfile). Le souci : `/app/data` est un VOLUME
# monté (bind mount, voir docker-compose.yml) — un volume écrase COMPLÈTEMENT l'appartenance du
# dossier de l'image par celle du dossier HÔTE au moment où il est monté, à chaque démarrage du
# conteneur. Portainer crée souvent ce dossier appartenant à root sur l'hôte : `appuser` (UID
# 1000, non-root) ne peut alors ni créer ni ouvrir `vault.db` dedans, quoi que le Dockerfile ait
# fait au build.
#
# Ce script tourne D'ABORD en ROOT (voir le retrait de `USER appuser` dans le Dockerfile — c'est
# CE script, pas directement le binaire, qui est maintenant le point d'entrée) pour corriger cette
# appartenance À CHAQUE démarrage, quel que soit l'état du volume hôte, PUIS bascule immédiatement
# sur l'utilisateur non-root pour l'exécution réelle — la protection "jamais root à l'intérieur du
# conteneur" reste donc intacte pour le VRAI process serveur, seule cette étape de préparation
# s'exécute brièvement en root.
set -e

chown -R appuser:appuser /app/data

# `exec` (les DEUX fois) : remplace le process courant plutôt que d'en lancer un nouveau en plus —
# le PID 1 du conteneur reste le process utile tout du long (signaux SIGTERM/arrêt propre du
# conteneur transmis correctement), pas un script shell qui traînerait inutilement en arrière-plan.
exec su -s /bin/sh appuser -c "exec /app/backend"
