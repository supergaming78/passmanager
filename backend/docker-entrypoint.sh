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

# CORRECTIF (retour utilisateur : le serveur ne s'arrêtait pas proprement, ni en local ni sur
# Docker) : `su -c "exec ..."` NE remplace PAS le process courant, contrairement à ce que le
# commentaire précédent affirmait — `su` reste PID 1 et ATTEND son enfant (le vrai `backend`
# tourne sur un PID distinct, enfant de `su`). Vérifié empiriquement avec un conteneur de test
# minimal : le processus applicatif reçoit bien SIGTERM au bout du compte, mais `su` (PID 1)
# lui-même ne se termine jamais proprement — le conteneur sort avec le code 143 (tué PAR un
# signal, pas une sortie volontaire) et ~1,7 s de latence supplémentaire avant que Docker le
# considère réellement arrêté. Sur un déploiement réel (plus de connexions ouvertes, plus de
# travail à finir proprement qu'un script de test), ce même défaut peut suffire à dépasser le
# délai de grâce de Docker et finir en SIGKILL forcé — la panne "pas d'arrêt propre" signalée.
#
# `setpriv` (déjà présent : fourni par `util-linux`, un paquet de base de toute image Debian,
# aucune dépendance supplémentaire à installer) fait un VRAI remplacement du process courant —
# aucun processus superviseur au-dessus, le binaire serveur devient RÉELLEMENT PID 1. Revérifié
# sur le même conteneur de test : code de sortie 0, latence de fermeture ~0 ms après le signal,
# identique à un lancement sans abaissement de privilèges du tout.
exec setpriv --reuid=appuser --regid=appuser --init-groups /app/backend
