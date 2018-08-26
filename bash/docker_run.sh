#!/usr/bin/env bash
docker rm -f hashcatwpaserver_app_1
docker-compose build
# nvidia-docker-compose build --build-arg branch=latest app
docker-compose up -d
