#!/usr/bin/env bash
docker rm -f hashcat-wpa-server_app_1
docker-compose build --build-arg branch=intel-cpu
# nvidia-docker-compose build --build-arg branch=latest app
docker-compose up -d
