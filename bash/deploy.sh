#!/usr/bin/env bash

source /home/vps/.bash_aliases
cd /home/vps/projects/hashcat-wpa-server/docker
sed -i '/flask db/d' Dockerfile
docker-compose build --build-arg branch=pocl
docker rm -f docker_hashcat-wpa-server_1
docker-compose up -d
