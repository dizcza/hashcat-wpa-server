#!/usr/bin/env bash
docker rm -f hashcatwpaserver_app_1
docker-compose build
docker-compose up -d