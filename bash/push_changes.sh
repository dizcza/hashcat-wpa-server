#!/usr/bin/env bash

rsync -rave "ssh" --exclude-from=rsync.exclude . root@85.217.171.57:/root/hashcat-wpa-server
scp bash/docker_run.sh root@85.217.171.57:/root/hashcat-wpa-server/
