#!/usr/bin/env bash

rsync -rave "ssh" --exclude-from=rsync.exclude . vps:/home/vps/projects/hashcat-wpa-server
