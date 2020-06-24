#!/usr/bin/env bash

rsync -rave "ssh" --exclude-from=rsync.exclude . vps:/home/vps/projects/hashcat-wpa-server
ssh -t vps "screen -S deploy -m bash /home/vps/projects/hashcat-wpa-server/bash/deploy.sh"
