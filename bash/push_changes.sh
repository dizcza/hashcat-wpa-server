#!/usr/bin/env bash

rsync -rave "ssh -i ${AWS_KEY}" --exclude-from=rsync.exclude . `whoami`@${AWS_HOST}:/home/`whoami`/hashcat-wpa-server
rsync -ve "ssh -i ${AWS_KEY}" bash/docker_run.sh `whoami`@${AWS_HOST}:/home/`whoami`/hashcat-wpa-server
