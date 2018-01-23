#!/usr/bin/env bash

rsync -rave "ssh -i ${AWS_KEY}" --exclude-from=rsync.exclude . dizcza@${AWS_HOST}:/home/dizcza/hashcat-wpa-server
rsync -ve "ssh -i ${AWS_KEY}" bash/docker_run.sh dizcza@${AWS_HOST}:/home/dizcza/hashcat-wpa-server
