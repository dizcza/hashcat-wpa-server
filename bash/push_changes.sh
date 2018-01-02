#!/usr/bin/env bash

root_dir=/home/dizcza/hashcat-wpa-server
root_dir_aws=dizcza@${AWS_HOST}:${root_dir}

ssh -i ${AWS_KEY} dizcza@${AWS_HOST} "mkdir -p ${root_dir}/app"

scp -i ${AWS_KEY} -r app \
               rules \
               server_keys \
               digits \
    ${root_dir_aws}/

scp -i ${AWS_KEY} config.yml \
             docker-compose.yml \
             Dockerfile \
             nginx.conf \
             requirements.txt \
             supervisor.conf \
             bash/docker_run.sh \
    ${root_dir_aws}/

# run.py is only for local debug
ssh -i ${AWS_KEY} dizcza@${AWS_HOST} "rm ${root_dir}/app/run.py"

# cleanup python cache
ssh -i ${AWS_KEY} dizcza@${AWS_HOST} "find ${root_dir} -type f -name '*.pyc' -delete"
