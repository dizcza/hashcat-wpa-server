#!/usr/bin/env bash

server_keys_dir="server_keys"

mkdir -p ${server_keys_dir}
cp -r ${server_keys_dir} ${server_keys_dir}_backup

openssl req -newkey rsa:4096 -nodes -keyout ${server_keys_dir}/private_key.pem -x509 -days 365 -out ${server_keys_dir}/certificate.pem -subj "/C=UA/ST=Kyiv/O=dizczaLock/CN=ec2-34-227-113-244.compute-1.amazonaws.com"
openssl dhparam -out ${server_keys_dir}/dhparam.pem 2048
openssl pkcs12 -inkey ${server_keys_dir}/private_key.pem -in ${server_keys_dir}/certificate.pem -export -out ${server_keys_dir}/certificate_client.p12

# verify password
# openssl pkcs12 -in ${server_keys_dir}/certificate_client.p12 -noout -info