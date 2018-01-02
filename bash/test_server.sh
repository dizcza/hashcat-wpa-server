#!/usr/bin/env bash

HASHCAT_WPA_URL="http://192.168.1.100:8000"
#HASHCAT_WPA_URL="https://ec2-34-227-113-244.compute-1.amazonaws.com:443"

curl --insecure ${HASHCAT_WPA_URL}
token=`curl --insecure -d ${HASHCAT_USERNAME}:${HASHCAT_PASSWORD} ${HASHCAT_WPA_URL}/auth | jq -r '.access_token'`
curl --insecure -H "Authorization: JWT $token" ${HASHCAT_WPA_URL}/ping
echo
#curl --insecure -H "Authorization: JWT $token" -H "wordlist: phpbb.txt" -H "rule: best64.rule" ${HASHCAT_WPA_URL}/estimate
#curl --insecure -H "Authorization: JWT $token" ${HASHCAT_WPA_URL}/benchmark
curl --insecure -H "Authorization: JWT $token" -H "filename: test_cap.cap" -H "timeout: 60" -H "wordlist: phpbb.txt" -H "rule: best64.rule" --data-binary "@captures/test_cap.cap" ${HASHCAT_WPA_URL}/upload
