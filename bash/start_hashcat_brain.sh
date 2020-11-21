#!/bin/bash
# run on server

cd /root/hashcat-wpa-server/brain
LC_ALL=C tr -dc '[:alnum:]' < /dev/urandom | head -c20 > hashcat_brain_password
hashcat --brain-server --brain-password=$(cat hashcat_brain_password)
