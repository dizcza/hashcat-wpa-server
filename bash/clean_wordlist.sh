#!/usr/bin/env bash

comm -23 <(sort /hashcat-wpa-server/wordlists/top304k.txt) <(sort <(hashcat --stdout -r /hashcat-wpa-server/rules/best64.rule /hashcat-wpa-server/wordlists/top4k.txt)) > /tmp/tmp && mv /tmp/tmp /hashcat-wpa-server/wordlists/top304k.txt
