#!/usr/bin/env bash

echo -n $1 | hashcat --stdout -r rules/best64.rule
