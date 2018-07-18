#!/usr/bin/env bash

grep_pattern=`python -c "print('^[a-zA-Z]\+\(' + '\|'.join(map(str, range(1980, 2019))) + '\)[a-zA-Z]*$')"`

grep "${grep_pattern}" wordlists/weakpass_2_wifi > wordlists/aYEARa
sort wordlists/aYEARa > tmp && mv tmp wordlists/aYEARa

awk '{ curr=$0; gsub("[0-9]","",curr) } curr != prev { prev=curr; prevfull=$0; flag=0; next } !flag { print prevfull; flag=1 }' wordlists/aYEARa | awk '{ curr=$0; gsub("[0-9]","",curr) } curr != prev { print; prev = curr }' > wordlists/aYEARa.unique

pip3 install tqdm
python3 weakpass_2_wifi.py