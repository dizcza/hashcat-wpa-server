ARG branch=latest
FROM dizcza/docker-hashcat:$branch

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y bzip2 python3-distutils python3-venv python3-pip nginx supervisor apt-utils

RUN useradd --no-create-home nginx

# wordlists
RUN mkdir -p /root/hashcat-wpa-server/wordlists
WORKDIR /root/hashcat-wpa-server/wordlists
RUN for dict in Top1575-probable-v2.txt Top304Thousand-probable-v2.txt; do \
    wget -q --no-check-certificate https://github.com/berzerk0/Probable-Wordlists/raw/master/Real-Passwords/$dict; \
    done
RUN for keymap in /root/kwprocessor/keymaps/*; do \
    kwp /root/kwprocessor/basechars/tiny.base $keymap \
        /root/kwprocessor/routes/2-to-16-max-3-direction-changes.route >> /root/hashcat-wpa-server/wordlists/keyboard-walk.txt; \
    done
RUN mkdir -p /root/.hashcat/wpa-server
RUN hashcat --stdout --rules=/root/hashcat/rules/best64.rule \
    /root/hashcat-wpa-server/wordlists/Top1575-probable-v2.txt | \
    sort -u > /root/hashcat-wpa-server/wordlists/Top1575-probable-v2-rule-best64.txt
RUN chmod -wx /root/hashcat-wpa-server/wordlists/*

# rules
RUN mkdir -p /root/.hashcat/wpa-server/rules
WORKDIR /root/hashcat-wpa-server/rules
RUN wget --no-check-certificate https://github.com/Unic0rn28/hashcat-rules/raw/main/unicorn%20rules/UnicornLorge.rule
RUN wget --no-check-certificate https://github.com/stealthsploit/OneRuleToRuleThemStill/raw/main/OneRuleToRuleThemStill.rule

COPY ./requirements.txt /root/hashcat-wpa-server/requirements.txt
RUN pip3 install -r /root/hashcat-wpa-server/requirements.txt

RUN mkdir -p /root/hashcat-wpa-server/logs/supervisor
RUN mkdir -p /root/.hashcat/wpa-server/brain
RUN mkdir -p /root/.hashcat/wpa-server/database
RUN mkdir -p /root/.hashcat/wpa-server/captures
RUN mkdir -p /root/.hashcat/wpa-server/wordlists

WORKDIR /root/hashcat-wpa-server

COPY ./nginx.conf /etc/nginx/nginx.conf
COPY ./supervisor.conf /etc/supervisor/conf.d/hashcat_wpa.conf
COPY . /root/hashcat-wpa-server

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
RUN flask db init --directory=/root/.hashcat/wpa-server/database/migrations
RUN flask db migrate --directory=/root/.hashcat/wpa-server/database/migrations
RUN flask db upgrade --directory=/root/.hashcat/wpa-server/database/migrations

CMD supervisord -n -c /etc/supervisor/supervisord.conf
