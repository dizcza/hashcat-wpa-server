ARG branch=intel-cpu
FROM dizcza/docker-hashcat:$branch

RUN apt-get update && \
    apt-get install -y bzip2 python3.6 nginx supervisor
RUN apt-get install -y python3-distutils
RUN useradd --no-create-home nginx

RUN wget --no-check-certificate https://bootstrap.pypa.io/get-pip.py -O /tmp/get-pip.py && \
    python3 /tmp/get-pip.py

# wordlists
RUN mkdir -p /hashcat-wpa-server/wordlists
WORKDIR /hashcat-wpa-server/wordlists
RUN for dict in phpbb.txt.bz2 rockyou.txt.bz2; do \
    wget -q --no-check-certificate http://downloads.skullsecurity.org/passwords/${dict} && \
    bzip2 -d ${dict}; done
RUN wget --no-check-certificate https://www.dropbox.com/s/6439rfwfy6qaz3h/conficker_elitehacker_john_riskypass_top1000.txt?dl=1 -O top4k.txt
RUN wget --no-check-certificate https://raw.githubusercontent.com/berzerk0/Probable-Wordlists/master/Real-Passwords/Top304Thousand-probable-v2.txt -O top304k.txt

RUN mkdir -p /hashcat-wpa-server/captures

COPY ./requirements.txt /hashcat-wpa-server/requirements.txt
RUN pip3 install -r /hashcat-wpa-server/requirements.txt

COPY ./digits /hashcat-wpa-server/digits
WORKDIR /hashcat-wpa-server
RUN python3 digits/create_digits.py

COPY ./nginx.conf /etc/nginx/nginx.conf

COPY ./supervisor.conf /etc/supervisor/conf.d/hashcat_wpa.conf

RUN mkdir -p /hashcat-wpa-server/logs/gunicorn/nginx
RUN mkdir -p /hashcat-wpa-server/logs/gunicorn/app
RUN mkdir -p /hashcat-wpa-server/logs/gunicorn/wordlist

COPY . /hashcat-wpa-server
WORKDIR /hashcat-wpa-server

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
RUN flask db init
RUN flask db migrate
RUN flask db upgrade

RUN mkdir -p /hashcat-wpa-server/logs/gunicorn

CMD supervisord -n -c /etc/supervisor/supervisord.conf
