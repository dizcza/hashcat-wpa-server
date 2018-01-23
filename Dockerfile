FROM dizcza/docker-hashcat:intel-cpu

RUN apt-get update && \
    apt-get install -y bzip2 python3.5 supervisor vim htop

RUN echo "deb http://nginx.org/packages/ubuntu/ xenial nginx" >> /etc/apt/sources.list && \
    echo "deb-src http://nginx.org/packages/ubuntu/ xenial nginx" >> /etc/apt/sources.list
WORKDIR /tmp
RUN wget --no-check-certificate http://nginx.org/keys/nginx_signing.key && \
    apt-key add nginx_signing.key && \
    apt-get update && \
    apt-get install nginx

RUN wget --no-check-certificate https://bootstrap.pypa.io/get-pip.py && \
    python3.5 get-pip.py

# wordlists
RUN mkdir -p /hashcat-wpa-server/wordlists
WORKDIR /hashcat-wpa-server/wordlists
RUN for dict in phpbb.txt.bz2 rockyou.txt.bz2 john.txt.bz2 conficker.txt.bz2; do \
    wget --no-check-certificate http://downloads.skullsecurity.org/passwords/${dict} && \
    bzip2 -d ${dict}; done

RUN mkdir -p /hashcat-wpa-server/captures

COPY ./requirements.txt /hashcat-wpa-server/requirements.txt
RUN pip3.5 install -r /hashcat-wpa-server/requirements.txt

COPY ./digits /hashcat-wpa-server/digits
WORKDIR /hashcat-wpa-server
RUN python3.5 digits/create_digits.py

RUN mkdir -p /etc/nginx/server_keys
COPY ./server_keys/ /etc/nginx/server_keys/
COPY ./nginx.conf /etc/nginx/nginx.conf

COPY ./supervisor.conf /etc/supervisor/conf.d/hashcat_wpa.conf

COPY . /hashcat-wpa-server
WORKDIR /hashcat-wpa-server

RUN mkdir -p /hashcat-wpa-server/logs/gunicorn

CMD supervisord -n -c /etc/supervisor/supervisord.conf
