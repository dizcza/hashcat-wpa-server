ARG branch=intel-cpu
FROM dizcza/docker-hashcat:$branch

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
RUN wget --no-check-certificate https://www.dropbox.com/s/tqsvy830b9m2fgn/phpbb.txt.bz2?dl=1 -O phpbb.txt.bz2 && \
    bzip2 -d phpbb.txt.bz2
RUN wget --no-check-certificate https://www.dropbox.com/s/1jidlq4706pd3x1/rockyou.txt.bz2?dl=1 -O rockyou.txt.bz2 && \
    bzip2 -d rockyou.txt.bz2
RUN wget --no-check-certificate https://www.dropbox.com/s/6439rfwfy6qaz3h/conficker_elitehacker_john_riskypass_top1000.txt?dl=1 -O conficker_elitehacker_john_riskypass_top1000.txt

RUN mkdir -p /hashcat-wpa-server/captures

COPY ./requirements.txt /hashcat-wpa-server/requirements.txt
RUN pip3.5 install -r /hashcat-wpa-server/requirements.txt

COPY ./digits /hashcat-wpa-server/digits
WORKDIR /hashcat-wpa-server
RUN python3.5 digits/create_digits.py

COPY ./nginx.conf /etc/nginx/nginx.conf

COPY ./supervisor.conf /etc/supervisor/conf.d/hashcat_wpa.conf

COPY . /hashcat-wpa-server
WORKDIR /hashcat-wpa-server

RUN mkdir -p /hashcat-wpa-server/logs/gunicorn

CMD supervisord -n -c /etc/supervisor/supervisord.conf
