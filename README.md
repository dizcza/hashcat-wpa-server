[![Docker Hub](http://dockeri.co/image/dizcza/hashcat-wpa-server)](https://hub.docker.com/r/dizcza/hashcat-wpa-server/)

[![](https://images.microbadger.com/badges/version/dizcza/hashcat-wpa-server:latest.svg)](https://microbadger.com/images/dizcza/hashcat-wpa-server:latest)
[![](https://images.microbadger.com/badges/image/dizcza/hashcat-wpa-server:latest.svg)](https://microbadger.com/images/dizcza/hashcat-wpa-server:latest)

[![](https://images.microbadger.com/badges/version/dizcza/hashcat-wpa-server:intel-cpu.svg)](https://microbadger.com/images/dizcza/hashcat-wpa-server:intel-cpu)
[![](https://images.microbadger.com/badges/image/dizcza/hashcat-wpa-server:intel-cpu.svg)](https://microbadger.com/images/dizcza/hashcat-wpa-server:intel-cpu)


# Hashcat WPA/WPA2 server

Yet another WPA/WPA2 hashes cracker. Powered by [hashcat](https://hashcat.net/hashcat/). It uses the most common wordlists and rules. Written in Python 3.6.

Check out running server on AWS free tier instance: http://85.217.171.57:9111. To surf the site, login with the `guest:guest` credentials. (Yes, you don't have the permissions to start jobs. Contact me if necessary.)

## Deployment

#### Building your local image

```
export HASHCAT_ADMIN_USER=admin
export HASHCAT_ADMIN_PASSWORD=<your-secret-password>
docker-compose up -d
```

That's all! Navigate to [localhost:9111](localhost:9111). SQLite database with all users and uploaded tasks will be located in `$HOME/hashcat_database/hashcat_wpa.db` on your host machine.


#### Using docker hub. Nvidia GPU

Make sure you've installed [nvidia-docker2](https://github.com/NVIDIA/nvidia-docker).

Then run `:latest` docker container from the [docker hub](https://hub.docker.com/r/dizcza/hashcat-wpa-server/): 

```
docker run --runtime=nvidia -d -e HASHCAT_ADMIN_USER=admin -e HASHCAT_ADMIN_PASSWORD=<your-secret-password> -v ${HOME}/hashcat_database:/hashcat-wpa-server/database -p 9111:80 dizcza/hashcat-wpa-server:latest
```

Or build your own image with Nvidia support: 

```
docker build --build-arg branch=latest -t hashcat-wpa-server:latest -f Dockerfile .
```

Then run your `hashcat-wpa-server:latest` docker image instead of `dizcza/hashcat-wpa-server:latest`. You'll still need [nvidia-docker2](https://github.com/NVIDIA/nvidia-docker) package installed to start containers.

#### Using docker hub. Intel CPU

For those who don't have GPUs, use `:intel-cpu` tag (suitable for AWS free tier instances):

```
docker run -d -e HASHCAT_ADMIN_USER=admin -e HASHCAT_ADMIN_PASSWORD=<your-secret-password> -v ${HOME}/hashcat_database:/hashcat-wpa-server/database -p 9111:80 dizcza/hashcat-wpa-server:intel-cpu
```