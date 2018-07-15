[![Docker Hub](http://dockeri.co/image/dizcza/hashcat-wpa-server)](https://hub.docker.com/r/dizcza/hashcat-wpa-server/)

[![](https://images.microbadger.com/badges/version/dizcza/hashcat-wpa-server.svg)](https://microbadger.com/images/dizcza/hashcat-wpa-server)
[![](https://images.microbadger.com/badges/image/dizcza/hashcat-wpa-server.svg)](https://microbadger.com/images/dizcza/hashcat-wpa-server)

# Hashcat WPA/WPA2 server

Yet another WPA/WPA2 hashes cracker. Powered by [hashcat](https://hashcat.net/hashcat/). It uses the most common wordlists and rules.

Check out running server on AWS free tier instance: [http://ec2-34-227-113-244.compute-1.amazonaws.com:9111](http://ec2-34-227-113-244.compute-1.amazonaws.com:9111). To surf the site, login with the `guest:guest` credentials. (Yes, you don't have the permissions to start jobs. Contact me if necessary.)

## Deployment

#### Building your local image

```
export HASHCAT_ADMIN_USER=admin
export HASHCAT_ADMIN_PASSWORD=<your-secret-password>
docker-compose up -d
```

That's all! Navigate to [localhost:9111](localhost:9111). SQLite database with all users and uploaded tasks will be located at `$HOME/hashcat_database/hashcat_wpa.db` in your host machine.


#### Using docker hub

Alternatively, you can just pull the container from the docker hub and pass all arguments from docker-compose mannualy.

```
docker run -d -e HASHCAT_ADMIN_USER=admin -e HASHCAT_ADMIN_PASSWORD=<your-secret-password> -v /home/dizcza/hashcat_database:/hashcat-wpa-server/database -p 9111:80 dizcza/hashcat-wpa-server
```

## Nvidia GPU

1. Make sure you've installed [nvidia-docker2](https://github.com/NVIDIA/nvidia-docker).
2. Build image with Nvidia support: `docker build --build-arg branch=nvidia-full -t hashcat-wpa-server:nvidia-full -f Dockerfile .`
3. Run docker container: `docker run --runtime=nvidia -d -e HASHCAT_ADMIN_USER=admin -e HASHCAT_ADMIN_PASSWORD=<your-secret-password> -v /home/dizcza/hashcat_database:/hashcat-wpa-server/database -p 9111:80 hashcat-wpa-server:nvidia-full`