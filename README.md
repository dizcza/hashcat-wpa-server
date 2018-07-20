[![Docker Hub](http://dockeri.co/image/dizcza/hashcat-wpa-server)](https://hub.docker.com/r/dizcza/hashcat-wpa-server/)

[![](https://images.microbadger.com/badges/version/dizcza/hashcat-wpa-server:intel-cpu.svg)](https://microbadger.com/images/dizcza/hashcat-wpa-server:intel-cpu)
[![](https://images.microbadger.com/badges/image/dizcza/hashcat-wpa-server:intel-cpu.svg)](https://microbadger.com/images/dizcza/hashcat-wpa-server:intel-cpu)

[![](https://images.microbadger.com/badges/version/dizcza/hashcat-wpa-server:nvidia.svg)](https://microbadger.com/images/dizcza/hashcat-wpa-server:nvidia)
[![](https://images.microbadger.com/badges/image/dizcza/hashcat-wpa-server:nvidia.svg)](https://microbadger.com/images/dizcza/hashcat-wpa-server:nvidia)

[![](https://images.microbadger.com/badges/version/dizcza/hashcat-wpa-server:nvidia-full.svg)](https://microbadger.com/images/dizcza/hashcat-wpa-server:nvidia-full)
[![](https://images.microbadger.com/badges/image/dizcza/hashcat-wpa-server:nvidia-full.svg)](https://microbadger.com/images/dizcza/hashcat-wpa-server:nvidia-full)


# Hashcat WPA/WPA2 server

Yet another WPA/WPA2 hashes cracker. Powered by [hashcat](https://hashcat.net/hashcat/). It uses the most common wordlists and rules. Written in Python 3.6.

Check out running server on AWS free tier instance: [http://ec2-34-227-113-244.compute-1.amazonaws.com:9111](http://ec2-34-227-113-244.compute-1.amazonaws.com:9111). To surf the site, login with the `guest:guest` credentials. (Yes, you don't have the permissions to start jobs. Contact me if necessary.)

## Deployment

#### Building your local image

```
export HASHCAT_ADMIN_USER=admin
export HASHCAT_ADMIN_PASSWORD=<your-secret-password>
docker-compose up -d
```

That's all! Navigate to [localhost:9111](localhost:9111). SQLite database with all users and uploaded tasks will be located at `$HOME/hashcat_database/hashcat_wpa.db` in your host machine.


#### Using docker hub. Nvidia GPU

Make sure you've installed [nvidia-docker2](https://github.com/NVIDIA/nvidia-docker).

Then run `:nvidia` or `:nvidia-full` docker container from the [docker hub](https://hub.docker.com/r/dizcza/hashcat-wpa-server/): 

```
docker run --runtime=nvidia -d -e HASHCAT_ADMIN_USER=admin -e HASHCAT_ADMIN_PASSWORD=<your-secret-password> -v /home/dizcza/hashcat_database:/hashcat-wpa-server/database -p 9111:80 dizcza/hashcat-wpa-server:nvidia-full
```

Or build your own image with Nvidia support: 

```
docker build --build-arg branch=nvidia-full -t hashcat-wpa-server:nvidia-full -f Dockerfile .
```

Then run your `hashcat-wpa-server:nvidia-full` docker image instead of `dizcza/hashcat-wpa-server:nvidia-full`. You'll still need [nvidia-docker2](https://github.com/NVIDIA/nvidia-docker) package installed to start containers.

#### Using docker hub. Intel CPU

For those who don't have GPUs, use `:intel-cpu` tag (suitable for AWS free tier instances):

```
docker run -d -e HASHCAT_ADMIN_USER=admin -e HASHCAT_ADMIN_PASSWORD=<your-secret-password> -v /home/dizcza/hashcat_database:/hashcat-wpa-server/database -p 9111:80 dizcza/hashcat-wpa-server:intel-cpu
```