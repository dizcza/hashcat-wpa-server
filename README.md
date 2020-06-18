[![Docker Hub](http://dockeri.co/image/dizcza/hashcat-wpa-server)](https://hub.docker.com/r/dizcza/hashcat-wpa-server/)

[![](https://images.microbadger.com/badges/version/dizcza/hashcat-wpa-server:latest.svg)](https://microbadger.com/images/dizcza/hashcat-wpa-server:latest)
[![](https://images.microbadger.com/badges/image/dizcza/hashcat-wpa-server:latest.svg)](https://microbadger.com/images/dizcza/hashcat-wpa-server:latest)

[![](https://images.microbadger.com/badges/version/dizcza/hashcat-wpa-server:intel-cpu.svg)](https://microbadger.com/images/dizcza/hashcat-wpa-server:intel-cpu)
[![](https://images.microbadger.com/badges/image/dizcza/hashcat-wpa-server:intel-cpu.svg)](https://microbadger.com/images/dizcza/hashcat-wpa-server:intel-cpu)

[![](https://images.microbadger.com/badges/version/dizcza/hashcat-wpa-server:pocl.svg)](https://microbadger.com/images/dizcza/hashcat-wpa-server:pocl)
[![](https://images.microbadger.com/badges/image/dizcza/hashcat-wpa-server:pocl.svg)](https://microbadger.com/images/dizcza/hashcat-wpa-server:pocl)


# Hashcat WPA/WPA2 server

Yet another WPA/WPA2 hashes cracker web server. Powered by [hashcat](https://hashcat.net/hashcat/), written in Python 3.6. The
backend is implemented with Flask.

Supported capture file formats:
* .pcapng (hcxdumptool)
* .cap and .pcap (airodump)
* .hccapx and .2500 (EAPOL)
* .pmkid and .16800 (PMKID)
* .22000 (PMKID/EAPOL)

The server uses [Hashcat Brain](https://hashcat.net/forum/thread-7903.html) transparently for the user (the user is allowed to activate and deactivate the feature).

Every password cracking researcher is proud of his/her wordlists and rules. Here is my strategy of checking the most
probable passwords that require only a few minutes to run on any laptop or Raspberry Pi. The strategy is marked as
`'(fast)'` among wordlist choices in UI. They are all run in [`BaseAttack.run_all()`](
https://github.com/dizcza/hashcat-wpa-server/blob/c9285676668c1c64fd5a62282366d3cb92dff969/app/attack/base_attack.py#L220)
method:

* `run_essid_attack`: ESSID + digits_append.txt combinator attack (`-a1`), ESSID + best64.rule attack. It uses
[wordninja](https://github.com/keredson/wordninja) to split ESSID in words and create all possible permutations of word
compounds. For example "PetitCafe2017" ESSID will be split in `['2017', '2017Cafe', '2017CafePetit', '2017Petit', '2017PetitCafe', 'Cafe', 'Cafe2017', 'Cafe2017Petit', 'CafePetit', 'CafePetit2017', 'Petit', 'Petit2017', 'Petit2017Cafe', 'PetitCafe', 'PetitCafe2017']`
which increases the chance of finding passwords of type "PetitXXXX" by running a combinator attack for each of the word
compounds combination.
* `run_top1k`: Top1575-probable-v2.txt + best64.rule attack.
* `run_top304k`: Top304Thousand-probable-v2.txt attack.
* `run_digits8`: birthdays 100 years backward, digits masks like aabbccdd (refer to [mask_8-12.txt](app/word_magic/digits/mask_8-12.txt)), digits cycles, and more.
* `run_keyboard_walk`: [keyboard-walk](https://github.com/hashcat/kwprocessor) attack.
* `run_names`: names_ua-ru.txt with [essid.rule](rules/essid.rule) attack.

Check out a running server on a CPU instance: http://85.217.171.57:9111. To surf the site, login with the `guest:guest` credentials. (Yes, you don't have the permissions to start jobs. Contact me if necessary.)


## Deployment

**Note**. Using GPU hardware requires [nvidia-docker2](https://github.com/NVIDIA/nvidia-docker) to be installed on your host machine.


### Using Docker Hub

There are 3 docker tags (branches):

* `latest`: Nvidia GPUs;
* `intel-cpu`: Intel CPUs;
* `pocl`: an alternative to `intel-cpu` tag, an open source implementation of OpenCL.

For example, to run the `latest` tag (makes sense only if you have at least 1 GPU), open a terminal and run

```
docker run --runtime=nvidia -d -e HASHCAT_ADMIN_USER=admin -e HASHCAT_ADMIN_PASSWORD=<your-secret-password> -v ${HOME}/hashcat_database:/root/hashcat-wpa-server/database -p 9111:80 dizcza/hashcat-wpa-server:latest
```

If you don't posses a GPU, try `intel-cpu` or `pocl` tag:

```
docker run -d -e HASHCAT_ADMIN_USER=admin -e HASHCAT_ADMIN_PASSWORD=<your-secret-password> -v ${HOME}/hashcat_database:/root/hashcat-wpa-server/database -p 9111:80 dizcza/hashcat-wpa-server:intel-cpu
```

That's all! Navigate to [localhost:9111](localhost:9111). SQLite database with all users and uploaded tasks will be located in `$HOME/hashcat_database/hashcat_wpa.db` on your host machine.


### Building the image locally

```
export HASHCAT_ADMIN_USER=admin
export HASHCAT_ADMIN_PASSWORD=<your-secret-password>
docker-compose -f docker-compose.yml build  # inside the docker/ folder
docker-compose -f docker-compose.yml up -d
```

That's all! Navigate to [localhost:9111](localhost:9111) as in the previous step. Run `docker volume inspect docker_hashcat-db` in a terminal to find where `hashcat_wpa.db` database file is stored on your host machine.

If you don't posses a GPU, run docker compose like so:

```
docker-compose -f docker-compose.yml build --build-arg branch=intel-cpu
docker-compose -f docker-compose.yml up -d
```
