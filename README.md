[![Docker Hub](http://dockeri.co/image/dizcza/hashcat-wpa-server)](https://hub.docker.com/r/dizcza/hashcat-wpa-server/)

[![](https://img.shields.io/docker/image-size/dizcza/hashcat-wpa-server/latest?label=latest)](https://hub.docker.com/r/dizcza/hashcat-wpa-server/tags)
[![](https://img.shields.io/docker/image-size/dizcza/hashcat-wpa-server/intel-cpu?label=intel-cpu)](https://hub.docker.com/r/dizcza/hashcat-wpa-server/tags)
[![](https://img.shields.io/docker/image-size/dizcza/hashcat-wpa-server/pocl?label=pocl)](https://hub.docker.com/r/dizcza/hashcat-wpa-server/tags)

# Hashcat WPA/WPA2 server

Yet another WPA/WPA2 hashes cracker web server. Powered by [hashcat](https://hashcat.net/hashcat/). The backend is written in Python Flask.

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

* `run_essid_attack`: 
  - Hamming ball ESSID attack (perturb ESSID name with at most Hamming distance '2');
  - Split ESSID in word compounds with [wordninja](https://github.com/keredson/wordninja). For example "PetitCafe2017" ESSID is split in `['2017', '2017Cafe', '2017CafePetit', '2017Petit', 'Cafe', ..., 'CafePetit2017']` which increases the chance of finding passwords of type "PetitXXXX" by running the combinator attack for each of the word compounds combination. Technically, for each `essid_i` word compound, it runs
      - essid_i + digits_append.txt (prepend and append) combinator attack (`-a1`);
      - essid_i + best64.rule attack;
* `run_top1k`: Top1575-probable-v2.txt + best64.rule attack.
* `run_digits8`: birthdays 100 years backward, digits masks like aabbccdd (refer to [mask_8-12.txt](app/word_magic/digits/mask_8-12.txt)), digits cycles, and more.
* `run_keyboard_walk`: [keyboard-walk](https://github.com/hashcat/kwprocessor) attack.
* `run_names`: names_ua-ru.txt with best64 attack.

## Demo

Check out a running server on a CPU instance: http://85.217.171.57:9111. To surf the site, login with the `guest:guest` credentials. (Yes, you don't have the permissions to start jobs. Contact me if necessary.)


## Deployment

### Launching from the terminal

Run the following commands from the root `hashcat-wpa-server` folder:

```
pip install -r requirements.txt  # required only once

HASHCAT_ADMIN_USER=admin HASHCAT_ADMIN_PASSWORD=<your-secret-password> gunicorn app:app
```

### Docker containers

**Note**. Using GPU hardware requires [nvidia-docker2](https://github.com/NVIDIA/nvidia-docker) to be installed on your host machine.

#### Using Docker Hub

There are 3 docker tags (branches):

* `latest`: Nvidia GPUs;
* `intel-cpu`: Intel CPUs;
* `pocl`: an alternative to `intel-cpu` tag, an open source implementation of OpenCL.

For example, to run the `latest` tag (makes sense only if you have at least one GPU), open a terminal and run

```
docker run --runtime=nvidia -d \
    -e HASHCAT_ADMIN_USER=admin \
    -e HASHCAT_ADMIN_PASSWORD=<your-secret-password> \
    -v ${HOME}/.hashcat/wpa-server:/root/.hashcat/wpa-server \
    -p 9111:80 \
    dizcza/hashcat-wpa-server:latest
```

If you don't have a GPU, try `intel-cpu` or `pocl` tag:

```
docker run -d \
    -e HASHCAT_ADMIN_USER=admin \
    -e HASHCAT_ADMIN_PASSWORD=<your-secret-password> \
    -v ${HOME}/.hashcat/wpa-server:/root/.hashcat/wpa-server \
    -p 9111:80 \
    dizcza/hashcat-wpa-server:intel-cpu
```

That's all! Navigate to [localhost:9111](localhost:9111). The captured hasdshakes, user-defined wordlists and rules, and the SQL database will be stored in the `~/.hashcat/wpa-server` folder.

#### Building the image locally

```
mkdir -p ~/.hashcat/wpa-server
export HASHCAT_ADMIN_USER=admin
export HASHCAT_ADMIN_PASSWORD=<your-secret-password>
cd ./docker
nvidia-docker-compose -f docker-compose.yml build
nvidia-docker-compose -f docker-compose.yml up -d
```


## User wordlists

Hashcat-wpa-server app is shipped with the default Top-xxx-probable [wordlists](https://github.com/berzerk0/Probable-Wordlists). If you want to make use of your custom wordlists, place them in the `~/.hashcat/wpa-server/wordlists` folder (create one).
