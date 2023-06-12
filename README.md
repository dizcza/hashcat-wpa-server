[![](https://img.shields.io/docker/image-size/dizcza/hashcat-wpa-server/latest?label=latest)](https://hub.docker.com/r/dizcza/hashcat-wpa-server/tags)
[![](https://img.shields.io/docker/image-size/dizcza/hashcat-wpa-server/cuda?label=cuda)](https://hub.docker.com/r/dizcza/hashcat-wpa-server/tags)
[![](https://img.shields.io/docker/image-size/dizcza/hashcat-wpa-server/intel-cpu?label=intel-cpu)](https://hub.docker.com/r/dizcza/hashcat-wpa-server/tags)
[![](https://img.shields.io/docker/image-size/dizcza/hashcat-wpa-server/pocl?label=pocl)](https://hub.docker.com/r/dizcza/hashcat-wpa-server/tags)

[Dockerhub](https://hub.docker.com/r/dizcza/hashcat-wpa-server)

# Hashcat WPA/WPA2 server

Yet another WPA/WPA2 hashes cracker web server. Powered by HashCat. The backend is written in Python Flask.

Supported capture file formats:
* .pcapng (hcxdumptool)
* .cap and .pcap (airodump)
* .hccapx and .2500 (EAPOL)
* .pmkid and .16800 (PMKID)
* .22000 (PMKID/EAPOL)

The server utilizes [Hashcat Brain](https://hashcat.net/forum/thread-7903.html) transparently for the user (the user is allowed to activate and deactivate the feature). HashBrain allows skipping already tried password candidates - useful in combination with hashcat rules or when you restore the progress you ran the other day.

Every password cracking researcher is proud of his/her wordlists and rules. Here is my strategy of checking the most
probable passwords that require only a few minutes to run on any laptop or Raspberry Pi. The strategy is marked as
`'(fast)'` among wordlist choices in UI. They are all run in the [`BaseAttack.run_all()`](
https://github.com/dizcza/hashcat-wpa-server/blob/c9285676668c1c64fd5a62282366d3cb92dff969/app/attack/base_attack.py#L220)
method:

* `run_essid_attack`: 
  - Hamming ball ESSID attack (perturb ESSID name with at most Hamming distance '2');
  - Split ESSID in word compounds. For example "PetitCafe2017" ESSID is split in `['2017', '2017Cafe', '2017CafePetit', '2017Petit', 'Cafe', ..., 'CafePetit2017']` which increases the chance of finding passwords of type "PetitXXXX" by running the combinator attack for each of the word compounds combination. Technically, for each `essid_i` word compound, it runs
      - essid_i + digits_append.txt (prepend and append) combinator attack (`-a1`);
      - essid_i + best64.rule attack;
* `run_top1k`: Top1575-probable-v2.txt + best64.rule attack.
* `run_digits8`: birthdays 100 years backward, digits masks like aabbccdd (refer to [mask\_8-12.txt](app/word_magic/digits/mask_8-12.txt)), digits cycles, and more.
* `run_keyboard_walk`: [keyboard-walk](https://github.com/hashcat/kwprocessor) attack.
* `run_names`: names\_ua-ru.txt with best64 attack.

## Demo

Check out a running server on a CPU instance: http://85.217.171.57:9111. To surf the site, login with the `guest:guest` credentials. (Yes, you don't have the permissions to start jobs. Contact me if necessary.)


## Command line interface

You can quickly test a handshake file against non-secure passwords, in other words, run the `(fast)` mode from a terminal:

```bash
python app/attack/base_attack.py /path/to/handshake.22000
```

```
optional arguments:
  --fast      Run ESSID+digits attack with fewer examples. Default: turned off
  --extra     Run extra attacks (names UA)
```

** Note **
This will take ~1 minute to run for the first time to download necessary files.


## Deployment

### Directly on your host machine

Run the following commands from the root `hashcat-wpa-server` folder:

```
pip install -r requirements.txt  # required only once

HASHCAT_ADMIN_USER=admin HASHCAT_ADMIN_PASSWORD=<your-secret-password> gunicorn app:app
```

### Docker containers


#### Using Docker Hub

There are 4 docker tags (platforms):

* `latest` and `cuda`: Nvidia GPUs (`cuda` tag preferred);
* `intel-cpu`: Intel CPUs;
* `pocl`: an alternative to `intel-cpu` tag, an open source implementation of OpenCL.

For example, to run the `latest` tag (makes sense only if you have at least one GPU), open a terminal and run

```
docker run --gpus all -d \
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

That's all! Navigate to [localhost:9111](localhost:9111). The captured handshakes, user-defined wordlists and rules, and the SQL database will be stored in the `~/.hashcat/wpa-server` folder.

#### Building the image locally

```
git clone https://github.com/dizcza/hashcat-wpa-server.git
cd hashcat-wpa-server/docker

# Set environment variables and create the home directory
mkdir -p ~/.hashcat/wpa-server
export HASHCAT_ADMIN_USER=admin
export HASHCAT_ADMIN_PASSWORD=<your-secret-password>

# Build & run
docker compose build
docker compose up
```

If you want to build an image targeting a specific platform, pass it as the `branch` arg to the build command:

```
docker compose build --build-arg branch=cuda
```

Available targets & platforms are shown in the readme header.


## User wordlists

Hashcat-wpa-server app is shipped with the default Top-xxx-probable [wordlists](https://github.com/berzerk0/Probable-Wordlists). If you want to make use of your custom wordlists, place them in the `~/.hashcat/wpa-server/wordlists` folder (create one).


## Troubleshooting

* If you get an error like "sql cannot write a database to readonly file", fix file permissions with the following command: `sudo chown -R $USER:$USER ~/.hashcat/wpa-server/`
