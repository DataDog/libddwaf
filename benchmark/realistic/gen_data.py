# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""Generate synthetic ASM_DATA-style configs (libddwaf "rules_data") for benchmarks.

The ASM_DD ruleset references two data ids:
  * blocked_ips   (rule blk-001-001, operator ip_match,    type ip_with_expiration)
  * blocked_users (rule blk-001-002, operator exact_match, type data_with_expiration)

The format mirrors what the RC backend sends in ASM_DATA, e.g.
  {"rules_data":[{"id":"blocked_ips","type":"ip_with_expiration",
                  "data":[{"value":"1.2.3.4"},{"value":"5.6.7.8","expiration":1792060800}]}]}
Each document can be passed as-is to ddwaf_builder_add_or_update_config.

Output is deterministic (fixed seed). Some well-known sentinel values are always
present so benchmarks can deliberately hit the blocking rules:
  IPs:   198.51.100.77 (exact v4), 203.0.113.0/24 (v4 CIDR),
         2001:db8:dead:beef::1 (exact v6), 2001:db8:cafe::/48 (v6 CIDR)
  users: blocked-user-sentinel, 31337
Expiration timestamps are fixed far in the future (or in the past for the small
expired fraction) so benchmark behaviour does not change over time.

Usage: uv run gen_data.py [output_dir]   (default: ./rulesets/data next to this script)
"""

import ipaddress
import json
import random
import sys
import uuid
from pathlib import Path

FUTURE_EXP = 4102444800  # 2100-01-01T00:00:00Z
PAST_EXP = 1600000000  # 2020-09-13, already expired

IP_SIZES = [10, 1000, 10000, 100000]
USER_SIZES = [10, 1000, 10000]

IP_SENTINELS = [
    {"value": "198.51.100.77"},
    {"value": "203.0.113.0/24", "expiration": FUTURE_EXP},
    {"value": "2001:db8:dead:beef::1"},
    {"value": "2001:db8:cafe::/48", "expiration": FUTURE_EXP},
]
USER_SENTINELS = [
    {"value": "blocked-user-sentinel"},
    {"value": "31337", "expiration": FUTURE_EXP},
]

RESERVED_V4 = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "198.51.100.0/24",
        "203.0.113.0/24", "224.0.0.0/3",
    )
]


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "rulesets" / "data"
    out.mkdir(parents=True, exist_ok=True)
    for n in IP_SIZES:
        write(out / f"blocked_ips_{n}.json", rules_data("blocked_ips", "ip_with_expiration", gen_ips(n)))
    for n in USER_SIZES:
        write(out / f"blocked_users_{n}.json", rules_data("blocked_users", "data_with_expiration", gen_users(n)))


def rules_data(data_id: str, data_type: str, entries: list[dict]) -> dict:
    return {"rules_data": [{"id": data_id, "type": data_type, "data": entries}]}


def write(path: Path, doc: dict) -> None:
    path.write_text(json.dumps(doc, separators=(",", ":")) + "\n")
    print(f"{path}: {len(doc['rules_data'][0]['data'])} entries, {path.stat().st_size} bytes")


def expiration(rng: random.Random) -> dict:
    # Real ASM_DATA: most entries are time-limited blocks, some permanent,
    # a few stale (expired but not yet removed by the backend).
    r = rng.random()
    if r < 0.55:
        return {"expiration": FUTURE_EXP - rng.randrange(0, 86400 * 365)}
    if r < 0.95:
        return {}
    return {"expiration": PAST_EXP + rng.randrange(0, 86400 * 365)}


def gen_ips(n: int) -> list[dict]:
    rng = random.Random(0xB10C + n)
    seen = {e["value"] for e in IP_SENTINELS}
    entries = list(IP_SENTINELS)
    while len(entries) < n:
        r = rng.random()
        if r < 0.70:
            value = str(rand_v4(rng))
        elif r < 0.85:
            value = str(rand_v6(rng))
        elif r < 0.95:
            prefix = rng.choice([16, 20, 22, 24, 24, 24, 28, 30, 32])
            value = str(ipaddress.ip_network(f"{rand_v4(rng)}/{prefix}", strict=False))
        else:
            prefix = rng.choice([32, 48, 48, 56, 64, 64, 96, 128])
            value = str(ipaddress.ip_network(f"{rand_v6(rng)}/{prefix}", strict=False))
        if value in seen:
            continue
        seen.add(value)
        entries.append({"value": value, **expiration(rng)})
    rng.shuffle(entries)
    return entries[:n]


def rand_v4(rng: random.Random) -> ipaddress.IPv4Address:
    while True:
        a = ipaddress.IPv4Address(rng.getrandbits(32))
        if not any(a in net for net in RESERVED_V4):
            return a


def rand_v6(rng: random.Random) -> ipaddress.IPv6Address:
    # Global unicast 2000::/3, avoiding the 2001:db8::/32 documentation range.
    while True:
        a = ipaddress.IPv6Address((0b001 << 125) | rng.getrandbits(125))
        if a not in ipaddress.ip_network("2001:db8::/32"):
            return a


FIRST = ["john", "maria", "wei", "ahmed", "olga", "lucas", "aisha", "kenji", "sofia", "raj"]
LAST = ["smith", "garcia", "li", "khan", "ivanova", "silva", "okafor", "tanaka", "rossi", "patel"]
DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "example.org", "corp.example.com"]


def gen_users(n: int) -> list[dict]:
    rng = random.Random(0x05E5 + n)
    seen = {e["value"] for e in USER_SENTINELS}
    entries = list(USER_SENTINELS)
    while len(entries) < n:
        r = rng.random()
        if r < 0.45:
            value = str(rng.randrange(1, 10**9))  # numeric DB ids
        elif r < 0.75:
            value = str(uuid.UUID(int=rng.getrandbits(128), version=4))
        elif r < 0.95:
            value = f"{rng.choice(FIRST)}.{rng.choice(LAST)}{rng.randrange(1000)}@{rng.choice(DOMAINS)}"
        else:
            value = f"usr_{rng.getrandbits(64):016x}"
        if value in seen:
            continue
        seen.add(value)
        entries.append({"value": value, **expiration(rng)})
    rng.shuffle(entries)
    return entries[:n]


if __name__ == "__main__":
    main()
