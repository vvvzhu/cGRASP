# cGRASP ASA examples

These are demonstration Autonomic Service Agents (ASAs) modeled on the
`ASA-examples/` directory of the upstream
[graspy](https://github.com/becarpenter/graspy) project, implemented against
the cGRASP-over-CoAP API (`cgrasp.cgrasp`).

All examples are **research demonstrations**, not production ASAs.  They do
not include the real DNS-SD, MUD or BRSKI transactions; they demonstrate the
cGRASP discovery, flood, negotiation and synchronization patterns around those
use cases.

## Included examples

| Example | Role | Graspy counterpart | Transport pattern |
|---|---|---|---|
| `cGray.py` | Negotiation requester (Gray) | `Gray.py` / `cGray.py` | unicast negotiation |
| `cBriggs.py` | Negotiation responder, sync server, flood source (Briggs) | `Briggs.py` / `cBriggs.py` | flood + unicast |
| `GetDNSSD.py` | DNS-SD responder | `GetDNSSD.py` / `cGetDNSSD.py` | unicast negotiation |
| `AskDNSSD.py` | DNS-SD requester | `AskDNSSD.py` / `cAskDNSSD.py` | unicast negotiation |
| `Mudlark.py` | MUD manager | `Mudlark.py` | unicast negotiation |
| `Mudslinger.py` | Node sending a MUD URL | `Mudslinger.py` | unicast negotiation |
| `Mudvault.py` | Local PEM trust-store helper | `Mudvault.py` | local file helper |
| `Reggie.py` | BRSKI registrar contact advertiser | `Reggie.py` | flood |
| `Procksy.py` | BRSKI join proxy advertiser | `Procksy.py` | flood |
| `Pledji.py` | BRSKI pledge listening for proxies | `Pledji.py` | flood |
| `cPfxm.py` | IPv6 edge prefix manager | `pfxm3.py` / `cPfxm.py` | advanced reference |
| `cgrasp_relay_e2e/` | Three-node relay topology with pcap validation | relay E2E | relay |

## Demonstration objective numbers

cGRASP encodes numeric objective identifiers.  The drafts use names such as
`AN_join_registrar`; these examples map them to private/demo numbers in the
41100–41199 range.

| Objective | Number | Used by |
|---|---|---|
| `EX1_FLOOD` | 70002 | Briggs flood |
| `EX2_SYNCH` | 70003 | Briggs synchronization |
| `EX3_NEGOTIATE` | 70001 | Gray/Briggs negotiation |
| `DNS-SD` | 41101 | GetDNSSD / AskDNSSD |
| `DNS-SD.SRV` | 41102 | reserved for SRV.* variants |
| `MUDURL` | 41110 | Mudlark / Mudslinger |
| `AN_join_registrar` | 41120 | Reggie / Procksy |
| `AN_proxy` | 41121 | Procksy / Pledji |

## Quick start: Gray and Briggs on one host

Terminal 1 — Briggs:

```bash
python ASA-examples/cBriggs.py \
  --listen-self --bind ::1 --coap-port 5683 --flood-interval-s 600
```

Terminal 2 — Gray, one negotiation:

```bash
python ASA-examples/cGray.py \
  --listen-self --same-host --no-sync --iterations 1 \
  --bind ::1 --coap-port 15683
```

Expected Gray output ends with:

```text
[gray] negotiation concluded by peer
[gray] attempts=1 successes=1 ...
```

## Quick start: DNS-SD

Terminal 1 — responder (static demo database, no extra dependency):

```bash
python ASA-examples/GetDNSSD.py --bind ::1 --coap-port 5683 --static
```

Terminal 2 — requester:

```bash
python ASA-examples/AskDNSSD.py --bind ::1 --coap-port 15683 \
  --peer coap://[::1]:5683 --domain _http._tcp.local
```

Without `--static`, GetDNSSD uses live PTR/SRV/TXT lookups when `dnspython` is
installed (`pip install dnspython`) and falls back to the static database
otherwise.

## Quick start: MUD

Terminal 1 — MUD manager:

```bash
python ASA-examples/Mudlark.py --bind ::1 --coap-port 5683
```

Terminal 2 — device sending a MUD URL:

```bash
python ASA-examples/Mudslinger.py --bind ::1 --coap-port 15683 \
  --peer coap://[::1]:5683 --url https://example.org/mud.json
```

`Mudlark` returns `{"status": "accepted", "url": ...}`.  With `--fetch` it also
fetches the URL and reports metadata; signature and policy verification are
intentionally out of scope.

`Mudvault.py` is a local helper (not a cGRASP ASA):

```bash
python ASA-examples/Mudvault.py --pem ca.pem --vault ./mud-certs.pem
```

## BRSKI flood flow

These examples need a real IPv6 link-local multicast-capable interface, not
just loopback.

| Terminal | Program | Action |
|---|---|---|
| 1 | `Reggie.py` | floods `AN_join_registrar` (41120) with `EST-TLS` + locator |
| 2 | `Procksy.py` | watches 41120, then floods `AN_proxy` (41121) with its locator |
| 3 | `Pledji.py` | watches 41121 and prints discovered join proxies |

Example (replace `fe80::...` with the local addresses):

```bash
python ASA-examples/Reggie.py  --bind :: --advertise coap://[fe80::1]:5683
python ASA-examples/Procksy.py --bind :: --advertise coap://[fe80::2]:5683
python ASA-examples/Pledji.py  --bind ::
```

Use `--interval` to shorten the demo loop.  Actual BRSKI enrollment is not
implemented.

A three-namespace E2E (Reggie -- Procksy -- Pledji) is included:

```bash
sudo -E PYTHON_BIN="$PWD/.venv/bin/python" bash scripts/test_brski_namespaces.sh
```

It creates two veth links and verifies that Procksy sees the registrar flood
and Pledji discovers the proxy flood.  The same test runs in CI as
`tests/test_brski_e2e_real.py` (marked `relay`).

## Prefix manager (advanced)

`cPfxm.py` is a compact cGRASP/CoAP version of the upstream `pfxm3` prefix
manager.  It runs as a standalone ASA and looks for a `PrefixManager`
objective (899201) and its companion `PrefixManager.Params` (899202).  It needs
a peer that actually offers prefixes; it is included as a reference for the
negotiation payload format and is not part of CI.

## Running from the repository root

The examples insert the repository root into `sys.path`, so they work from a
source checkout without installing the package:

```bash
python ASA-examples/cGray.py --help
python ASA-examples/AskDNSSD.py --help
```

For a packaged install, import the engine as `from cgrasp import cgrasp`;
the `cgrasp` wheel provides the package and the legacy GRASP API shims.
