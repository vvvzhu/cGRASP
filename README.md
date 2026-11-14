# cGRASP

**Research prototype — not production ready.**

cGRASP (constrained GRASP, specified in
[draft-ietf-anima-constrained-grasp](https://datatracker.ietf.org/doc/draft-ietf-anima-constrained-grasp/)) is a lightweight variant of the GeneRic Autonomic
Signaling Protocol (GRASP, [RFC 8990](https://www.rfc-editor.org/info/rfc8990))
that replaces TCP with CoAP.  This repository contains:

- a cGRASP engine and experimental ASA-facing API (`src/cgrasp/cgrasp.py`),
- discovery, flood and relay over CoAP multicast (`src/cgrasp/cgrasp_multicast.py`,
  `src/cgrasp/cgrasp_coap_transport.py`, `src/cgrasp/coap_multicast_adapter.py`),
- unicast negotiation and synchronization over CoAP (`src/cgrasp/coap_client.py`,
  `src/cgrasp/coap_server.py`),
- interoperability tests, namespace-based end-to-end tests and a relay
  demonstration.

This repository is a **cGRASP-focused subset** of the upstream
[graspy](https://github.com/becarpenter/graspy) project.  Upstream ASAs and
examples that are unrelated to cGRASP are not included.  The legacy GRASP API
(`grasp.py`, `graspi.py`, `acp.py`) is retained so existing import paths keep
working.

This code is an independent prototype; it is **not** an IETF reference
implementation and it does not claim conformance to every requirement of the
draft.

## Status and scope

| Area | Status |
|---|---|
| Discovery over CoAP multicast | Implemented (IPv6 link-local) |
| Flood synchronization over CoAP multicast | Implemented (IPv6 link-local) |
| Multi-link relay | Implemented; exercised by Linux namespace tests |
| Unicast negotiation / synchronization | Implemented |
| IPv4 multicast | Not implemented |
| QUADS encryption | Experimental, disabled by default |
| Production security (OSCORE/DTLS/ACP) | Out of scope |

This code is suitable for experimentation, protocol validation and research.
Do not deploy it on untrusted networks.


## Requirements

- Python 3.10 or newer.
- Linux is required for privileged namespace and relay tests (`ip`, `tcpdump`, `tshark`, and root privileges).
- Windows is supported for unit and loopback tests.
- macOS compatibility has not been verified and is not currently included in the supported test matrix.

CI runs unit and loopback tests on Ubuntu and Windows. Linux-specific namespace and relay functionality is validated on Linux environments. macOS is not currently covered by CI or maintainer testing.


## Install

```bash
git clone <your-fork-url> cGRASP
cd cGRASP
python3 -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -U pip
python -m pip install -e ".[test]"
```

For the Windows unit tests no additional system packages are required.
For the Linux namespace tests install `iproute2`, `tcpdump` and `tshark`.

## Quick start

Run the test suite:

```bash
pytest -q
```

On Windows seven end-to-end tests are skipped because aiocoap's fallback
transport cannot bind the any-address; run them on Linux.

Run a responder and an initiator in two terminals:

```bash
# terminal 1
python demo_coap_responder.py --asa ResponderASA --objnum 40001

# terminal 2
python demo_coap_initiator.py --asa InitiatorASA --objnum 40001
```

The demos use the legacy CoAP-wrapped link-local multicast mode
(`ff02::13:7018`, CoAP resource `/cgrasp/mc`) and loopback unicast.  The
standard mode (`ff02::fd:5683`, `/.well-known/grasp-coap`) is available through
`cgrasp.cgrasp.set_standard_coap_multicast(True)`.

## Tests

```bash
pytest -q                        # unit + loopback
pytest -q -m "not relay"         # explicit: skip privileged relay tests
pytest -q -m network             # loopback/IPv6 only
pytest -q -m relay               # Linux root: relay + BRSKI namespace E2E
pytest -q --cov --cov-report=term  # coverage baseline (see pyproject.toml)
python scripts/verify_package.py   # build wheel + clean-target import check
```

Privileged multi-link tests (Linux, root, network namespaces):

```bash
sudo -E PYTHON_BIN="$PWD/.venv/bin/python" \
    scripts/test_relay_multi_namespaces.sh relay

sudo -E PYTHON_BIN="$PWD/.venv/bin/python" \
    scripts/test_multicast_namespaces.sh loop
```

Captures and generated reports are written below `captures/` and are ignored by
git.  Never commit packet captures or generated evidence.

## Repository layout

```
src/cgrasp/                installable package
  cgrasp.py                cGRASP engine and ASA-facing API
  cgrasp_engine.py         engine boundary (registries, relay state, clock)
  cgrasp_multicast.py      codec, relay state, interface helpers
  cgrasp_coap_transport.py unicast-over-CoAP bridge and API shim
  coap_client.py           aiocoap client helpers (unicast + multicast)
  coap_server.py           aiocoap server helpers
  coap_multicast_adapter.py aiocoap multicast response adapter
  cgrasp_quiescence.py     lifecycle assertions for tests
  acp.py, grasp.py         legacy GRASP API compatibility modules
cgraspi.py                  cGRASP API wrapper
grasp.py, graspi.py, acp.py  top-level shims for the legacy GRASP API
tests/                     unit, loopback and interop tests
scripts/                   namespace, pcap and rendering tools
ASA-examples/              demonstration ASAs (Gray, Briggs, Pfxm, relay)
documentation/             implementation and user guide
```

## Legacy GRASP API

The upstream-compatible modules `grasp.py`, `graspi.py` and `acp.py` are kept
for compatibility with existing GRASP ASAs.  The cGRASP engine itself is
`src/cgrasp/cgrasp.py`; import it as `from cgrasp import cgrasp`.  Upstream
ASAs and demonstration tools are not part of this repository.

The old flat-layout cGRASP shims were removed in `0.1.2`.  Use
`from cgrasp import cgrasp` and `from cgrasp.cgrasp_multicast import ...`;
`import cgrasp2` and `import coap_client` are no longer provided.

## Configuration

| Variable | Purpose |
|---|---|
| `CGRASP_QUADS_KEY_FILE` | Path to a JSON file with `{"key": "<hex>", "iv": "<hex>"}` enabling QUADS |
| `CGRASP_QUADS_REQUIRED` | Set to `1` to refuse to start without a QUADS key |
| `CGRASP_BIND` | Override the CoAP listen address (default `::1`; set `::` for a Linux relay) |
| `CGRASP_PEER_ALLOWLIST` | Optional comma-separated CIDRs; when set, outbound peer IPs must match |
| `PYTHON_BIN` | Interpreter used by the shell test harnesses |

QUADS is **experimental** and is not a security boundary.  Without a key file
the engine runs in plaintext and logs a warning.

Ports and addresses:

- standard CoAP multicast: `ff02::fd`, UDP 5683, `/.well-known/grasp-coap`
- legacy GRASP multicast: `ff02::13`, UDP 7018
- unicast CoAP: configurable via `--coap-port` / `--bind`

## Examples

See [ASA-examples/README.md](./ASA-examples/README.md) for:

- **Gray** (`cGray.py`) — negotiation requester;
- **Briggs** (`cBriggs.py`) — negotiation responder, synchronization server and
  flood source;
- **DNS-SD** (`GetDNSSD.py`, `AskDNSSD.py`) — DNS-SD responder and requester;
- **MUD** (`Mudlark.py`, `Mudslinger.py`, `Mudvault.py`) — MUD manager, URL
  sender and local PEM trust-store helper;
- **BRSKI** (`Reggie.py`, `Procksy.py`, `Pledji.py`) — registrar flood,
  join-proxy flood and pledge listener; namespace E2E:
  `sudo -E PYTHON_BIN="$PWD/.venv/bin/python" bash scripts/test_brski_namespaces.sh`;
- **cPfxm** (`cPfxm.py`) — IPv6 edge prefix manager reference;
- **relay E2E** (`ASA-examples/cgrasp_relay_e2e/`) — three-node relay topology.

Quick loopback demo:

```bash
# terminal 1
python ASA-examples/cBriggs.py --listen-self --bind ::1 --coap-port 5683

# terminal 2
python ASA-examples/cGray.py --listen-self --same-host --no-sync --iterations 1 \
  --bind ::1 --coap-port 15683
```

## Documentation

- [documentation/CGRASP_PROJECT_GUIDE.md](./documentation/CGRASP_PROJECT_GUIDE.md) — implementation and user guide

Internal process records are intentionally not part of this public repository.

## Limitations

- IPv6 only; IPv4 multicast (224.0.1.187) is not implemented.
- The base profile does not use M_WAIT; `negotiate_wait()` returns `unspec`.
- Rapid mode and IP-independent operation are not part of this prototype.
- Multicast security and relay authentication are not implemented.
- The API is experimental and does not fully match RFC 8991.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md).  Security issues: see
[SECURITY.md](./SECURITY.md).

## License

BSD 3-Clause.  See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

This repository is derived from
[graspy](https://github.com/becarpenter/graspy) by Brian E Carpenter; upstream
copyright notices are retained in the originating source files.
