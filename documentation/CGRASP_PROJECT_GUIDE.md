# cGRASP Implementation and User Guide

**Status:** research prototype — not production ready
**Version:** 0.1.4
**Protocol baseline:** [`draft-ietf-anima-constrained-grasp-04`](https://datatracker.ietf.org/doc/html/draft-ietf-anima-constrained-grasp-04)
**Relationship to GRASP:** constrained GRASP variant over CoAP; derived from the
Python [`graspy`](https://github.com/becarpenter/graspy) demonstration code.

This guide describes what the implementation does, how it maps to the cGRASP
draft, how to use its public API, and where it deliberately differs from the
draft.  It is a companion to the shorter [`README.md`](../README.md); test details
live in the repository test suite and the scripts under `scripts/`.

---

## Contents

1. [Purpose and scope](#1-purpose-and-scope)
2. [Relationship to GRASP and the cGRASP draft](#2-relationship-to-grasp-and-the-cgrasp-draft)
3. [Architecture](#3-architecture)
4. [Implementation notes](#4-implementation-notes)
5. [Public API](#5-public-api)
6. [Running the prototype](#6-running-the-prototype)
7. [Security and limitations](#7-security-and-limitations)
8. [Relationship to graspy and legacy APIs](#8-relationship-to-graspy-and-legacy-apis)
9. [References](#9-references)
10. [Glossary](#10-glossary)

## 1. Purpose and scope

cGRASP is a lightweight variant of the GeneRic Autonomic Signaling Protocol
(GRASP, [RFC 8990](https://www.rfc-editor.org/info/rfc8990)).  It keeps the
GRASP message set and procedures, but:

- replaces TCP with CoAP;
- encodes the objective identifier as a number instead of a text name;
- uses CoAP multicast for link-local Discovery and Flood;
- uses CoAP request/response exchanges for unicast Negotiation and
  Synchronization;
- defines relay behaviour for extending multicast beyond one link.

The draft targets constrained nodes that can run CoAP/UDP but not a full TCP
stack.  This repository is a **Python research prototype** built on
[`aiocoap==0.4.17`](https://aiocoap.readthedocs.io/).  It is suitable for
experimentation, protocol validation and interoperability work on Linux hosts,
Linux gateways and (for unit/loopback tests) Windows.  It is **not** an MCU
implementation: CPython, asyncio and aiocoap are far too large for Class C0/C1
devices.  A production constrained-node implementation would need a C or Rust
CoAP stack.

### 1.1 Implemented functions

| Function | Status |
|---|---|
| Discovery over CoAP multicast | Implemented (IPv6 link-local, standard profile) |
| Flood synchronization over CoAP multicast | Implemented (IPv6 link-local) |
| Unicast Negotiation | Implemented (multi-round, CoAP POST) |
| Unicast Synchronization | Implemented (single-round, CoAP POST) |
| Multi-link Discovery/Flood relay | Implemented; validated with Linux network namespaces |
| Legacy GRASP API (`grasp.py`, `graspi.py`, `acp.py`) | Retained for compatibility |
| Standard CoAP multicast profile (`ff02::fd`, UDP 5683) | Implemented |
| Legacy CoAP-wrapped multicast profile (`ff02::13`, UDP 7018) | Retained for demonstrations/compatibility |
| IPv4 transport | Not implemented |
| M_WAIT | Not supported in the base profile; API returns `unspec` |
| Rapid mode | Rejected by `register_obj()`; draft -04 also excludes rapid negotiation/synchronization |
| IP-independent / BLE operation | Discussed in draft; not implemented |
| OSCORE / DTLS / ACP security | Out of scope; QUADS is experimental only |

---

## 2. Relationship to GRASP and the cGRASP draft

### 2.1 Messages retained

The implementation uses the GRASP/cGRASP message types:

| Value | Message | Purpose |
|---:|---|---|
| 1 | `M_DISCOVERY` | Link-local Discovery request |
| 2 | `M_RESPONSE` | Discovery response |
| 3 | `M_REQ_NEG` | Start Negotiation |
| 4 | `M_REQ_SYN` | Request Synchronization |
| 5 | `M_NEGOTIATE` | Negotiation step |
| 6 | `M_END` | End Negotiation |
| 8 | `M_SYNCH` | Synchronization response |
| 9 | `M_FLOOD` | Flood Synchronization |

Messages are CBOR arrays (`application/cbor`, CoAP Content-Format 60).  The
first three elements are common:

```text
[message-type, session-id, initiator-locator, ...]
```

The cGRASP objective (draft -04 §3.1) is:

```text
[objective-num, objective-flags, loop-count, ?objective-value]
```

with flags:

| Flag | Bit | Meaning |
|---|---:|---|
| `F_DISC` | 0 | valid for Discovery |
| `F_NEG` | 1 | valid for Negotiation |
| `F_SYNCH` | 2 | valid for Synchronization |
| `F_NEG_DRY` | 3 | dry-run Negotiation |

The implementation exposes these as `M_*`, `F_*`, `B_*`, `O_*` constants in
`cgrasp.cgrasp` and `cgrasp.cgrasp_multicast`.

### 2.2 CoAP mapping (draft -04 §4.1–§4.2)

| Procedure | CoAP method/type | Destination | Response |
|---|---|---|---|
| Discovery | `FETCH`, NON | `ff02::fd`, UDP 5683, `/.well-known/grasp-coap` | unicast `2.05 Content` (CON) carrying `M_RESPONSE` |
| Flood | `POST`, NON, No-Response 26 | same multicast group | none expected |
| Negotiation | `POST`, CON | peer unicast URI | `2.05 Content`, separate or piggybacked |
| Synchronization | `POST`, CON | peer unicast URI | `2.05 Content` carrying `M_SYNCH` |

The CoAP Token and Message ID are **hop-by-hop**.  The cGRASP `session-id` in
the payload is the protocol session identifier, and a CoAP Token must not be
used as a persistent cGRASP session identifier.  For relayed Discovery, the
session-id plus initiator Locator correlate the request and its responses.

The standard resource path is:

```text
/.well-known/grasp-coap
```

The legacy demonstration profile uses `/cgrasp/mc`, `ff02::13` and UDP 7018.
Both paths exist in the codebase; `enable_coap_transport()` selects the
standard profile by default.

Draft -04 adds IANA assignments for the media type `application/grasp-coap`,
the content format `application/grasp-cbor` and the resource type
`core.grasp-coap`; its §4.1 still describes the payload as `application/cbor`.
This implementation currently uses CoAP Content-Format 60
(`application/cbor`) and has not adopted the proposed names.

### 2.3 Draft-to-implementation differences

The implementation follows draft -04 in structure, but it is an independent
prototype and does not claim full conformance.  The important differences are:

| Topic | draft -04 | This implementation |
|---|---|---|
| Objective number | `0..255` (192–255 private) | `0..0xFFFFFFFF`; examples use 41100+ private numbers for legacy compatibility.  The codec accepts the wider range; this is an intentional extension, not a claim of draft conformance. |
| Successful negotiation response | `2.04 Changed` in the examples | `2.05 Content`; centralized as `CGRASP_UNICAST_SUCCESS_CODE`.  This is a compatibility decision retained pending a broader wire change. |
| M_WAIT | Base profile MUST NOT send M_WAIT | `negotiate_wait()` exists but returns `errors.unspec`; `enable_coap_transport(enable_wait=...)` is accepted and ignored. |
| Rapid mode | Base profile does not support rapid negotiation/synchronization; Discovery MUST NOT initiate them | `register_obj(rapid=True)` returns `errors.unspec`; Discovery is processed as ordinary Discovery. |
| Content format | IANA proposes `application/grasp-cbor`; §4.1 still says `application/cbor` | Uses Content-Format 60 (`application/cbor`); the proposed `application/grasp-cbor` name is not adopted. |
| IPv4 multicast | `224.0.1.187` is defined | IPv6 only; IPv4 constants/locator parsing exist but no transport path. |
| IP-independent operation | Discussed (BLE example) | Not implemented. |
| Security | Draft has a TODO in Security Considerations | No OSCORE/DTLS; QUADS is experimental and disabled by default. |
| Discovery response callback | Response is a normal CoAP response | Callback POST is deliberately disabled; responses use the FETCH exchange. |

---

## 3. Architecture

### 3.1 Component view

```text
                         ASA application
                               |
                 public API (cgrasp.cgrasp)
                               |
        +----------------------+----------------------+
        |                      |                      |
  registries/caches      relay state           transport hooks
  (CgraspEngine)        (RelayState)         (socket-like + CoAP)
        |                      |                      |
        +----------+-----------+----------+-----------+
                   |                      |
           legacy TCP/UDP          CoAP transport
           grasp.py / acp.py       cgrasp_coap_transport.py
                                   coap_client.py / coap_server.py
                                   coap_multicast_adapter.py
```

### 3.2 Module responsibilities

| Module | Responsibility |
|---|---|
| `src/cgrasp/cgrasp.py` | cGRASP engine and ASA-facing API; registries, discovery/flood/negotiation/synchronization logic; legacy compatibility globals. |
| `src/cgrasp/cgrasp_engine.py` | `CgraspEngine` boundary: registries, caches, locks, relay state, clock and responder leisure policy. |
| `src/cgrasp/cgrasp_multicast.py` | Protocol-neutral CBOR codec, Discovery/Flood helpers, `RelayConfig`, `RelayState`, rate limits, response validation. |
| `src/cgrasp/cgrasp_coap_transport.py` | Socket-like adaptation for the engine (`CoapUnicastSocket`, `CoapServerSessionSocket`), session/exchange bridge (`CgraspCoapApiBridge`). |
| `src/cgrasp/coap_client.py` | Synchronous aiocoap client helpers for unicast and multicast. |
| `src/cgrasp/coap_server.py` | aiocoap server context and resource dispatch. |
| `src/cgrasp/coap_multicast_adapter.py` | Multicast exchange, repeated-response collection, pipe/stream adaptation. |
| `src/cgrasp/cgrasp_quiescence.py` | Test-only lifecycle/quiescence assertions. |
| `src/cgrasp/grasp.py`, `src/cgrasp/acp.py` | Legacy GRASP engine/ACP compatibility modules. |
| `cgraspi.py` | cGRASP API wrapper (the `graspi`-style facade). |
| `grasp.py`, `graspi.py`, `acp.py` | Top-level shims for the legacy GRASP API; not part of cGRASP proper. |

### 3.3 Concurrency model

- The engine uses re-entrant locks around registries, discovery cache, session
  cache and flood cache.
- The CoAP bridge runs a background aiocoap event loop and marshals work
  between the engine's threads and the loop.
- `RelayState` can be bound to one owner loop/thread; cross-thread calls are
  dispatched onto that owner.  This keeps relay state single-threaded while
  allowing callbacks from aiocoap.
- `listen_negotiate()` blocks in the calling thread; run it in a dedicated
  thread when the ASA needs to do other work.
- `listen_synchronize()` starts a listener thread and returns.

### 3.4 Discovery flow (draft -04 §4.2.2)

1. The initiator builds `M_DISCOVERY` with the requested objective and
   `loop_count`.
2. It sends a non-confirmable CoAP `FETCH` to `ff02::fd:5683` at
   `/.well-known/grasp-coap`, with the cGRASP message as the payload.
3. Responders that support the objective send a unicast `2.05 Content`
   response carrying `M_RESPONSE`; the response is confirmable by default.
4. The initiator caches locators for the objective until their TTL expires.
5. A relay may forward eligible multicast Discovery to other interfaces; see
   §3.7.

The implementation deliberately does **not** use a No-Response value for
Discovery that would suppress successful responses.  The CoAP server rejects a
Discovery FETCH that carries a No-Response option.  Draft -04 also forbids
Discovery from initiating negotiation or synchronization directly; this
implementation rejects rapid-mode objective registration and treats Discovery
as ordinary Discovery only.

### 3.5 Flood flow (draft -04 §4.2.2)

1. The initiator builds `M_FLOOD` with one or more tagged objectives.
2. It sends a non-confirmable `POST` to `ff02::fd:5683` with No-Response
   value 26 (suppress 2.xx, 4.xx and 5.xx).
3. Receivers validate the CBOR, check the objective flags and loop-count, and
   store unexpired values in the flood cache.
4. `get_flood()` reads cached values; `expire_flood()` removes a value that
   the ASA has determined to be stale.

Relayed Flood messages are forwarded only after the relay checks its duplicate
cache and decrements the objective loop-count.

### 3.6 Negotiation and synchronization (draft -04 §4.2.1)

Negotiation is a multi-round CoAP exchange:

```text
Initiator                                  Responder
   |  POST CON M_REQ_NEG (value A)             |
   |------------------------------------------>|
   |  2.05 Content M_NEGOTIATE (value B)       |
   |<------------------------------------------|
   |  POST CON M_NEGOTIATE (value C)           |
   |------------------------------------------>|
   |  2.05 Content M_END (O_ACCEPT)            |
   |<------------------------------------------|
```

Synchronization is the single-round case:

```text
Initiator                                  Responder
   |  POST CON M_REQ_SYN (value empty)         |
   |------------------------------------------>|
   |  2.05 Content M_SYNCH (value V)           |
   |<------------------------------------------|
```

The implementation keeps a per-peer/per-session exchange in
`CgraspCoapApiBridge`.  Duplicate confirmable requests are answered from a
bounded idempotency cache instead of being processed twice.  A CoAP Token is
scoped to one exchange; a new request in the same cGRASP session uses a fresh
Token and Message ID.

The draft -04 base profile says a cGRASP node MUST NOT send M_WAIT and does not
support rapid negotiation/synchronization.  This implementation returns
`errors.unspec` from `negotiate_wait()` and rejects `rapid=True` at objective
registration; applications that need more time should use a suitable timeout or
start a new cGRASP session.

### 3.7 Relay (draft -04 §4.2.3)

A relay terminates an incoming CoAP exchange and originates a new exchange on
each outgoing interface.  It preserves the cGRASP `session-id` and initiator
Locator while changing the CoAP Token and Message ID.

Relay state is keyed by message type + `(session-id, initiator-Locator)`:

- `M_DISCOVERY` entries record the incoming interface, upstream endpoint,
  upstream CoAP Token and expiration time.
- `M_FLOOD` entries record the incoming interface and seen-interface state; no
  upstream response is expected.
- An `M_RESPONSE` is matched to its Discovery transaction using session-id +
  initiator + downstream Token; it is not an independent relay type.
- A Discovery transaction MAY produce multiple `M_RESPONSE` messages.  The
  initiator or relay MUST maintain a finite response window; receiving the
  first response MUST NOT terminate it.  A relay retains the entry and its
  upstream/downstream request contexts until the window expires; after expiry
  it stops forwarding responses and releases the relay state without touching
  CoAP retransmission/duplicate state.
- Loop-count is decremented before forwarding.  Zero means discard; one means
  do not forward further.
- Duplicate messages do not overwrite existing relay state.
- Rate and resource limits are enforced by `RelayConfig` and `TokenBucket`.

Relevant limits and defaults:

| `RelayConfig` field | Default |
|---|---:|
| `discovery_hard_timeout_ms` | 5000 |
| `discovery_quiet_timeout_ms` | 500 |
| `flood_seen_timeout_ms` | 10000 |
| `max_discovery_transactions` | 256 |
| `max_flood_seen_entries` | 1024 |
| `max_responses_per_transaction` | 64 |
| `max_response_digests` | 128 |
| `max_responders_per_objective_interface` | 16 |
| `relay_rate_per_second` | 20 |
| `relay_burst` | 10 |
| `responder_leisure_min_ms` | 50 |
| `responder_leisure_max_ms` | 250 |

Relay configuration can be supplied programmatically, by CLI arguments
(`add_relay_arguments()` / `relay_config_from_args()`), or by a JSON file
(`RelayConfig.from_json_file()`).

---

## 4. Implementation notes

### 4.1 Constants

| Constant | Value |
|---|---|
| `CGRASP_RESOURCE_PATH` | `/.well-known/grasp-coap` |
| `CGRASP_IPV6_MULTICAST_GROUP` | `ff02::fd` |
| `CGRASP_COAP_PORT` | 5683 |
| `CGRASP_CONTENT_FORMAT` | 60 (`application/cbor`; draft -04 IANA proposes `application/grasp-cbor`, not yet adopted) |
| `GRASP_DEF_TIMEOUT` | 60000 ms |
| `GRASP_DEF_LOOPCT` | 6 |
| `GRASP_DEF_MAX_SIZE` | 2048 bytes |
| `MAX_CGRASP_PAYLOAD` (transport) | 65536 bytes |

The codec's default maximum message size is 2048 bytes; the transport allows
up to 64 KiB for blockwise-reassembled payloads.  Larger cGRASP messages must
use CoAP Blockwise; the implementation has a blockwise test for a 16 KiB
synchronization.

### 4.2 Codec

`cgrasp.cgrasp_multicast` provides:

- `decode_message(payload, *, max_size=2048)` — strict shape/type/range checks
  for Discovery, Response and Flood messages;
- `encode_canonical(message)` — canonical CBOR encoding, validated by a
  decode round-trip;
- `decrement_loop_count(message)` — copy/decrement/validate for relay;
- `response_digest(message)` — stable 8-byte digest for duplicate-response
  detection;
- `validate_discovery_response(...)` — token, session-id, initiator and
  response-shape validation.

Invalid CBOR, wrong object shapes, an objective number outside
`0..0xFFFFFFFF`, a loop-count outside `0..255`, or a Flood with inconsistent
loop-counts raises `CodecError`.

### 4.3 Registries and caches

The engine owns:

- ASA registry;
- objective registry;
- Discovery cache;
- session-ID cache;
- Flood cache.

Limits are implementation constants (for example, 100 ASAs, 200 objectives,
500 Discovery cache entries, 100 Flood entries).  A full registry returns the
corresponding error code rather than growing without bound.

`CgraspEngine` exposes a snapshot for diagnostics:

```python
from cgrasp.cgrasp_engine import CgraspEngine

engine = CgraspEngine()
print(engine.snapshot())
```

The default engine's lists are aliased to the historical module globals so
existing functions continue to work.  Multiple independent engines in one
process are not yet a supported API.

### 4.4 Logging and diagnostics

Library code uses the `cgrasp` logger.  Applications should configure logging
themselves; `configure_logging()` is a convenience for demos and legacy CLIs:

```python
from cgrasp import cgrasp

cgrasp.configure_logging()
```

`get_coap_bridge_snapshot()` returns the live bridge state when the CoAP
transport is enabled.  `RelayState.snapshot()` and `CgraspEngine.snapshot()`
provide bounded diagnostic views without exposing mutable objects.

Diagnostic print helpers (`tprint`, `ttprint`, `dump_all`) remain for the
legacy GRASP compatibility layer and interactive debugging; new library code
should use `logging`.

---

## 5. Public API

The stable import is:

```python
from cgrasp import cgrasp as cg
```

The module exports the ASA-facing names listed in `cg.cgrasp.__all__`.
Legacy ASAs may still import `grasp`, `graspi` or `acp`; those are separate
compatibility layers, not the cGRASP API.

### 5.1 Initialization

```python
cg.skip_dialogue(testing=False, selfing=True, diagnosing=False, be_dull=True)
handle = cg.enable_coap_transport(
    True,
    bind="::1",
    port=5683,
    path="/.well-known/grasp-coap",
    autostart=True,
    strict_coap=True,
)
err, asa_handle = cg.register_asa("ExampleASA")
...
handle.stop()
```

`enable_coap_transport()` must normally be called **before** `register_asa()`.
`strict_coap=True` selects the standard multicast profile and forbids TCP and
legacy multicast fallbacks.

`skip_dialogue(be_dull=True)` is a test/experiment shortcut; it disables the
security checks that would otherwise return `errors.noSecurity`.  Do not use
DULL mode on an untrusted network.

### 5.2 Registration

| Call | Returns |
|---|---|
| `register_asa(name)` | `(errors.ok, asa_handle)` or `(errorcode, None)` |
| `deregister_asa(handle, name)` | error code |
| `register_obj(handle, obj, ttl=None, discoverable=False, overlap=False, local=False, rapid=False, locators=None)` | error code |
| `deregister_obj(handle, obj)` | error code |

`cobjective` fields:

```python
obj = cg.cobjective(41101)
obj.neg = True          # supports negotiation
obj.synch = False       # supports synchronization
obj.discoverable = True
obj.loop_count = cg.GRASP_DEF_LOOPCT
obj.value = None
```

`rapid=True` is rejected with `errors.unspec`; `overlap` is not supported by
this implementation.

### 5.3 Discovery

```python
err, locators = cg.discover(asa_handle, obj, timeout=1000)
```

- `timeout` is in milliseconds.
- Returns `(errors.ok, [asa_locator, ...])`; an empty list means no peer was
  found.
- Cached results are returned immediately; `flush=True` clears the cache
  first; `minimum_TTL` can discard stale entries.
- `locators[i]` is an `asa_locator` with `.locator`, `.protocol`, `.port`,
  `.ifi`, `.expire`, `.diverted`, `.is_ipaddress`, `.is_fqdn`, `.is_uri`.

### 5.4 Negotiation

```python
err, shandle, peer_obj = cg.req_negotiate(asa_handle, obj, peer, timeout)
```

Four outcomes are possible:

| Return | Meaning |
|---|---|
| `(errors.ok, None, objective)` | peer accepted; `objective` contains the agreed value |
| `(errors.ok, session_handle, objective)` | negotiation continues; use `session_handle` and the returned objective (it carries the loop count) in the next call |
| `(errors.declined, None, reason)` | peer declined; `reason` may be a string |
| `(errorcode, None, None)` | failure; back off before retrying |

Responder side:

```python
err, shandle, requested_obj = cg.listen_negotiate(asa_handle, obj)
err, next_obj = cg.negotiate_step(asa_handle, shandle, obj, timeout)
err = cg.end_negotiate(asa_handle, shandle, result=True)
```

`listen_negotiate()` blocks until a request arrives; run it in a thread if the
ASA has other work.  `negotiate_wait()` always returns `errors.unspec` because
M_WAIT is outside the supported profile.

### 5.5 Synchronization

```python
err, result_obj = cg.synchronize(asa_handle, obj, locator, timeout=5000)
```

- `locator` is an `asa_locator` from `discover()`; if `None`, discovery and
  the flood cache are tried.
- Returns the synchronized objective, or `(errorcode, None)`.
- Responder side: `listen_synchronize(asa_handle, obj)` starts a listener;
  repeat it when the value changes; `stop_synchronize()` stops it.

### 5.6 Flood

```python
err = cg.flood(asa_handle, ttl_ms, cg.tagged_objective(obj, source))
err, tagged = cg.get_flood(asa_handle, obj)
err = cg.expire_flood(asa_handle, tagged_obj)
```

- `ttl` is in milliseconds; `0` means no expiry.
- A Flood tagged with the unspecified address (`::`) is treated as
  link-local: the source locator is replaced by the relevant link-local
  address and the loop count is forced to 1.
- `get_flood()` returns unexpired `tagged_objective` entries;
  `expire_flood()` removes one that the ASA has judged stale.

### 5.7 Minimal ASA skeleton

```python
from __future__ import annotations

import threading
import time

from cgrasp import cgrasp as cg


def run() -> None:
    cg.skip_dialogue(selfing=True, diagnosing=False, be_dull=True)
    transport = cg.enable_coap_transport(
        True, bind="::1", port=5683, strict_coap=True)

    err, asa = cg.register_asa("ExampleASA")
    if err:
        raise SystemExit(f"register_asa failed: {err}")

    obj = cg.cobjective(41101)
    obj.discoverable = True
    obj.neg = True
    obj.loop_count = cg.GRASP_DEF_LOOPCT
    if (err := cg.register_obj(asa, obj, discoverable=True)):
        raise SystemExit(f"register_obj failed: {err}")

    def responder() -> None:
        while True:
            err, shandle, requested = cg.listen_negotiate(asa, obj)
            if err:
                break
            # Application logic goes here; use requested.value.
            cg.end_negotiate(asa, shandle, True)

    threading.Thread(target=responder, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    finally:
        cg.deregister_asa(asa, "ExampleASA")
        transport.stop()


if __name__ == "__main__":
    run()
```

This skeleton is intentionally small; the full working ASAs are in
`ASA-examples/` (`cGray.py`, `cBriggs.py`, DNS-SD, MUD and BRSKI examples).

---

## 6. Running the prototype

### 6.1 Install

```bash
python3 -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -U pip
python -m pip install -e ".[test]"
```

### 6.2 Quick loopback demo

```bash
# terminal 1: responder
python ASA-examples/cBriggs.py --listen-self --bind ::1 --coap-port 5683

# terminal 2: requester
python ASA-examples/cGray.py --listen-self --same-host --no-sync --iterations 1 \
  --bind ::1 --coap-port 15683
```

Standard CoAP multicast is selected by `enable_coap_transport()`; the legacy
`ff02::13:7018`/`/cgrasp/mc` profile is retained for older demonstrations.

Demonstration ASAs:

| Example | Role | Entry point |
|---|---|---|
| Gray / Briggs | Negotiation requester / responder, synchronization and flood | `ASA-examples/cGray.py`, `ASA-examples/cBriggs.py` |
| DNS-SD | DNS-SD responder / requester | `ASA-examples/GetDNSSD.py`, `ASA-examples/AskDNSSD.py` |
| MUD | MUD manager, URL sender and local PEM trust store | `ASA-examples/Mudlark.py`, `Mudslinger.py`, `Mudvault.py` |
| BRSKI | Registrar, join proxy and pledge listener | `ASA-examples/Reggie.py`, `Procksy.py`, `Pledji.py` |
| Prefix manager | IPv6 edge prefix manager | `ASA-examples/cPfxm.py` |
| Relay E2E | Three-node relay topology | `ASA-examples/cgrasp_relay_e2e/` |

The BRSKI namespace end-to-end test is:

```bash
sudo -E PYTHON_BIN="$PWD/.venv/bin/python"   bash scripts/test_brski_namespaces.sh
```

### 6.3 Configuration

| Variable / option | Purpose |
|---|---|
| `CGRASP_BIND` | Override the CoAP listen address |
| `CGRASP_PEER_ALLOWLIST` | Comma-separated CIDRs allowed for outbound peers |
| `CGRASP_QUADS_KEY_FILE` | JSON file with `{"key": "<hex>", "iv": "<hex>"}`; enables experimental QUADS |
| `CGRASP_QUADS_REQUIRED` | `1` refuses to start without a QUADS key |
| `--bind`, `--coap-port`, `--path` | Per-process CoAP endpoint settings |
| `--relay-interface`, `--relay-config` | Relay interfaces and JSON configuration |

Relay JSON example:

```json
{
  "enabled_interfaces": ["eth0", "eth1"],
  "discovery_hard_timeout_ms": 5000,
  "discovery_quiet_timeout_ms": 500,
  "relay_rate_per_second": 20,
  "relay_burst": 10
}
```

### 6.4 Tests

```bash
pytest -q -m "not relay"            # unit + loopback (Linux: 126 passed)
pytest -q -m relay                  # Linux root: relay + BRSKI namespace E2E
python scripts/verify_package.py    # wheel + clean-target import check
```

The relay and BRSKI tests require Linux, root, `ip`, `tcpdump` and `tshark`.
See the tests under `tests/` and the scripts under `scripts/` for the full
matrix.

### 6.5 Platform support

| Platform | Unit/loopback | Multicast/relay | Notes |
|---|---|---|---|
| Linux | Yes | Yes | Full validation, including network namespaces |
| Windows | Yes (CI) | No/unsupported | aiocoap's Windows fallback cannot bind any-address; seven E2E tests are skipped |
| macOS | Intended, not CI-verified | Not validated | No hosted macOS runner in this private repository |
| MCU/RTOS | No | No | CPython/aiocoap are not suitable for Class C0/C1 devices |

Python 3.10–3.12 is supported.  The aiocoap dependency is pinned because the
multicast adapter uses private TokenManager behaviour; see `pyproject.toml`
and `requirements.txt` for the exact version.

---

## 7. Security and limitations

### 7.1 Security (draft -04 §7)

This prototype does **not** provide production security:

- no OSCORE, DTLS or CoAPs transport;
- no relay authentication;
- no multicast source authentication;
- QUADS is experimental and not a security boundary;
- DULL mode bypasses security checks and is for test/experiment only.

The draft's Security Considerations section is explicitly a TODO; this
implementation inherits the general GRASP security caveats in RFC 8990 and
adds none of the constrained-node cryptographic protections that a production
deployment would need.

### 7.2 Limitations

- IPv6 only; IPv4 multicast (`224.0.1.187`) is not implemented.
- The objective-number range is wider than draft -04 (`0..0xFFFFFFFF`).
- Negotiation success uses `2.05 Content`, not the draft example's
  `2.04 Changed`.
- M_WAIT is unsupported (`negotiate_wait()` returns `unspec`).
- Rapid mode is rejected.
- Callback POST for Discovery responses is disabled; responses ride the FETCH
  exchange.
- The cGRASP API is experimental and does not fully match RFC 8991.
- The Python/aiocoap implementation is not an MCU/RTOS implementation.
- Windows multicast/any-address is unsupported by aiocoap's fallback.
- macOS is not CI-verified in this private repository.

---

## 8. Relationship to graspy and legacy APIs

This repository is a cGRASP-focused subset of upstream
[`graspy`](https://github.com/becarpenter/graspy).  The upstream GRASP API
modules are retained:

```python
import grasp       # legacy GRASP engine
import graspi      # legacy GRASP API
import acp         # legacy ACP
```

The cGRASP engine is separate:

```python
from cgrasp import cgrasp
```

`cgraspi.py` is the cGRASP API wrapper; it is not a flat-layout shim.  The old
top-level `cgrasp2.py`, `cgrasp_*.py` and `coap_*.py` shims were removed in
0.1.2.  See `README.md` and `CHANGELOG.md` for the migration.

The Gray/Briggs examples are adapted from graspy's demonstration ASAs; the
DNS-SD, MUD and BRSKI examples show cGRASP-specific use cases.

---

## 9. References

### Normative / protocol

- [draft-ietf-anima-constrained-grasp-04](https://datatracker.ietf.org/doc/html/draft-ietf-anima-constrained-grasp-04)
  — cGRASP protocol baseline used by this implementation.
- [RFC 8990](https://www.rfc-editor.org/info/rfc8990) — GeneRic Autonomic
  Signaling Protocol (GRASP).
- [RFC 8991](https://www.rfc-editor.org/info/rfc8991) — GRASP API.
- [RFC 7252](https://www.rfc-editor.org/info/rfc7252) — CoAP.
- [RFC 8132](https://www.rfc-editor.org/info/rfc8132) — CoAP FETCH/PATCH.
- [RFC 7967](https://www.rfc-editor.org/info/rfc7967) — CoAP No-Response.
- [RFC 8949](https://www.rfc-editor.org/info/rfc8949) — CBOR.
- [RFC 8610](https://www.rfc-editor.org/info/rfc8610) — CDDL.
- [RFC 7228](https://www.rfc-editor.org/info/rfc7228) — constrained-node
  terminology.

### Project documents

- [`README.md`](../README.md) — install, quick start and limitations.
- [`CGRASP_PROJECT_GUIDE.md`](./CGRASP_PROJECT_GUIDE.md) — this implementation
  and user guide.

---

## 10. Glossary

| Term | Meaning |
|---|---|
| **ASA** | Autonomic Service Agent; an application using GRASP/cGRASP. |
| **cGRASP** | Constrained GRASP; GRASP over CoAP with numeric objectives. |
| **DULL** | Discovery Unsolicited Link-Local; a test/experiment mode that relaxes security. |
| **GRASP** | GeneRic Autonomic Signaling Protocol (RFC 8990). |
| **M_*** | cGRASP message types (Discovery, Response, Negotiation, End, Synchronization, Flood). |
| **NZD** | Negotiation zone data; used by the Gray/Briggs demonstration. |
| **Objective** | A named/numbered autonomic parameter with flags, loop count and value. |
| **Relay** | A node that forwards Discovery/Flood between cGRASP-enabled interfaces. |
| **QUADS** | Experimental encryption helper used by the prototype; not a security boundary. |
