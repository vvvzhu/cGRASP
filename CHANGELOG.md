# Changelog

All notable changes to this project are documented here.  This project is a
research prototype and is **not production ready**.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.4] - 2026-11-14

### Documentation

- Consolidated `documentation/` to a single
  `CGRASP_PROJECT_GUIDE.md` file.
- Updated the guide to `draft-ietf-anima-constrained-grasp-04`: M_WAIT and
  rapid-mode restrictions, Discovery restrictions, the finite relay response
  window, and the proposed IANA media/content-format names.
- No runtime or public-API changes; this is a documentation/version release.

## [0.1.3] - 2026-11-14

### Documentation

- Added `documentation/CGRASP_PROJECT_GUIDE.md`, an implementation and user
  guide covering the draft -03 mapping, architecture, flows, public API,
  examples, platform support, security and limitations.
- Added the Chinese translation
  `documentation/CGRASP_PROJECT_GUIDE.zh-CN.md` with the same structure.
- Archived pre-0.1.0 optimization, audit, E2E-matrix and WP decision records
  under `documentation/history/`, with a historical-snapshot banner.
- No runtime or public-API changes; this is a documentation/version release.

## [0.1.2] - 2026-11-14

### Changed

- Removed the old flat-layout compatibility shims (`cgrasp2.py`,
  `cgrasp_*.py`, `coap_*.py`).  Use package imports such as
  `from cgrasp import cgrasp` and `from cgrasp.cgrasp_multicast import ...`.
- Renamed the cGRASP engine module from `src/cgrasp/cgrasp2.py` to
  `src/cgrasp/cgrasp.py`.
- Kept the legacy GRASP API shims `grasp.py`, `graspi.py` and `acp.py`.

### Fixed / quality

- Added the three missing test SPDX headers.
- Documented every public definition in `src/cgrasp`.
- Replaced bare `except:` clauses with `except Exception:`.
- Package verification now checks the new layout and rejects the removed
  flat-layout shims.

## [0.1.1] - 2026-11-14

### Added

- Gray and Briggs ASA examples for cGRASP negotiation, synchronization and
  flooding.
- DNS-SD responder/requester examples (`GetDNSSD`, `AskDNSSD`).
- MUD manager/URL sender examples (`Mudlark`, `Mudslinger`) and a local PEM
  trust-store helper (`Mudvault`).
- BRSKI registrar/join-proxy/pledge flood examples (`Reggie`, `Procksy`,
  `Pledji`), a three-namespace BRSKI E2E test, and a prefix-manager reference
  example (`cPfxm`).
- See `ASA-examples/README.md` for the objective-number map and quick starts.

## [0.1.0] - 2026-11-14

Initial public snapshot of the cGRASP-focused repository.

### Added

- CoAP-based cGRASP engine and ASA-facing API (`src/cgrasp/cgrasp.py`).
- Discovery, flood and multi-link relay over CoAP multicast.
- Unicast negotiation and synchronization over CoAP.
- Namespace-based relay and multicast end-to-end harnesses, including pcap
  validation.
- Unit, loopback and integration tests, plus packaging verification.
- Relay example under `ASA-examples/cgrasp_relay_e2e/`.
- Legacy GRASP API compatibility modules (`grasp.py`, `graspi.py`, `acp.py`).

### Security

- CoAP listen address defaults to loopback (`::1`); use `CGRASP_BIND` to
  override.
- Optional peer allowlist (`CGRASP_PEER_ALLOWLIST`).
- QUADS key material is read at runtime from `CGRASP_QUADS_KEY_FILE`; no key
  is committed.
- QUADS is experimental and is not a security boundary.

### Known limitations

- IPv6 only; IPv4 multicast is not implemented.
- Production security (OSCORE/DTLS/ACP) is out of scope.
- The API is experimental and does not fully match RFC 8991.
- macOS is supported for unit/loopback tests but is not part of push CI for
  this private repository (hosted macOS runner entitlement).

[0.1.0]: https://github.com/virazhu/cGRASP/releases/tag/v0.1.0

[0.1.1]: https://github.com/virazhu/cGRASP/releases/tag/v0.1.1

[0.1.2]: https://github.com/virazhu/cGRASP/releases/tag/v0.1.2

[0.1.3]: https://github.com/virazhu/cGRASP/releases/tag/v0.1.3

[0.1.4]: https://github.com/virazhu/cGRASP/releases/tag/v0.1.4
