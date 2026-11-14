# Security policy

## Status of this code

cGRASP is a **research prototype**. It is not intended for production use and
has not been security-reviewed. Do not deploy it on untrusted networks or use
it to protect sensitive data.

In particular:

- The experimental QUADS option is **not** a substitute for ACP, OSCORE or
  DTLS. It is disabled by default; when enabled it uses a symmetric key read
  from a local file.
- The CoAP endpoints are unauthenticated by default.
- Relay and multicast behaviour can be abused for amplification if exposed to
  untrusted networks.

## Supported versions

| Version | Supported |
|---|---|
| `main` / `master` (development) | Yes |
| tagged releases `0.x` | Best effort |

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

Use GitHub's private vulnerability reporting ("Security" tab → "Report a
vulnerability") on the project repository. If that is unavailable, contact the
maintainers listed in `AUTHORS.md` directly.

Please include:

- affected version or commit,
- a minimal reproduction (configuration, commands, packet capture if
  relevant),
- impact assessment,
- whether you plan to disclose publicly and on what timeline.

We aim to acknowledge reports within 7 days. We will coordinate disclosure
with you and credit reporters unless you prefer to remain anonymous.

## Secrets

Never commit key material. QUADS keys must be supplied at runtime through
`CGRASP_QUADS_KEY_FILE` (permissions 0600) and must never be added to the
repository.
