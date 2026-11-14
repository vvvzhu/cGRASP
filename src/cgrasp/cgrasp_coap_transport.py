# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""CoAP transport bridge for cGRASP.

This module maps cGRASP session sockets and exchanges onto aiocoap
unicast and multicast operations.  It is the boundary that isolates
aiocoap-specific details from the protocol engine.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import os
import queue
import socket
import threading
import time
import urllib.parse
from collections import deque
from dataclasses import dataclass
from enum import Enum
from typing import Awaitable, Callable, Dict, Optional, Tuple

import cbor2 as cbor

from .coap_client import CoapClient
from .coap_client import coap_pool_close_key
from .coap_client import coap_post_pooled_sync
from .coap_server import default_bind, make_default_cgrasp_server

DEFAULT_CGRASP_RESOURCE_PATH = ".well-known/grasp-coap"

# Bound inbound cGRASP payloads before CBOR decoding.  GRASP's default maximum
# message size is 2048 bytes; blockwise CoAP can legitimately reassemble larger
# payloads (the test suite exercises a 16 KiB synchronization), so allow up to
# 64 KiB while still rejecting oversized datagrams early.
MAX_CGRASP_PAYLOAD = 65536

# NOTE: This module is imported by cgrasp.cgrasp during startup (to install
# the unicast-over-CoAP shim and to start an in-process CoAP endpoint).
# Importing cgrasp.cgrasp here at module import time would create a circular
# import.
#
# Instead, resolve the active GRASP implementation lazily at runtime.
_cg = None


def _resolve_cg():
    """Return the active cGRASP module (prefer cgrasp.cgrasp).

    This avoids circular import issues while allowing this transport shim to be
    used by both the legacy ``cgrasp.grasp`` engine and the cGRASP engine.
    """

    global _cg
    if _cg is not None:
        return _cg

    import importlib
    import sys

    # Prefer already-loaded modules (common when called from inside cgrasp.cgrasp).
    for name in ("cgrasp.cgrasp", "cgrasp.grasp", "grasp"):
        mod = sys.modules.get(name)
        if mod is not None:
            _cg = mod
            return _cg

    # Fall back to importing.
    for name in ("cgrasp.cgrasp", "cgrasp.grasp", "grasp"):
        try:
            _cg = importlib.import_module(name)
            return _cg
        except Exception:
            continue

    _cg = None
    return None


# ---- GRASP/cGRASP message type constants (match cgrasp.py) ----
M_NOOP = 0
M_REQ_NEG = 3
M_REQ_SYN = 4
M_NEGOTIATE = 5
M_END = 6
M_WAIT = 7
M_SYNCH = 8
M_INVALID = 99

O_ACCEPT = 101
O_DECLINE = 102


class CoapFailureCause(str, Enum):
    """Failure categories exposed by the CoAP transport bridge."""
    TRANSPORT_TIMEOUT = "transport_timeout"
    TRANSPORT_ERROR = "transport_error"
    CANCELLED = "cancelled"


class CoapTransportError(OSError):
    """Transport error carrying a CoapFailureCause and optional detail."""
    def __init__(self, cause: CoapFailureCause, detail: str):
        super().__init__(detail)
        self.cause = cause


class CoapUnicastSocket:
    """A minimal socket-like shim that maps cgrasp unicast I/O to CoAP.

    This object is designed to satisfy the interface expected by cgrasp's
    existing negotiation/synchronization state machines:
      - settimeout(seconds)
      - sendall(data, flags=0)
      - recvfrom(bufsize)
      - close()

    Semantics:
    - sendall(): performs a CoAP POST carrying the provided bytes and stores
      the response payload for the next recvfrom().
    - recvfrom(): returns the stored response payload.

    Notes:
    - This uses coap_client.coap_post_sync(), so it must run outside an
      already-running asyncio event loop. In async code, call cgrasp APIs via
      asyncio.to_thread().
    """

    # A CoAP response is one complete GRASP wire message.  The TCP-era
    # ``_recvraw`` helper must not apply its legacy "read another chunk" probe
    # merely because that message happens to be larger than an IPv6 MTU.
    message_oriented = True

    def __init__(self, peer_base_uri: str, *, sid: int, path: str = DEFAULT_CGRASP_RESOURCE_PATH):
        self._peer_base_uri = peer_base_uri.rstrip("/")
        self._path = path.strip("/")
        self._sid = int(sid)
        # Pool key ensures per-session *and* per-direction reuse:
        # - same sid + same peer_base_uri => reuse one ClientContext
        # - different peer (or other direction) => different key
        self._pool_key = ("cgrasp", int(self._sid), str(self._peer_base_uri), str(self._path))

        self._timeout_s: Optional[float] = None
        self._closed = False
        self._last_failure: Optional[CoapFailureCause] = None

        self._pending: "list[bytes]" = []

    def settimeout(self, seconds: float) -> None:
        """Set the socket timeout in seconds (socket-compatible API)."""
        self._timeout_s = float(seconds)

    def gettimeout(self) -> Optional[float]:
        """Return the current socket timeout in seconds."""
        return self._timeout_s

    @property
    def last_failure(self) -> Optional[CoapFailureCause]:
        """Return the most recent CoapFailureCause for this socket."""
        return self._last_failure

    def connect(self, _addr) -> None:
        # No-op: CoAP is connectionless from this caller's perspective.
        """Record the peer address; this bridge is datagram-based."""
        return

    def close(self) -> None:
        """Close the socket and drop queued state."""
        self._closed = True
        self._pending.clear()
        try:
            coap_pool_close_key(self._pool_key)
        except Exception:
            pass

    def sendall(self, data: bytes, _flags: int = 0) -> None:
        """Send one CoAP datagram through the bridge."""
        if self._closed:
            raise OSError("Socket is closed")

        uri = f"{self._peer_base_uri}/{self._path}"
        try:
            cg = _resolve_cg()
            if cg is not None and hasattr(cg, "_audit_transport"):
                cg._audit_transport("coap_unicast_requests")
            # cGRASP payload bytes are CBOR (optionally QUADS-encrypted), so
            # advertise application/cbor to help analyzers (e.g. tshark) decode.
            resp = coap_post_pooled_sync(
                self._pool_key,
                uri,
                data,
                timeout=self._timeout_s,
                content_format=60,
                block2_size_exp=6,
            )
        except Exception as ex:
            cause = CoapFailureCause.TRANSPORT_TIMEOUT \
                if isinstance(ex, (TimeoutError, socket.timeout)) \
                else CoapFailureCause.TRANSPORT_ERROR
            self._last_failure = cause
            raise CoapTransportError(cause, str(ex))

        self._pending.append(resp)

    def recvfrom(self, _bufsize: int):
        """Receive one inbound datagram, or raise on timeout/close."""
        if self._closed:
            return b"", ("::", 0, 0, 0)

        if self._pending:
            out = self._pending.pop(0)
            return out, ("::", 0, 0, 0)

        # No pending data; behave like peer closed.
        return b"", ("::", 0, 0, 0)


def _is_wait_message(raw: bytes) -> bool:
    cg = _resolve_cg()
    try:
        plain = cg._decrypt_msg(raw) if (cg is not None and hasattr(cg, "_decrypt_msg")) else raw  # type: ignore[attr-defined]
        payload = cbor.loads(plain)
        return bool(isinstance(payload, list) and payload and int(payload[0]) == M_WAIT)
    except Exception:
        return False


def _peek_mtype(raw: bytes) -> Optional[int]:
    """Best-effort extract of GRASP/cGRASP message type from on-the-wire bytes."""
    cg = _resolve_cg()
    try:
        plain = cg._decrypt_msg(raw) if (cg is not None and hasattr(cg, "_decrypt_msg")) else raw  # type: ignore[attr-defined]
        payload = cbor.loads(plain)
        if isinstance(payload, list) and payload:
            return int(payload[0])
    except Exception:
        return None
    return None


class BridgeExchangeCapacityError(RuntimeError):
    """The bounded per-session CoAP exchange registry is full."""


class BridgeExchangeConflictError(RuntimeError):
    """The same CoAP token/direction is already active for this session."""


class CoapServerExchange:
    """One inbound CoAP request and its independently routed ASA response."""

    def __init__(self, *, sid: int, peer_addr: ipaddress.IPv6Address,
                 token: bytes, direction: str, on_close: Callable):
        self.sid = int(sid)
        self.peer_addr = peer_addr
        self.token = bytes(token)
        self.direction = str(direction)
        self._on_close = on_close
        self._response_q: "queue.Queue[Optional[bytes]]" = queue.Queue(maxsize=1)
        self._closed = False
        self._response_routed = False
        self._has_response = False
        self._close_notified = False
        self._lock = threading.Lock()
        # An event-loop-native wait path avoids blocking asyncio's default
        # thread pool for every inbound POST.
        self._async_loop: Optional[asyncio.AbstractEventLoop] = None
        self._async_event: Optional[asyncio.Event] = None

    @property
    def closed(self) -> bool:
        """Return True once this exchange has been closed."""
        with self._lock:
            return self._closed

    @property
    def response_routed(self) -> bool:
        """Return True if a response was already routed for this exchange."""
        with self._lock:
            return self._response_routed

    def route_response(self, data: bytes) -> bool:
        """Route an inbound response to the matching exchange."""
        with self._lock:
            if self._closed or self._response_routed:
                return False
            self._response_q.put_nowait(bytes(data))
            self._response_routed = True
            self._has_response = True
            loop = self._async_loop
            event = self._async_event
        if loop is not None and event is not None and not loop.is_closed():
            try:
                loop.call_soon_threadsafe(event.set)
            except RuntimeError:
                pass
        return True

    def _finalize_response(self, response: Optional[bytes]) -> Optional[bytes]:
        notify = False
        with self._lock:
            self._has_response = False
            if self._closed and not self._close_notified:
                self._close_notified = True
                notify = True
        if notify:
            self._on_close(self)
        return response

    def pop_response(self, *, timeout_s: Optional[float]) -> Optional[bytes]:
        """Pop the next routed response for this exchange."""
        try:
            if timeout_s is None:
                response = self._response_q.get()
            elif self.closed:
                response = self._response_q.get_nowait()
            else:
                response = self._response_q.get(timeout=timeout_s)
        except queue.Empty:
            return None
        return self._finalize_response(response)

    async def pop_response_async(self, *, timeout_s: Optional[float]) -> Optional[bytes]:
        """Event-loop-native variant of :meth:`pop_response`.

        The response is produced by an ASA thread and pushed into the bounded
        queue; this method waits on an asyncio.Event that is signalled via
        ``call_soon_threadsafe`` instead of occupying a thread-pool worker.
        """
        loop = asyncio.get_running_loop()
        if self._async_loop is not loop:
            self._async_loop = loop
            self._async_event = asyncio.Event()
        event = self._async_event
        assert event is not None
        deadline = None if timeout_s is None else loop.time() + float(timeout_s)

        while True:
            try:
                return self._finalize_response(self._response_q.get_nowait())
            except queue.Empty:
                pass
            if self.closed:
                return None

            # Clear then re-check to avoid losing a wakeup between the empty
            # check and the event wait.
            event.clear()
            try:
                return self._finalize_response(self._response_q.get_nowait())
            except queue.Empty:
                pass

            if deadline is None:
                await event.wait()
                continue
            remaining = deadline - loop.time()
            if remaining <= 0:
                return None
            try:
                await asyncio.wait_for(event.wait(), timeout=remaining)
            except asyncio.TimeoutError:
                return None

    def close(self) -> None:
        """Close the exchange and release queued responses."""
        notify = False
        with self._lock:
            if not self._closed:
                self._closed = True
                notify = True
                if not self._has_response:
                    try:
                        self._response_q.put_nowait(None)
                    except queue.Full:
                        pass
                    self._close_notified = True
                else:
                    notify = False
        if notify:
            self._on_close(self)

    def snapshot(self) -> dict:
        """Return a diagnostic snapshot of exchange state."""
        with self._lock:
            return {
                "sid": self.sid,
                "peer": str(self.peer_addr),
                "token": self.token.hex(),
                "direction": self.direction,
                "closed": self._closed,
                "response_routed": self._response_routed,
                "pending_responses": int(self._has_response),
            }


class CoapServerSessionSocket:
    """A socket-like object used by the *server side* cgrasp state machines.

    cgrasp.listen_negotiate() expects to receive a connected TCP socket in the
    objective listen queue. cgrasp.negotiate_step()/end_negotiate() then use
    that socket for sendall()/recvfrom().

    This shim lets a CoAP server handler feed inbound GRASP bytes into recvfrom(),
    and lets cgrasp sendall() produce outbound GRASP bytes that the CoAP handler
    can return as the CoAP response.
    """

    def __init__(self, *, sid: int, peer_addr: ipaddress.IPv6Address,
                 peer_port: int = 0,
                 on_close: Optional[Callable[["CoapServerSessionSocket"], None]] = None,
                 on_exchange_change: Optional[
                     Callable[["CoapServerSessionSocket"], None]] = None,
                 max_pending_exchanges: int = 8):
        self._sid = int(sid)
        self._peer_addr = peer_addr
        self._peer_port = int(peer_port or 0)
        self._timeout_s: Optional[float] = None
        self._closed = False
        self._on_close = on_close
        self._on_exchange_change = on_exchange_change
        self._in_q: "queue.Queue[bytes]" = queue.Queue()
        self._out_q: "queue.Queue[bytes]" = queue.Queue()
        self._max_pending_exchanges = max(1, int(max_pending_exchanges))
        self._exchanges: Dict[Tuple[bytes, str], CoapServerExchange] = {}
        self._exchange_order = deque()
        self._exchange_lock = threading.Lock()

    @property
    def sid(self) -> int:
        """Return the cGRASP session id."""
        return self._sid

    @property
    def peer_addr(self) -> ipaddress.IPv6Address:
        """Return the peer IPv6 address."""
        return self._peer_addr

    @property
    def closed(self) -> bool:
        """Return True when the session socket is closed."""
        return self._closed

    @property
    def can_prune(self) -> bool:
        """Return True when the session has no live exchanges or queued data."""
        with self._exchange_lock:
            return self._closed and not self._exchanges

    def settimeout(self, seconds: float) -> None:
        """Set the logical socket timeout in seconds."""
        self._timeout_s = float(seconds)

    def gettimeout(self) -> Optional[float]:
        """Return the logical socket timeout in seconds."""
        return self._timeout_s

    def connect(self, _addr) -> None:
        # No-op; used only to satisfy socket-like expectations.
        """Record the peer address for this logical session socket."""
        return

    def close(self) -> None:
        """Close the session socket and its exchanges."""
        if self._closed:
            return
        self._closed = True
        try:
            # Unblock any waiters.
            self._in_q.put_nowait(b"")
        except Exception:
            pass
        try:
            self._out_q.put_nowait(b"")
        except Exception:
            pass
        with self._exchange_lock:
            exchanges = tuple(self._exchanges.values())
            self._exchange_order.clear()
        for exchange in exchanges:
            exchange.close()
        if self._on_close is not None:
            try:
                self._on_close(self)
            except Exception:
                pass

    def sendall(self, data: bytes, _flags: int = 0) -> None:
        """Send one datagram through the logical session socket."""
        if self._closed:
            raise OSError("Socket is closed")

        exchange = None
        with self._exchange_lock:
            while self._exchange_order:
                candidate = self._exchange_order.popleft()
                if not candidate.closed and not candidate.response_routed:
                    exchange = candidate
                    break
        if exchange is None:
            # Compatibility path for direct socket users that have not opened
            # an exchange. Bridge-managed requests always use the registry.
            self._out_q.put(data)
        elif not exchange.route_response(data):
            raise OSError("CoAP exchange closed before ASA response routing")
        if _peek_mtype(data) == M_END:
            self.close()

    def recvfrom(self, _bufsize: int):
        """Receive one inbound datagram for this session."""
        if self._closed:
            return b"", (str(self._peer_addr), self._peer_port, 0, 0)

        try:
            if self._timeout_s is None:
                raw = self._in_q.get()
            else:
                raw = self._in_q.get(timeout=self._timeout_s)
        except Exception:
            raise socket.timeout("recvfrom timeout")

        terminal = _peek_mtype(raw) == M_END
        result = raw, (str(self._peer_addr), self._peer_port, 0, 0)
        if terminal:
            self.close()
        return result

    def push_inbound(self, raw: bytes) -> None:
        """Queue an inbound datagram for recvfrom()."""
        if self._closed:
            return
        self._in_q.put(raw)

    def begin_exchange(self, *, token: bytes, direction: str = "inbound",
                       inbound: Optional[bytes] = None) -> CoapServerExchange:
        """Atomically register an exchange and optionally queue its input."""
        key = bytes(token), str(direction)
        with self._exchange_lock:
            if self._closed:
                raise OSError("Socket is closed")
            if key in self._exchanges:
                raise BridgeExchangeConflictError(
                    "CoAP exchange token/direction is already active")
            if len(self._exchanges) >= self._max_pending_exchanges:
                raise BridgeExchangeCapacityError(
                    "CoAP session pending exchange limit reached")

            def remove(closed_exchange, *, exchange_key=key):
                """Remove a closed exchange from the session registry and notify listeners."""
                removed = False
                with self._exchange_lock:
                    if self._exchanges.get(exchange_key) is closed_exchange:
                        self._exchanges.pop(exchange_key, None)
                        removed = True
                if removed and self._on_exchange_change is not None:
                    self._on_exchange_change(self)

            exchange = CoapServerExchange(
                sid=self._sid,
                peer_addr=self._peer_addr,
                token=key[0],
                direction=key[1],
                on_close=remove,
            )
            self._exchanges[key] = exchange
            self._exchange_order.append(exchange)
            if inbound is not None:
                self._in_q.put(bytes(inbound))
            return exchange

    def exchange_snapshots(self) -> tuple:
        """Return diagnostic snapshots for exchanges owned by this socket."""
        with self._exchange_lock:
            exchanges = tuple(self._exchanges.values())
        return tuple(exchange.snapshot() for exchange in exchanges)

    def pop_outbound(self, *, timeout_s: Optional[float]) -> Optional[bytes]:
        """Pop the next outbound datagram for the bridge."""
        try:
            if self._closed:
                return self._out_q.get_nowait()
            if timeout_s is None:
                return self._out_q.get()
            return self._out_q.get(timeout=timeout_s)
        except Exception:
            return None


def _parse_aiocoap_remote_ipv6(request) -> ipaddress.IPv6Address:
    """Best-effort extract of remote IP address from an aiocoap request."""
    hostinfo = ""
    try:
        hostinfo = getattr(getattr(request, "remote", None), "hostinfo", "") or ""
    except Exception:
        hostinfo = ""

    host = ""
    if hostinfo.startswith("[") and "]" in hostinfo:
        host = hostinfo[1:hostinfo.index("]")]
    else:
        # Could be "ip" or "ip:port" for IPv4.
        host = hostinfo.split(":")[0] if hostinfo else ""

    if not host:
        return ipaddress.IPv6Address("::")

    # Strip any RFC6874 zone id if present.
    if "%" in host:
        host = host.split("%", 1)[0]

    ip = ipaddress.ip_address(host)
    if isinstance(ip, ipaddress.IPv4Address):
        return ipaddress.IPv6Address("::ffff:" + host)
    return ip


def _parse_aiocoap_remote_port(request) -> int:
    """Best-effort extract of the remote UDP port from an aiocoap request."""
    try:
        hostinfo = getattr(getattr(request, "remote", None), "hostinfo", "") or ""
    except Exception:
        return 0

    if hostinfo.startswith("[") and "]" in hostinfo:
        rest = hostinfo[hostinfo.index("]") + 1:]
        if not rest.startswith(":"):
            return 0
        try:
            return int(rest[1:])
        except ValueError:
            return 0

    # IPv4 form "a.b.c.d:port"; a bare IPv6 literal has multiple colons.
    if hostinfo.count(":") == 1:
        try:
            return int(hostinfo.rsplit(":", 1)[1])
        except ValueError:
            return 0
    return 0


def _validate_peer_uri(uri: str) -> None:
    """Reject peer URIs that cannot be legitimate unicast CoAP endpoints.

    Blocks non-CoAP schemes, credentials in the URI, multicast/unspecified
    destinations, and optionally enforces ``CGRASP_PEER_ALLOWLIST`` (comma
    separated CIDRs).  Hostnames are allowed unless an allowlist is set.
    """
    parsed = urllib.parse.urlsplit(uri)
    if parsed.scheme not in ("coap", "coaps"):
        raise ValueError(f"unsupported peer URI scheme: {parsed.scheme!r}")
    if parsed.username or parsed.password:
        raise ValueError("peer URI must not contain credentials")
    host = parsed.hostname
    if not host:
        raise ValueError("peer URI has no host")

    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return  # FQDN/URI locator; protocol permits it

    if ip.is_multicast or ip.is_unspecified:
        raise ValueError(f"peer URI must be unicast: {host}")

    allowlist = os.environ.get("CGRASP_PEER_ALLOWLIST", "").strip()
    if not allowlist:
        return
    networks = []
    for item in allowlist.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid CGRASP_PEER_ALLOWLIST entry: {item!r}") from exc
    if networks and not any(ip in network for network in networks):
        raise ValueError(f"peer address not in CGRASP_PEER_ALLOWLIST: {host}")


def _parse_aiocoap_remote_zone(request) -> Optional[str]:
    """Best-effort extract of IPv6 zone id (interface name) from aiocoap request."""
    hostinfo = ""
    try:
        hostinfo = getattr(getattr(request, "remote", None), "hostinfo", "") or ""
    except Exception:
        hostinfo = ""
    if not hostinfo:
        return None
    try:
        if hostinfo.startswith("[") and "]" in hostinfo:
            host = hostinfo[1:hostinfo.index("]")]
        else:
            host = hostinfo.split(":")[0]
        if "%" not in host:
            return None
        zone = host.split("%", 1)[1]
        # Normalize RFC6874 artifact if present.
        zone = zone.replace("%25", "%")
        return zone or None
    except Exception:
        return None


def _coap_uri_for_ipv6(ip: ipaddress.IPv6Address, *, zone: Optional[str], port: int, path: str) -> str:
    host = str(ip)
    if zone:
        host = f"{host}%{zone}"
    return f"coap://[{host}]:{int(port)}/{str(path).strip('/')}"


def _coap_debug_enabled() -> bool:
    return str(os.environ.get("CGRASP_COAP_DEBUG", "")).strip() not in ("", "0", "false", "False")


def _coap_debug(msg: str) -> None:
    if not _coap_debug_enabled():
        return
    try:
        print(str(msg), flush=True)
    except Exception:
        pass


class CgraspCoapApiBridge:
    """Bridge CoAP POSTs into cgrasp's public listen/negotiation APIs.

    This does *not* implement a negotiation state machine. It only provides:
      - per-session socket-like objects for cgrasp
      - request injection into cgrasp's listen queue for M_REQ_NEG/M_REQ_SYN
    """

    def __init__(
        self,
        *,
        wait_ttl_ms: int = 200,
        piggyback_response_wait_s: float = 0.5,
        asa_response_timeout_s: float = 30.0,
        separate_response_timeout_s: Optional[float] = None,
        max_pending_exchanges_per_session: int = 8,
        cg=None,
    ):
        cg = cg if cg is not None else _resolve_cg()
        if cg is None:
            raise RuntimeError("cGRASP module not available")
        self._cg = cg
        # Accepted for compatibility with older callers. M_WAIT generation is
        # no longer supported, so this value is intentionally unused.
        # ``separate_response_timeout_s`` was the old name for the short
        # piggyback window; keep it as an alias so existing callers retain the
        # same fast-response threshold.
        if separate_response_timeout_s is not None:
            piggyback_response_wait_s = float(separate_response_timeout_s)
        self._piggyback_response_wait_s = max(0.0, float(piggyback_response_wait_s))
        self._asa_response_timeout_s = max(
            self._piggyback_response_wait_s,
            float(asa_response_timeout_s),
        )
        self._max_pending_exchanges_per_session = max(
            1, int(max_pending_exchanges_per_session))
        self._sessions: Dict[Tuple[int, ipaddress.IPv6Address, int], CoapServerSessionSocket] = {}
        self._counters: Dict[str, int] = {}
        self._registry_lock = threading.RLock()
        # Bounded idempotency cache for CoAP retransmissions.  A duplicate
        # confirmable request (same peer+token+payload) must return the original
        # response instead of being processed a second time.
        self._idem_lock = threading.Lock()
        self._idem_cache: Dict[Tuple[str, int, bytes, str], Tuple[float, bytes]] = {}
        self._idem_ttl_s = 30.0
        self._idem_max_entries = 256

    def _count(self, event: str) -> None:
        with self._registry_lock:
            self._counters[event] = self._counters.get(event, 0) + 1

    @staticmethod
    def _idempotency_key(peer, port: int, token: bytes, payload: bytes) -> Tuple[str, int, bytes, str]:
        return (str(peer), int(port), bytes(token), hashlib.sha256(payload).hexdigest())

    def _idempotency_get(self, key: Tuple[str, int, bytes, str]) -> Optional[bytes]:
        now = time.monotonic()
        with self._idem_lock:
            entry = self._idem_cache.get(key)
            if entry is None:
                return None
            expires_at, response = entry
            if expires_at <= now:
                self._idem_cache.pop(key, None)
                return None
            return response

    def _idempotency_put(self, key: Tuple[str, int, bytes, str], response: bytes) -> None:
        now = time.monotonic()
        with self._idem_lock:
            for stale in [k for k, (expires_at, _) in self._idem_cache.items()
                          if expires_at <= now]:
                self._idem_cache.pop(stale, None)
            if key not in self._idem_cache and len(self._idem_cache) >= self._idem_max_entries:
                # Drop the oldest insertion; dicts preserve insertion order.
                self._idem_cache.pop(next(iter(self._idem_cache)), None)
            self._idem_cache[key] = (now + self._idem_ttl_s, bytes(response))

    @staticmethod
    def _session_key(sid: int, peer: ipaddress.IPv6Address,
                     port: int = 0) -> Tuple[int, ipaddress.IPv6Address, int]:
        # The peer transport endpoint is (address, port); the port prevents two
        # processes on the same host from sharing one cGRASP session.
        return int(sid), peer, int(port or 0)

    def snapshot(self) -> dict:
        """Return lifecycle state for diagnostics and quiescence assertions."""
        with self._registry_lock:
            self._prune_closed_sessions()
            exchange_snapshots = tuple(
                exchange
                for sock in self._sessions.values()
                for exchange in sock.exchange_snapshots()
            )
            return {
                "active_sessions": len(self._sessions),
                "sessions": tuple((sid, str(peer), port)
                                  for sid, peer, port in self._sessions),
                "active_exchanges": len(exchange_snapshots),
                "exchanges": exchange_snapshots,
                "counters": dict(self._counters),
            }

    def _prune_closed_sessions(self) -> None:
        with self._registry_lock:
            for key, sock in list(self._sessions.items()):
                if sock.can_prune:
                    self._sessions.pop(key, None)

    def _find_session(self, key) -> Optional[CoapServerSessionSocket]:
        with self._registry_lock:
            return self._sessions.get(key)

    def _get_or_create_session(self, sid: int, peer: ipaddress.IPv6Address,
                               port: int = 0) -> CoapServerSessionSocket:
        key = self._session_key(sid, peer, port)
        with self._registry_lock:
            sock = self._sessions.get(key)
            if sock is not None and sock.closed and not sock.can_prune:
                # Keep the terminal exchange observable until its response is
                # consumed; a new operation cannot reuse this logical session.
                return sock
            if sock is None or sock.closed:
                def remove(closed_sock, *, session_key=key):
                    """Remove a prunable closed session from the registry."""
                    with self._registry_lock:
                        if (self._sessions.get(session_key) is closed_sock and
                                closed_sock.can_prune):
                            self._sessions.pop(session_key, None)
                            self._count("sessions_closed")

                sock = CoapServerSessionSocket(
                    sid=int(sid),
                    peer_addr=peer,
                    peer_port=port,
                    on_close=remove,
                    on_exchange_change=remove,
                    max_pending_exchanges=self._max_pending_exchanges_per_session,
                )
                self._sessions[key] = sock
                self._count("sessions_created")
            return sock

    def _maybe_gc(self, sock: CoapServerSessionSocket) -> None:
        if sock.closed:
            self._prune_closed_sessions()

    def _decline_message(self, sid: int, reason: str) -> bytes:
        opt = self._cg._option(O_DECLINE)  # type: ignore[attr-defined]
        opt.reason = str(reason)
        return self._cg._ass_message(M_END, int(sid), None, [opt])  # type: ignore[attr-defined]

    async def _await_asa_response(self, exchange: CoapServerExchange) -> Optional[bytes]:
        """Wait for ASA output long enough to allow CoAP separate response.

        The first window is only the chance to piggyback a response. If it
        expires, keep the handler coroutine alive; aiocoap can acknowledge the
        request separately and later send the final response with the original
        token.
        """

        first = min(self._piggyback_response_wait_s, self._asa_response_timeout_s)
        if first > 0:
            resp = await exchange.pop_response_async(timeout_s=first)
            if resp:
                return resp

        remaining = max(0.0, self._asa_response_timeout_s - first)
        if remaining <= 0:
            return None
        return await exchange.pop_response_async(timeout_s=remaining)

    def _begin_exchange(self, sock: CoapServerSessionSocket, request,
                        *, inbound: Optional[bytes] = None) -> CoapServerExchange:
        token = bytes(getattr(request, "token", b"") or b"")
        try:
            exchange = sock.begin_exchange(
                token=token, direction="inbound", inbound=inbound)
        except BridgeExchangeCapacityError:
            self._count("exchange_overflow")
            raise
        except BridgeExchangeConflictError:
            self._count("exchange_conflict")
            raise
        except OSError:
            self._count("exchange_session_closing")
            raise
        self._count("exchanges_created")
        return exchange

    def _close_exchange(self, exchange: CoapServerExchange) -> None:
        exchange.close()
        self._count("exchanges_closed")

    async def handle_post(self, payload: bytes, request) -> bytes:
        """Handle a CoAP POST, returning a cached response for retransmissions.

        CoAP retransmits a confirmable request with the same Token and payload
        when the response is lost.  Without this cache the bridge would either
        process the cGRASP message twice or reject the duplicate token.
        """
        peer = _parse_aiocoap_remote_ipv6(request)
        peer_port = _parse_aiocoap_remote_port(request)
        token = bytes(getattr(request, "token", b"") or b"")

        cache_key = None
        if token and isinstance(payload, (bytes, bytearray)):
            cache_key = self._idempotency_key(peer, peer_port, token, payload)
            cached = self._idempotency_get(cache_key)
            if cached is not None:
                self._count("duplicate_request_cache_hit")
                return cached

        response = await self._handle_post_uncached(payload, request)
        if cache_key is not None and isinstance(response, (bytes, bytearray)):
            self._idempotency_put(cache_key, bytes(response))
        return response

    async def _handle_post_uncached(self, payload: bytes, request) -> bytes:
        """Process a CoAP POST payload without the idempotency cache."""
        peer = _parse_aiocoap_remote_ipv6(request)
        peer_port = _parse_aiocoap_remote_port(request)

        if not isinstance(payload, (bytes, bytearray)):
            return self._cg._ass_message(M_INVALID, 0, None, "Bad message")  # type: ignore[attr-defined]
        if len(payload) > MAX_CGRASP_PAYLOAD:
            return self._cg._ass_message(M_INVALID, 0, None, "Message too large")  # type: ignore[attr-defined]

        # Determine mtype/sid quickly; fall back to INVALID on decode errors.
        try:
            decoded = decode_grasp_bytes(payload)
            if not isinstance(decoded, list) or len(decoded) < 2:
                return self._cg._ass_message(M_INVALID, 0, None, "Bad message")  # type: ignore[attr-defined]
            mtype = int(decoded[0])
            sid = int(decoded[1])
        except Exception:
            return self._cg._ass_message(M_INVALID, 0, None, "CBOR decode failed")  # type: ignore[attr-defined]

        if mtype == M_WAIT:
            return self._cg._ass_message(M_INVALID, int(sid), None, "M_WAIT disabled")  # type: ignore[attr-defined]

        key = self._session_key(sid, peer, peer_port)
        if mtype not in (M_REQ_NEG, M_REQ_SYN):
            sock0 = self._find_session(key)
            if sock0 is None or sock0.closed:
                return b""

        # For request messages, inject into the listen queue so listen_negotiate()
        # can return and the ASA can drive negotiation via public APIs.
        if mtype in (M_REQ_NEG, M_REQ_SYN):
            try:
                msg_obj = self._cg._parse_msg(decoded)  # type: ignore[attr-defined]
            except Exception:
                msg_obj = None
            if not msg_obj:
                return self._cg._ass_message(M_INVALID, int(sid), None, "Invalid request")  # type: ignore[attr-defined]

            if mtype == M_REQ_SYN:
                try:
                    sync_resp = self._cg._coap_immediate_synchronize_response(msg_obj)  # type: ignore[attr-defined]
                except Exception:
                    sync_resp = None
                if sync_resp:
                    return sync_resp
                self._count("sync_no_listener")
                return self._decline_message(sid, "No local synchronization listener for objective")

            sock = self._get_or_create_session(sid, peer, peer_port)
            try:
                exchange = self._begin_exchange(sock, request)
            except BridgeExchangeCapacityError:
                return self._decline_message(sid, "CoAP session exchange queue is full")
            except BridgeExchangeConflictError:
                return self._decline_message(sid, "Duplicate active CoAP exchange token")
            except OSError:
                return self._decline_message(sid, "CoAP session is closing")

            try:
                found, queued = self._cg._queue_unicast_request(sock, peer, msg_obj)  # type: ignore[attr-defined]
            except Exception:
                found, queued = False, False

            if not found or not queued:
                # No listener: mirror TCP behavior (drop/close). For CoAP we must respond.
                reason = "No local negotiation listener for objective"
                if found and not queued:
                    reason = "Local negotiation listener queue is full"
                self._close_exchange(exchange)
                sock.close()
                return self._decline_message(sid, reason)

            # Wait for the ASA to produce the GRASP reply. The short first
            # window only decides whether CoAP can piggyback; it is not a GRASP
            # negotiation timeout.
            try:
                resp = await self._await_asa_response(exchange)
            finally:
                self._close_exchange(exchange)
            if resp:
                if _is_wait_message(resp):
                    sock.close()
                    self._maybe_gc(sock)
                    return self._decline_message(sid, "M_WAIT is not supported")
                self._maybe_gc(sock)
                return resp
            sock.close()
            self._maybe_gc(sock)
            return self._decline_message(
                sid,
                "Local responder did not produce a negotiation response within the configured deadline1",
            )

        sock = self._find_session(key)
        if sock is None:
            return b""
        if mtype == M_END:
            sock.push_inbound(payload)
            return b""

        # Register and enqueue atomically so ASA receive order and exchange
        # response routing order cannot diverge under concurrent POSTs.
        try:
            exchange = self._begin_exchange(sock, request, inbound=payload)
        except BridgeExchangeCapacityError:
            return self._decline_message(sid, "CoAP session exchange queue is full")
        except BridgeExchangeConflictError:
            return self._decline_message(sid, "Duplicate active CoAP exchange token")
        except OSError:
            return self._decline_message(sid, "CoAP session is closing")

        # Wait for cgrasp to emit the response for this inbound message. A
        # delayed ASA response is carried as a CoAP separate response when the
        # CoAP stack needs to acknowledge the request before the final payload.
        try:
            resp = await self._await_asa_response(exchange)
        finally:
            self._close_exchange(exchange)
        if resp:
            if _is_wait_message(resp):
                sock.close()
                self._maybe_gc(sock)
                return self._decline_message(sid, "M_WAIT is not supported")
            self._maybe_gc(sock)
            return resp
        sock.close()
        self._maybe_gc(sock)
        return self._decline_message(
            sid,
            "Local responder did not produce a negotiation response within the configured deadline1",
        )


def install_cgrasp_unicast_over_coap(*, path: str = DEFAULT_CGRASP_RESOURCE_PATH, default_port: int = 5683) -> None:
    """Install a cgrasp unicast transport hook that uses CoAP.

    After calling this, cgrasp.req_negotiate()/negotiate_step()/synchronize()
    will keep their existing state machines but perform unicast I/O via CoAP.

    This sets cgrasp.set_unicast_socket_factory(...) to create CoapUnicastSocket.
    """
    cg = _resolve_cg()
    if cg is None or not hasattr(cg, "set_unicast_socket_factory"):
        raise RuntimeError("cgrasp.set_unicast_socket_factory() not available")

    def _factory(loc: object, session_id: int, purpose: str):
        peer_base_uri = coap_peer_base_uri_from_asa_locator(loc, default_port=default_port)
        return CoapUnicastSocket(peer_base_uri, sid=int(session_id), path=path)

    cg.set_unicast_socket_factory(_factory)  # type: ignore[attr-defined]


def _maybe_decrypt(raw: bytes) -> bytes:
    """Optionally decrypt inbound GRASP payload bytes.

    If the local `cgrasp` module is importable and QUADS crypto helpers
    are available, this delegates to `cgrasp._decrypt_msg()`.
    Otherwise returns `raw` unchanged.
    """
    cg = _resolve_cg()
    if cg is not None and hasattr(cg, "_decrypt_msg"):
        return cg._decrypt_msg(raw)  # type: ignore[attr-defined]
    return raw


def _maybe_encrypt(raw: bytes) -> bytes:
    """Optionally encrypt outbound GRASP payload bytes.

    If the local `cgrasp` module is importable and QUADS crypto helpers
    are available, this delegates to `cgrasp._encrypt_msg()`.
    Otherwise returns `raw` unchanged.
    """
    cg = _resolve_cg()
    if cg is not None and hasattr(cg, "_encrypt_msg"):
        return cg._encrypt_msg(raw)  # type: ignore[attr-defined]
    return raw


def decode_grasp_bytes(raw: bytes) -> list:
    """Decode on-the-wire GRASP message bytes into a Python list.

    The expected input is CBOR-encoded GRASP message bytes.
    If QUADS is enabled in `cgrasp`, decryption is applied first.

    Returns the decoded CBOR root object (expected: a list).
    """
    plain = _maybe_decrypt(raw)
    return cbor.loads(plain)


def encode_grasp_list(msg: list) -> bytes:
    """Encode a Python list into on-the-wire GRASP message bytes.

    The message is CBOR-encoded.
    If QUADS is enabled in `cgrasp`, encryption is applied after encoding.
    """
    plain = cbor.dumps(msg)
    return _maybe_encrypt(plain)


def obj_to_list(obj: object) -> list:
    """
    Convert a cGRASP objective-like object to the on-the-wire list:
      [num:int, flags:int, loop_count:int, value:any]
    Expects attributes: num, discoverable, neg, synch, dry, loop_count, value
    """
    num = int(getattr(obj, "num"))
    discoverable = bool(getattr(obj, "discoverable", True))
    neg = bool(getattr(obj, "neg", False))
    synch = bool(getattr(obj, "synch", False))
    dry = bool(getattr(obj, "dry", False))
    loop_count = int(getattr(obj, "loop_count"))
    value = getattr(obj, "value", None)

    # flag bits: DISC=0, NEG=1, SYNCH=2, DRY=3
    flags = 0
    if discoverable:
        flags |= 1 << 0
    if neg:
        flags |= 1 << 1
    if synch:
        flags |= 1 << 2
    if dry:
        flags |= 1 << 3

    return [num, flags, loop_count, value]


def _to_cgrasp_cobjective(obj: object) -> object:
    """Best-effort conversion of an objective-like object to `cgrasp.cobjective`.

    cgrasp's internal message assembler `_ass_message()` only recognizes objects
    whose `tname(x)` is "cobjective" (or legacy "objective"). Our CoAP test
    scripts often use a local dataclass `Objective`, so we convert it here.

    If `cgrasp` is not importable, or `cgrasp.cobjective` is unavailable, this
    returns `obj` unchanged.
    """
    cg = _resolve_cg()
    if cg is None or not hasattr(cg, "cobjective"):
        return obj

    try:
        # If already a cgrasp.cobjective instance, keep it.
        if type(obj).__name__ == "cobjective":
            return obj

        cobj = cg.cobjective(int(getattr(obj, "num")))  # type: ignore[attr-defined]
        cobj.discoverable = bool(getattr(obj, "discoverable", True))
        cobj.neg = bool(getattr(obj, "neg", False))
        cobj.synch = bool(getattr(obj, "synch", False))
        cobj.dry = bool(getattr(obj, "dry", False))
        cobj.loop_count = int(getattr(obj, "loop_count"))
        cobj.value = getattr(obj, "value", None)
        return cobj
    except Exception:
        return obj


def _ass_message_bytes(msg_type: int, sid: int, payload: object = None) -> bytes:
    """Assemble a GRASP/cGRASP message as on-the-wire bytes.

    This prefers using cgrasp's internal assembler `_ass_message()` (the same
    helper used by cgrasp's negotiation functions), so the transport layer
    doesn't re-implement message formatting.

    Fallback (when cgrasp is unavailable): encode a Python list with CBOR.
    """
    cg = _resolve_cg()
    if cg is not None and hasattr(cg, "_ass_message"):
        if payload is None:
            return cg._ass_message(int(msg_type), int(sid), None)  # type: ignore[attr-defined]
        return cg._ass_message(int(msg_type), int(sid), None, payload)  # type: ignore[attr-defined]

    # Fallback path: keep the old wire format (Python list -> CBOR).
    if payload is None:
        return encode_grasp_list([int(msg_type), int(sid)])
    return encode_grasp_list([int(msg_type), int(sid), payload])


def _validate_with_cgrasp_parser(msg_list: list) -> None:
    """Validate decoded payload using `cgrasp._parse_msg()` when available."""
    cg = _resolve_cg()
    if cg is None or not hasattr(cg, "_parse_msg"):
        return
    try:
        parsed = cg._parse_msg(msg_list)  # type: ignore[attr-defined]
    except Exception:
        parsed = None
    if not parsed:
        raise ValueError("Invalid GRASP/cGRASP message per cgrasp._parse_msg()")


def coap_peer_base_uri_from_asa_locator(
    loc: object,
    *,
    scheme: str = "coap",
    default_port: int = 5683,
) -> str:
    """Map a cGRASP `asa_locator`-like object to a CoAP peer base URI.

    This converts GRASP discovery output (transport locators) into a URI string
    suitable for `CgraspCoapTransport.post_grasp()`.

    Supported locator styles:
    - IP address locator: `.is_ipaddress == True` and `.locator` is
      `ipaddress.IPv6Address`/`ipaddress.IPv4Address` or packed bytes.
    - FQDN locator: `.is_fqdn == True` and `.locator` is a hostname string.
    - URI locator: `.is_uri == True` and `.locator` is a URI string.

    IPv6 link-local addresses require a zone identifier. In theory, RFC6874
    requires encoding the '%' as '%25' inside URIs. However, aiocoap expects
    a literal zone id inside the IPv6 literal (e.g. `[fe80::1%eth0]`).
    Therefore this function normalizes any `%25<ifname>` to `%<ifname>`.

    Args:
        loc: An object compatible with cgrasp.asa_locator fields.
        scheme: URI scheme (typically "coap" or "coaps").
        default_port: Used when the locator doesn't specify a usable port.

    Returns:
        A base URI like `coap://[2001:db8::1]:5683` or
        `coap://[fe80::1%eth0]:5683`.

    Raises:
        ValueError: If the locator cannot be converted.
    """

    # URI locator: trust the provided URI but normalize scheme/port if missing.
    if bool(getattr(loc, "is_uri", False)):
        raw_uri = str(getattr(loc, "locator"))
        parsed = urllib.parse.urlsplit(raw_uri)
        if not parsed.scheme:
            raw_uri = f"{scheme}://{raw_uri.lstrip('/')}"
            parsed = urllib.parse.urlsplit(raw_uri)

        # If no netloc (eg. 'coap://[::1]' is netloc, OK), reject.
        if not parsed.netloc:
            raise ValueError(f"Invalid URI locator: {raw_uri}")

        # Normalize IPv6 zone-id encoding for aiocoap: %25eth0 -> %eth0.
        # A zone-id embedded in a discovered URI locator is scoped to the
        # responder's node/namespace. For link-local peers, prefer the local
        # interface that received the Discovery response.
        host = parsed.hostname
        if host is None:
            raise ValueError(f"Invalid URI locator host: {raw_uri}")
        host = host.replace("%25", "%")
        try:
            bare_host = host.split("%", 1)[0]
            ip = ipaddress.ip_address(bare_host)
            if isinstance(ip, ipaddress.IPv6Address) and ip.is_link_local:
                ifi = int(getattr(loc, "ifi", 0) or 0)
                if ifi > 0:
                    host = f"{bare_host}%{socket.if_indextoname(ifi)}"
        except Exception:
            pass

        port2 = parsed.port
        if port2 is None:
            port2 = int(default_port)

        netloc = host
        if ":" in host and not host.startswith("["):
            netloc = f"[{host}]"
        netloc = f"{netloc}:{int(port2)}"

        # Strip any path/query/fragment for base URI usage.
        return urllib.parse.urlunsplit((parsed.scheme, netloc, "", "", ""))

    port = int(getattr(loc, "port", 0) or 0)
    if port <= 0:
        port = default_port

    if bool(getattr(loc, "is_fqdn", False)):
        host = str(getattr(loc, "locator"))
        return f"{scheme}://{host}:{port}"

    if not bool(getattr(loc, "is_ipaddress", False)):
        raise ValueError("Unsupported locator type (expected ipaddress/fqdn/uri)")

    raw = getattr(loc, "locator")

    # Normalize to ipaddress object.
    if isinstance(raw, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        ip_obj = raw
    elif isinstance(raw, (bytes, bytearray)):
        if len(raw) == 16:
            ip_obj = ipaddress.IPv6Address(bytes(raw))
        elif len(raw) == 4:
            ip_obj = ipaddress.IPv4Address(bytes(raw))
        else:
            raise ValueError("Packed IP locator must be 4 or 16 bytes")
    else:
        # Accept string input as a last resort.
        ip_obj = ipaddress.ip_address(str(raw))

    # Format host with IPv6 brackets; add RFC6874 zone id for link-local.
    if isinstance(ip_obj, ipaddress.IPv6Address):
        host = str(ip_obj)
        if ip_obj.is_link_local:
            ifi = int(getattr(loc, "ifi", 0) or 0)
            if ifi:
                try:
                    ifname = socket.if_indextoname(ifi)
                except Exception:
                    ifname = str(ifi)
                # aiocoap expects a literal zone id (not RFC6874 '%25').
                host = f"{host}%{ifname}"
        return f"{scheme}://[{host}]:{port}"

    # IPv4
    return f"{scheme}://{ip_obj}:{port}"


@dataclass
class NegSession:
    """Server-side event-driven negotiation context."""
    sid: int
    objnum: int
    _outq: "asyncio.Queue[bytes]"

    def enqueue_response(self, msg_list: list) -> None:
        """Queue an encoded GRASP response for immediate handler use."""
        self._outq.put_nowait(encode_grasp_list(msg_list))


NegHandler = Callable[[NegSession, int, list], Awaitable[Optional[list]]]
# signature: handler(session, mtype, decoded_msg_list) -> response_msg_list or None


SyncHandler = Callable[[int, list], Awaitable[list]]
# signature: handler(sid, decoded_req_list) -> synch_response_msg_list


class CgraspCoapTransport:
    """
    CoAP transport for cGRASP unicast negotiation + synchronization.
    - single CoAP resource: POST coap://<peer>:5683/.well-known/grasp-coap
    - payload: raw cGRASP message bytes (CBOR, optionally QUADS-encrypted)
    - baseline negotiation has no M_WAIT or M_NOOP polling.

    You keep UDP multicast discovery/flood unchanged.
    You should advertise CoAP locators via register_obj(..., locators=[...]).
    """

    def __init__(
        self,
        bind: Tuple[str, int] = default_bind(),
        path: str = DEFAULT_CGRASP_RESOURCE_PATH,
    ):
        """Create a CoAP transport endpoint for cGRASP unicast messaging.

        Args:
            bind: (host, port) for the local CoAP server to bind.
            path: CoAP resource path used for GRASP message exchange.
        """
        self._bind = bind
        self._path = path

        self._client = CoapClient()
        self._server = make_default_cgrasp_server(self._on_coap_message, bind=bind, base_path=path)

        self._neg_handlers: Dict[int, NegHandler] = {}
        self._sync_handlers: Dict[int, SyncHandler] = {}

        # sid -> (objnum, outq)
        self._neg_sessions: Dict[int, Tuple[int, asyncio.Queue[bytes]]] = {}

    # -------- registration (event-driven) --------

    def register_negotiation_handler(self, objnum: int, handler: NegHandler) -> None:
        """Register an event-driven negotiation handler for an objective number.

        The handler is invoked for M_REQ_NEG / M_NEGOTIATE / M_END messages.
        It must return a GRASP message list to respond immediately. Returning
        `None` declines the exchange in the baseline profile.
        """
        self._neg_handlers[int(objnum)] = handler

    def register_synchronization_handler(self, objnum: int, handler: SyncHandler) -> None:
        """Register a synchronization handler for an objective number.

        The handler is invoked for incoming M_REQ_SYN messages and must
        return a full GRASP response message list (typically M_SYNCH).
        """
        self._sync_handlers[int(objnum)] = handler

    # -------- lifecycle --------

    async def start(self) -> None:
        """Start local CoAP server and initialize the CoAP client context."""
        await self._server.start()
        await self._client.start()

    async def stop(self) -> None:
        """Stop local CoAP server and shut down the CoAP client context."""
        self._neg_sessions.clear()
        await self._client.close()
        await self._server.stop()

    # -------- client-side operations --------

    async def post_grasp(self, peer_base_uri: str, msg_bytes: bytes, timeout: Optional[float] = None) -> bytes:
        """
        Send one GRASP message over CoAP.
        peer_base_uri example: "coap://[fe80::1%eth0]" or "coap://[2001:db8::1]"
        """
        _validate_peer_uri(peer_base_uri)
        uri = peer_base_uri.rstrip("/") + "/" + self._path.strip("/")
        return await self._client.post(uri, payload=msg_bytes, timeout=timeout)

    async def post_grasp_to_locator(self, loc: object, msg_bytes: bytes, timeout: Optional[float] = None) -> bytes:
        """Send one GRASP message over CoAP to a peer described by `asa_locator`.

        This is a convenience wrapper around:
        - `coap_peer_base_uri_from_asa_locator()`
        - `post_grasp()`
        """
        peer_base_uri = coap_peer_base_uri_from_asa_locator(loc)
        return await self.post_grasp(peer_base_uri, msg_bytes, timeout=timeout)

    async def negotiate_req_to_locator(self, loc: object, sid: int, obj: object, timeout_s: float) -> list:
        """Locator-based variant of `negotiate_req()` (discovers URI from `asa_locator`)."""
        peer_base_uri = coap_peer_base_uri_from_asa_locator(loc)
        return await self.negotiate_req(peer_base_uri, sid, obj, timeout_s)

    async def negotiate_step_to_locator(self, loc: object, sid: int, obj: object, timeout_s: float) -> list:
        """Locator-based variant of `negotiate_step()` (discovers URI from `asa_locator`)."""
        peer_base_uri = coap_peer_base_uri_from_asa_locator(loc)
        return await self.negotiate_step(peer_base_uri, sid, obj, timeout_s)

    async def negotiate_end_to_locator(
        self,
        loc: object,
        sid: int,
        accept: bool,
        reason: Optional[str],
        timeout_s: float,
    ) -> list:
        """Locator-based variant of `negotiate_end()` (discovers URI from `asa_locator`)."""
        peer_base_uri = coap_peer_base_uri_from_asa_locator(loc)
        return await self.negotiate_end(peer_base_uri, sid, accept, reason, timeout_s)

    async def negotiate_req(self, peer_base_uri: str, sid: int, obj: object, timeout_s: float) -> list:
        """
        Initiator sends M_REQ_NEG and waits for the first peer reply.
        Returns decoded reply list.
        """
        # NOTE: Keep the previous self-assembled negotiation message code for reference.
        # req = [M_REQ_NEG, int(sid), obj_to_list(obj)]
        # rep_bytes = await self.post_grasp(peer_base_uri, encode_grasp_list(req), timeout=timeout_s)
        # return self._decode_non_wait_reply(rep_bytes)

        # Preferred: delegate message formatting to cgrasp's internal assembler.
        cobj = _to_cgrasp_cobjective(obj)
        req_bytes = _ass_message_bytes(M_REQ_NEG, int(sid), cobj)
        rep_bytes = await self.post_grasp(peer_base_uri, req_bytes, timeout=timeout_s)
        return self._decode_non_wait_reply(rep_bytes)

    async def negotiate_step(self, peer_base_uri: str, sid: int, obj: object, timeout_s: float) -> list:
        """Send one M_NEGOTIATE step and await the peer reply."""
        # step = [M_NEGOTIATE, int(sid), obj_to_list(obj)]
        # rep_bytes = await self.post_grasp(peer_base_uri, encode_grasp_list(step), timeout=timeout_s)
        # return self._decode_non_wait_reply(rep_bytes)

        cobj = _to_cgrasp_cobjective(obj)
        step_bytes = _ass_message_bytes(M_NEGOTIATE, int(sid), cobj)
        rep_bytes = await self.post_grasp(peer_base_uri, step_bytes, timeout=timeout_s)
        return self._decode_non_wait_reply(rep_bytes)

    async def negotiate_end(self, peer_base_uri: str, sid: int, accept: bool, reason: Optional[str], timeout_s: float) -> list:
        """Send M_END (accept/decline) and return the peer's decoded reply."""
        # opt = [O_ACCEPT] if accept else ([O_DECLINE, reason] if reason else [O_DECLINE])
        # msg = [M_END, int(sid), opt]
        # rep_bytes = await self.post_grasp(peer_base_uri, encode_grasp_list(msg), timeout=timeout_s)
        # return decode_grasp_bytes(rep_bytes)

        opt = [O_ACCEPT] if accept else ([O_DECLINE, reason] if reason else [O_DECLINE])
        # cgrasp._ass_message expects a list of options for M_END.
        end_bytes = _ass_message_bytes(M_END, int(sid), [opt])
        rep_bytes = await self.post_grasp(peer_base_uri, end_bytes, timeout=timeout_s)
        rep = decode_grasp_bytes(rep_bytes)
        _validate_with_cgrasp_parser(rep)
        return rep

    async def synchronize(self, peer_base_uri: str, sid: int, obj: object, timeout_s: float) -> list:
        """Send M_REQ_SYN and return the peer's decoded M_SYNCH (or other) reply."""
        # req = [M_REQ_SYN, int(sid), obj_to_list(obj)]
        # rep_bytes = await self.post_grasp(peer_base_uri, encode_grasp_list(req), timeout=timeout_s)
        # return decode_grasp_bytes(rep_bytes)

        cobj = _to_cgrasp_cobjective(obj)
        req_bytes = _ass_message_bytes(M_REQ_SYN, int(sid), cobj)
        rep_bytes = await self.post_grasp(peer_base_uri, req_bytes, timeout=timeout_s)
        rep = decode_grasp_bytes(rep_bytes)
        _validate_with_cgrasp_parser(rep)
        return rep

    def _decode_non_wait_reply(self, reply_bytes: bytes) -> list:
        rep = decode_grasp_bytes(reply_bytes)
        _validate_with_cgrasp_parser(rep)
        if int(rep[0]) == M_WAIT:
            raise RuntimeError("M_WAIT is not supported by the baseline profile")
        return rep

    # -------- server-side dispatch --------

    async def _on_coap_message(self, payload: bytes, _request_msg) -> bytes:
        """
        CoAP handler (single endpoint). Payload is raw GRASP bytes.
        Returns raw GRASP bytes (response).
        """
        try:
            msg = decode_grasp_bytes(payload)
            mtype = int(msg[0])
            sid = int(msg[1])

            # Negotiation-related
            if mtype in (M_WAIT, M_NOOP):
                return encode_grasp_list([M_INVALID, sid, "M_WAIT disabled"])
            if mtype in (M_REQ_NEG, M_NEGOTIATE, M_END):
                return await self._handle_neg(mtype, sid, msg)

            # Synchronization
            if mtype == M_REQ_SYN:
                return await self._handle_sync(sid, msg)

            return encode_grasp_list([M_INVALID, sid, "Unsupported message"])

        except Exception:
            return encode_grasp_list([M_INVALID, 0, "internal error"])

    async def _handle_neg(self, mtype: int, sid: int, msg: list) -> bytes:
        """Server-side negotiation dispatcher.

        Implements strict multi-round behavior with immediate CoAP replies.
        """
        # For messages carrying an objective: msg[2] = objective list, objective[0]=objnum
        objnum = None
        if mtype in (M_REQ_NEG, M_NEGOTIATE):
            objnum = int(msg[2][0])

        # Session creation on REQ_NEG
        if mtype == M_REQ_NEG:
            outq: asyncio.Queue[bytes] = asyncio.Queue()
            self._neg_sessions[sid] = (objnum, outq)
            handler = self._neg_handlers.get(objnum)

            if not handler:
                # decline immediately if no handler
                decline = [M_END, sid, [O_DECLINE, "No handler for objective"]]
                return encode_grasp_list(decline)

            sess = NegSession(sid=sid, objnum=objnum, _outq=outq)
            resp = await handler(sess, mtype, msg)
            if resp is not None:
                return encode_grasp_list(resp)
            return encode_grasp_list([M_END, sid, [O_DECLINE, "Deferred response unsupported"]])

        # Existing session required for subsequent steps
        st = self._neg_sessions.get(sid)
        if not st:
            return encode_grasp_list([M_END, sid, [O_DECLINE, "Unknown session"]])

        sess_objnum, outq = st
        handler = self._neg_handlers.get(sess_objnum)
        if not handler:
            return encode_grasp_list([M_END, sid, [O_DECLINE, "Handler removed"]])

        sess = NegSession(sid=sid, objnum=sess_objnum, _outq=outq)
        resp = await handler(sess, mtype, msg)
        if resp is not None:
            return encode_grasp_list(resp)

        return encode_grasp_list([M_END, sid, [O_DECLINE, "Deferred response unsupported"]])

    async def _handle_sync(self, sid: int, msg: list) -> bytes:
        """Server-side synchronization handler.

        Dispatches M_REQ_SYN based on objective number and returns an encoded
        response message. If no handler is registered, returns an explicit decline.
        """
        objnum = int(msg[2][0])
        handler = self._sync_handlers.get(objnum)
        if not handler:
            resp = [M_END, sid, [O_DECLINE, "No synchronization handler for objective"]]
            return encode_grasp_list(resp)

        resp_list = await handler(sid, msg)
        return encode_grasp_list(resp_list)
