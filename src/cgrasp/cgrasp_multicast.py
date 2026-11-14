# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Protocol-neutral state and codec helpers for cGRASP over CoAP multicast.

This module deliberately contains no aiocoap private API usage.  Wire transport
details are isolated in :mod:`coap_multicast_adapter`.
"""

from __future__ import annotations

import copy
import argparse
import concurrent.futures
import functools
import hashlib
import ipaddress
import json
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Hashable, Iterable

import cbor2


CGRASP_RESOURCE_PATH = "/.well-known/grasp-coap"
CGRASP_IPV6_MULTICAST_GROUP = "ff02::fd"
CGRASP_COAP_PORT = 5683
CGRASP_CONTENT_FORMAT = 60

DISCOVERY_METHOD = "FETCH"
DISCOVERY_MESSAGE_TYPE = "NON"
DISCOVERY_USE_NO_RESPONSE = False
DISCOVERY_RESPONSE_CODE = 69  # 2.05 Content
DISCOVERY_RESPONSE_CONFIRMABLE = True

FLOOD_METHOD = "POST"
FLOOD_MESSAGE_TYPE = "NON"
FLOOD_NO_RESPONSE_VALUE = 26

M_DISCOVERY = 1
M_RESPONSE = 2
M_FLOOD = 9


@dataclass(frozen=True)
class RelayConfig:
    """Configuration for a cGRASP relay (interfaces, timers, rate limits)."""
    enabled_interfaces: tuple[str, ...]
    discovery_hard_timeout_ms: int = 5000
    discovery_quiet_timeout_ms: int = 500
    flood_seen_timeout_ms: int = 10000
    max_discovery_transactions: int = 256
    max_flood_seen_entries: int = 1024
    max_responses_per_transaction: int = 64
    max_response_digests: int = 128
    max_responders_per_objective_interface: int = 16
    relay_rate_per_second: float = 20.0
    relay_burst: int = 10
    responder_leisure_min_ms: int = 50
    responder_leisure_max_ms: int = 250
    multicast_group: str = CGRASP_IPV6_MULTICAST_GROUP

    def __post_init__(self) -> None:
        if not self.enabled_interfaces or any(not str(x).strip() for x in self.enabled_interfaces):
            raise ValueError("enabled_interfaces must contain at least one non-empty interface")
        positive = (
            "discovery_hard_timeout_ms", "discovery_quiet_timeout_ms",
            "flood_seen_timeout_ms", "max_discovery_transactions",
            "max_flood_seen_entries", "max_responses_per_transaction",
            "max_response_digests", "max_responders_per_objective_interface",
            "relay_rate_per_second", "relay_burst",
        )
        for name in positive:
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        if self.responder_leisure_min_ms < 0 or self.responder_leisure_max_ms < 0:
            raise ValueError("responder leisure must not be negative")
        if self.responder_leisure_min_ms > self.responder_leisure_max_ms:
            raise ValueError("responder leisure minimum exceeds maximum")
        group = ipaddress.IPv6Address(self.multicast_group)
        if not group.is_multicast:
            raise ValueError("multicast_group must be an IPv6 multicast address")

    @classmethod
    def from_mapping(cls, values: dict) -> "RelayConfig":
        """Build a RelayConfig from a mapping of option names."""
        data = dict(values)
        if "enabled_interfaces" in data:
            data["enabled_interfaces"] = tuple(data["enabled_interfaces"])
        return cls(**data)

    @classmethod
    def from_json_file(cls, path: str) -> "RelayConfig":
        """Load a RelayConfig from a JSON file."""
        with open(path, "r", encoding="utf-8") as stream:
            data = json.load(stream)
        if not isinstance(data, dict):
            raise ValueError("relay configuration file must contain an object")
        return cls.from_mapping(data)


def add_relay_arguments(parser: argparse.ArgumentParser) -> None:
    """Add relay CLI options to an argparse parser."""
    parser.add_argument("--relay-interface", action="append", dest="relay_interfaces")
    parser.add_argument("--relay-config", help="JSON file containing RelayConfig fields")
    parser.add_argument("--relay-hard-timeout-ms", type=int)
    parser.add_argument("--relay-quiet-timeout-ms", type=int)
    parser.add_argument("--relay-rate", type=float)
    parser.add_argument("--relay-burst", type=int)
    parser.add_argument("--relay-leisure-min-ms", type=int)
    parser.add_argument("--relay-leisure-max-ms", type=int)


def relay_config_from_args(args) -> RelayConfig:
    """Build a RelayConfig from parsed CLI arguments."""
    data = {}
    path = getattr(args, "relay_config", None)
    if path:
        with open(path, "r", encoding="utf-8") as stream:
            data = json.load(stream)
    overrides = {
        "enabled_interfaces": getattr(args, "relay_interfaces", None),
        "discovery_hard_timeout_ms": getattr(args, "relay_hard_timeout_ms", None),
        "discovery_quiet_timeout_ms": getattr(args, "relay_quiet_timeout_ms", None),
        "relay_rate_per_second": getattr(args, "relay_rate", None),
        "relay_burst": getattr(args, "relay_burst", None),
        "responder_leisure_min_ms": getattr(args, "relay_leisure_min_ms", None),
        "responder_leisure_max_ms": getattr(args, "relay_leisure_max_ms", None),
    }
    data.update({key: value for key, value in overrides.items() if value is not None})
    return RelayConfig.from_mapping(data)


@dataclass(frozen=True)
class InterfaceInfo:
    """Metadata for one IPv6 interface used by multicast/relay."""
    name: str
    index: int
    link_local_address: str
    multicast_group: str = CGRASP_IPV6_MULTICAST_GROUP


class InterfaceManager:
    """Discover and select link-local interfaces for multicast."""
    def __init__(self, enabled_interfaces: Iterable[str], *, group: str = CGRASP_IPV6_MULTICAST_GROUP,
                 inventory: Iterable[InterfaceInfo] | None = None):
        self._enabled = tuple(enabled_interfaces)
        self._group = group
        self._inventory = tuple(inventory) if inventory is not None else None

    def list_enabled_interfaces(self) -> list[InterfaceInfo]:
        """Return metadata for enabled interfaces."""
        if self._inventory is not None:
            by_name = {x.name: x for x in self._inventory}
            missing = [x for x in self._enabled if x not in by_name]
            if missing:
                raise ValueError("enabled interfaces missing from inventory: " + ", ".join(missing))
            return [by_name[x] for x in self._enabled]
        try:
            import netifaces
        except ImportError as exc:
            raise RuntimeError("netifaces is required to inspect interfaces") from exc
        result = []
        for name in self._enabled:
            if name not in netifaces.interfaces():
                raise ValueError(f"unknown interface: {name}")
            addresses = netifaces.ifaddresses(name).get(netifaces.AF_INET6, [])
            link_local = None
            for item in addresses:
                raw = str(item.get("addr", "")).split("%", 1)[0]
                try:
                    if ipaddress.IPv6Address(raw).is_link_local:
                        link_local = raw
                        break
                except ValueError:
                    continue
            if link_local is None:
                raise ValueError(f"interface has no IPv6 link-local address: {name}")
            result.append(InterfaceInfo(name, socket.if_nametoindex(name), link_local, self._group))
        return result

    def get_interface_by_index(self, index: int) -> InterfaceInfo:
        """Return interface metadata for an ifindex, or None."""
        for info in self.list_enabled_interfaces():
            if info.index == index:
                return info
        raise KeyError(index)

    def eligible_outgoing_interfaces(self, incoming_interface: str) -> list[InterfaceInfo]:
        """Return interfaces eligible for forwarding, excluding the incoming one."""
        return [x for x in self.list_enabled_interfaces() if x.name != incoming_interface]


class CodecError(ValueError):
    """Raised when a cGRASP message cannot be decoded or encoded."""
    pass


def _validate_objective(raw: object) -> None:
    if not isinstance(raw, list) or len(raw) not in (3, 4):
        raise CodecError("invalid objective shape")
    number, flags, loop_count = raw[:3]
    if not isinstance(number, int) or not 0 <= number <= 0xFFFFFFFF:
        raise CodecError("invalid objective number")
    if not isinstance(flags, int) or flags < 0 or flags > 0x0F:
        raise CodecError("invalid objective flags")
    if not isinstance(loop_count, int) or not 0 <= loop_count <= 255:
        raise CodecError("invalid loop-count")


def decode_message(payload: bytes, *, max_size: int = 2048) -> list:
    """Decode a CBOR cGRASP message into the internal model."""
    if not isinstance(payload, bytes) or not payload or len(payload) > max_size:
        raise CodecError("invalid message size")
    try:
        message = cbor2.loads(payload)
    except Exception as exc:
        raise CodecError("invalid CBOR") from exc
    if not isinstance(message, list) or len(message) < 4:
        raise CodecError("invalid message shape")
    mtype, session_id, initiator = message[:3]
    if mtype not in (M_DISCOVERY, M_RESPONSE, M_FLOOD):
        raise CodecError("unsupported multicast message type")
    if not isinstance(session_id, int) or not 0 <= session_id <= 0xFFFFFFFF:
        raise CodecError("invalid session-id")
    if not isinstance(initiator, bytes) or len(initiator) not in (4, 16):
        raise CodecError("invalid initiator")
    if mtype == M_DISCOVERY:
        if len(message) != 4:
            raise CodecError("M_DISCOVERY has unexpected fields")
        _validate_objective(message[3])
    elif mtype == M_RESPONSE:
        if len(message) < 5 or not isinstance(message[3], int) or message[3] < 0:
            raise CodecError("invalid M_RESPONSE")
        # At least one locator or O_DIVERT option is mandatory. An optional
        # objective may follow, but it cannot be the only content.
        options = [x for x in message[4:] if isinstance(x, list) and x and x[0] in (100, 103, 104, 105, 106)]
        if not options:
            raise CodecError("M_RESPONSE has no locator or O_DIVERT")
    else:
        if len(message) < 5 or not isinstance(message[3], int) or message[3] < 0:
            raise CodecError("invalid M_FLOOD")
        loops = set()
        for tagged in message[4:]:
            if not isinstance(tagged, list) or len(tagged) != 2:
                raise CodecError("invalid flooded objective")
            _validate_objective(tagged[0])
            loops.add(tagged[0][2])
        if len(loops) != 1:
            raise CodecError("all objectives in M_FLOOD must have the same loop-count")
    return message


def encode_canonical(message: list) -> bytes:
    # Validation also rejects unsupported and over-specified messages.
    """Encode a message using the canonical CBOR profile."""
    raw = cbor2.dumps(message, canonical=True)
    decode_message(raw, max_size=max(2048, len(raw)))
    return raw


def decrement_loop_count(message: list) -> list:
    """Decrement and validate a message loop count."""
    result = copy.deepcopy(message)
    if result[0] == M_DISCOVERY:
        targets = [result[3]]
    elif result[0] == M_FLOOD:
        targets = [x[0] for x in result[4:]]
    else:
        raise CodecError("message type has no relay loop-count")
    loops = {x[2] for x in targets}
    if len(loops) != 1 or next(iter(loops)) <= 0:
        raise CodecError("message is not forwardable")
    for objective in targets:
        objective[2] -= 1
    return result


def response_digest(message: list) -> bytes:
    """Return a stable digest used for duplicate-response detection."""
    if not message or message[0] != M_RESPONSE:
        raise CodecError("response digest requires M_RESPONSE")
    return hashlib.sha256(encode_canonical(message)).digest()[:8]


@dataclass(frozen=True)
class DiscoveryKey:
    """Key identifying a discovery transaction."""
    initiator: Hashable
    session_id: int


@dataclass(frozen=True)
class ResponseValidationResult:
    """Result of validating a discovery response."""
    accepted: bool
    reason: str
    digest: bytes | None = None


def validate_discovery_response(
    message: list,
    *,
    expected_key: DiscoveryKey,
    expected_token: bytes,
    received_token: bytes,
    seen_digests: set[bytes] | None = None,
) -> ResponseValidationResult:
    """Validate a downstream M_RESPONSE before relay forwarding."""

    try:
        decoded = decode_message(encode_canonical(message))
    except Exception:
        return ResponseValidationResult(False, "invalid_message")
    if decoded[0] != M_RESPONSE:
        return ResponseValidationResult(False, "not_response")
    if bytes(received_token or b"") != bytes(expected_token or b""):
        return ResponseValidationResult(False, "response_token_mismatch")
    if decoded[1] != expected_key.session_id:
        return ResponseValidationResult(False, "response_session_mismatch")
    if decoded[2] != expected_key.initiator:
        return ResponseValidationResult(False, "response_initiator_mismatch")
    try:
        digest = response_digest(decoded)
    except Exception:
        return ResponseValidationResult(False, "invalid_response_digest")
    if seen_digests is not None and digest in seen_digests:
        return ResponseValidationResult(False, "response_duplicate_dropped", digest)
    return ResponseValidationResult(True, "accepted", digest)


@dataclass
class DownstreamExchangeState:
    """State for one downstream discovery branch."""
    interface: str
    token: bytes
    exchange: object
    state: str = "OPEN"
    accepted_responses: int = 0


@dataclass
class DiscoveryTransaction:
    """State for an in-flight discovery transaction."""
    key: DiscoveryKey
    incoming_interface: str
    upstream_remote: object
    upstream_token: bytes
    upstream_request_context: object
    downstream: dict[str, DownstreamExchangeState] = field(default_factory=dict)
    created_at: float = field(default_factory=time.monotonic)
    hard_deadline: float = 0.0
    quiet_deadline: float | None = None
    response_count: int = 0
    response_digests: set[bytes] = field(default_factory=set)
    closed: bool = False
    close_reason: str | None = None

    def close(self, reason: str) -> bool:
        """Close exactly once; return whether this call changed the state."""
        if self.closed:
            return False
        self.closed = True
        self.close_reason = str(reason)
        for branch in self.downstream.values():
            branch.state = "CLOSED"
            request_close = getattr(branch.exchange, "request_close", None)
            if callable(request_close):
                request_close()
        return True


@dataclass(frozen=True)
class FloodKey:
    """Key identifying a flooded objective."""
    initiator: Hashable
    session_id: int


@dataclass
class FloodSeenEntry:
    """Flood-cache entry recording the interfaces that saw it."""
    key: FloodKey
    incoming_interface: str
    outgoing_interfaces: set[str]
    created_at: float
    expires_at: float


@dataclass
class ResponderCacheEntry:
    """Cached responder locators for an objective."""
    objective_num: int
    responder_identity: str
    locators: tuple
    learned_interface: str
    learned_at: float
    expires_at: float


def normalize_responder_identity(identity: object, locators: tuple) -> str:
    """Return a stable cache identity for a downstream responder."""
    if identity is None:
        digest = hashlib.sha256(cbor2.dumps(locators, canonical=True)).hexdigest()[:16]
        return f"locator:{digest}"
    if isinstance(identity, bytes):
        return "bytes:" + identity.hex()
    if isinstance(identity, (tuple, list)):
        return "endpoint:" + json.dumps(
            [str(value) for value in identity], separators=(",", ":"))
    return "value:" + str(identity)


class TokenBucket:
    """Simple token bucket used by the relay rate limiter."""
    def __init__(self, rate: float, burst: int, *, now: float | None = None):
        if rate <= 0 or burst <= 0:
            raise ValueError("rate and burst must be positive")
        self.rate = float(rate)
        self.capacity = float(burst)
        self.tokens = float(burst)
        self.updated_at = time.monotonic() if now is None else float(now)

    def allow(self, now: float, cost: float = 1.0) -> bool:
        """Consume tokens if available; return True when the request is allowed."""
        if cost <= 0:
            raise ValueError("cost must be positive")
        now = max(float(now), self.updated_at)
        self.tokens = min(self.capacity, self.tokens + (now - self.updated_at) * self.rate)
        self.updated_at = now
        if self.tokens < cost:
            return False
        self.tokens -= cost
        return True


def _relay_owner_method(method):
    """Run RelayState operations on its bound event-loop thread."""

    @functools.wraps(method)
    def wrapped(self, *args, **kwargs):
        """Run a callable, returning a fallback when tokens are exhausted."""
        return self._run_on_owner(method, args, kwargs)

    return wrapped


class RelayState:
    """Bounded, independently-expiring relay state tables."""

    def __init__(self, config: RelayConfig, *, clock: Callable[[], float] = time.monotonic):
        self.config = config
        self.clock = clock
        self.discovery: dict[DiscoveryKey, DiscoveryTransaction] = {}
        self.flood_seen: dict[FloodKey, FloodSeenEntry] = {}
        self.responders: list[ResponderCacheEntry] = []
        self.counters: dict[str, int] = {}
        self._buckets: dict[tuple[str, str], TokenBucket] = {}
        self._owner_loop = None
        self._owner_thread_id: int | None = None
        self._owner_dispatches = 0

    def bind_owner_loop(self, loop) -> None:
        """Bind all subsequent operations to the calling event-loop thread."""
        if loop.is_closed():
            raise RuntimeError("relay owner loop is closed")
        thread_id = threading.get_ident()
        if self._owner_loop is not None and (
                self._owner_loop is not loop or self._owner_thread_id != thread_id):
            raise RuntimeError("relay state already has a different owner")
        self._owner_loop = loop
        self._owner_thread_id = thread_id

    def unbind_owner_loop(self) -> None:
        """Release ownership from the owner thread during loop shutdown."""
        if (self._owner_thread_id is not None and
                threading.get_ident() != self._owner_thread_id):
            raise RuntimeError("relay state must be unbound by its owner")
        self._owner_loop = None
        self._owner_thread_id = None

    def _run_on_owner(self, method, args, kwargs):
        loop = self._owner_loop
        owner_thread_id = self._owner_thread_id
        if loop is None or owner_thread_id is None:
            return method(self, *args, **kwargs)
        if threading.get_ident() == owner_thread_id:
            return method(self, *args, **kwargs)
        if not loop.is_running():
            raise RuntimeError("relay owner loop is not running")

        result = concurrent.futures.Future()

        def invoke():
            """Invoke the wrapped callable once and resolve the future."""
            if result.cancelled():
                return
            try:
                self._owner_dispatches += 1
                result.set_result(method(self, *args, **kwargs))
            except BaseException as exc:
                result.set_exception(exc)

        try:
            loop.call_soon_threadsafe(invoke)
        except RuntimeError as exc:
            raise RuntimeError("relay owner loop is unavailable") from exc
        return result.result()

    @_relay_owner_method
    def count(self, event: str) -> None:
        """Increment a named relay counter."""
        self.counters[event] = self.counters.get(event, 0) + 1

    @_relay_owner_method
    def snapshot(self) -> dict:
        """Return bounded-state diagnostics without exposing mutable objects."""
        self.cleanup()
        return {
            "active_discovery_transactions": len(self.discovery),
            "active_downstream_branches": sum(len(tx.downstream) for tx in self.discovery.values()),
            "flood_seen_entries": len(self.flood_seen),
            "responder_entries": len(self.responders),
            "response_digests": sum(len(tx.response_digests) for tx in self.discovery.values()),
            "owner_bound": self._owner_loop is not None,
            "owner_thread_id": self._owner_thread_id,
            "owner_dispatches": self._owner_dispatches,
            "counters": dict(self.counters),
        }

    @_relay_owner_method
    def clear_discovery_transactions(self, *, reason: str = "manual") -> int:
        """Clear active Discovery relay transactions without touching other caches.

        This is intentionally small and deterministic so tests can prove that a
        late M_RESPONSE is accepted only when a matching relay transaction still
        exists. It is also safe to expose behind a test-only runtime trigger.
        """

        removed = len(self.discovery)
        for tx in self.discovery.values():
            tx.close(reason)
        self.discovery.clear()
        self.count("discovery_transactions_cleared")
        self.count(f"discovery_transactions_cleared_{reason}")
        return removed

    @_relay_owner_method
    def remaining_discovery_transactions(self) -> int:
        """Return the number of active discovery transactions."""
        self.cleanup()
        return len(self.discovery)

    @_relay_owner_method
    def register_downstream(self, key: DiscoveryKey, interface: str, token: bytes,
                            exchange: object) -> DownstreamExchangeState | None:
        """Register a downstream branch and its token/interface."""
        tx = self.discovery.get(key)
        if tx is None or tx.closed:
            self.count("downstream_unknown_transaction")
            return None
        branch = DownstreamExchangeState(str(interface), bytes(token), exchange)
        tx.downstream[str(interface)] = branch
        self.count("downstream_branch_created")
        return branch

    @_relay_owner_method
    def reserve_downstream(self, key: DiscoveryKey, interface: str,
                           exchange: object) -> DownstreamExchangeState | None:
        """Own an exchange before its transport assigns a token or sends."""
        return self.register_downstream(key, interface, b"", exchange)

    @_relay_owner_method
    def bind_downstream_token(self, key: DiscoveryKey, interface: str, token: bytes,
                              exchange: object) -> DownstreamExchangeState | None:
        """Bind the transport-assigned token to an already-owned exchange."""
        tx = self.discovery.get(key)
        branch = None if tx is None else tx.downstream.get(str(interface))
        if tx is None or tx.closed or branch is None or branch.exchange is not exchange:
            self.count("downstream_token_bind_rejected")
            return None
        branch.token = bytes(token)
        self.count("downstream_token_bound")
        return branch

    @_relay_owner_method
    def get_downstream(self, key: DiscoveryKey,
                       interface: str) -> DownstreamExchangeState | None:
        """Return an owned branch while preserving relay-state synchronization."""
        tx = self.discovery.get(key)
        if tx is None or tx.closed:
            return None
        return tx.downstream.get(str(interface))

    @_relay_owner_method
    def close_discovery(self, key: DiscoveryKey, *, reason: str) -> bool:
        """Close a discovery transaction and release its branches."""
        tx = self.discovery.pop(key, None)
        if tx is None:
            return False
        changed = tx.close(reason)
        if changed:
            self.count(f"discovery_closed_{reason}")
        return changed

    @_relay_owner_method
    def validate_transaction_response(
        self,
        key: DiscoveryKey,
        message: list,
        *,
        expected_token: bytes,
        received_token: bytes,
    ) -> ResponseValidationResult:
        """Validate a response against an active transaction and update counters."""

        tx = self.discovery.get(key)
        if tx is None or tx.closed:
            self.count("response_unknown_transaction")
            return ResponseValidationResult(False, "response_unknown_transaction")
        if tx.response_count >= self.config.max_responses_per_transaction:
            self.count("response_limit_reached")
            return ResponseValidationResult(False, "response_limit_reached")
        if len(tx.response_digests) >= self.config.max_response_digests:
            self.count("response_digest_limit_reached")
            return ResponseValidationResult(False, "response_digest_limit_reached")
        result = validate_discovery_response(
            message,
            expected_key=key,
            expected_token=expected_token,
            received_token=received_token,
            seen_digests=tx.response_digests,
        )
        self.count(result.reason)
        if result.accepted and result.digest is not None:
            tx.response_digests.add(result.digest)
            tx.response_count += 1
            tx.quiet_deadline = self.clock() + self.config.discovery_quiet_timeout_ms / 1000
        return result

    @_relay_owner_method
    def cleanup(self) -> None:
        """Expire stale transactions and cache entries."""
        now = self.clock()
        self.flood_seen = {k: v for k, v in self.flood_seen.items() if v.expires_at > now}
        self.responders = [x for x in self.responders if x.expires_at > now]
        for key, tx in list(self.discovery.items()):
            quiet = tx.response_count and tx.quiet_deadline is not None and now >= tx.quiet_deadline
            if tx.closed or now >= tx.hard_deadline or quiet:
                reason = tx.close_reason or ("hard_timeout" if now >= tx.hard_deadline else "quiet_timeout")
                tx.close(reason)
                self.discovery.pop(key, None)
                self.count(f"discovery_closed_{reason}")

    @_relay_owner_method
    def create_discovery(self, key: DiscoveryKey, **kwargs) -> DiscoveryTransaction | None:
        """Create a discovery transaction for a key."""
        self.cleanup()
        if key in self.discovery:
            self.count("discovery_duplicate_dropped")
            return None
        if len(self.discovery) >= self.config.max_discovery_transactions:
            self.count("cache_full_drop")
            return None
        now = self.clock()
        tx = DiscoveryTransaction(key=key, created_at=now,
                                  hard_deadline=now + self.config.discovery_hard_timeout_ms / 1000,
                                  **kwargs)
        self.discovery[key] = tx
        self.count("discovery_relay_created")
        return tx

    @_relay_owner_method
    def remember_flood(self, key: FloodKey, incoming: str, outgoing: Iterable[str]) -> bool:
        """Record a flood key and its seen interfaces."""
        self.cleanup()
        if key in self.flood_seen:
            self.count("flood_duplicate_dropped")
            return False
        if len(self.flood_seen) >= self.config.max_flood_seen_entries:
            self.count("cache_full_drop")
            return False
        now = self.clock()
        self.flood_seen[key] = FloodSeenEntry(key, incoming, set(outgoing), now,
                                              now + self.config.flood_seen_timeout_ms / 1000)
        return True

    @_relay_owner_method
    def remember_responder(self, objective_num: int, locators: Iterable,
                           learned_interface: str, ttl_ms: int,
                           *, responder_identity: object = None) -> None:
        """Cache a responder locator for an objective."""
        if ttl_ms <= 0:
            raise ValueError("responder ttl must be positive")
        self.cleanup()
        now = self.clock()
        normalized = copy.deepcopy(tuple(locators))
        identity = normalize_responder_identity(responder_identity, normalized)
        matching = [
            entry for entry in self.responders
            if entry.objective_num == int(objective_num)
            and entry.learned_interface == str(learned_interface)
        ]
        existing = next(
            (entry for entry in matching if entry.responder_identity == identity),
            None,
        )
        if existing is not None:
            self.responders.remove(existing)
            self.count("responder_cache_refreshed")
        elif len(matching) >= self.config.max_responders_per_objective_interface:
            victim = min(
                matching,
                key=lambda entry: (
                    entry.learned_at,
                    entry.responder_identity,
                    repr(entry.locators),
                ),
            )
            self.responders.remove(victim)
            self.count("responder_cache_evicted")
        self.responders.append(ResponderCacheEntry(
            int(objective_num), identity, normalized, str(learned_interface),
            now, now + ttl_ms / 1000))

    @_relay_owner_method
    def get_responders(self, objective_num: int) -> list[ResponderCacheEntry]:
        """Return unexpired responder locators for an objective."""
        self.cleanup()
        interface_rank = {
            name: index for index, name in enumerate(self.config.enabled_interfaces)
        }
        return sorted(
            (entry for entry in self.responders
             if entry.objective_num == objective_num),
            key=lambda entry: (
                interface_rank.get(entry.learned_interface, len(interface_rank)),
                entry.learned_interface,
                entry.responder_identity,
                repr(entry.locators),
            ),
        )

    @_relay_owner_method
    def allow(self, kind: str, interface: str) -> bool:
        """Apply the relay rate limiter for a request kind/interface."""
        key = (kind, interface)
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = self._buckets[key] = TokenBucket(
                self.config.relay_rate_per_second, self.config.relay_burst, now=self.clock())
        allowed = bucket.allow(self.clock())
        if not allowed:
            self.count("rate_limit_drop")
        return allowed


def structured_event(node: str, event: str, **fields) -> str:
    """Render a structured, JSON-serializable event dictionary."""
    record = {"node": node, "event": event, "monotonic": time.monotonic(), **fields}
    for key in ("upstream_token", "downstream_token", "response_digest"):
        if isinstance(record.get(key), bytes):
            record[key] = record[key].hex()[:16]
    return json.dumps(record, sort_keys=True, separators=(",", ":"))
