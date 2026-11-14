# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""########################################################
########################################################
#
#Constrained Generic Autonomic Signaling Protocol (cGRASP)
#
# cGRASP engine and experimental API
#
# Module name is 'cgrasp'
#
# This is a prototype/demo implementation of cGRASP. It was
# developed using Python 3.4 and above.
#
# It is based on draft-ietf-anima-constrained-grasp and RFC8990. The API is not fully compatible
# with RFC8991; for that, use the module cgraspi.py, which
# imports this module.
#
# This code is not guaranteed or validated in any way and is
# both incomplete and probably wrong. It makes no claim
# to be production-quality code. Its main purpose is to
# help validate the protocol specification.
#
# Because it's demonstration code written in an
# interpreted language, performance is slow.
#
# SECURITY WARNINGS:
#  - assumes ACP up on all interfaces (or none)
#  - does not watch for interface up/down changes
#  - no support for wrapping TCP in TLS
#  - it is strongly recommended to use the built-in QUADS security
#    unless a truly secure ACP is available
#
# LIMITATIONS:
#  - only coded for IPv6, no IPv4 support
#  - survival of address changes and CPU sleep/wakeup is patchy
#  - FQDN and URI locators incompletely supported
#  - no code for handling rapid mode negotiation
#  - relay code is lazy (no rate control)
#  - workarounds for defects in Python socket module and
#    Windows socket peculiarities. Not tested on Android.
#
# Released under the BSD "Revised" License as follows:
#
# Copyright (C) xxxx.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with
# or without modification, are permitted provided that the
# following conditions are met:
#
# 1. Redistributions of source code must retain the above
# copyright notice, this list of conditions and the following
# disclaimer.
#
# 2. Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following
# disclaimer in the documentation and/or other materials
# provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of
# its contributors may be used to endorse or promote products
# derived from this software without specific prior written
# permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS
# AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
########################################################
########################################################"""


_version = "xxx"

##########################################################
# The following change log records significant changes,
# not small bug fixes, in older versions.

# Version 05 added proto/port to discovery responses

# 1. Update constants for revised CDDL
# 2. Add fields to discovered locator (class asa_locator) and objective
#    registry (class _registered_objective)
# 3. Add option code and fields in response messages
# 4. Update generation and parsing of response messages accordingly
# 5. Change from a global TCP listener to a per-objective TCP listener
# 6. Change register_objective to obtain a TCP port and socket and
#    launch its own listener
# 7. Make this listener exit if the objective is deregistered (but only
#    if new requests come in, otherwise it sleeps harmlessly for ever)

# 20160601 Added discovery cache timeout, and detection of address changes

# 20160605 Added partial recovery after system sleep

# 20160619 Fixed to allow reentrant calls to listen_neg (and listen_syn)

# Version 06 added no protocol changes

# Version 07 added ttl & locator to flood cache entries, and ttl to discovery response

# 20161003 added bubble output option with tkinter

# Version 08 added partial support of M_INVALID

# Version 09 added the F_NEG_DRY flag, modified M_FLOOD format

# 20170122 added Flag24 handling to API

# 20170124 changed error returns to integers (incompatible change to API)

# 20170221 changed session nonce to store packed locator insted of IPv6Address

# 20170224 improved flag bit handling

# 20170429 port 7017 assigned

# 20170518 added interactive choice of test mode (instead of countdown)

# 20170528 fixed several bugs in discovery relaying

# Version 13 improved calculation of discovery timeouts

# 20170604 added initialisation deferral

# Version 15 should conform to RFC-to-be

# 20170721 multicast addresses ff02::13 and 224.0.0.119 assigned

# 20170819 improved handling for long messages

# 20170824 added skip_dialogue() to API

# 20170929 added send_invalid() to API

# 20171003 added inbound message checking option, fixed bug in M_FLOOD format

# 20171013 replaced inbound checking by full parsing, and use parsed
#          messages wherever possible

# 20171023 updated _ass_message() to use 'option' class,
#          added multiple locators to M_RESPONSE and O_DIVERT,
#          added rapid mode objective to M_RESPONSE
#          updated register_obj() and synchronize() APIs accordingly

# 20190126 restructure to put IP address/interface discovery
#          in the ACP module. There are now no operating system
#          dependencies in the grasp.py module (although some
#          may be hidden in imported Python modules).

# 20190206 added socket timeouts when sending discovery responses
#          or request messages, since there should always be a listener

# 20190410 improved flood() to allow all locator types
#          (based on patch from Robin Jaeger)

# 20190724 added exception handler to _mchandler to increase robustness

# 20190912 inserted diagnostics for _mchandler hang

# 20190913 fixed lock bug in _mchandler for expired discovery

# 20190925 commented out diagnostics for _mchandler hang

# 20191017 added QUADS crypto

# 20191025 made all threads daemonic to force proper exit

# 20191102 improved password entry code

# 20191113 added gsend() and grecv()

# 20200408 fixed historic bug in flood()

# 20200913 improved interaction between acp.status() and security checks

# 20200920 added DULL flag and behaviour

# 20210105 started API upgrade to draft-ietf-anima-grasp-api-10
#          (aka API RFC)
#          - tweaked default objective.value to None
#          - renamed nonces as handles in API
#          - fixed a printing bug

# 20210106 - added overlap parameter to register_obj

# 20210109 - added minimum_TTL parameter to discover
#          - documented remaining deviations from API RFC

# 20210110 - renamed snonce as shandle throughout
#          - cleaned up naming of some globals, classes and functions
#            to tidy up the 'help' results

# 20210111 - cleaned up help texts
#          - did all remaining s/nonce/handle/
#          - made flood() RFC-compatible

# 20210112 - cosmetic improvements

# 20210115 - added partial option to dump_all()

# 20210118 - tweak to allow "No key" bypass

# 20210205 - graceful behaviour if import cryptography fails

# 20210306 - store interface index with flooded objective

# 20210309 - allow for objectives with F_DISC = 0

# 20210722 - corrected Tag 24 handling

# 20210820 - prefer cbor2 over cbor (more error handling)
#          - allow receiving long unicast messages
#          - separate max message size settings
#
# 20210826 - fixed off-by-one in loop count check
#
# 20210918 - fixed bug in flood expiry for floods with no locator
#
# 20210919 - added experimental _figger ASA (self-configuration ASA)
#
# 20210920 - added "ask" options to skip_dialogue(), removed "quadsing" parameter
#
# 20211010 - fixed dependency on CBOR library tag handling
#          - tuned startup dialogue defaults
#
# 20211014 - fixed Linux-only bug in CBORTag usage
#
# 20211015 - cosmetic improvement in cbor vs cbor2 usage
#
# 20220316 - fixed grievous bug in O_DIVERT format and other related bugs
#          - added duplicate detection when storing locator in discovery cache
#
# 20220429 - ignore cache entries discovered on same interface
#
# 20230224 - parser bug if objective contains no value
#
# 20230226 - missing initialisation (for corner case)
#
##########################################################

####################################
#                                  #
# Python version check             #
#                                  #
####################################

import sys
if sys.version_info < (3, 10):
    raise RuntimeError("Must use Python 3.10 or later")

# Each ASA starts with "import graspi" for the RFC8991 API,
# or "import grasp" for the old API.
# Public names exported by ``from cgrasp.cgrasp import *``:
__all__ = [
    'cobjective', 'asa_locator', 'tagged_objective',
    'register_asa', 'deregister_asa', 'register_obj',
    'deregister_obj', 'discover',
    'req_negotiate', 'negotiate_step', 'negotiate_wait',
    'end_negotiate', 'listen_negotiate', 'stop_negotiate',
    'synchronize', 'listen_synchronize', 'stop_synchronize',
    'flood', 'get_flood', 'expire_flood',
    'enable_coap_transport', 'disable_coap_transport',
    'get_coap_bridge_snapshot', 'configure_logging',
]

####################################
#                                  #
# Imports                          #
#                                  #
####################################

import time
import logging
import threading
import queue
import socket
import struct
import ipaddress
import random
import binascii
import copy
import traceback
_LOGGER = logging.getLogger("cgrasp")
_LOGGER.addHandler(logging.NullHandler())


def configure_logging(level=logging.INFO):
    """Attach a console handler to the ``cgrasp`` logger (CLI convenience).

    Library users should configure logging themselves; this helper exists for
    the demonstration scripts and legacy CLI entry points.
    """
    logger = logging.getLogger("cgrasp")
    logger.setLevel(level)
    if not any(isinstance(handler, logging.StreamHandler) for handler in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(threadName)s %(message)s"))
        logger.addHandler(handler)
    return logger


# ## for bubbles
try:
    import tkinter as tk
    from tkinter import font
except Exception:
    _LOGGER.warning("Could not import tkinter. No pretty printing.")
###
try:
    import cbor2 as cbor
    from cbor2 import CBORTag
except Exception:
    _LOGGER.warning("Could not import cbor2. Will try to import cbor instead.")
    try:
        import cbor
        from cbor import Tag as CBORTag
    except Exception as ex:
        raise ImportError("cbor2 is required; install the declared project dependencies") from ex
try:
    from . import acp
except Exception:
    raise ImportError("acp.py is required and is included in this project")

# imports for QUADS
import os
import json
_cryptography = False
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    _cryptography = True
except Exception:
    pass

# check for latest ACP
try:
    acp.new2019()
except Exception:
    raise ImportError("acp.py does not provide the required 2019 API")

# work-around for Python system error
try:
    socket.IPPROTO_IPV6
except Exception:
    socket.IPPROTO_IPV6 = 41

#########################################
# A very handy function...
#########################################

def tname(x):
    """-> name of type of x"""
    return type(x).__name__

####################################
#                                  #
# Data types and global data       #
#                                  #
####################################


####################################
# ASA registry                     #
####################################

class _asa_instance:
    """Internal use only"""
    def __init__(self, handle, name):
        self.handle = handle  # the ASA's handle
        self.name = name      # the ASA's name string

# _asa_registry - list of _asa_instance
# _asa_lock - lock for _asa_registry

####################################
# cObjectives & registry            #
####################################

class cobjective:
    """
A cGRASP objective:
 .num   int
 .neg    True if cobjective supports negotiation
 .dry    True if cobjective supportd dry-run negotiation
 .synch  True if cobjective supports synchronization
 .loop_count  Limit on negotiation steps etc.
 .value  A valid Python object
"""
    def __init__(self, num):
        self.num = num  # Unique number, int
        self.discoverable = True # Set False if unwanted (unusual!)
        self.neg = False  # Set True if cobjective supports negotiation
        self.dry = False  # Set True if cobjective also supports dry-run negotiation
        self.synch = False  # Set True if cobjective supports synch
        self.loop_count = GRASP_DEF_LOOPCT # Default starting value
        self.value = None # Place holder; format undefined

def _oclone(obj):
    """Internal use only"""
###################################################
# Clones an objective for local use
# If you don't use this, you may unintenionally
# modify the caller's objective
# Just do obj=_oclone(obj)
###################################################
    cobj=cobjective(obj.num)
    cobj.neg=obj.neg
    cobj.dry=obj.dry
    cobj.synch=obj.synch
    cobj.loop_count=obj.loop_count
    cobj.value=obj.value
    return cobj

class _registered_objective:
    """Internal use only"""
    def __init__(self, objective, asa_handle):
        self.objective = objective
        self.asa_id    = [asa_handle]
        self.overlap_OK = False
        self.protocol = socket.IPPROTO_TCP # default
        self.locators = [] # list of explicit locators, if any
        self.port = 0
        self.discoverable = False # not discoverable until first listening
        self.local = False # link-local iff True
        self.rapid = False # support rapid mode iff True
        self.ttl = _discCacheDefTimeOut # discovery cache timeout in milliseconds
        self.listening = 0 # counts active listeners
        self.listen_q = None


# _obj_registry - list of _registered_objective
# _obj_lock - lock for _obj_registry



####################################
# Discovery cache                  #
####################################

class _discovered_objective:
    """Internal use only"""
    def __init__(self, objective, asa_locators):
        self.objective = objective
        self.asa_locators  = asa_locators # list of asa_locator
        self.received = None # objective received in M_RESPONSE

class asa_locator:
    """
Locator for a discovered peer ASA, also used for flooded objectives.
Values:
 .locator  The actual locator
 .protocol Transport protocol number
 .port     Port number
 .ifi      Interface identifier via which this was discovered
 .expire   int(time.monotonic()) value when this entry expires (0=never)
Booleans:
 .diverted
 .is_ipaddress
 .is_fqdn
 .is_uri
"""
    def __init__(self, locator, ifi, diverted):

        self.locator = locator
        self.ifi = ifi   # Remember which interface this came from
        self.diverted = diverted  # True iff it was in a Divert option

        # Defaults
        self.protocol = socket.IPPROTO_TCP
        self.port = CGRASP_LISTEN_PORT
        self.expire = 0

        # One of the following must be set when the object is created
        # Addresses to be stored in Python ipaddress class
        self.is_ipaddress = False
        self.is_fqdn = False
        self.is_uri = False

# _discovery_cache - list of _discovered_objective
# _disc_lock - lock for _discovery_cache



####################################
# Session ID cache                 #
####################################

class _session_instance:
    """Internal use only"""
    def __init__(self, id_value, id_active, id_source):
        self.id_value = id_value   # Integer
        self.id_active = id_active # True if active
        self.id_source = id_source # Source locator of ID if needed (packed)
        self.id_dq = None          # Queue if discovering
        self.id_sock = None        # Socket if negotiating
        self.id_relayed = False    # True if has been relayed

class _session_handle:
    """Internal use only"""
    def __init__(self, id_value, id_source):
        self.id_value = id_value   # Integer
        self.id_source = id_source # Source locator of ID if non-local (packed)

# _session_id_cache - list of _session_instance
# _sess_lock - lock for _session_id_cache

# Session_ID cache contains
#  - all currently active Session_IDs
#  - foreign source address if any
#  - status for each one (in use or inactive)
#  - as memory permits, all previously seen Session_IDs (status inactive) to avoid reuse

####################################
# Flood cache                      #
####################################

class tagged_objective:
    """
An objective tagged with its source asa_locator:
 .objective  the objective
 .source     an asa_locator (including expiry time) or None
"""
    def __init__(self, objective, source):
        self.objective = objective
        self.source    = source # an asa_locator (including expiry time)

# _flood_cache  - list of tagged_objective
# _flood_lock - lock for _flood_cache

# Flood cache contains flooded objectives with their values and tagged
# with their source address

####################################
# Classes for message parsing      #
####################################

class _flooded_objective:
    """
An objective embedded in a flood:
 .obj    the objective
 .loco   its locator option, or None
"""
    def __init__(self, obj, loco):
        self.obj = obj             # an objective
        self.loco = loco           # associated locator option

class _message:
    """
A GRASP message:
 .mtype         message type, integer
 .id_value      session ID, integer
 .id_source     source address (packed)
 .ttl           ttl or waiting time (ms)
 .options       list of embedded option
 .obj           embedded objective
 .flood_list    list of _flooded_objective
 .content       arbitrary content
"""
    def __init__(self, mtype):
        self.mtype = mtype          # message type, integer
        self.id_value = 0           # session ID, integer
        self.id_source = _unspec_address.packed # source address
        self.ttl = 0                # ttl or waiting time, integer
        self.options = []           # list of options
        self.obj = None             # embedded objective
        self.flood_list = None      # list of _flooded_objective
        self.content = None         # arbitrary content

class _option:
    """
A GRASP option:
 .otype  option type, integer
 .embedded  embedded option if any
 .locator   if locator option: packed address or string
 .protocol  if locator option: protocol #
 .port      if locator option: port #
 .reason    if decline option: reason string
"""
    def __init__(self, otype):
        self.otype = otype          # option type, integer
        self.embedded = []          # list of embedded options (if any)
        self.locator = None         # if locator option: packed address
                                    # or string
        self.protocol = 0           # if locator option: protocol #
        self.port = 0               # if locator option: port #
        self.reason = None          # if decline option: reason string

####################################
# Other global variables           #
#                                  #
# Reminder: any of these that get  #
# assigned inside any function or  #
# thread must be declared 'global' #
# inside that function             #
####################################

_grasp_initialised = False # true after GRASP core has been initialised
_skip_dialogue = False     # true if ASA calls grasp.skip_dialogue
# Optional hook: replace TCP sockets used for unicast negotiation/synchronization.
# When set, this must be a callable that returns a socket-like object providing
# at least: settimeout(seconds), sendall(bytes, flags=0), recvfrom(bufsize), close().
# Signature: factory(peer_locator, session_id, purpose) -> socket_like
# where purpose is a string such as "neg" or "syn".
_unicast_socket_factory = None

# Optional hook: wrap GRASP link-local multicasts in CoAP messages.
# When enabled, Discovery and Flood multicasts are sent/received as CoAP
# (still over UDP, still to ff02::13, still using CGRASP_LISTEN_PORT by default).
# The CoAP payload carries the original GRASP on-wire bytes (CBOR, optionally
# QUADS-encrypted), so GRASP semantics and message formats are preserved.
_use_coap_multicast = False
_coap_mc_uri_path = (".well-known", "grasp-coap")

# Standard CoAP multicast (RFC7252): use udp/5683 to ff02::fd with aiocoap.
_use_coap_std_multicast = False
from .cgrasp_multicast import (
    CGRASP_COAP_PORT, CGRASP_IPV6_MULTICAST_GROUP, CGRASP_RESOURCE_PATH,
    FLOOD_NO_RESPONSE_VALUE, DiscoveryKey, FloodKey, RelayConfig,
)
from .cgrasp_engine import CgraspEngine

_coap_std_mc_group = CGRASP_IPV6_MULTICAST_GROUP
_coap_std_mc_port = CGRASP_COAP_PORT
_coap_std_mc_uri_path = tuple(x for x in CGRASP_RESOURCE_PATH.split("/") if x)
_coap_relay_state = None
_coap_relay_config_override = None
_coap_engine = None

# Default engine owns the registries, caches and locks.  The historical
# module globals below are aliases so existing functions keep working while
# the engine boundary is introduced incrementally.
_engine = CgraspEngine()
_asa_registry = _engine.asa_registry
_obj_registry = _engine.obj_registry
_discovery_cache = _engine.discovery_cache
_session_id_cache = _engine.session_id_cache
_flood_cache = _engine.flood_cache
_asa_lock = _engine.asa_lock
_obj_lock = _engine.obj_lock
_disc_lock = _engine.disc_lock
_sess_lock = _engine.sess_lock
_flood_lock = _engine.flood_lock

_DEFAULT_RESPONDER_LEISURE_MIN_MS = 50
_DEFAULT_RESPONDER_LEISURE_MAX_MS = 250


def _responder_leisure_seconds():
    """Return the RFC 7252 multicast response leisure in seconds.

    Uses the relay configuration when available so the CLI/config file controls
    both relay pacing and the local responder delay.
    """
    config = getattr(_coap_relay_state, "config", None) if _coap_relay_state is not None else None
    low = int(getattr(config, "responder_leisure_min_ms", _DEFAULT_RESPONDER_LEISURE_MIN_MS))
    high = int(getattr(config, "responder_leisure_max_ms", _DEFAULT_RESPONDER_LEISURE_MAX_MS))
    if high < low:
        low, high = high, low
    if high == low:
        return low / 1000.0
    return random.uniform(low, high) / 1000.0

# Optional: advertise CoAP-based unicast locators in Discovery responses.
# When enabled, local Discovery replies will advertise a CoAP URI locator
# (typically udp/5683) instead of the per-objective TCP listener port.
_advertise_coap_unicast = False
_advertise_coap_unicast_port = 5683
_advertise_coap_unicast_path = CGRASP_RESOURCE_PATH.strip("/")

# Optional: run an in-process CoAP endpoint for unicast negotiation/synchronization.
# When enabled, cGRASP will:
#  - advertise CoAP unicast locators in Discovery (set_advertise_coap_unicast)
#  - wrap Discovery/Flood multicasts in minimal CoAP (set_multicast_coap)
#  - replace TCP unicast sockets via the unicast socket factory hook
#  - start a local aiocoap server from _initialise_grasp()
_coap_transport_enabled = False
_coap_server_autostart = False
_coap_server_bind = "::1" if os.name == "nt" else "::"
_coap_server_port = 5683
_coap_server_path = CGRASP_RESOURCE_PATH.strip("/")
_coap_server_thread = None
_coap_server_started = False
_coap_server_loop = None
_coap_server_instance = None
_coap_server_bridge = None
_coap_server_ready = None
_coap_server_start_exc = None
_coap_fault_mode = ""
_coap_fault_remaining = 0
_coap_fault_installed = False

# Protocol-verification controls. Strict mode makes transport selection a
# contract: CoAP failures are surfaced and no TCP or legacy multicast path is
# allowed to run silently.
_strict_coap = False
_allow_tcp_fallback = True
_allow_legacy_multicast = True
# M_WAIT is outside the supported cGRASP negotiation profile. The parser keeps
# the message type so peers can be rejected deterministically, but negotiation
# no longer sends, waits on, polls for, or pushes after M_WAIT.
_transport_audit_lock = threading.Lock()
_transport_audit = {
    "coap_unicast_requests": 0,
    "coap_multicast_requests": 0,
    "coap_callback_requests": 0,
    "coap_callback_successes": 0,
    "tcp_connections": 0,
    "legacy_udp_messages": 0,
    "fallback_count": 0,
    "errors": [],
}


def reset_transport_audit():
    """Reset counters used to prove which transport path a test exercised."""
    with _transport_audit_lock:
        for key in _transport_audit:
            _transport_audit[key] = [] if key == "errors" else 0


def get_transport_audit():
    """Return a snapshot of transport counters and recorded errors."""
    with _transport_audit_lock:
        return copy.deepcopy(_transport_audit)


def get_coap_bridge_snapshot():
    """Return the inbound unicast bridge lifecycle snapshot, if active."""
    bridge = _coap_server_bridge
    return bridge.snapshot() if bridge is not None else None


def _audit_transport(key, detail=None):
    with _transport_audit_lock:
        if key == "errors":
            _transport_audit["errors"].append(str(detail))
        else:
            _transport_audit[key] = int(_transport_audit.get(key, 0)) + 1


def configure_coap_receive_fault(mode="", count=0):
    """Install a test-only receive hook before aiocoap handles a message.

    The hook runs after the UDP datagram has been received and is visible to
    tcpdump, but before aiocoap sends ACKs or dispatches the message to cGRASP.
    Supported modes:
      - drop-first-response: drop inbound CON 2.05 responses carrying M_RESPONSE
      - ignore-first-ack: drop inbound Empty ACKs
    """

    global _coap_fault_mode, _coap_fault_remaining
    global _coap_fault_installed

    _coap_fault_mode = str(mode or "")
    _coap_fault_remaining = max(0, int(count or 0))
    if not _coap_fault_mode or _coap_fault_remaining <= 0:
        return
    if _coap_fault_installed:
        return

    from .coap_multicast_adapter import install_receive_dispatch_hook

    def on_drop(_message):
        """Callback invoked when a queued CoAP message is dropped."""
        global _coap_fault_remaining
        _coap_fault_remaining -= 1
        _audit_transport("coap_test_receive_fault_drops")
        _audit_transport(f"coap_test_receive_fault_{_coap_fault_mode}")

    install_receive_dispatch_hook(
        observer=lambda _message: None,
        should_drop=lambda message: (
            _coap_fault_remaining > 0 and _coap_fault_should_drop(message)),
        on_drop=on_drop,
    )
    _coap_fault_installed = True


def _coap_fault_should_drop(message) -> bool:
    import aiocoap
    if _coap_fault_mode == "ignore-first-ack":
        return message.mtype is aiocoap.ACK and message.code is aiocoap.Code.EMPTY
    if _coap_fault_mode == "drop-first-response":
        if message.mtype is not aiocoap.CON or message.code is not aiocoap.Code.CONTENT:
            return False
        try:
            decoded = cbor.loads(_decrypt_msg(message.payload or b""))
            return isinstance(decoded, list) and len(decoded) >= 3 and decoded[0] == M_RESPONSE
        except Exception:
            return False
    return False

# Retained callback plumbing for historical compatibility only. The endpoint is
# no longer registered and the standard Discovery path never uses callback POST.
_coap_std_disc_reply_path = CGRASP_RESOURCE_PATH.strip("/")
_coap_std_disc_reply_query_port_key = "rp"
_coap_std_disc_reply_query_path_key = "rpath"


class _CoapTransportHandle:
    """Best-effort lifecycle handle for the in-process CoAP transport."""

    def stop(self, *, stop_server=True):
        """Stop the in-process CoAP transport (optionally its server)."""
        disable_coap_transport(stop_server=stop_server)
# _tls_required       #true if neither ACP nor QUADS is secure
# _crypto             #true if QUADS is secure
# _secure             #true if either ACP or TLS or QUADS is secure
# _rapid_supported    #true if rapid mode allowed
# _mcq                #FIFO for incoming multicasts
# _drq                #FIFO for pending discovery responses
# _my_address         #this node's preferred global address
# _my_link_local      #this node's preferred link local address
# _session_locator    #address used to disambiguate session ids (if initiator field used)
# _ll_zone_ids        #list of [IPv6 Zone (interface) index,LL address]
# _said_no_route      #flag used by watcher to limit printing
# _mcssocks           #list of multicast sending sockets
# _relay_needed       #True if multiple interfaces require Discovery/Flood relaying
# _mc_restart         #True if system wakeup detected - multicast listeners must restart
# _i_sent_it          #session ID of most recent discovery multicast, used in a hack
# _multi_asas         #flag used by ASA loader
# test_mode           #True iff module is running in test mode
# _listen_self        #True iff listening to own LL multicasts for testing
# _test_divert        #True to force a divert message from discovery
# _mess_check         #True to trigger message check diagnostics
# _make_invalid       #True to throw a test M_INVALID
# _make_badmess       #True to throw a malformed message
# _dobubbles          #True to enable bubble printing



####################################
# GRASP protocol constants         #
####################################

# Note: there is no reasonable way to define constants in Python.
# These objects could all be overwritten by programming errors.

M_NOOP = 0
M_DISCOVERY = 1
M_RESPONSE = 2
M_REQ_NEG = 3
M_REQ_SYN = 4
M_NEGOTIATE = 5
M_END = 6
M_WAIT = 7
M_SYNCH = 8
M_FLOOD = 9
M_INVALID = 99

O_DIVERT = 100
O_ACCEPT = 101
O_DECLINE = 102
O_IPv6_LOCATOR = 103
O_IPv4_LOCATOR = 104
O_FQDN_LOCATOR = 105
O_URI_LOCATOR = 106

F_DISC = 0    # valid for discovery
F_NEG = 1     # valid for negotiation
F_SYNCH = 2   # valid for synchronization
F_NEG_DRY = 3 # negotiation is dry-run


ALL_GRASP_NEIGHBORS_6 = ipaddress.IPv6Address('ff02::13')   # LL multicast
ALL_GRASP_NEIGHBORS_4 = ipaddress.IPv4Address('224.0.0.119') # LL multicast
GRASP_LISTEN_PORT = 7017 # IANA port number
GRASP_DEF_TIMEOUT = 60000 # milliseconds
GRASP_DEF_LOOPCT = 6
GRASP_DEF_MAX_SIZE = 2048 # max message size
CGRASP_LISTEN_PORT = 7018 # Assigned port number for cGRASP

_multicast_size = GRASP_DEF_MAX_SIZE
_unicast_size = GRASP_DEF_MAX_SIZE

_unspec_address = ipaddress.IPv6Address('::') # Used in special cases
                                              # to indicate link local

####################################
# Support for flag bits            #
####################################

def _bit(b):
    """Return integer with bit b on"""
    return 2**b

B_DISC = _bit(F_DISC)
B_NEG =  _bit(F_NEG)
B_SYNCH = _bit(F_SYNCH)
B_DRY = _bit(F_NEG_DRY)

def _flagword(obj):
    """Create the flags word for an objective"""
    _f = 0
    if obj.discoverable:
        _f = B_DISC
    if obj.neg:
        _f |= B_NEG
    if obj.synch:
        _f |= B_SYNCH
    if obj.dry:
        _f |= B_DRY
    return _f

def _flags(flagword):
    """Internal use only"""
    # return Boolean flags for an objective
    return bool(flagword&B_NEG), bool(flagword&B_SYNCH), \
           bool(flagword&B_DRY)

def _objective_supports(registered, requested):
    """Return True if a registered objective can serve the requested flags.

    A request may only require a capability that the registered objective
    advertises.  The previous check compared booleans pairwise and therefore
    accepted almost every request (e.g. two default-False flags matched).
    """
    for flag in ("neg", "dry", "synch"):
        if getattr(requested, flag, False) and not getattr(registered, flag, False):
            return False
    return True


####################################
# GRASP engine internal constants  #
####################################

_asaRegistryLimit = 100
_sessionCacheLimit = _asaRegistryLimit + 1000
_objRegistryLimit = 200
_discCacheLimit = 500
_discCacheDefTimeOut = 10*GRASP_DEF_TIMEOUT  # milliseconds
_floodCacheLimit = 100
_discQlimit = 10
_listenQlimit = 5
_multQlimit = 100
_minRelayGap = 500      # milliseconds (unused, intended for relay throttling)
_discTimeoutUnit = 100  # milliseconds (discovery timeout per hop)

####################################
# List offsets for raw message     #
# contents (for poor man's parsing)#
#                                  #
# These constants are used only in #
# the various _parse_ functions,   #
# _relay() and _ass_message()      #
####################################

_Op_Opt = 0 # option code in an option
_Op_Con = 1 # first specific item in an option
_Op_Proto = 2 # protocol number in a locator option
_Op_Port = 3  # port number in a locator option

_Pl_Msg = 0 # message type in a message payload
_Pl_Ses = 1 # session ID in a message payload
_Pl_Ini = 2 # initiator in a message payload
_Pl_Con = 2 # first specific item in a normal message payload
_Pl_TTL  = _Pl_Ini+1  # TTL in response or flood payload
_Pl_Rloc = _Pl_TTL+1  # locator option in response payload
_Pl_Robj = _Pl_Rloc+1 # objective in response payload
_Pl_FCon = _Pl_TTL+1  # list of [locator,objective] in flood payload
_Pl_Dobj = _Pl_Ini+1  # objective in discovery payload

_Fo_Fobj = 0 # objective in tagged objective in flood
_Fo_Floc = 1 # locator in tagged objective in flood

_Ob_Nam = 0 # name in an objective
_Ob_Flg = 1 # flags in an objective
_Ob_LCt = 2 # loop count in an objective
_Ob_Val = 3 # value object in an objective

####################################
# Error codes and English-language #
# error texts                      #
####################################

class _error_codes:
    """names for the error codes"""
    def __init__(self):
        self.ok = 0
        self.declined = 1 # "Declined"
        self.noReply = 2 # "No reply"
        self.unspec = 3 # "Unspecified error"
        self.ASAfull = 4 # "ASA registry full"
        self.dupASA = 5 # "Duplicate ASA name"
        self.noASA = 6 # "ASA not registered"
        self.notYourASA = 7 # "ASA registered but not by you"
        self.notBoth = 8 # "Objective cannot support both negotiation and synchronization"
        self.notDry = 9 # "Dry-run allowed only with negotiation"
        self.notOverlap = 10 # "Overlap not supported by this implementation"
        self.objFull = 11 # "Objective registry full"
        self.objReg = 12 # "Objective already registered"
        self.notYourObj = 13 # "Objective not registered by this ASA"
        self.notObj = 14 # "Objective not found"
        self.notNeg = 15 # "Objective not negotiable"
        self.noSecurity = 16 # "No security"
        self.noDiscReply = 17 # "No reply to discovery"
        self.sockErrNegRq = 18 # "Socket error sending negotiation request"
        self.noSession = 19 # "No session"
        self.noSocket = 20 # "No socket"
        self.loopExhausted = 21 # "Loop count exhausted"
        self.sockErrNegStep = 22 # "Socket error sending negotiation step"
        self.noPeer = 23 # "Negotiation peer not listening"
        self.CBORfail = 24 # "CBOR decode failure"
        self.invalidNeg = 25 # "Invalid Negotiate message"
        self.invalidEnd = 26 # "Invalid end message"
        self.noNegReply = 27 # "No reply to negotiation step"
        self.noValidStep = 28 # "No valid reply to negotiation step"
        self.sockErrWait = 29 # "Socket error sending wait message"
        self.sockErrEnd = 30 # "Socket error sending end message"
        self.IDclash = 31 # "Incoming request Session ID clash"
        self.notSynch = 32 # "Not a synchronization objective"
        self.notFloodDisc = 33 # "Not flooded and no reply to discovery"
        self.sockErrSynRq = 34 # "Socket error sending synch request"
        self.noListener = 35 # "Synchronization peer not listening"
        self.noSynchReply = 36 # "No reply to synchronization request"
        self.noValidSynch = 37 # "No valid reply to synchronization request"
        self.invalidLoc = 38 # "Invalid locator"
        self.sockErr = 39  # "Socket error sending gmessage"
errors = _error_codes()

etext = ["OK",
        "Declined",
        "No reply",
        "Unspecified error",
        "ASA registry full",
        "Duplicate ASA name",
        "ASA not registered",
        "ASA registered but not by you",
        "Objective cannot support both negotiation and synchronization",
        "Dry-run allowed only with negotiation",
        "Overlap not supported by this implementation",
        "Objective registry full",
        "Objective already registered",
        "Objective not registered by this ASA",
        "Objective not found",
        "Objective not negotiable",
        "No security",
        "No reply to discovery",
        "Socket error sending negotiation request",
        "No session",
        "No socket",
        "Loop count exhausted",
        "Socket error sending negotiation step",
        "Negotiation peer not listening",
        "CBOR decode failure",
        "Invalid Negotiate message",
        "Invalid end message",
        "No reply to negotiation step",
        "No valid reply to negotiation step",
        "Socket error sending wait message",
        "Socket error sending end message",
        "Incoming request Session ID clash",
        "Not a synchronization objective",
        "Not flooded and no reply to discovery",
        "Socket error sending synch request",
        "Synchronization peer not listening",
        "No reply to synchronization request",
        "No valid reply to synchronization request",
        "Invalid locator",
        "Socket error sending gmessage"
       ]

#############################################
#                                           #
# QUick And Dirty Secrecy for GRASP (QUADS) #
#                                           #
#############################################

# Global variables for QUADS

_crypto = False
_key = 0
_iv = 0
_cipher = None

def _ini_crypt(key=None, iv=None):
    """Internal use only: enable QUADS with a caller-supplied key and IV.

    There is no interactive password prompt.  Callers must pass a 32-byte key
    and a 16-byte IV, normally loaded from CGRASP_QUADS_KEY_FILE.
    """
    global _crypto, _key, _iv, _cipher
    if not _cryptography:
        tprint("Could not import cryptography: QUADS unavailable.")
        return
    if not key:
        raise ValueError("QUADS requires an explicit key and IV")
    if key == "No key":
        tprint("No encryption key: GRASP is insecure.")
        return
    _key = key
    _iv = iv
    backend = default_backend()
    _cipher = Cipher(algorithms.AES(_key), modes.CBC(_iv), backend=backend)
    _crypto = True
    return

def _encrypt_msg(raw):
    """Returns encrypted bytes"""
    if not _crypto:
        return raw
    padder = padding.PKCS7(128).padder()
    encryptor = _cipher.encryptor()
    msg = padder.update(raw) + padder.finalize()
    return encryptor.update(msg) + encryptor.finalize()

def _decrypt_msg(crypt):
    """Returns decrypted bytes"""
    if not _crypto:
        return crypt
    decryptor = _cipher.decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decryptor.update(crypt)) + unpadder.finalize()

####################################
#                                  #
# Registration functions           #
#                                  #
####################################

####################################
#
# Tell GRASP to skip initial dialogue
#
####################################

def skip_dialogue(testing=False, selfing=False, diagnosing=True,
                  quadsing=True, be_dull=False):
    """
####################################################################
# skip_dialogue(testing=False, selfing=False, diagnosing=True,
#               be_dull=False)
#
# A utility function that tells GRASP to skip some or all of its
# initial dialogue. Each parameter may be True, False or the string "ask".
# Default is:
# not test mode
# not listening to own multicasts
# printing message syntax diagnostics
# and not DULL
#
# Must be called before register_asa()
#
# No return value
#
# The quadsing parameter is obsolete (defined for compatibility)
####################################################################
"""
    global _skip_dialogue, test_mode, _listen_self, _mess_check, _be_dull
    if _grasp_initialised:
        return
    _skip_dialogue = True
    test_mode = testing
    _listen_self = selfing
    _mess_check = diagnosing
    _be_dull = be_dull       # too early to set the actual DULL flag


def set_multicast_coap(enabled=False, uri_path=("cgrasp", "mc")):
    """Enable/disable *legacy* CoAP-wrapped GRASP link-local multicasts.

    This keeps using GRASP's original LL multicast destination
    (ff02::13 / CGRASP_LISTEN_PORT) and merely wraps GRASP bytes inside a
    minimal CoAP message.

    For standard CoAP multicast (ff02::fd:5683) handled by aiocoap, use
    set_standard_coap_multicast().
    """
    global _use_coap_multicast, _coap_mc_uri_path
    _use_coap_multicast = bool(enabled)
    if uri_path is None:
        _coap_mc_uri_path = ()
    elif tname(uri_path) == "tuple":
        _coap_mc_uri_path = tuple(str(x) for x in uri_path)
    else:
        _coap_mc_uri_path = tuple(str(x) for x in str(uri_path).strip("/").split("/") if x)


def set_standard_coap_multicast(enabled=False, *, group=CGRASP_IPV6_MULTICAST_GROUP,
                                port=CGRASP_COAP_PORT, uri_path=CGRASP_RESOURCE_PATH):
    """Enable/disable standard CoAP multicast for cGRASP Discovery/Flood.

    When enabled, multicast send/receive uses aiocoap on udp/port (default 5683)
    to the IPv6 link-local group address (default ff02::fd) and Uri-Path
    (default /.well-known/grasp-coap).

    This enables a "one request, many responses" client model.
    """
    global _use_coap_std_multicast, _coap_std_mc_group, _coap_std_mc_port, _coap_std_mc_uri_path

    _use_coap_std_multicast = bool(enabled)
    _coap_std_mc_group = str(group).strip() if group else "ff02::fd"
    try:
        _coap_std_mc_port = int(port)
    except Exception:
        _coap_std_mc_port = 5683

    if uri_path is None:
        _coap_std_mc_uri_path = ()
    elif tname(uri_path) == "tuple":
        _coap_std_mc_uri_path = tuple(str(x) for x in uri_path)
    else:
        _coap_std_mc_uri_path = tuple(str(x) for x in str(uri_path).strip("/").split("/") if x)


def set_advertise_coap_unicast(enabled=False, port=5683, path=CGRASP_RESOURCE_PATH):
    """Control whether Discovery advertises CoAP unicast locators.

    If enabled, local Discovery responses (M_RESPONSE) will advertise a CoAP
    URI locator pointing to the given UDP port and path. This is intended for
    deployments where unicast negotiation/synchronization is carried over CoAP
    via an external bridge/shim (for example cgrasp_coap_transport.py).

    This does not change unicast transport by itself; it only changes what
    locators are advertised in Discovery responses.
    """
    global _advertise_coap_unicast, _advertise_coap_unicast_port, _advertise_coap_unicast_path
    _advertise_coap_unicast = bool(enabled)
    try:
        _advertise_coap_unicast_port = int(port)
    except Exception:
        _advertise_coap_unicast_port = 5683
    _advertise_coap_unicast_path = str(path).strip("/")


def _coap_remote_ifi_from_request(request):
    """Best-effort extract of inbound interface index from an aiocoap request."""
    try:
        ra = getattr(request, "remote", None)
        sockaddr = getattr(ra, "sockaddr", None)
        if sockaddr and len(sockaddr) > 3:
            return int(sockaddr[3])
    except Exception:
        pass
    return 0


def _coap_remote_ipv6_from_request(request):
    """Best-effort extract of remote IPv6 address from an aiocoap request."""
    # Prefer sockaddr: it reliably contains the source address.
    try:
        ra = getattr(request, "remote", None)
        sockaddr = getattr(ra, "sockaddr", None)
        if sockaddr and len(sockaddr) >= 1 and sockaddr[0]:
            host = str(sockaddr[0])
            if "%" in host:
                host = host.split("%", 1)[0]
            ip = ipaddress.ip_address(host)
            if isinstance(ip, ipaddress.IPv4Address):
                return ipaddress.IPv6Address("::ffff:" + host)
            return ip
    except Exception:
        pass

    # Fallback: parse hostinfo (format varies across aiocoap versions/transports).
    hostinfo = ""
    try:
        hostinfo = getattr(getattr(request, "remote", None), "hostinfo", "") or ""
    except Exception:
        hostinfo = ""

    host = ""
    if hostinfo.startswith("[") and "]" in hostinfo:
        host = hostinfo[1:hostinfo.index("]")]
    elif hostinfo.count(":") >= 2:
        # Looks like an IPv6 literal (no brackets).
        host = hostinfo
    elif ":" in hostinfo:
        # IPv4:port or hostname:port
        host = hostinfo.split(":", 1)[0]
    else:
        host = hostinfo

    host = (host or "").strip()
    if not host:
        return ipaddress.IPv6Address("::")
    if "%" in host:
        host = host.split("%", 1)[0]
    try:
        ip = ipaddress.ip_address(host)
        if isinstance(ip, ipaddress.IPv4Address):
            return ipaddress.IPv6Address("::ffff:" + host)
        return ip
    except Exception:
        return ipaddress.IPv6Address("::")


def _std_coap_mc_build_discovery_response(msg, from_ifi):
    """Build a GRASP M_RESPONSE for an inbound Discovery.

    Returns:
        (resp_bytes, is_rapid) or (None, False)
    """

    try:
        onum = msg.obj.num
    except Exception:
        return None, False

    _found = False
    _rapid = False
    _ttl = _discCacheDefTimeOut
    _found_obj = None
    _alist = None

    if not _test_divert:
        try:
            _obj_lock.acquire()
            for x in _obj_registry:
                if x.objective.num == onum and x.discoverable:
                    _found_obj = x.objective
                    _rapid = x.rapid
                    _ttl = x.ttl
                    if x.locators:
                        _alist = x.locators
                    else:
                        if x.local or (_my_address is None):
                            _a = None
                            for y in _ll_zone_ids:
                                if y[0] == from_ifi:
                                    _a = y[1]
                                    break
                        else:
                            _a = _my_address

                        if _advertise_coap_unicast:
                            host = str(_a) if _a is not None else "::1"
                            if _a is not None and getattr(_a, "is_link_local", False):
                                try:
                                    ifname = socket.if_indextoname(from_ifi)
                                except Exception:
                                    ifname = None
                                if ifname:
                                    host = host + "%25" + ifname
                            uri = f"coap://[{host}]:{int(_advertise_coap_unicast_port)}/{_advertise_coap_unicast_path.strip('/')}"
                            _aloc = asa_locator(uri, None, False)
                            _aloc.is_uri = True
                            _aloc.is_ipaddress = False
                            _aloc.is_fqdn = False
                            _aloc.protocol = socket.IPPROTO_UDP
                            _aloc.port = int(_advertise_coap_unicast_port)
                        else:
                            _aloc = asa_locator(_a, None, False)
                            _aloc.protocol = x.protocol
                            _aloc.port = x.port
                            _aloc.is_ipaddress = True
                        _alist = [_aloc]
                    _found = True
                    break
        finally:
            try:
                _obj_lock.release()
            except Exception:
                pass

    if _found and _alist is not None:
        _los = []
        for _aloc in _alist:
            try:
                if getattr(_aloc, "is_uri", False):
                    _los.append([O_URI_LOCATOR, _aloc.locator, _aloc.protocol, _aloc.port])
                elif getattr(_aloc, "is_fqdn", False):
                    _los.append([O_FQDN_LOCATOR, _aloc.locator, _aloc.protocol, _aloc.port])
                elif getattr(_aloc, "is_ipaddress", False):
                    _los.append([O_IPv6_LOCATOR, _aloc.locator.packed, _aloc.protocol, _aloc.port])
                else:
                    _los.append([O_IPv6_LOCATOR, _aloc.locator.packed, _aloc.protocol, _aloc.port])
            except Exception:
                pass

        if _rapid:
            return _ass_message(M_RESPONSE, msg.id_value, msg.id_source, _ttl, _los, _found_obj), True
        return _ass_message(M_RESPONSE, msg.id_value, msg.id_source, _ttl, _los), False

    if DULL:
        return None, False

    if getattr(msg.obj, "loop_count", GRASP_DEF_LOOPCT) <= 1:
        return None, False

    if _coap_relay_state is not None:
        cached = _coap_relay_state.get_responders(onum)
        if cached:
            divo = _option(O_DIVERT)
            _ttl = 0
            seen_locators = set()
            now = time.monotonic()
            for entry in cached:
                for locator in entry.locators:
                    if isinstance(locator, list) and locator and locator[0] in (
                            O_IPv6_LOCATOR, O_IPv4_LOCATOR, O_FQDN_LOCATOR, O_URI_LOCATOR):
                        locator_key = cbor.dumps(locator, canonical=True)
                        if locator_key in seen_locators:
                            continue
                        seen_locators.add(locator_key)
                        divo.embedded.append(locator)
                remaining = int((entry.expires_at - now) * 1000)
                if remaining > 0:
                    _ttl = remaining if _ttl == 0 else min(_ttl, remaining)
            if divo.embedded:
                return _ass_message(M_RESPONSE, msg.id_value, msg.id_source,
                                    _ttl or _discCacheDefTimeOut, divo), False

    # Not local: check discovery cache for divert.
    ll = False
    try:
        _disc_lock.acquire()
        for i in range(len(_discovery_cache)):
            x = _discovery_cache[i]
            if x.objective.num == onum:
                ll = x.asa_locators
                if ll:
                    del (_discovery_cache[i])
                    _discovery_cache.append(x)
                break
    finally:
        try:
            _disc_lock.release()
        except Exception:
            pass

    if not ll:
        return None, False

    _ttl = 0
    divo = _option(O_DIVERT)
    for y in ll:
        try:
            if y.is_ipaddress:
                if (not y.locator.is_link_local) and (y.expire > int(time.monotonic())):
                    lo = [O_IPv6_LOCATOR, y.locator.packed, socket.IPPROTO_TCP, y.port]
                    divo.embedded.append(lo)
                    if _test_divert:
                        break
            elif y.is_fqdn:
                divo.embedded.append([O_FQDN_LOCATOR, y.locator, y.protocol, y.port])
            elif y.is_uri:
                divo.embedded.append([O_URI_LOCATOR, y.locator])

            if y.expire > 0:
                if _ttl > 0:
                    _ttl = min(int((y.expire - time.monotonic()) * 1000), _ttl)
                else:
                    _ttl = int((y.expire - time.monotonic()) * 1000)
        except Exception:
            continue

    if _ttl == 0:
        _ttl = _discCacheDefTimeOut
    if len(divo.embedded):
        return _ass_message(M_RESPONSE, msg.id_value, msg.id_source, _ttl, divo), False
    return None, False


def _std_coap_relay_discovery(
        msg, from_ifi, *, upstream_remote=None, upstream_token=b"",
        upstream_request_context=None, cancel_event=None,
        response_callback=None):
    """Relay Discovery and return unchanged downstream M_RESPONSE payloads."""
    if (_coap_relay_state is None or msg.obj.loop_count <= 1 or
            (cancel_event is not None and cancel_event.is_set())):
        return []
    try:
        incoming = socket.if_indextoname(from_ifi)
    except Exception:
        incoming = str(from_ifi)
    key = DiscoveryKey(bytes(msg.id_source), msg.id_value)
    tx = _coap_relay_state.create_discovery(
        key, incoming_interface=incoming, upstream_remote=upstream_remote,
        upstream_token=bytes(upstream_token or b""),
        upstream_request_context=upstream_request_context)
    if tx is None:
        return []
    if cancel_event is not None and cancel_event.is_set():
        _coap_relay_state.close_discovery(key, reason="upstream_cancelled")
        return []

    forwarded_obj = _oclone(msg.obj)
    forwarded_obj.loop_count -= 1
    payload = _ass_message(M_DISCOVERY, msg.id_value, msg.id_source, forwarded_obj)
    responses = []

    def accept_reply(reply):
        """Accept a discovery reply into the response queue."""
        _sockaddr, raw, _token, _mid, code, branch_interface = reply
        if code != 69:  # CoAP 2.05 Content
            return None
        _coap_relay_state.count("response_received")
        learned_interface = incoming
        try:
            decoded = decode_message(_decrypt_msg(raw), max_size=_multicast_size)
            branch = _coap_relay_state.get_downstream(key, branch_interface)
            if branch is None:
                _coap_relay_state.count("response_unknown_branch")
                return None
            validation = _coap_relay_state.validate_transaction_response(
                key, decoded, expected_token=branch.token, received_token=_token)
            if not validation.accepted:
                return None
            parsed = _parse_msg(decoded)
            if not parsed or parsed.mtype != M_RESPONSE:
                return None
            if len(_sockaddr) > 3:
                try:
                    learned_interface = socket.if_indextoname(int(_sockaddr[3]))
                except Exception:
                    learned_interface = str(_sockaddr[3])
            locators = [option for option in decoded[4:]
                        if isinstance(option, list) and option and option[0] in (
                            O_IPv6_LOCATOR, O_IPv4_LOCATOR, O_FQDN_LOCATOR, O_URI_LOCATOR)]
            if locators:
                try:
                    _coap_relay_state.remember_responder(
                        msg.obj.num, locators, learned_interface,
                        max(1, int(parsed.ttl)), responder_identity=_sockaddr)
                    _coap_relay_state.count("responder_cache_learned")
                except Exception:
                    pass
        except Exception:
            return None
        if not _coap_relay_state.allow("response", learned_interface):
            return None
        _coap_relay_state.count("response_forwarded")
        if response_callback is not None:
            response_callback(raw)
        return raw

    try:
        from .coap_client import coap_fetch_multicast_collect_sync
        from .cgrasp_multicast import decode_message

        uris = _std_coap_mc_uris(exclude_ifi=from_ifi)

        def reserve_branch(branch_interface, exchange):
            """Reserve a downstream branch for a discovery response."""
            branch = _coap_relay_state.reserve_downstream(
                key, branch_interface, exchange)
            if branch is None:
                exchange.request_close()

        def bind_branch_token(branch_interface, token, exchange):
            """Bind a CoAP token to a reserved downstream branch."""
            branch = _coap_relay_state.bind_downstream_token(
                key, branch_interface, token, exchange)
            if branch is None:
                exchange.request_close()

        replies = coap_fetch_multicast_collect_sync(
            uris, payload,
            hard_timeout=_coap_relay_state.config.discovery_hard_timeout_ms / 1000,
            quiet_timeout=_coap_relay_state.config.discovery_quiet_timeout_ms / 1000,
            max_responses=_coap_relay_state.config.max_responses_per_transaction,
            on_exchange_created=reserve_branch,
            on_exchange_started=bind_branch_token,
            on_response=accept_reply if response_callback is not None else None,
        )
        if response_callback is None:
            for reply in replies:
                accepted = accept_reply(reply)
                if accepted is not None:
                    responses.append(accepted)
    finally:
        _coap_relay_state.close_discovery(key, reason="relay_complete")
    return responses


def _std_coap_mc_process_flood(msg, from_ifi):
    """Process an inbound Flood message (update flood cache)."""

    lobjs = msg.flood_list
    for lo in lobjs:
        if lo.loco:
            _locs = _opt_to_asa_loc(lo.loco, from_ifi, False)
            if len(_locs) == 1:
                _loc = _locs[0]
            else:
                tprint("Anomalous locator in flood ignored")
                _loc = asa_locator(None, None, False)
        else:
            _loc = asa_locator(None, None, False)

        if msg.ttl > 0:
            _loc.expire = int(time.monotonic() + msg.ttl / 1000)
        else:
            _loc.expire = 0

        obj = lo.obj
        obj = _detag_obj(obj)
        if obj.synch:
            _flood_lock.acquire()
            try:
                for j in range(len(_flood_cache)):
                    if _flood_cache[j].objective.num == obj.num and \
                       _flood_cache[j].source.locator == _loc.locator and \
                       _flood_cache[j].source.port == _loc.port:
                        _flood_cache[j] = None
                    elif _flood_cache[j].source.expire != 0 and \
                         _flood_cache[j].source.expire < int(time.monotonic()):
                        _flood_cache[j] = None

                j = 0
                while j < len(_flood_cache):
                    if _flood_cache[j] is None:
                        del _flood_cache[j]
                    else:
                        j += 1

                if len(_flood_cache) >= _floodCacheLimit:
                    del (_flood_cache[0])
                _flood_cache.append(tagged_objective(obj, _loc))
            finally:
                _flood_lock.release()


async def _std_coap_relay_flood_async(payload, msg, from_ifi):
    """Relay a standard CoAP Flood from inside aiocoap's event loop."""
    if msg.mtype != M_FLOOD:
        return
    try:
        loop_counts = [
            int(item[0][2])
            for item in payload[4:]
            if isinstance(item, list) and item and isinstance(item[0], list) and len(item[0]) > 2
        ]
        if loop_counts and min(loop_counts) <= 1:
            return
    except Exception:
        return
    try:
        from .cgrasp_multicast import decrement_loop_count
        from .coap_client import CoapClient
        forwarded = decrement_loop_count(payload)
    except Exception as ex:
        _audit_transport("errors", "standard CoAP flood relay prepare: " + repr(ex))
        return

    msg_bytes = _encrypt_msg(cbor.dumps(forwarded))
    path = "/".join(_coap_std_mc_uri_path)
    client = CoapClient()
    try:
        sent_interfaces = set()
        for info in _ll_zone_ids:
            outgoing_ifi = info[0]
            if outgoing_ifi == from_ifi or outgoing_ifi in sent_interfaces:
                continue
            sent_interfaces.add(outgoing_ifi)
            try:
                ifname = socket.if_indextoname(outgoing_ifi)
            except Exception:
                continue
            if _coap_relay_state is not None and not _coap_relay_state.allow("flood", ifname):
                continue
            uri = f"coap://[{_coap_std_mc_group}%{ifname}]:{int(_coap_std_mc_port)}/{path}"
            await client.post_many([uri], msg_bytes, content_format=60,
                                   no_response=FLOOD_NO_RESPONSE_VALUE, grace=0.02)
            _audit_transport("coap_multicast_requests")
    except Exception as ex:
        _audit_transport("errors", "standard CoAP flood relay async: " + repr(ex))
    finally:
        await client.close()


def _std_coap_mc_uris(*, exclude_ifi=0):
    """Build per-interface scoped multicast URIs for standard CoAP multicast."""
    uris = []
    seen_interfaces = set()
    path = "/".join(_coap_std_mc_uri_path)
    for _x in _ll_zone_ids:
        ifi = _x[0]
        if ifi in seen_interfaces:
            continue
        seen_interfaces.add(ifi)
        if exclude_ifi and ifi == exclude_ifi:
            continue
        try:
            ifname = socket.if_indextoname(ifi)
        except Exception:
            ifname = None
        if not ifname:
            continue
        if exclude_ifi and _coap_relay_state is not None and \
           not _coap_relay_state.allow("discovery", ifname):
            continue
        # NOTE: aiocoap expects the zone identifier in the form '%ifname' inside
        # the IPv6 literal (not '%25ifname').
        host = f"{_coap_std_mc_group}%{ifname}"
        uris.append(f"coap://[{host}]:{int(_coap_std_mc_port)}/{path}")
    return uris


def _std_coap_disc_reply_target_from_request(request, from_ifi):
    """Extract (port, path) for responder-initiated discovery replies.

    The discovery requester may include Uri-Query options:
      - rp=<port>
      - rpath=<path>
    """
    port = 5683
    path = _coap_std_disc_reply_path
    try:
        # aiocoap stores Uri-Query as a tuple of strings.
        qs = getattr(getattr(request, "opt", None), "uri_query", None) or ()
        for q in qs:
            if not q or "=" not in q:
                continue
            k, v = q.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k == _coap_std_disc_reply_query_port_key and v:
                try:
                    port = int(v)
                except Exception:
                    pass
            elif k == _coap_std_disc_reply_query_path_key and v:
                path = v.strip("/")
    except Exception:
        pass
    if not path:
        path = _coap_std_disc_reply_path
    return port, path


def _std_coap_disc_reply_requested(request) -> bool:
    """Return True if requester asked for responder-initiated POST replies."""
    try:
        qs = getattr(getattr(request, "opt", None), "uri_query", None) or ()
        for q in qs:
            if not q or "=" not in q:
                continue
            k, _v = q.split("=", 1)
            k = (k or "").strip()
            if k in (_coap_std_disc_reply_query_port_key, _coap_std_disc_reply_query_path_key):
                return True
    except Exception:
        pass
    return False


async def _std_coap_post_discovery_response(resp_bytes, *, request, from_addr, from_ifi, confirmable=False):
    """Send M_RESPONSE to the discovery requester as a CoAP POST with No-Response.

    IMPORTANT: This runs inside aiocoap's event loop (server handler), so it must
    be async. Do not call sync helpers here.
    """
    raise RuntimeError("Discovery callback POST is disabled; use the FETCH response")
    try:
        from .coap_client import CoapClient
    except Exception:
        return

    client = CoapClient()
    try:
        port, path = _std_coap_disc_reply_target_from_request(request, from_ifi)
        host = str(from_addr)
        if getattr(from_addr, "is_link_local", False) and from_ifi:
            try:
                ifname = socket.if_indextoname(from_ifi)
            except Exception:
                ifname = None
            if ifname:
                host = host + "%" + ifname
        uri = f"coap://[{host}]:{int(port)}/{str(path).strip('/')}"
        if test_mode:
            try:
                ttprint("STD-CoAP DISC POST-back ->", uri, "bytes=", len(resp_bytes) if resp_bytes else 0)
            except Exception:
                pass

        await client.post_many(
            [uri],
            resp_bytes,
            content_format=60,
            no_response=0x1F,
            confirmable=bool(confirmable),
            grace=0.02,
        )
        _audit_transport("coap_callback_requests")
        _audit_transport("coap_callback_successes")
    except Exception as ex:
        _audit_transport("errors", "discovery callback: " + repr(ex))
        if test_mode:
            try:
                ttprint("STD-CoAP DISC POST-back failed")
            except Exception:
                pass
    finally:
        try:
            await client.close()
        except Exception:
            pass


# ---- Minimal CoAP codec (enough for NON POST + NON CONTENT with Uri-Path) ----

_COAP_VER = 1
_COAP_TYPE_CON = 0
_COAP_TYPE_NON = 1

_COAP_CODE_EMPTY = 0
_COAP_CODE_POST = 2  # 0.02
_COAP_CODE_CONTENT = 69  # 2.05

_COAP_OPT_URI_PATH = 11
_COAP_OPT_NO_RESPONSE = 258  # RFC7967


def _coap_build(code, payload=b"", mid=None, token=b"", mtype=_COAP_TYPE_NON, uri_path=(), no_response=None):
    """Build a minimal CoAP message.

    Supports:
      - Version 1
      - Types CON/NON
      - Token length 0..8
            - Options: Uri-Path (11)
            - Options: No-Response (258, RFC7967)
      - Payload marker 0xFF
    """
    if token is None:
        token = b""
    if len(token) > 8:
        token = token[:8]
    if mid is None:
        mid = random.SystemRandom().randint(0, 0xFFFF)

    first = ((_COAP_VER & 0x03) << 6) | ((int(mtype) & 0x03) << 4) | (len(token) & 0x0F)
    out = bytearray()
    out.append(first)
    out.append(int(code) & 0xFF)
    out.extend(struct.pack("!H", int(mid) & 0xFFFF))
    out.extend(token)

    # Options: only Uri-Path
    last_opt_num = 0

    def _encode_ext(n):
        if n < 13:
            return (n, b"")
        if n < 269:
            return (13, bytes([n - 13]))
        return (14, struct.pack("!H", n - 269))

    def _add_option(opt_num, opt_value_bytes):
        nonlocal last_opt_num
        delta = int(opt_num) - int(last_opt_num)
        last_opt_num = int(opt_num)
        length = len(opt_value_bytes)

        dn, dext = _encode_ext(delta)
        ln, lext = _encode_ext(length)
        out.append(((dn & 0x0F) << 4) | (ln & 0x0F))
        out.extend(dext)
        out.extend(lext)
        out.extend(opt_value_bytes)

    if uri_path:
        for seg in uri_path:
            if seg is None:
                continue
            segb = str(seg).encode("utf-8")
            _add_option(_COAP_OPT_URI_PATH, segb)

    if no_response is not None:
        # Value is a uint; our uses fit in a single byte.
        _add_option(_COAP_OPT_NO_RESPONSE, bytes([int(no_response) & 0xFF]))

    if payload:
        out.append(0xFF)
        out.extend(payload)
    return bytes(out)


def _coap_parse(raw):
    """Parse minimal CoAP message -> (code, mid, token, payload_bytes).

    Raises on invalid encoding.
    """
    if raw is None or len(raw) < 4:
        raise ValueError("CoAP too short")
    b0 = raw[0]
    ver = (b0 >> 6) & 0x03
    if ver != _COAP_VER:
        raise ValueError("CoAP bad version")
    tkl = b0 & 0x0F
    if tkl > 8:
        raise ValueError("CoAP bad token length")
    code = raw[1]
    mid = struct.unpack("!H", raw[2:4])[0]
    idx = 4
    token = raw[idx : idx + tkl]
    idx += tkl

    # Skip options until payload marker or end
    current_opt = 0
    while idx < len(raw):
        if raw[idx] == 0xFF:
            idx += 1
            return code, mid, token, raw[idx:]

        if raw[idx] == 0x00:
            raise ValueError("CoAP option header 0")

        hb = raw[idx]
        idx += 1
        dn = (hb >> 4) & 0x0F
        ln = hb & 0x0F

        def _read_ext(n):
            nonlocal idx
            if n < 13:
                return n
            if n == 13:
                if idx >= len(raw):
                    raise ValueError("CoAP truncated ext")
                v = raw[idx] + 13
                idx += 1
                return v
            if n == 14:
                if idx + 1 >= len(raw):
                    raise ValueError("CoAP truncated ext")
                v = struct.unpack("!H", raw[idx : idx + 2])[0] + 269
                idx += 2
                return v
            raise ValueError("CoAP reserved ext")

        delta = _read_ext(dn)
        length = _read_ext(ln)
        current_opt += delta
        if idx + length > len(raw):
            raise ValueError("CoAP truncated option")
        idx += length

    return code, mid, token, b""


def _coap_wrap_mc_request(grasp_bytes):
    if not _use_coap_multicast:
        return grasp_bytes
    return _coap_build(_COAP_CODE_POST, payload=grasp_bytes, mtype=_COAP_TYPE_NON, uri_path=_coap_mc_uri_path)


def _coap_wrap_mc_response(grasp_bytes, token=b""):
    if not _use_coap_multicast:
        return grasp_bytes
    return _coap_build(_COAP_CODE_CONTENT, payload=grasp_bytes, token=token or b"", mtype=_COAP_TYPE_NON)


def _coap_wrap_mc_response_post(grasp_bytes, token=b"", no_response=0x1F):
    """Wrap a legacy discovery M_RESPONSE as a NON POST with No-Response.

    Used only when _use_coap_multicast is enabled (the minimal CoAP wrapper
    mode). The receiver unwraps CoAP and parses the payload as GRASP bytes.
    """
    if not _use_coap_multicast:
        return grasp_bytes
    return _coap_build(
        _COAP_CODE_POST,
        payload=grasp_bytes,
        token=token or b"",
        mtype=_COAP_TYPE_NON,
        uri_path=_coap_mc_uri_path,
        no_response=no_response,
    )


def set_unicast_socket_factory(factory=None):
    """Install (or clear) a unicast socket factory hook.

    This hook allows replacing cGRASP's built-in TCP unicast I/O with an
    alternate transport, while keeping the negotiation/synchronization state
    machines unchanged.

    The factory must return a *socket-like* object that supports:
    - settimeout(seconds)
    - sendall(data: bytes, flags=0)
    - recvfrom(bufsize)
    - close()

    The returned object may be a real socket, or a shim that maps the above
    operations onto a different protocol (e.g., CoAP request/response + polling).
    """
    global _unicast_socket_factory
    _unicast_socket_factory = factory


def enable_coap_transport(enabled=True, *, bind="::", port=5683, path=CGRASP_RESOURCE_PATH,
                          mc_uri_path=CGRASP_RESOURCE_PATH, autostart=True,
                          strict_coap=False, allow_tcp_fallback=None,
                          allow_legacy_multicast=None, standard_multicast=True,
                          enable_wait=False, relay_config=None):
    """Enable CoAP as the transport for cGRASP unicast + multicasts.

    When enabled:
      - Unicast negotiation/synchronization uses CoAP POST (via a socket factory shim)
        instead of per-objective TCP listeners.
      - Discovery/Flood link-local multicasts are wrapped in a minimal CoAP message.
      - Discovery replies advertise a CoAP URI locator pointing to (port,path).
      - A local CoAP server endpoint is started automatically from _initialise_grasp().

    M_WAIT is not part of the supported negotiation profile. The enable_wait
    keyword is accepted for older callers but is ignored.

    Call this before register_asa() for clean startup.

    Returns:
        A best-effort stop handle (with .stop()) when enabling, else None.
    """
    global _coap_transport_enabled, _coap_server_autostart
    global _coap_server_bind, _coap_server_port, _coap_server_path
    global _strict_coap, _allow_tcp_fallback, _allow_legacy_multicast
    global _coap_relay_config_override

    _coap_transport_enabled = bool(enabled)
    _coap_server_autostart = bool(autostart) and _coap_transport_enabled
    _coap_server_bind = str(bind)
    try:
        _coap_server_port = int(port)
    except Exception:
        _coap_server_port = 5683
    _coap_server_path = str(path).strip("/")
    _strict_coap = bool(strict_coap)
    _allow_tcp_fallback = (not _strict_coap) if allow_tcp_fallback is None else bool(allow_tcp_fallback)
    _allow_legacy_multicast = (not _strict_coap) if allow_legacy_multicast is None else bool(allow_legacy_multicast)
    # M_WAIT is not supported by the cGRASP negotiation profile. Keep the
    # keyword accepted for older callers, but never enable WAIT behavior.
    _coap_relay_config_override = relay_config

    if _strict_coap and (_allow_tcp_fallback or _allow_legacy_multicast or not standard_multicast):
        raise ValueError("strict_coap requires standard multicast and forbids TCP/legacy fallback")

    if not _coap_transport_enabled:
        return None

    # Prefer standard CoAP multicast for Discovery/Flood (aiocoap + ff02::fd:5683).
    # IMPORTANT: the standard multicast port is independent of the local unicast
    # CoAP server port. On a single host you may run multiple ASAs with different
    # unicast ports; they must still send discovery/flood multicasts to the
    # standard port so they can find each other.
    # Disable the legacy minimal wrapper mode to avoid ambiguous behaviour.
    set_multicast_coap(False)
    set_standard_coap_multicast(bool(standard_multicast), group=_coap_std_mc_group, port=_coap_std_mc_port, uri_path=mc_uri_path)

    # Discovery advertises CoAP URI locators so peers do not attempt TCP.
    set_advertise_coap_unicast(True, port=_coap_server_port, path=_coap_server_path)

    # If already initialised, start the CoAP server + install unicast shim now.
    if _grasp_initialised:
        _maybe_start_coap_transport()

    return _CoapTransportHandle()


def disable_coap_transport(*, stop_server=True, clear_multicast=True,
                           clear_advertisement=True, clear_unicast_factory=True):
    """Disable CoAP transport hooks and optionally stop the in-process server.

    Notes:
      - This clears the unicast socket factory hook so future unicast sessions
        use the built-in TCP sockets again.
      - This disables CoAP-wrapped multicasts and Discovery CoAP locator advertising.
      - It does not retroactively create TCP listeners for already-registered
        objectives that were registered while CoAP advertising was enabled.
        If you need to switch transports at runtime, re-register objectives.
    """
    global _coap_transport_enabled, _coap_server_autostart, _strict_coap
    global _coap_relay_config_override

    _coap_transport_enabled = False
    _coap_server_autostart = False
    _strict_coap = False
    _coap_relay_config_override = None

    if clear_multicast:
        set_multicast_coap(False)
        set_standard_coap_multicast(False)
    if clear_advertisement:
        set_advertise_coap_unicast(False)
    if clear_unicast_factory:
        set_unicast_socket_factory(None)

    if stop_server:
        _stop_coap_server()


def _maybe_start_coap_transport():
    """Internal use only: install unicast-over-CoAP and start CoAP server once."""
    global _coap_server_started

    if not (_coap_transport_enabled or _use_coap_std_multicast):
        return

    # Standard multicast depends on private aiocoap TokenManager behavior.
    # Reject an unreviewed version before starting a partially usable endpoint.
    if _use_coap_std_multicast:
        from .coap_multicast_adapter import assert_aiocoap_private_contract

        assert_aiocoap_private_contract()

    # Replace TCP unicast sockets with CoAP shim (req_negotiate/synchronize, etc.).
    if _coap_transport_enabled:
        try:
            from .cgrasp_coap_transport import install_cgrasp_unicast_over_coap

            install_cgrasp_unicast_over_coap(path=_coap_server_path, default_port=_coap_server_port)
        except Exception as ex:
            _audit_transport("errors", "unicast transport install: " + repr(ex))
            if _strict_coap:
                raise
            try:
                tprint("WARNING: cannot install cGRASP-over-CoAP unicast transport:", ex)
            except Exception:
                pass

    # Start the in-process CoAP endpoint to receive inbound unicast requests.
    if _coap_server_started:
        return

    try:
        _start_coap_server_in_thread(bind=_coap_server_bind, port=_coap_server_port, path=_coap_server_path)
        _coap_server_started = True
    except Exception as ex:
        _audit_transport("errors", "CoAP server start: " + repr(ex))
        if _strict_coap:
            raise
        try:
            tprint("WARNING: cannot start in-process CoAP server:", ex)
        except Exception:
            pass


def _start_coap_server_in_thread(*, bind="::", port=5683, path=CGRASP_RESOURCE_PATH):
    """Internal use only: run aiocoap server in a daemon thread."""
    global _coap_server_thread
    global _coap_server_bridge
    global _coap_server_ready, _coap_server_start_exc

    if _coap_server_thread is not None:
        return

    import asyncio

    import aiocoap
    from .cgrasp_coap_transport import CgraspCoapApiBridge
    from .coap_server import CoapServer

    _coap_server_ready = threading.Event()
    _coap_server_start_exc = None

    # Baseline cGRASP does not support GRASP-layer M_WAIT. A slow ASA response
    # is still allowed to use CoAP separate response semantics: this short
    # window only controls piggyback opportunity, while the longer bridge
    # timeout controls when the local responder is considered stalled.
    #
    # The ASA response timeout must be generous enough to accommodate network
    # delay (e.g. across network namespaces or containers) and multi-step
    # negotiation processing. GRASP_DEF_TIMEOUT (60 s) is the GRASP-layer
    # default; using 30 s here strikes a practical balance.
    bridge = CgraspCoapApiBridge(
        piggyback_response_wait_s=0.0,
        asa_response_timeout_s=30.0,
    )
    _coap_server_bridge = bridge

    multicast = []
    if _use_coap_std_multicast:
        multicast_interfaces = set()
        for _x in _ll_zone_ids:
            if _x[0] in multicast_interfaces:
                continue
            multicast_interfaces.add(_x[0])
            try:
                ifname = socket.if_indextoname(_x[0])
            except Exception:
                ifname = None
            if ifname:
                multicast.append((_coap_std_mc_group, ifname))

    srv = CoapServer(bind=(str(bind), int(port)), multicast=multicast)

    async def _disc_reply_handler(method, payload, request):
        """Receive responder-initiated POSTs carrying GRASP M_RESPONSE bytes."""
        if method != "POST":
            return (aiocoap.Code.METHOD_NOT_ALLOWED, b"POST only", 0)

        from_ifi = _coap_remote_ifi_from_request(request)
        from_addr = _coap_remote_ipv6_from_request(request)

        try:
            decoded = cbor.loads(_decrypt_msg(payload))
            msg = _parse_msg(decoded)
        except Exception:
            return (aiocoap.Code.BAD_REQUEST, b"", 0)

        if not msg or msg.mtype != M_RESPONSE:
            return (aiocoap.Code.BAD_REQUEST, b"", 0)

        if test_mode:
            try:
                ttprint(
                    "STD-CoAP DISC callback /.well-known/grasp-coap from",
                    str(from_addr),
                    "ifi=", from_ifi,
                    "sid=", getattr(msg, "id_value", None),
                )
            except Exception:
                pass

        try:
            sh = _session_handle(msg.id_value, msg.id_source)
            s = _get_session(sh)
            if s and getattr(s, "id_dq", None):
                try:
                    s.id_dq.put([from_addr, from_ifi, msg], block=False)
                    if test_mode:
                        try:
                            ttprint("STD-CoAP DISC enqueued callback for sid=", msg.id_value)
                        except Exception:
                            pass
                except Exception:
                    pass
            elif test_mode:
                try:
                    ttprint("STD-CoAP DISC callback dropped (no active session/queue) sid=", msg.id_value)
                except Exception:
                    pass
        except Exception:
            pass

        # The sender should set No-Response; still return a small success.
        return (aiocoap.Code.CHANGED, b"", 0)

    async def _unicast_handler(method, payload, request):
        if method != "POST":
            return (aiocoap.Code.METHOD_NOT_ALLOWED, b"POST only", 0)
        resp = await bridge.handle_post(payload, request)
        return (aiocoap.Code.CONTENT, resp or b"", 60)

    unicast_path_parts = tuple(x for x in str(path).strip("/").split("/") if x)
    multicast_path_parts = tuple(_coap_std_mc_uri_path)
    unified_resource_path = bool(_use_coap_std_multicast and unicast_path_parts == multicast_path_parts)
    if not unified_resource_path:
        srv.register(str(path), _unicast_handler)

    if _use_coap_std_multicast:
        async def _mc_handler(method, payload, request):
            if method not in ("POST", "FETCH"):
                return (aiocoap.Code.METHOD_NOT_ALLOWED, b"POST/FETCH only", 0)

            from_ifi = _coap_remote_ifi_from_request(request)
            from_addr = _coap_remote_ipv6_from_request(request)

            if test_mode:
                try:
                    qs = getattr(getattr(request, "opt", None), "uri_query", None) or ()
                    ttprint("STD-CoAP MC rx", method, "from", str(from_addr), "ifi=", from_ifi, "q=", qs)
                except Exception:
                    pass

            try:
                from .cgrasp_multicast import decode_message
                decoded = decode_message(_decrypt_msg(payload), max_size=_multicast_size)
                msg = _parse_msg(decoded)
            except Exception:
                return (aiocoap.Code.BAD_REQUEST, b"", 0)

            if not msg:
                return (aiocoap.Code.BAD_REQUEST, b"", 0)

            if getattr(request.opt, "content_format", None) != 60 or \
               not getattr(request.remote, "is_multicast_locally", False):
                return (aiocoap.Code.BAD_REQUEST, b"", 0)
            if msg.mtype == M_DISCOVERY and (
                    method != "FETCH" or request.mtype != aiocoap.NON or
                    getattr(request.opt, "no_response", None) is not None):
                return (aiocoap.Code.BAD_REQUEST, b"", 0)
            if msg.mtype == M_FLOOD and method != "POST":
                return (aiocoap.Code.BAD_REQUEST, b"", 0)

            # Mirror the classic UDP multicast handler behaviour: when running
            # with _listen_self enabled, do not answer our own discovery
            # multicasts (otherwise we can discover ourselves and pick the wrong
            # locator).
            try:
                if (not _listen_self) and (msg.mtype == M_DISCOVERY) and (msg.id_value == _i_sent_it) and not _multi_asas:
                    return (aiocoap.Code.VALID, b"", 0)
            except Exception:
                pass

            if DULL and not getattr(from_addr, "is_link_local", False):
                return (aiocoap.Code.NOT_FOUND, b"", 0)

            if msg.mtype == M_DISCOVERY:
                resp_bytes, is_rapid = _std_coap_mc_build_discovery_response(msg, from_ifi)
                if not resp_bytes:
                    return (aiocoap.Code.NOT_FOUND, b"", 0)

                if test_mode:
                    try:
                        ttprint("STD-CoAP MC discovery match; rapid=", bool(is_rapid), "sid=", msg.id_value)
                    except Exception:
                        pass

                # Discovery responses are ordinary responses to this FETCH.
                # TokenManager copies the request Token and the message layer
                # allocates a fresh MID. No Observe and no callback POST.
                return (aiocoap.Code.CONTENT, resp_bytes, 60)

            if msg.mtype == M_FLOOD:
                if request.mtype != aiocoap.NON or getattr(request.opt, "no_response", None) != FLOOD_NO_RESPONSE_VALUE:
                    return (aiocoap.Code.BAD_REQUEST, b"", 0)
                relay_seen = False
                if _relay_needed and _coap_relay_state is not None:
                    outgoing = []
                    outgoing_seen = set()
                    for info in _ll_zone_ids:
                        if info[0] != from_ifi and info[0] not in outgoing_seen:
                            outgoing_seen.add(info[0])
                            try:
                                outgoing.append(socket.if_indextoname(info[0]))
                            except Exception:
                                pass
                    relay_seen = _coap_relay_state.remember_flood(
                        FloodKey(bytes(msg.id_source), msg.id_value), str(from_ifi), outgoing)
                    if not relay_seen:
                        return (aiocoap.Code.CHANGED, b"", 0)
                try:
                    _std_coap_mc_process_flood(msg, from_ifi)
                except Exception:
                    pass
                if _relay_needed:
                    try:
                        await _std_coap_relay_flood_async(decoded, msg, from_ifi)
                    except Exception:
                        pass
                return (aiocoap.Code.CHANGED, b"", 0)

            return (aiocoap.Code.VALID, b"", 0)

        async def _mc_pipe_handler(request, pipe):
            from .coap_multicast_adapter import finish_pipe_silently
            # With the unified cGRASP URI, ordinary unicast CoAP requests and
            # multicast discovery/flood requests arrive at the same resource.
            # Keep unicast POST on the bridge path, while multicast FETCH/POST
            # continues through the multicast pipe path.
            if not getattr(request.remote, "is_multicast_locally", False):
                if request.code.name != "POST":
                    finish_pipe_silently(pipe)
                    return
                try:
                    resp = await bridge.handle_post(request.payload or b"", request)
                    response = aiocoap.Message(code=aiocoap.Code.CONTENT, payload=resp or b"")
                    response.opt.content_format = 60
                    pipe.add_response(response, is_last=True)
                except Exception:
                    response = aiocoap.Message(code=aiocoap.Code.INTERNAL_SERVER_ERROR, payload=b"")
                    pipe.add_response(response, is_last=True)
                return

            result = await _mc_handler(request.code.name, request.payload or b"", request)
            code, out_payload, content_format = result[:3]
            if code == aiocoap.Code.NOT_FOUND and _relay_needed:
                try:
                    decoded = cbor.loads(_decrypt_msg(request.payload or b""))
                    parsed = _parse_msg(decoded)
                    from_ifi = _coap_remote_ifi_from_request(request)
                    if parsed and parsed.mtype == M_DISCOVERY and parsed.obj.loop_count > 1:
                        relay_cancelled = threading.Event()
                        relay_key = DiscoveryKey(bytes(parsed.id_source), parsed.id_value)
                        server_loop = asyncio.get_running_loop()

                        async def emit_upstream(payload):
                            """Emit an upstream response onto the bridge queue."""
                            response = aiocoap.Message(
                                code=aiocoap.Code.CONTENT, payload=payload)
                            response.mtype = aiocoap.CON
                            response.opt.content_format = 60
                            pipe.add_response(response, is_last=False)

                        def stream_upstream(payload):
                            # The collector runs in a worker thread; marshal
                            # every accepted response onto the server Pipe's
                            # owning loop and wait until it has been emitted.
                            """Stream upstream responses from a worker thread to the bridge."""
                            future = asyncio.run_coroutine_threadsafe(
                                emit_upstream(payload), server_loop)
                            future.result()

                        try:
                            await asyncio.to_thread(
                                _std_coap_relay_discovery, parsed, from_ifi,
                                upstream_remote=request.remote,
                                upstream_token=bytes(request.token or b""),
                                upstream_request_context=pipe,
                                cancel_event=relay_cancelled,
                                response_callback=stream_upstream,
                            )
                        except asyncio.CancelledError:
                            relay_cancelled.set()
                            if _coap_relay_state is not None:
                                _coap_relay_state.close_discovery(
                                    relay_key, reason="upstream_cancelled")
                            raise
                        finish_pipe_silently(pipe)
                        return
                except Exception as ex:
                    _audit_transport("errors", "standard CoAP discovery relay: " + repr(ex))
            if code != aiocoap.Code.CONTENT:
                finish_pipe_silently(pipe)
                return
            # RFC 7252 multicast response leisure, configurable via RelayConfig.
            await asyncio.sleep(_responder_leisure_seconds())
            response = aiocoap.Message(code=code, payload=out_payload or b"")
            response.mtype = aiocoap.CON
            if content_format is not None:
                response.opt.content_format = content_format
            pipe.add_response(response, is_last=True)

        srv.register_pipe(_coap_std_mc_uri_path, _mc_pipe_handler)

    def _thread_main():
        global _coap_server_loop, _coap_server_instance, _coap_server_start_exc

        loop = asyncio.new_event_loop()
        relay_state = _coap_relay_state
        _coap_server_loop = loop
        _coap_server_instance = srv
        asyncio.set_event_loop(loop)
        if relay_state is not None:
            relay_state.bind_owner_loop(loop)
        try:
            loop.run_until_complete(srv.start())
            try:
                tprint(f"cGRASP-over-CoAP (in-process) listening: coap://[{bind}]:{int(port)}/{str(path).strip('/')}" )
            except Exception:
                pass
        except Exception as ex:
            _coap_server_start_exc = ex
        finally:
            _coap_server_ready.set()

        # Run until told to stop.
        try:
            loop.run_forever()
        finally:
            # Best-effort cleanup.
            try:
                loop.run_until_complete(srv.stop())
            except Exception:
                pass
            if relay_state is not None:
                try:
                    relay_state.unbind_owner_loop()
                except Exception:
                    pass
            try:
                loop.close()
            except Exception:
                pass

    _coap_server_thread = threading.Thread(target=_thread_main, daemon=True)
    _coap_server_thread.start()

    # Wait for server start (or failure) so callers can detect issues.
    if not _coap_server_ready.wait(timeout=5):
        raise RuntimeError(
            "cGRASP CoAP server did not become ready within 5 seconds")
    if _coap_server_start_exc is not None:
        raise _coap_server_start_exc


def _stop_coap_server(timeout_s=5.0):
    """Internal use only: stop the in-process CoAP server and its thread."""
    global _coap_server_thread, _coap_server_loop, _coap_server_instance
    global _coap_server_bridge
    global _coap_server_started, _coap_server_ready, _coap_server_start_exc

    if _coap_server_thread is None:
        _coap_server_started = False
        _coap_server_bridge = None
        return

    loop = _coap_server_loop
    srv = _coap_server_instance

    try:
        import asyncio

        if loop is not None and srv is not None:
            async def _shutdown():
                # Let the event loop finish handing any in-flight response to
                # the UDP transport before the socket is closed. Without this
                # yield, a responder that shuts down immediately after
                # end_negotiate() can drop the final CoAP response; the peer
                # then retransmits, receives ICMPv6 port-unreachable
                # (ECONNREFUSED) and reports a spurious transport error.
                try:
                    await asyncio.sleep(0)
                    await asyncio.sleep(0)
                except Exception:
                    pass
                try:
                    await srv.stop()
                except Exception:
                    pass

            fut = asyncio.run_coroutine_threadsafe(_shutdown(), loop)
            try:
                fut.result(timeout=timeout_s)
            except Exception:
                pass

        if loop is not None:
            try:
                loop.call_soon_threadsafe(loop.stop)
            except Exception:
                pass
    except Exception:
        # If asyncio tooling is unavailable for any reason, just try to stop loop.
        try:
            if loop is not None:
                loop.call_soon_threadsafe(loop.stop)
        except Exception:
            pass

    try:
        _coap_server_thread.join(timeout=timeout_s)
    except Exception:
        pass

    _coap_server_thread = None
    _coap_server_loop = None
    _coap_server_instance = None
    _coap_server_bridge = None
    _coap_server_ready = None
    _coap_server_start_exc = None
    _coap_server_started = False



def register_asa(asa_name):
    """
####################################################################
# register_asa(asa_name)
#
# Tells the GRASP engine that a new ASA is starting up.
# Also triggers GRASP initialisation if needed.
#
# return zero, asa_handle  if successful
# return errorcode, None if failure
#
# Note - the ASA must store the asa_handle (an opaque Python object)
# and use it in every subsequent GRASP call.
####################################################################
"""

    if not _grasp_initialised:
        _initialise_grasp()

    _asa_lock.acquire()
    if len(_asa_registry) >= _asaRegistryLimit:
        # no free space, fail
        _asa_lock.release()
        return errors.ASAfull, None
    elif ([clash for clash in _asa_registry if clash.name == asa_name]):
        # duplicate, fail
        _asa_lock.release()
        return errors.dupASA, None
    else:
        # append new one
        asa_handle = _new_session(None)
        new_asa = _asa_instance(asa_handle, asa_name)
        _asa_registry.append(new_asa)
        _asa_lock.release()
        return errors.ok, asa_handle



def deregister_asa(asa_handle, asa_name):
    """
####################################################################
# deregister_asa(asa_handle, asa_name)
#
# Tells the GRASP engine that an ASA is going away.
# Deregisters its objectives too.
# We need this to happen automatically when an ASA crashes.
#
# return zero if successful
# return errorcode if failure
####################################################################
"""
    # Stop all operations for this ASA (if registered with same PID)
    # and remove all relevant data.
    # (Need this to happen automatically if ASA exits)

    i = _retrieve_asa(asa_name)
    if i == -1:
        return errors.noASA
    elif (_asa_registry[i].handle != asa_handle):
        _asa_lock.release()
        return errors.notYourASA
    else:
        # Stops all operations for this ASA
        # by removing all registered objectives
        # and the ASA itself from their registries.
        # We have to keep the ASA lock for the whole time!

        _obj_lock.acquire()
        # The following loop looks unPythonesque, because
        # it shortens the list that it's looping over, so
        # it has to be done the old-fashioned way.
        j=0
        while j < len(_obj_registry):
            x = _obj_registry[j]
            if asa_handle in x.asa_id:
                x.asa_id.remove(asa_handle)
                if x.asa_id == []:
                    # last one - delete it, which shortens the list
                    del _obj_registry[j]
            else:
                j += 1
        _obj_lock.release()

        del _asa_registry[i]
        # mark the handle as inactive
        _update_session(_session_instance(asa_handle,False,None))
        _asa_lock.release()
        return errors.ok



def register_obj(asa_handle, obj, ttl=None, discoverable=False, \
                 overlap=False, local=False, rapid=False, locators=None):
    """
####################################################################
# register_obj(asa_handle, objective,ttl=None, discoverable=False,
#              overlap=False, local=False, locators=[])
#
# Store an objective that this ASA supports and may modify.
#
# The objective becomes available for discovery only after
# a call to listen_negotiate() or listen_synchronize()
# unless the optional parameter discoverable is True.
#
# ttl is discovery time to live in milliseconds; the default
# is the GRASP default timeout.
#
# if discoverable==True, the objective is *immediately* discoverable
# even if the ASA is not listening.
#
# if overlap==True, more than one ASA may register this objective.
#
# if local==True, discovery must return a link-local address
# (also applies in DULL mode)
#
# if rapid==True, supplied value should be used in rapid mode
# (only works for synchronization)
#
# locators is a list of explicit asa_locators, trumping normal
# discovery
#
# The ASA may negotiate the objective or send synch or flood data.
# (Not needed if the ASA only wants to receive synch or flood data.)
# May be repeated for multiple objectives.
#
# return zero if successful
# return errorcode if failure
####################################################################
"""

    if _no_handle(asa_handle):
        return errors.noASA
    if rapid:
        # Rapid Mode is outside the supported cGRASP baseline profile. Reject
        # it at registration instead of advertising behavior this engine does
        # not implement end to end.
        return errors.unspec
    if not isinstance(obj.num, int) or not 0 <= obj.num <= 0xFFFFFFFF:
        return errors.unspec
    if (obj.neg and obj.synch) or (obj.dry and obj.synch):
        return errors.notBoth
    if (not obj.neg) and obj.dry:
        return errors.notDry
# #    if overlap:
# #        return errors.notOverlap

    # Clone the objective to avoid unintended side effects:
    # the copy in the registry will be distinct from the instance
    # supplied by the ASA
    obj=_oclone(obj)

    # Search the registry to detect any duplicate
    _obj_lock.acquire()
    if len(_obj_registry) >= _objRegistryLimit:
        # no free space, fail
        _obj_lock.release()
        return errors.objFull

    for clash in _obj_registry:
        if clash.objective.num == obj.num:
            if clash.overlap_OK and overlap:
                # allowed overlap
                ttprint("Overlapping for", obj.num)
                clash.asa_id.append(asa_handle)
                _obj_lock.release()
                return errors.ok
            else:
                # disallowed overlap, fail
                _obj_lock.release()
                return errors.objReg

    # not previously registered, start a listener thread if needed
    if obj.neg or obj.synch or obj.dry:
        if _advertise_coap_unicast:
            # If unicast is carried over CoAP via an external bridge/shim,
            # do not start a per-objective TCP listener. Discovery should
            # advertise the CoAP port instead.
            listen_port = int(_advertise_coap_unicast_port)
        else:
            listen_sock=socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listen_sock.bind(('',0))
            listen_port = listen_sock.getsockname()[1]
            _tcp_listen(listen_sock).start()
    else:
        listen_port = 0
    # append new one
    new_obj = _registered_objective(obj, asa_handle)
    new_obj.overlap_OK = overlap
    new_obj.port = listen_port
    if _advertise_coap_unicast and (obj.neg or obj.synch or obj.dry):
        # Best-effort protocol hint for CoAP (UDP). Prefer URI locators.
        new_obj.protocol = socket.IPPROTO_UDP
    new_obj.discoverable = discoverable # whether it can be discovered immediately
    new_obj.local = local or DULL # whether it must be assigned a link-local address
    new_obj.rapid = rapid # whether it should support rapid mode
    if locators is None:
        locators = []
    new_obj.locators = list(locators)
    if tname(ttl) == "int" and ttl>0:
        new_obj.ttl = ttl
    _obj_registry.append(new_obj)
    _obj_lock.release()
    return errors.ok



def deregister_obj(asa_handle, obj):
    """
####################################################################
# deregister_obj(asa_handle, objective)
#
# Stops all operations on this objective (if registered)
# by removing it from the registry. (Except for an objective
# with overlapped registrations.)
#
# return zero if successful
# return errorcode if failure
####################################################################
"""

    if _no_handle(asa_handle):
        return errors.noASA
    _obj_lock.acquire()
    # Can't use a comprehension because we need the actual
    # list entry in order to delete it.
    for i in range(len(_obj_registry)):
        x =_obj_registry[i]
        if x.objective.num == obj.num:
            # found it
            if asa_handle not in x.asa_id:
                _obj_lock.release()
                return errors.notYourObj
            # deregister the ASA from the objective
            x.asa_id.remove(asa_handle)
            if x.asa_id == []:
                # last one - delete it, which shortens the list
                del _obj_registry[i]
            _obj_lock.release()
            return errors.ok
    _obj_lock.release()
    return errors.notObj

####################################
#                                  #
# Support function:                #
# Receive complete raw message     #
# from TCP socket.                 #
#                                  #
####################################

def _recvraw(sock):
    """Internal use only"""
    rawmsg, send_addr = sock.recvfrom(_unicast_size)
    if len(rawmsg) > 1200 and not getattr(sock, "message_oriented", False):
        # A stream socket may have returned only its first TCP segment. CoAP
        # transports expose one fully reassembled response per recvfrom(), so
        # probing them for a second "chunk" would incorrectly discard the
        # already complete Block2 payload boundary.
        # need to check for more chunks
        ttprint("First chunk length",len(rawmsg),"; waiting for more")
        _to = sock.gettimeout()
        sock.settimeout(0.2)
        while True:
            try:
                raw2, _ = sock.recvfrom(_unicast_size)
                if len(raw2):
                    rawmsg += raw2
                else:
                    break # no more bytes
            except Exception:
                break # timeout, assume there's nothing more
        sock.settimeout(_to)

# #        #need to check briefly for a second chunk
# #        ttprint("Raw chunk length",len(rawmsg),"; waiting for more")
# #        _to = sock.gettimeout()
# #        sock.settimeout(0.2)
# #        try:
# #            raw2, _ = sock.recvfrom(GRASP_DEF_MAX_SIZE)
# #            if len(raw2):
# #                rawmsg += raw2
# #        except:
# #            pass #timeout, assume there's nothing more
# #        sock.settimeout(_to)

    return rawmsg, send_addr

####################################
#                                  #
# Discovery functions              #
#                                  #
####################################



def discover(asa_handle, obj, timeout, flush=False, minimum_TTL=-1,
             relay_ifi=False, relay_shandle=None):
    """
##############################################################
# discover(asa_handle, objective, timeout)
#
# Call in separate thread if asynchronous operation required.
# timeout in milliseconds (None for default)
#
# If there are cached results, they are returned immediately.
# If not, results will be collected until the timeout occurs.
#
# Optional parameter flush=True will flush all cached results first
# Optional parameter minimum_TTL will flush stale cached results first
#
# Other optional parameters are for GRASP internal use only
#
# return zero, list of asa_locator if successful
#    If no peers discovered, list is []
# return errorcode, [] if failure
# Exponential backoff RECOMMENDED before retry.
##############################################################
"""
    global _i_sent_it
    if not relay_ifi:
        if not _secure and not DULL:
            return errors.noSecurity, [] # allowed in DULL mode
        errorcode = _check_asa_obj(asa_handle, obj, False)
        if errorcode:
            # raise RuntimeError("grasp.discover:"+etext[errorcode])
            return errorcode, []

    # In DULL mode we relax security checks, but we must NOT mutate the
    # caller's objective (it may be re-used for negotiation where loop_count
    # is semantically meaningful).
    _disc_loop_count = 1 if DULL else obj.loop_count

    if minimum_TTL > 0:
        # user's expiry deadline
        _exdl = int(time.monotonic()) + minimum_TTL/1000
    else:
        # normal expiry deadline is NOW
        _exdl = int(time.monotonic())

    _disc_lock.acquire()
    # Can't use a comprehension because we need the actual
    # list entry in order to delete it.
    for i in range(len(_discovery_cache)):
        x = _discovery_cache[i]
        if x.objective.num == obj.num:
            del(_discovery_cache[i])
            if flush or (minimum_TTL == 0):
                ttprint("Discover flushing",obj.num)
                break
            else:
                _discovery_cache.append(x)   # make it Most Recently Used
                if not _test_divert:
                    # delete any expired locators
                    j = 0
                    while len(x.asa_locators) > j:
                        _ex = x.asa_locators[j].expire
                        ttprint("Discovery expiry data:",obj.num,_ex, int(time.monotonic()))
                        if _ex and (_ex < _exdl):
                            ttprint("Deleting stale discovery",j)
                            del x.asa_locators[j]
                        else:
                            j += 1

                    # is there anything to return?
                    if len(x.asa_locators) > 0:
                        _found = copy.deepcopy(x.asa_locators)
                        _disc_lock.release()

                        # 20220429 - ignore cache entries discovered on same interface
                        # (RFC8990 section 2.5.4.3 2nd paragraph, last sentence)

                        if relay_ifi:
                            j = 0
                            while len(_found) > j:
                                if _found[j].ifi == relay_ifi:
                                    # Remove the entry
                                    ttprint("Ignoring LL discovery result", _found[j].locator)
                                    del _found[j]
                                else:
                                    j += 1

                        if len(_found) > 0:
                            return errors.ok, _found
    try:
        _disc_lock.release()
    except Exception:
        pass

    # Not already discovered (or flushed), launch discovery session

    if not relay_ifi:
        _initiator_locator = _session_locator
        try:
            if _ll_zone_ids:
                _initiator_locator = _ll_zone_ids[0][1]
        except Exception:
            _initiator_locator = _session_locator
        _sloc = _initiator_locator.packed
        disc_sess = _new_session(_initiator_locator)
        shandle=_session_handle(disc_sess,_sloc)
        # hack to detect own replies when running two instances
        _i_sent_it = disc_sess
        _to = _discTimeoutUnit*_disc_loop_count
        if not timeout:
            timeout = _to
        else:
            timeout = max(timeout, _to)
    else:
        # We are relaying, so cache remote session
        # We trust the timeout set by the relay process
        # (Note that if session is already cached, _insert_session will do nothing)
        shandle = relay_shandle
        disc_sess = shandle.id_value
        news = _session_instance(shandle.id_value,True,shandle.id_source)
        news.id_relayed = True
        _insert_session(news)


    # Prepare the message
    if relay_ifi:
        _sloc = shandle.id_source
    msg_bytes = _ass_message(M_DISCOVERY, disc_sess, _sloc, obj)

    # Standard CoAP multicast path: ff02::fd:5683 /.well-known/grasp-coap handled by aiocoap.
    if _use_coap_std_multicast:
        try:
            _maybe_start_coap_transport()
            from .coap_client import coap_fetch_multicast_collect_sync
            from .cgrasp_multicast import decode_message, response_digest
            uris = _std_coap_mc_uris(exclude_ifi=relay_ifi or 0)
            replies = coap_fetch_multicast_collect_sync(
                uris, msg_bytes,
                hard_timeout=max(0.001, float(timeout) / 1000.0),
                quiet_timeout=min(0.5, max(0.001, float(timeout) / 1000.0)),
                max_responses=_discQlimit,
            )
            _audit_transport("coap_multicast_requests")
            digests = set()
            for sockaddr, raw_response, _token, _mid, code, _branch_interface in replies:
                try:
                    decoded = decode_message(_decrypt_msg(raw_response), max_size=_multicast_size)
                    digest = response_digest(decoded)
                    if digest in digests:
                        continue
                    digests.add(digest)
                    parsed = _parse_msg(decoded)
                    if parsed and parsed.mtype == M_RESPONSE and \
                       parsed.id_value == disc_sess and parsed.id_source == _sloc:
                        from_ifi = sockaddr[3] if len(sockaddr) > 3 else 0
                        _drloop(int(from_ifi), parsed.ttl, parsed.options, parsed.obj, obj, False)
                except Exception:
                    continue
        except Exception as ex:
            _audit_transport("errors", "standard CoAP discovery: " + repr(ex))
            if _strict_coap or not _allow_legacy_multicast:
                _disactivate_session(shandle)
                raise RuntimeError("strict CoAP discovery failed") from ex
            _audit_transport("fallback_count")
        else:
            # Collect complete: extract results from discovery cache.
            _disc_lock.acquire()
            for x in _discovery_cache:
                if x.objective.num == obj.num:
                    answer = x.asa_locators
                    _disc_lock.release()
                    _disactivate_session(shandle)
                    return errors.ok, answer
            _disc_lock.release()

            _disactivate_session(shandle)
            ttprint("Returning empty discovery result")
            return errors.ok, []

    # In cGRASP we receive unicast discovery responses over UDP, not TCP.
    # Create a per-discovery UDP socket bound to an ephemeral port, send
    # multicasts on each interface (selected via scope id), then recvfrom()
    # replies on the same socket.
    dsock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    dsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if not _listen_self:
        dsock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
    dsock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
    dsock.bind(('', 0))

    # Send discovery multicast on all interfaces (except the source when relaying)
    for i in range(len(_ll_zone_ids)):
        ifi = _ll_zone_ids[i][0]
        if ifi != relay_ifi:
            ttprint("Sending discovery on interface", ifi)
            try:
                wire_bytes = _coap_wrap_mc_request(msg_bytes)
                _audit_transport("legacy_udp_messages")
                dsock.sendto(wire_bytes, 0, (str(ALL_GRASP_NEIGHBORS_6), CGRASP_LISTEN_PORT, 0, ifi))
            except Exception: # Might fail if CPU suspended etc; ignore and continue.
                tprint("MC socket failure in discover()")

    # Until timeout, wait for and handle UDP responses
    et = time.time() + timeout/1000
    while et > time.time():
        tleft = et - time.time()
        if tleft <= 0:
            break
        try:
            dsock.settimeout(tleft)
            rawmsg, send_addr = dsock.recvfrom(_unicast_size)

            # If multicast is CoAP-wrapped, responses are expected to be CoAP-wrapped too.
            if _use_coap_multicast:
                try:
                    _cc, _cmid, _ctok, _cpayload = _coap_parse(rawmsg)
                    if _cpayload:
                        rawmsg = _cpayload
                except Exception:
                    pass

            # send_addr is (host, port, flowinfo, scopeid) on IPv6
            from_ifi = send_addr[3] if len(send_addr) > 3 else 0

            # Parse message using existing GRASP parsing machinery
            payload = cbor.loads(_decrypt_msg(rawmsg))
            msg = _parse_msg(payload)

            if (msg.id_value == disc_sess) and (msg.id_source == _sloc):
                _drloop(from_ifi, msg.ttl, msg.options, msg.obj, obj, False)
            else:
                tprint("Discovery response to wrong session")

        except socket.timeout:
            pass
        except Exception:
            # Ignore malformed/irrelevant replies
            pass
    dsock.close()

    # when we get here the timeout has expired and anything
    # received is now in the discovery cache

    # extract results from discovery cache
    _disc_lock.acquire()
    for x in _discovery_cache:
        if x.objective.num == obj.num:
            answer = x.asa_locators
            _disc_lock.release()
            _disactivate_session(shandle)
            # garbage collect
            return errors.ok, answer
    _disc_lock.release()

    # no reply, return empty list
    _disactivate_session(shandle)
    ttprint("Returning empty discovery result")
    # garbage collect
    return errors.ok, []




def _drloop(ifi,ttl,options,rec_obj,obj,inDivert):
    """Internal use only"""
##################################
# internal function for discover()
# input is an option list and
# the relevant objective.
# recurse when Divert found
##################################
    # options is a list of grasp.option
    ttprint("Entering drloop")
    # ttprint("payload", payload)
    for opti in options:
        if opti.otype == O_DIVERT:
            ttprint("drloop got a Divert option", opti.embedded)
            # recurse on embedded list of options
            _drloop(ifi, ttl, opti.embedded, None, obj, True)
            # ttprint("back from recursion")
        else:
            alocs = _opt_to_asa_loc(opti, ifi, inDivert)
            if len(alocs) == 1:
                aloc = alocs[0]
            else:
                tprint("Anomalous locator option in drloop")

        # if we have something, complete the ASA locator
        # and add it to discovery cache entry for obj
        if 'aloc' in locals():
            aloc.protocol = opti.protocol
            aloc.port = opti.port
            aloc.expire = int(time.monotonic() + ttl/1000)
            _found = False
            _disc_lock.acquire()
            for x in _discovery_cache:
                if x.objective.num == obj.num:
                    ttprint("Adding locator to discovery cache for",obj.num)
                    # 20220316 - add check for duplicate
                    _duplicate = False
                    for existing in x.asa_locators:
                        if aloc.locator == existing.locator:
                            # same answer already in cache
                            _duplicate = True
                            ttprint("Found duplicate locator in discovery cache for",obj.num)
                            if aloc.expire > existing.expire:
                                # fresher reply, prefer it
                                existing.expire = aloc.expire
                    if not _duplicate:
                        x.asa_locators.append(aloc)
                    x.received = rec_obj # always prefer latest value
                    _found = True
                    break
            if not _found:
                ttprint("Adding objective to discovery cache for", obj.num)
                # add entry to discovery cache
                # but first, check length and garbage collect
                if len(_discovery_cache) >= _discCacheLimit:
                    del(_discovery_cache[0]) # delete Least Recently Used
                _new_do = _discovered_objective(obj,[aloc])
                _new_do.received = rec_obj
                _discovery_cache.append(_new_do)
            _disc_lock.release()


####################################
#                                  #
# Negotiation functions            #
#                                  #
####################################

def req_negotiate(asa_handle, obj, peer, timeout, noloop=False):
    """
##############################################################
# req_negotiate(asa_handle, obj, peer, timeout)
#
# Request negotiation session with a peer ASA.
#
# (DIFFERENT from the official API)
#
# asa_handle identifies the calling ASA
#
# obj is a GRASP objective including the requested value
#
# The objective's loop_count value should be set to a suitable
# value by the ASA. If not, the GRASP default will apply.
#
# peer is the target node, an asa_locator as returned by discover()
# If peer is None, discovery is performed first.
#
# timeout in milliseconds (None for default)
#
# noloop=True in order to use gsend() and grecv() for this session
#
# Launch in a new thread if asynchronous operation required.
#
# Four possible return conditions are possible:
#
# 1) return zero, None, objective
#
# The peer has agreed; the returned objective contains the agreed value.
#
# 2) return zero, session_handle, objective
#
# Negotiation continues.
#
# The returned objective contains the first value offered by the
# negotiation peer. This instance of the objective MUST be used in
# subsequent negotiation steps because it contains the loop count.
#
# The ASA MUST store the session_handle (an opaque Python object)
# and use it in the subsequent negotiation steps.
#
# 3) return errors.declined, None, string
#
# The peer declined further negotiation, the string gives a reason
# if provided by the peer.
#
# 4) For any non-zero errorcode except errors.declined:
#    return errorcode, None, None
#
# The negotiation failed, errorcode gives reason,
# exponential backoff RECOMMENDED before retry.
##############################################################
"""

    # check that objective is registered and is owned by
    # the calling ASA
    errorcode = _check_asa_obj(asa_handle, obj, False)
    if errorcode:
        return errorcode, None, None
    if not (obj.neg or obj.dry):
        return errors.notNeg, None, None
    # check that GRASP is running securely
    # (allowed in DULL mode for testing/experiments)
    if not _secure and not DULL:
        return errors.noSecurity, None, None

    if peer == None:
        # Caller did not supply locator, we can try discovery
        _, ll = discover(asa_handle, obj, timeout)
        if len(ll)==0:
            return errors.noDiscReply, None, None
        else:
            # choose the first locator discovered
            peer = ll[0]

    # got a peer

    # build a Request message for the peer

    if not timeout:
        timeout = GRASP_DEF_TIMEOUT

    # Create unicast session, assemble message and send it.
    # By default, cGRASP uses TCP sockets. If a unicast socket factory hook
    # is installed, it may return an alternate socket-like transport.
    neg_sess = _new_session(None)
    shandle = _session_handle(neg_sess,None)

    try:
        if _unicast_socket_factory:
            sock = _unicast_socket_factory(peer, neg_sess, "neg")
        else:
            if _strict_coap or not _allow_tcp_fallback:
                raise OSError("TCP negotiation disabled by strict CoAP mode")
            _audit_transport("tcp_connections")
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            if peer.locator.is_link_local:
                _ifi = peer.ifi
            else:
                _ifi = 0
            ttprint("Sending req_negotiate to",peer.locator, peer.port)
            sock.settimeout(5) # there should always be a listener
            sock.connect((str(peer.locator), peer.port,0,_ifi))

        msg_bytes = _ass_message(M_REQ_NEG, neg_sess, None, obj)
        sock.sendall(msg_bytes,0)
    except OSError as ex:
        tprint("Socket error sending negotiation request", ex)
        try:
            sock.close()
        except Exception:
            pass
        _disactivate_session(shandle)
        return errors.sockErrNegRq, None, None

    if noloop:
        # user wants to use session for grecv()/gsend()
        # first operation for this socket - hang it onto session
        #  - this is normally done by _negloop()
        sess = _get_session(shandle)
        if not sess:
            return errors.noSession, None, None
        sess.id_sock = sock
        _update_session(sess)
        return errors.noReply, shandle, None

    # call common code to wait for reply and handle it
    return _negloop(shandle, obj, timeout, sock, True)


def negotiate_step(asa_handle, shandle, obj, timeout):
    """
##############################################################
# negotiate_step(asa_handle, session_handle, objective, timeout)
#
# Continue negotiation session
#
# (DIFFERENT from the official API)
#
# objective contains the next proffered value
# Note that this instance of the objective
# MUST be used in the subsequent negotiation calls because
# it contains the loop count.
#
# timeout in milliseconds (None for default)
#
# return: exactly like req_negotiate
##############################################################
"""
    global _make_invalid
    global _make_badmess

    # check that objective is registered and is owned by
    # the calling ASA
    errorcode = _check_asa_obj(asa_handle, obj, False)
    if errorcode:
        return errorcode, None, None
    if not obj.neg:
        return errors.notNeg, None, None
    # check that GRASP is running securely
    # (allowed in DULL mode for testing/experiments)
    if not _secure and not DULL:
        return errors.noSecurity, None, None
    # verify session
    neg_sess = shandle.id_value
    s = _get_session(shandle)
    if not s:
        return errors.noSession, None, None
    # retrieve the socket
    sock = s.id_sock
    if sock == None:
        return errors.noSocket, None, None

    # loop count check
    # (loop count will be decremented in _negloop)
    if obj.loop_count <2:
        # no point continuing??????????
        # note that other end times out in this case
        return errors.loopExhausted, None, None

    if _make_invalid:  # this is a special hack for a test case only
        msg_bytes = _ass_message(M_INVALID, neg_sess, None, "Surprise!")
        sock.sendall(msg_bytes,0)
        _make_invalid = False


    # now send a negotiate message
    if _make_badmess: # this is a special hack for a test case only
        msg_bytes = _ass_message(M_NEGOTIATE, neg_sess, None, ["Rubbish"])
        _make_badmess = False
    else:
        msg_bytes = _ass_message(M_NEGOTIATE, neg_sess, None, obj)
    try:
        sock.sendall(msg_bytes,0)
    except OSError as ex:
        ttprint("Socket error sending negotiation step", ex)
        sock.close()
        _disactivate_session(shandle)
        return errors.sockErrNegStep, None, None

    if not timeout:
        timeout = GRASP_DEF_TIMEOUT

    # call common code to wait for reply and handle it
    return _negloop(shandle, obj, timeout, sock, False)





def _negloop(shandle, obj, timeout, sock, new_request):
    """Internal use only"""
############################################
# internal function for req_negotiate()
# and negotiate_step()
#
# waits for a negotiation response and
# handles it
#
# inputs are session handle, user's objective,
# user's timeout, open socket, and a flag
# set by req_negotiate
#
# return: exactly like req_negotiate
#
############################################

    neg_sess = shandle.id_value
    loopAgain = True
    while loopAgain:
        loopAgain = False  # will loop only if we get a Wait message
        try:
            sock.settimeout(timeout/1000)
            rawmsg, send_addr = _recvraw(sock)

            if len(rawmsg) == 0:
                sock.close()
                _disactivate_session(shandle)
                return errors.noPeer, None, None

            ttprint("negloop: raw reply:", rawmsg,"bytecount",len(rawmsg))
            try:
                payload = cbor.loads(_decrypt_msg(rawmsg))
            except Exception:
                sock.close()
                _disactivate_session(shandle)
                return errors.CBORfail, None, None
            ttprint("negloop: CBOR->Python:", payload)
            msg = _parse_msg(payload)
            if not msg:
                # invalid message, cannot process it
                tprint("Negotiate_step: invalid message format")
                sock.close()
                _disactivate_session(shandle)
                return errors.noValidStep, None, None

            if msg.id_value == neg_sess and new_request:
                # first operation for this socket - hang it onto session
                sess = _get_session(shandle)
                if not sess:
                    return errors.noSession, None, None
                sess.id_sock = sock
                _update_session(sess)

            if msg.mtype == M_INVALID:
                tprint("Got M_INVALID", msg.id_value, msg.content)
            elif msg.mtype == M_NEGOTIATE and msg.id_value == neg_sess:
                ttprint("negloop: got NEGOTIATE")
                rec_obj = msg.obj
                if rec_obj.dry:
                    ttprint("Received Dry")
                # decrement loop count
                rec_obj.loop_count -= 1
                rec_obj = _detag_obj(rec_obj)
                if (rec_obj.num == obj.num) and (rec_obj.neg == True):
                    return errors.ok, shandle, rec_obj # session and socket still open
                else:
                    sock.close()
                    _disactivate_session(shandle)
                    return errors.invalidNeg, None, None

            elif msg.mtype == M_WAIT and msg.id_value == neg_sess:
                sock.close()
                _disactivate_session(shandle)
                return errors.noValidStep, None, None

            elif msg.mtype == M_END and msg.id_value == neg_sess:
                ttprint("Negotiate_step: got END")
                # we're done
                sock.close()
                _disactivate_session(shandle)
                if msg.options[0].otype == O_ACCEPT:
                    return errors.ok, None, obj
                elif msg.options[0].otype == O_DECLINE:
                    return errors.declined, None, msg.options[0].reason
                else:
                    return errors.invalidEnd, None, None
            else:
                # if it isn't a valid message, ignore it
                ttprint("Negotiate_step: invalid negotiation response")
        except OSError as ex:
            sock.close()
            _disactivate_session(shandle)
            ttprint("Socket error receiving negotiation response", ex)
            return errors.noNegReply, None, None
    # if all else fails...
    sock.close()
    _disactivate_session(shandle)
    return errors.noValidStep, None, None




def negotiate_wait(asa_handle, shandle, timeout):
    """
##############################################################
# negotiate_wait(asa_handle, session_handle, timeout)
#
# Delay negotiation session
#
# timeout in milliseconds (None for default)
#
# return zero if successful
# return errorcode if failure
##############################################################
"""

    # M_WAIT is not supported by the baseline cGRASP negotiation profile.
    # Keep the API entry point so older callers get a deterministic error.
    return errors.unspec



def end_negotiate(asa_handle, shandle, result, reason=None):
    """
##############################################################
# end_negotiate(asa_handle, session_handle, result, reason="why")
#
# End negotiation session
#
# result = True for accept, False for decline
# reason = optional string describing reason for decline
#
# return zero if successful
# return errorcode if failure
#
# Note that a redundant call to end_negotiate will get an
# errorcode such as noSession, which does not need
# to be treated as an error.
##############################################################
"""
    # check that the calling ASA is registered
    if _no_handle(asa_handle):
        return errors.noASA
    # check that GRASP is running securely
    # (allowed in DULL mode for testing/experiments)
    if not _secure and not DULL:
        return errors.noSecurity
    # verify session
    s = _get_session(shandle)
    if not s:
        return errors.noSession
    # retrieve the socket
    sock = s.id_sock
    if sock == None:
        return errors.noSocket

    # now send an end message, close the socket etc & return
    if result:
        end_opt = _option(O_ACCEPT)
    else:
        end_opt = _option(O_DECLINE)
        end_opt.reason = reason
        ttprint("Set decline reason:",end_opt.reason)
    msg_bytes = _ass_message(M_END, s.id_value, None, [end_opt])
    try:
        sock.sendall(msg_bytes,0)
        sock.close()
        _disactivate_session(shandle)
    except OSError as ex:
        ttprint("Socket error sending end message", ex)
        sock.close()
        _disactivate_session(shandle)
        return errors.sockErrEnd
    return errors.ok


def send_invalid(asa_handle, shandle, info="No information"):
    """
##############################################################
# send_invalid(asa_handle, shandle, info="Diagnostic data")
#
# Send invalid message
#
# info = optional diagnostic data
#
# return zero if successful
# return errorcode if failure
#
# Ends the session abruptly.
# For use of this see M_INVALID in GRASP specification
##############################################################
"""
    # check that the calling ASA is registered
    if _no_handle(asa_handle):
        return errors.noASA
    # check that GRASP is running securely
    # (allowed in DULL mode for testing/experiments)
    if not _secure and not DULL:
        return errors.noSecurity
    # verify session
    s = _get_session(shandle)
    if not s:
        return errors.noSession
    # retrieve the socket
    sock = s.id_sock
    if sock == None:
        return errors.noSocket

    # now send an invalid message, close the socket etc & return
    msg_bytes = _ass_message(M_INVALID, s.id_value, None, info)
    try:
        sock.sendall(msg_bytes,0)
        sock.close()
        _disactivate_session(shandle)
    except OSError as ex:
        ttprint("Socket error sending end message", ex)
        sock.close()
        _disactivate_session(shandle)
        return errors.sockErrEnd
    return errors.ok



def listen_negotiate(asa_handle, obj):
    """
##############################################################
# listen_negotiate(asa_handle, objective)
#
# Instructs GRASP to listen for negotiation requests for the
# given objective. Its current value is not significant.
#
# This function will block waiting for an incoming request.
# Call in a separate thread if asynchronous operation required.
#
# This call only returns after an incoming negotiation request
# and must be followed by negotiate_step and/or negotiate_wait
# and/or end_negotiate.
# listen_negotiate must then be repeated to restart listening.
#
# return zero, session_handle, requested_objective
#
# The requested_objective contains the first value requested by the
# negotiation peer. Note that this instance of the objective
# MUST be used in the subsequent negotiation calls because
# it contains the loop count.
#
# The ASA MUST store the session_handle (an opaque Python object)
# and use it in the subsequent negotiation calls.
#
# return errorcode, None, None in case of error
##############################################################
"""

    # check that objective is registered and is owned by
    # the calling ASA
    errorcode = _check_asa_obj(asa_handle, obj, False)
    if errorcode:
        return errorcode, None, None
    if (not obj.neg) or (not obj.discoverable):
        return errors.notNeg, None, None
    # check that GRASP is running securely
    # (allowed in DULL mode for testing/experiments)
    if not _secure and not DULL:
        return errors.noSecurity, None, None

    # set up the listening queue
    q = None
    _obj_lock.acquire()
    for x in _obj_registry:
        if x.objective.num == obj.num:
            if not x.listening:
                # set status in objective registry and start listener
                x.discoverable = True # as from now, discovery is possible
                x.listening += 1
                x.listen_q = queue.Queue(_listenQlimit)
                q = x.listen_q
                # note that there is no separate listener thread as for listen_synchronize
                break
            else:
                # already listening, this is a reentrant listen
                x.listening += 1
                q = x.listen_q
                break
    _obj_lock.release()

    # now we start to listen right here in the calling thread


    # get next request from queue
    # what we find in the queue is [asock,send_addr,message]
    # message is a Request Neg message
    # asock is a connected TCP socket

    # we block here until a request arrives
    ttprint("listen_negotiate: Waiting for a negotiate request")
    rq = q.get()
    ttprint("listen_negotiate: Got negotiate request from queue")

    # no longer listening until called again, so
    # decrement listening count in objective registry
    # and garbage-collect the queue
    _obj_lock.acquire()
    for x in _obj_registry:
        if x.objective.num == obj.num:
            x.listening -= 1
    _obj_lock.release()
    del q

    # build the session instance and handle
    s_id = rq[2].id_value
    s_source = rq[1]
    s_handle = _session_handle(s_id,s_source.packed)
    # cache remote session along with socket
    news = _session_instance(s_id,True,s_source.packed)
    news.id_sock=rq[0]
    if _insert_session(news, _check_race = not (test_mode or _multi_asas)):
        # (we bypass the race condition check iff in test mode or multi ASA mode)
        # return proffered objective to caller
        prof_obj = rq[2].obj
        if prof_obj.dry:
            ttprint("Received Dry Request")
        return errors.ok, s_handle, _detag_obj(prof_obj)  # Negotiation starting
    else:
        # race condition clash between s_id and an existing session
        # this should be incredibly rare unless both sides are
        # using very poor random number generators
        return errors.IDclash, None, None

def stop_negotiate(asa_handle, obj):
    """
##############################################################
# stop_negotiate(asa_handle, objective)
#
# Instructs GRASP to stop listening for negotiation
# requests for the given objective.
#
# return zero if successful
# return errorcode if failure
##############################################################
"""

    # check that objective is registered and is owned by
    # the calling ASA

    errorcode = _check_asa_obj(asa_handle, obj, False)
    if errorcode:
        return errorcode

    # clear its listening status in objective registry
    _obj_lock.acquire()
    for x in _obj_registry:
        if x.objective.num == obj.num:
            x.listening = 0
    _obj_lock.release()
    return errors.ok

def gsend(asa_handle, shandle, message):
    """
##############################################################
# gsend(asa_handle, shandle, message)
#
# (NOT part of the official API)
#
# Sends over the socket for an opened negotiation session
#
# message is a Python object.
#
# return zero if successful
# return errorcode if failure
##############################################################
"""
    # check that the calling ASA is registered
    if _no_handle(asa_handle):
        return errors.noASA
    # check that GRASP is running securely
    # (allowed in DULL mode for testing/experiments)
    if not _secure and not DULL:
        return errors.noSecurity
    # verify session
    s = _get_session(shandle)
    if not s:
        return errors.noSession
    # retrieve the socket
    sock = s.id_sock
    if sock == None:
        return errors.noSocket
    else:
        # Convert message to CBOR, encrypt, and send
        try:
            # Convert message to CBOR, encrypt, and send
            sock.sendall(_encrypt_msg(cbor.dumps(message)),0)
            return errors.ok
        except OSError as ex:
            ttprint("Socket error in gsend", ex)
            sock.close()
            _disactivate_session(shandle)
            return errors.sockErr

def grecv(asa_handle, shandle, timeout):
    """
##############################################################
# grecv(asa_handle, shandle, timeout)
#
# (NOT part of the official API)
#
# Receives over the socket for an opened negotiation session
#
# return zero, message if successful
#     message is a Python object.
# return errorcode, None if failure
##############################################################
"""
    # check that the calling ASA is registered
    if _no_handle(asa_handle):
        return errors.noASA, None
    # check that GRASP is running securely
    # (allowed in DULL mode for testing/experiments)
    if not _secure and not DULL:
        return errors.noSecurity, None
    # verify session
    s = _get_session(shandle)
    if not s:
        return errors.noSession, None
    # retrieve the socket
    sock = s.id_sock
    if sock == None:
        return errors.noSocket, None
    else:
        try:
            sock.settimeout(timeout/1000)
            rawmsg, send_addr = _recvraw(sock)

            if len(rawmsg) == 0:
                sock.close()
                _disactivate_session(shandle)
                return errors.noPeer, None

            ttprint("grecv: raw reply:", rawmsg,"bytecount",len(rawmsg))
            try:
                payload = cbor.loads(_decrypt_msg(rawmsg))
            except Exception:
                sock.close()
                _disactivate_session(shandle)
                return errors.CBORfail, None
            ttprint("grecv: CBOR->Python:", payload)
            return errors.ok, payload

        except OSError as ex:
            sock.close()
            _disactivate_session(shandle)
            ttprint("Socket error receiving gmessage", ex)
            return errors.noReply, None



####################################
#                                  #
# Synchronization functions        #
#                                  #
####################################



def synchronize(asa_handle, obj, loc, timeout):
    """
##############################################################
# synchronize(asa_handle, obj, locator, timeout)
#
# Request synchronized value of the given GRASP objective.
#
# locator is an asa_locator as returned by discover()
#
# timeout in milliseconds (None for default)
#
# If the locator is None and the objective was already flooded,
# the first flooded value in the cache is returned.
#
# Otherwise, synchronization with a discovered ASA is performed.
# In that case, if the locator is None, discovery is performed,
# unless the objective is in the discovery cache already.
# If the discovery response provides a rapid mode objective,
# synchronization is skipped and that objective is returned
#
# This call should be repeated whenever the latest value is needed.
# Call in a separate thread if asynchronous operation required.
#
# Since this is essentially a read operation, any ASA can do
# it. GRASP checks that the ASA is registered, but the
# objective doesn't need to be registered by the calling ASA.
#
# return zero, synch_objective returns objective with its
# latest synchronized value
#
# return errorcode, None synchronization failed
#                        errorcode gives reason.
#                        Exponential backoff RECOMMENDED before retry.
##############################################################
"""

    if _no_handle(asa_handle):
        return errors.noASA, None
    if not obj.synch:
        return errors.notSynch, None
    if not _secure and not DULL:
        return errors.noSecurity, None # receiving a flood is allowed in DULL

    # Has the objective been flooded?

    if loc == None:
        _flood_lock.acquire()
        for x in _flood_cache:
            if x.objective.num == obj.num and \
               (x.source.expire == 0 or x.source.expire > int(time.monotonic())):
                _result = x.objective
                _flood_lock.release()
                return errors.ok, _result # return first unexpired flooded value
                # (Note that expired floods are garbage collected when
                # new flood multicasts are received, not here.)
        _flood_lock.release()

    # not flooded
    if not _secure and not DULL:
        return errors.noSecurity, None

    # we need to ask the network

    if not timeout:
        timeout = GRASP_DEF_TIMEOUT

    if loc == None:
        # Caller did not supply locator, we can try discovery
        _, ll = discover(asa_handle, obj, timeout)
        if len(ll)==0:
            return errors.notFloodDisc, None
        else:
            # choose the first locator discovered
            loc = ll[0]

    # Did a value arrive with the discovery response (i.e. rapid mode synch)?
    _disc_lock.acquire()
    for x in _discovery_cache:
        if x.objective.num == obj.num and x.received:
            # No need to execute synchronization
            _result = x.received
            _disc_lock.release()
            return errors.ok, _result # return rapid mode reply
    _disc_lock.release()

    # request synch from the given locator
    # By default, cGRASP uses TCP sockets. If a unicast socket factory hook
    # is installed, it may return an alternate socket-like transport.
    sync_sess = _new_session(None)
    shandle = _session_handle(sync_sess, None)
    try:
        if _unicast_socket_factory:
            sock = _unicast_socket_factory(loc, sync_sess, "syn")
        else:
            if _strict_coap or not _allow_tcp_fallback:
                raise OSError("TCP synchronization disabled by strict CoAP mode")
            _audit_transport("tcp_connections")
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            if loc.locator.is_link_local:
                _ifi = loc.ifi
            else:
                _ifi = 0
            ttprint("Sending request_syn to",loc.locator,loc.port,_ifi)
            sock.settimeout(5) # there should always be a listener
            sock.connect((str(loc.locator), loc.port,0,_ifi))

        msg_bytes = _ass_message(M_REQ_SYN, sync_sess, None, obj)
        sock.sendall(msg_bytes,0)
    except OSError as ex:
        tprint("Socket error sending synch request", ex)
        try:
            sock.close()
        except Exception:
            pass
        _disactivate_session(shandle)
        return errors.sockErrSynRq, None
    # now listen for reply
    try:
        sock.settimeout(timeout/1000)
        rawmsg, send_addr = _recvraw(sock)
        sock.close()
        if len(rawmsg) == 0:
            _disactivate_session(shandle)
            return errors.noListener, None
        ttprint("Synch: raw reply:", rawmsg)
        try:
            payload = cbor.loads(_decrypt_msg(rawmsg))
        except Exception:
            _disactivate_session(shandle)
            return errors.CBORfail, None
        msg = _parse_msg(payload)
        if not msg:
            # invalid message, cannot process it
            _disactivate_session(shandle)
            return errors.noValidSynch, None
        ttprint("Synch: CBOR->Python:", payload)
        if msg.mtype == M_SYNCH and msg.id_value == sync_sess:
            rec_obj = msg.obj
            rec_obj.loop_count -= 1
            if rec_obj.num == obj.num:
                _disactivate_session(shandle)
                return errors.ok, _detag_obj(rec_obj) # we're done!
        elif msg.mtype == M_END and msg.id_value == sync_sess and msg.options and \
             msg.options[0].otype == O_DECLINE:
            _disactivate_session(shandle)
            return errors.noListener, None
        else:
            # if it isn't a valid synch message, ignore it
            ttprint("Invalid synch response")
    except OSError as ex:
        sock.close()
        _disactivate_session(shandle)
        tprint("Socket error receiving synch message", ex)
        return errors.noSynchReply, None
    # all else fails...
    _disactivate_session(shandle)
    return errors.noValidSynch, None



def listen_synchronize(asa_handle, obj):
    """
##############################################################
# listen_synchronize(asa_handle, objective)
#
# Instructs GRASP to listen for synchronization
# requests for the given objective, and to
# respond with the objective value given in the call.
#
# This call should be repeated whenever the value changes.
#
# return zero if successful
# return errorcode if failure
##############################################################
"""

    # clone the objective to avoid unintended side effects
    obj = _oclone(obj)
    # check that objective is registered and is owned by
    # the calling ASA
    errorcode = _check_asa_obj(asa_handle, obj, True)
    if errorcode:
        return errorcode
    # check that sync and discovery are allowed
    if (not obj.synch) or (not obj.discoverable):
        return errors.notSynch
    # check that GRASP is running securely
    if not _secure and not DULL:
        return errors.noSecurity

    # ttprint("listen_synchronize: Obj value recvd:",obj.num,obj.value)
    _obj_lock.acquire()
    for x in _obj_registry:
        if x.objective.num == obj.num:
            # Set value in objective registry.
            # Note that this objective has not been transmitted
            # so the value does not need detagging.
            x.objective.value = obj.value
            # ttprint("listen_synchronize: Obj value set",i,obj.num,obj.value,_obj_registry[i].objective.value)
            if not x.listening:
                # set status in objective registry and start listener
                x.discoverable = True # as from now, discovery is possible
                x.listening = 1
                x.listen_q =  queue.Queue(_listenQlimit)
                _synch_listen(obj).start()
                break
    _obj_lock.release()

    return errors.ok



def _coap_immediate_synchronize_response(msg):
    """Internal use only.

    Build an M_SYNCH reply for the CoAP baseline profile.

    The TCP-era synchronize listener used a queue plus a listener thread. For
    CoAP baseline, M_REQ_SYN must not depend on GRASP-layer M_WAIT. This helper
    reads the latest value installed by listen_synchronize() and returns
    encoded M_SYNCH bytes when a matching synchronization listener exists.
    """

    try:
        if msg.mtype != M_REQ_SYN:
            return None
        objnum = msg.obj.num
        sid = msg.id_value
    except Exception:
        return None

    reply_obj = None
    _obj_lock.acquire()
    try:
        for x in _obj_registry:
            if x.objective.num != objnum:
                continue
            if not x.listening:
                break
            if not _objective_supports(x.objective, msg.obj):
                break
            reply_obj = _oclone(x.objective)
            break
    finally:
        _obj_lock.release()

    if reply_obj is None:
        return None
    return _ass_message(M_SYNCH, sid, None, reply_obj)



class _synch_listen(threading.Thread):
    """Internal use only"""
####################################################
# Listener thread for synch requests               #
#                                                  #
# This thread is invoked by listen_synchronize     #
# and must not be activated otherwise.             #
####################################################
    def __init__(self, obj):
        threading.Thread.__init__(self, daemon=True)
        self.obj = obj

    def run(self):
        # ttprint("synch_listen Obj in:", self.obj.num,self.obj.value)
        """Run the synchronization listener until stopped."""
        keep_going = True
        while keep_going:
            not_found = True
            _obj_lock.acquire()
            for x in _obj_registry:
                if x.objective.num == self.obj.num:
                    # we found our objective
                    # ttprint("synch_listen registry value:", x.objective.value)
                    not_found = False
                    if not x.listening:
                        # can stop listening and exit thread
                        _obj_lock.release()
                        keep_going = False
                    else:
                        # we're still listening
                        q = x.listen_q
                        _obj_lock.release()
                        # get next request from queue
                        # what we find in the queue is [asock,send_addr,message]
                        # message is a Request Synch message
                        # asock is a connected TCP socket
                        rq = q.get()

                        ttprint("Got synch request from queue")
                        # get the latest value from the registry
                        # (could have changed while we waited for the request)

                        # Note - we use this apparently pointless extra variable
                        # 'ovalue' because when testing inside a single node, there
                        # might be cases where the 'obj' parameter is the exact same
                        # object as the entry in '_obj_registry'
                        ovalue = None
                        _obj_lock.acquire()
                        for y in _obj_registry:
                            if y.objective.num == self.obj.num:
                                # ttprint("Objectives", y.objective, self.obj)
                                ovalue = y.objective.value
                                # ttprint("synch_listen Obj value:", ovalue)
                        # Note - this is the value stored in the registry so
                        # does not need detagging
                        self.obj.value = ovalue
                        _obj_lock.release()
                        # send back reply
                        msg_bytes = _ass_message(M_SYNCH, rq[2].id_value, None, self.obj)
                        try:
                            rq[0].sendall(msg_bytes,0)
                            ttprint("Sent Synch")
                        except OSError as ex:
                            ttprint("Synch socket failure",ex)
                        rq[0].close()
                        break

            # should never need to do this, but race conditions
            # could perhaps arise
            if not_found:
                _obj_lock.release()
                keep_going = False
        ttprint("Exit synch_listen thread")


def stop_synchronize(asa_handle, obj):
    """
##############################################################
# stop_synchronize(asa_handle, objective)
#
# Instructs GRASP to stop listening for synchronization
# requests for the given objective.
#
# return zero if successful
# return errorcode if failure
##############################################################
"""
    # check that objective is registered and is owned by
    # the calling ASA

    errorcode = _check_asa_obj(asa_handle, obj, True)
    if errorcode:
        return errorcode

    # clear its listening status in objective registry
    _obj_lock.acquire()
    for x in _obj_registry:
        if x.objective.num == obj.num:
            x.listening = 0
    _obj_lock.release()
    return errors.ok



def flood(asa_handle, ttl, *tagged_obj):
    """
##############################################################
# flood(asa_handle, ttl, *tagged_obj)
#
# Instructs GRASP to flood the given synchronization
# objective(s) and their value(s) to all GRASP nodes.
# Checks that the ASA registered each objective.
# This call may be repeated whenever the value changes.
#
# The tagged objective(s) are in the class tagged_objective,
# so must be tagged with a locator, which is either None or
# a valid asa_locator
#
# The 3rd parameter can be a list of [tagged_objective,]
# as per the official API, or a repeated parameter
# of type tagged_objective.
#
# If the first objective is tagged with the unspecified
# address, the entire flood is treated as link-local:
#
#  - the address in the locator is replaced by the
#    relevant link local address
#  - the loop count is forced to 1
#
# ttl is in milliseconds (0 = infinity)
#
# return zero if successful
# return errorcode if failure
##############################################################
"""

    if not _secure and not DULL:
        return errors.noSecurity # allowed in DULL mode

    # For compatibility between the experimental API and the
    # RFC API, we have to scan the inputs...
    tagged_objs = []
    for x in tagged_obj:
        if tname(x) == "tagged_objective":
            # assume experimental API
            tagged_objs.append(x)
        elif tname(x) == "list":
            # assume RFC API
            tagged_objs = x
            break
        else:
            return errors.unspec

    for x in tagged_objs:
        errorcode = _check_asa_obj(asa_handle, x.objective, True)
        if errorcode:
            return errorcode

    # Work on a deep copy: the loop-count forcing and per-interface locator
    # rewriting below must never mutate the caller's tagged_objective list.
    tagged_objs = copy.deepcopy(tagged_objs)

    if DULL or (tagged_objs[0].source and (tagged_objs[0].source.locator == _unspec_address)):
        tagged_objs[0].objective.loop_count = 1 # force link-local loop count

    _floodl = []

    for x in tagged_objs:
        if x.source == None:
            _l = [] # empty option
        elif x.source.locator == None:
            _l = [] # empty option
        elif x.source.is_ipaddress:
            # ttprint("Tagged obj source",x.source.locator, tname(x.source.locator))
            if tname(x.source.locator) == 'IPv6Address':  # fixed 20200408
                _l = [O_IPv6_LOCATOR, x.source.locator.packed, x.source.protocol, x.source.port]
            else:
                _l = [O_IPv4_LOCATOR, x.source.locator.packed, x.source.protocol, x.source.port]
        elif x.source.is_fqdn:
            _l = [O_FQDN_LOCATOR, x.source.locator, x.source.protocol, x.source.port]
        elif x.source.is_uri:
            _l = [O_URI_LOCATOR, x.source.locator, x.source.protocol, x.source.port]
        else:
            return errors.invalidLoc
        _floodl.append([x.objective, _l])
        # ttprint("Flood list:",_floodl)

    flood_session = _new_session(_session_locator)

    # ttprint("Flood TTL:",ttl)

    if not ttl:
        ttl = 0 # Make it an integer rather than None or False

    # Can't use a comprehension because we need the actual
    # list index in order select the correct socket.
    if _use_coap_std_multicast:
        try:
            from .coap_client import coap_post_many_sync

            path = "/".join(_coap_std_mc_uri_path)
            sent_interfaces = set()
            for i in range(len(_ll_zone_ids)):
                ifi = _ll_zone_ids[i][0]
                if ifi in sent_interfaces:
                    continue
                sent_interfaces.add(ifi)
                _send_floodl = copy.deepcopy(_floodl)
                for _o in _send_floodl:
                    _l = _o[1]
                    if _l != []:
                        if _l[1] == _unspec_address.packed:
                            _l[1] = _ll_zone_ids[i][1].packed  # replace with LL address
                msg_bytes = _ass_message(M_FLOOD, flood_session, _session_locator.packed, ttl, _send_floodl)
                try:
                    ifname = socket.if_indextoname(ifi)
                except Exception:
                    ifname = None
                if not ifname:
                    continue
                uri = f"coap://[{_coap_std_mc_group}%{ifname}]:{int(_coap_std_mc_port)}/{path}"
                coap_post_many_sync([uri], msg_bytes, content_format=60,
                                    no_response=FLOOD_NO_RESPONSE_VALUE, grace=0.02)
                _audit_transport("coap_multicast_requests")
        except Exception as ex:
            _audit_transport("errors", "standard CoAP flood: " + repr(ex))
            if _strict_coap or not _allow_legacy_multicast:
                _disactivate_session(_session_handle(flood_session, None))
                raise RuntimeError("strict CoAP flood failed") from ex
            _audit_transport("fallback_count")
        else:
            _disactivate_session(_session_handle(flood_session, None))
            return errors.ok

    for i in range(len(_ll_zone_ids)):
        _send_floodl = copy.deepcopy(_floodl)
        for _o in _send_floodl:
            _l = _o[1]
            if _l != []:
                if _l[1] == _unspec_address.packed:
                    _l[1] = _ll_zone_ids[i][1].packed # replace with LL address
        msg_bytes = _ass_message(M_FLOOD, flood_session, _session_locator.packed, ttl, _send_floodl)
        wire_bytes = _coap_wrap_mc_request(msg_bytes)
        try:
            _audit_transport("legacy_udp_messages")
            _mcssocks[i][1].sendto(wire_bytes,0,(str(ALL_GRASP_NEIGHBORS_6), CGRASP_LISTEN_PORT))
        except Exception: # might fail if CPU suspended etc
            ttprint("MC socket failure in flood()")
            _fixmcsock(i)
    _disactivate_session(_session_handle(flood_session, None))
    return errors.ok

def get_flood(asa_handle, obj):
    """
##############################################################
# get_flood(asa_handle, objective)
#
# Request unexpired flooded values of the given objective.
#
# This call should be repeated whenever the value is needed.
#
# Since this is essentially a read operation, any ASA can do
# it. GRASP checks that the ASA is registered, but the
# objective doesn't need to be registered by the calling ASA.
#
# return zero, tagged_objectives   returns a list of tagged_objective
#
# return errorcode, None call failed
#                        errorcode gives reason.
#                        Exponential backoff RECOMMENDED before retry.
##############################################################
"""

    if _no_handle(asa_handle):
        return errors.noASA, None
    if not obj.synch:
        return errors.notSynch, None

    # Collect list of unexpired flooded tagged_objective
    # (Note that expired floods are garbage collected when
    # new flood multicasts are received, not here.)

    _l = []  # Initialise empty list

    _flood_lock.acquire()
    for x in _flood_cache:
        if x.objective.num == obj.num and \
           (x.source.expire == 0 or (x.source.expire > int(time.monotonic()))):
            _l.append(x)
    _flood_lock.release()

    return errors.ok, _l

def expire_flood(asa_handle, tagged_obj):
    """
##############################################################
# expire_flood(asa_handle, tagged_obj)
#
# Mark a flooded objective as expired
#
# This is a call that can only be used after a preceding
# call to get_flood() by an ASA that is capable of deciding
# that the flooded value is stale or invalid. To be used
# with care.
#
# tagged_obj   the tagged_objective to be expired
#
# return zero if successful
# return errorcode if failure
##############################################################
"""

    if _no_handle(asa_handle):
        return errors.noASA

    # (Note that expired floods are garbage collected when
    # new flood multicasts are received, not here.)
    _flood_lock.acquire()
    for x in _flood_cache:
        if (x == tagged_obj) and (x.source.expire > 0):
            x.source.expire = int(time.monotonic())-1
    _flood_lock.release()

    return errors.ok

# ######### END OF OFFICIAL API FUNCTIONS ###########

####################################
#                                  #
# Internal functions               #
#                                  #
####################################

def _hexit(xx):
    """Internal use only - bytes to hex ASCII"""
    if tname(xx) == "bytes":
        return binascii.b2a_hex(xx)
    elif tname(xx) == "list":
        for i in range(len(xx)):
            xx[i] = _hexit(xx[i])
    return(xx)

def tprint(*whatever,ttp=False):
    """Log a diagnostic message with thread context.

    Kept as ``tprint`` for source compatibility with the legacy CLI code, but
    library output now goes through the ``cgrasp`` logger instead of stdout.
    """

    # NOTE: Older code tried to parse threading.current_thread()'s string
    # representation. That is not stable across Python versions and may
    # contain multiple '(' characters, causing ValueError. Use the thread
    # object's fields directly.
    thr = threading.current_thread()
    label = getattr(thr, "name", "MainThread")
    tid = threading.get_ident()

    parts = []
    for x in whatever:
        try:
            if test_mode:  # want bytes printed in hex
                try:
                    xx = _hexit(copy.deepcopy(x))  # avoid overwriting anything
                except Exception:
                    xx = x  # cannot be deep copied (example: cbor2.CBORTag)
            else:
                xx = x
            parts.append(str(xx))
        except Exception:
            # in case UTF-8 string (or something else) can't be formatted
            parts.append("[unprintable]")

    _s = " ".join(parts)
    _LOGGER.info("%s %s %s", label, tid, _s)

    if _dobubbles and not ttp:
        # Queue the text for bubble printing
        if len(_s) > 200:
            _s = _s[:200] + ' ...'  # truncate to fit
        try:
            _bubbleQ.put(_s, block=False)
        except Exception:
            pass  # Skip it if queue is full
    return


def ttprint(*whatever):
    """Utility function for thread-safe printing in test mode only,
used exactly like print()"""

    if test_mode:
        tprint(*whatever,ttp=True)
    return

######################################
#
# Package to speak in bubbles
#
######################################


def init_bubble_text(cap):
    """
    Utility function to enable bubble printing, which uses tkinter.
    cap: a string that labels the bubble window.
    """

#------------
# Classes and functions

    class speakEasy:
        """Simple class to describe a message

        x, y: (int) anchor point for the message
        txt: (string) text of the message
        i: after drawing, canvas item for image
        j: after drawing, canvas item for text"""

        def __init__(self, x, y, txt):
            self.x = x     # coordinates
            self.y = y
            self.txt = txt # words

    def draw_bubble(can, bubble):
        """
        can : tkinter canvas
        bubble : a speakEasy object
        """

        # print("Drawing x",bubble.x,"y",bubble.y,"text",bubble.txt)
        bubble.i=can.create_image((bubble.x, bubble.y), image=_bubblim)

        bubble.j=can.create_text((bubble.x-180,bubble.y-80), font=_myfont,
                             text=bubble.txt, anchor=tk.NW,width=_wrap_at)


    def raise_bubble(can, bubble):
        """
        can : tkinter canvas
        bubble : a speakEasy object
        """
        bubble.y -=step
        can.move(bubble.i,0,-step)
        can.move(bubble.j,0,-step)
        return

    class bubbler(threading.Thread):
        """Internal use only"""
        def __init__(self, cap):
            threading.Thread.__init__(self, daemon=True)
            self.cap = cap

        def run(self):

            """Run the bubble-text UI thread until stopped."""
            global _bubblim, _logoim, _myfont, _bigstring, _bigstring2

            try:
                # make a window
                # Validate caption first
                _c=self.cap
                if _c == "":
                    _c=" GRASP" # default caption if blank
                elif _c[0] in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                    _c = " "+_c # get round 'feature' in Tk
                root = tk.Tk(className=_c)

                # make images and a font
                _bubblim = tk.PhotoImage(data=_bigstring)
                _logoim = tk.PhotoImage(data=_bigstring2)
                del _bigstring
                del _bigstring2
                _myfont = font.Font(family='Arial',size=12,weight='bold')

                # set an icon
                root.tk.call('wm', 'iconphoto', root._w, _logoim)

                # window on top (doesn't work in all cases)
                root.lift()

                # size the window
                root.geometry(str(HEIGHT)+"x"+str(WIDTH))

                # make a canvas
                can = tk.Canvas(root)
                can.config(background=backgroundCol) # colour it
                can.pack(fill=tk.BOTH, expand=1) # always full size

                # draw blank canvas
                root.update_idletasks()
                root.update()
                bubbles = [] # empty message list
                _looping = True
                _pause = 0
            except Exception:
                tprint("Could not start Tkinter")
                _looping = False

            while _looping:

                # Check print queue unless pausing
                if _pause <= 0:
                    try:
                        _tx = _bubbleQ.get(block=False)

                        # Build a bubble
                        _m=speakEasy(random.randrange(250,270),int(HEIGHT-70),_tx)

                        # Raise existing bubbles
                        for i in range(len(bubbles)):
                            if i==len(bubbles)-1:
                                # Extra raise for the most recent
                                raise_bubble(can,bubbles[i])
                            raise_bubble(can,bubbles[i])

                        # Draw the new one
                        draw_bubble(can,_m)
                        # Add new one to the display list
                        bubbles.append(_m)

                        # Delete the oldest one if off screen
                        if bubbles[0].y<-2*step:
                            can.delete(bubbles[0].i)
                            can.delete(bubbles[0].j)
                            del bubbles[0]
                        # tprint(len(bubbles),"bubbles now")

                        # Ask for a display pause
                        _pause = int(FRAMERATE/2)
                    except Exception:
                        pass

                # Decrement pause
                if _pause > 0:
                    _pause -= 1

                # Update our display
                if bubbles != []:
                    try:
                        root.update_idletasks()
                        root.update()
                    except Exception:
                        _looping=False # Somebody closed the window

                # Wait before next loop
                time.sleep(1/FRAMERATE)

            # Exiting
            tprint("Bubbles over")
            # #_dobubbles = False ##That was a bug, must never restart bubbles!

    #--------------
    # constants and global vars
    global _dobubbles, _bubblim, _myfont, _wrap_at

    if _dobubbles:
        return  # can only start tkinter once

    WIDTH = 500
    HEIGHT = 500
    _wrap_at = 350 # width for text wrap
    step = 50 # how much to raise a bubble each time
    FRAMERATE = 10
    # make a random colour for the background
    r=random.randrange(1,255)
    g=random.randrange(1,255)
    b=random.randrange(1,255)
    backgroundCol="#{0:02x}{1:02x}{2:02x}".format(r,g,b)
    _bubblim = None
    _logoim = None
    _myfont = None
    _dobubbles = True
    # start a thread to do the work
    bubbler(cap).start()

    return


####################################
# ASA registry  functions          #
####################################

def _retrieve_asa(asa_name):
    """Internal use only"""
####################################
# Retrieve an ASA entry by name    #
#                                  #
# return index in registry         #
# RETURNS WITH _asa_lock ACQUIRED!  #
# return -1 if nonesuch            #
####################################
    _asa_lock.acquire()
    asa_ct = len(_asa_registry)
    for i in range(asa_ct):
        if asa_name == _asa_registry[i].name:
            return i
    _asa_lock.release()
    return -1



def _no_handle(asa_handle):
    """Internal use only"""
####################################
# Check a handle                    #
#                                  #
# return True if handle is absent   #
####################################
    # don't think we need the lock for this
    return not([x for x in _asa_registry if x.handle == asa_handle])



def _check_asa_obj(asa_handle, obj, sending_synch):
    """Internal use only"""
####################################
# Check a calling ASA              #
#                                  #
# Return errorcode if              #
# - objective invalid              #
# - ASA unregistered               #
# - ASA doesn't own the objective  #
#  (for negotiation)               #
####################################
    if obj.neg and obj.synch:
        return errors.notBoth
    if sending_synch and not obj.synch:
        return errors.notSynch
    if _no_handle(asa_handle):
        return errors.noASA
    _obj_lock.acquire()
    if (obj.neg or sending_synch) and not([x for x in _obj_registry if x.objective.num == obj.num and asa_handle in x.asa_id]):
        _obj_lock.release()
        return errors.notYourObj
    _obj_lock.release()

    return errors.ok

####################################
# Session ID cache functions       #
####################################

_prng = random.SystemRandom() # best PRNG we can get
def _new_session(locator):
    """Internal use only"""
####################################
# Create and insert a new Session
# in state active, local
# _new_session(locator) returns integer
####################################
    with _sess_lock:
        for i in range(10):
            # x = _prng.randint(0, 0xffffff) #old 24 bit version
            x = _prng.randint(0, 0xffffffff)
            # does _session_id_cache contain an id_value = x?
            if not([clash for clash in _session_id_cache if clash.id_value == x]):
                if locator == None:
                    _session_id_cache.append(_session_instance(x,True,None))
                else:
                    _session_id_cache.append(_session_instance(x,True,locator.packed))
                return x
    # If we're here, something is deeply suspect and we have to give up.
    # The lock has been released by the ``with`` block, so callers cannot
    # deadlock after this exception.
    raise RuntimeError("Ten successive pseudo-random session ID clashes")




def _insert_session(session_inst, _check_race = False):
    """Internal use only"""
####################################
# Insert a Session ID entry        #
#                                  #
# return True if successful        #
#                                  #
# set _check_race to check for     #
# race condition                   #
####################################
    new_id = session_inst.id_value
    # check for a clash
    _sess_lock.acquire()

    if ([clash for clash in _session_id_cache if clash.id_value == new_id]):
        # duplicate, need to check source address
        _sess_lock.release()
        if _check_race:
            return False # incredibly unlikely race condition, do nothing
        clash = _get_session(_session_handle(new_id,session_inst.id_source))
        # the following test is because in theory the session could have
        # just been deleted by another thread...
        if clash:
            if clash.id_source == session_inst.id_source:
                # now we have a confirmed clash, cannot continue
                return False
        # duplicate has a different source address (or it vanished)
        # so we can continue
        _sess_lock.acquire()
    session_ct = len(_session_id_cache)
    if session_ct >= _sessionCacheLimit:
        # try to free a space
        for i in range(session_ct):
            if not _session_id_cache[i].id_active:
                # found first inactive entry - delete it and append new one
                del _session_id_cache[i]
                _session_id_cache.append(session_inst)
                _sess_lock.release()
                return True
        # no free space, fail
        tprint("Session cache overflow!")
        _sess_lock.release()
        return False
    else:
        # append new one
        _session_id_cache.append(session_inst)
        _sess_lock.release()
        return True



def _get_session(shandle):
    """Internal use only"""
####################################
# Get a Session ID entry by ID and #
# source locator                   #
#                                  #
# _get_session(_session_handle)     #
# return False if not found active #
# else return _session_instance    #
####################################
    _sess_lock.acquire()
    for s in _session_id_cache:
        if shandle.id_value == s.id_value and shandle.id_source == s.id_source and s.id_active:
            _sess_lock.release()
            return s
    _sess_lock.release()
    return False



def _update_session(session_inst):
    """Internal use only"""
####################################
# Update a Session ID entry        #
#                                  #
# return True if successful        #
####################################
    old_id = session_inst.id_value
    old_src = session_inst.id_source
    _sess_lock.acquire()
    session_ct = len(_session_id_cache)
    for i in range(session_ct):
        if old_id == _session_id_cache[i].id_value and old_src == _session_id_cache[i].id_source:
            _session_id_cache[i] = session_inst
            _sess_lock.release()
            return True
    # no such ID/source, fail
    _sess_lock.release()
    return False



def _disactivate_session(shandle):
    """Internal use only"""
####################################
# Disactivate a Session ID entry   #
#                                  #
# parameter is _session_handle      #
#                                  #
# ignores mismatch                 #
# returns nothing                  #
####################################
    s = _get_session(shandle)
    if s:
        s.id_active = False
        _update_session(s)
    return

def _ass_obj(x):
    """Internal use only"""
######################################
# Assemble an objective ready for CBOR
######################################

    obj_flags = _flagword(x)
    _val = x.value
    if tname(_val) == "bytes":
        # see if user supplied value as CBOR bytes
        try:
            _ = cbor.loads(_val)
            # seems to be valid CBOR, build Tag 24
            _val = CBORTag(24, _val)
        except Exception: # not valid CBOR, we'll send the raw bytes
            pass
    return [x.num, obj_flags, x.loop_count, _val]

def _ass_opt(x):
    """Internal use only"""
######################################
# Assemble an option ready for CBOR
######################################
    if tname(x) == "_option":
        _opt = [x.otype]
        if x.otype == O_DIVERT:
            ttprint("Assembling O_DIVERT")
            for y in x.embedded:
                ttprint("Assembling an O_DIVERT locator")
                _opt.append(_ass_opt(y))
        elif x.otype == O_DECLINE and x.reason:
            _opt.append(x.reason)
        elif x.otype in (O_IPv4_LOCATOR,O_IPv6_LOCATOR,O_FQDN_LOCATOR,O_URI_LOCATOR):
            _opt.append(x.locator)
            _opt.append(x.protocol)
            _opt.append(x.port)
        return _opt
    elif tname(x) == "list":
        # assume it's already assembled (legacy code, should be redundant)
        return x
    else:
        # not valid
        return [M_INVALID]


def _ass_message(msg_type, session_id, initiator, *whatever):
    """Internal use only"""
####################################
# Assemble a CBOR message          #
#                                  #
# returns CBOR bytes               #
####################################

    # Initialise message with type and session idenntifier
    msg =[msg_type, session_id]

    # Insert initiator in Discovery, Response and Flood
    if msg_type in (M_DISCOVERY, M_RESPONSE, M_FLOOD):
        msg.append(initiator) # must be already packed

    # Insert remaining contents
    for x in whatever:
        if tname(x) in ("objective", "cobjective"):
            # needs to be embedded as a list object
            # (cGRASP uses numeric objectives; legacy GRASP uses name strings)
            msg.append(_ass_obj(x))
        elif tname(x) == "_option":
            # some option (e.g. for M_DIVERT)  20220316
            msg.append(_ass_opt(x))
        elif tname(x) == "list":
            if msg_type == M_FLOOD:
                for y in x:
                    msg.append([_ass_obj(y[_Fo_Fobj]),y[_Fo_Floc]]) # objective & locator option
            else:
                # lazy code: assume we have a list of options
                # and insert them
                for o in x:
                    msg.append(_ass_opt(o))
        elif msg_type in (M_WAIT, M_FLOOD, M_RESPONSE):
            msg.append(x) # insert timeout (first time round the for-loop)
        elif msg_type == M_INVALID:
            msg.append(x) # insert arbitrary content

        # more cases to be added if new GRASP messages or options are defined

    ttprint("Assembled Python message", msg)

    # Convert to CBOR bytes
    msg_bytes = cbor.dumps(msg)
    ttprint("Assembled CBOR message:",msg_bytes)
    return _encrypt_msg(msg_bytes)


def _detag_obj(x):
    """Internal use only"""
####################################
# If value is embedded CBOR, remove tagging.
# Call this before storing or returning
# a received objective.
# If called twice on the same objective,
# it is a no-op.
####################################

    try:
        if x.value.tag != 24:
            # wrong tag, return it as is
            return x
        x.value = x.value.value
    except Exception: # no tag, return it as is
        pass
    return x

#########################################
#########################################
# Inbound message parsing functions
#########################################
#########################################


def _parse_diag(*e):
    """Internal use only"""
#########################################
# Print diagnostic for invalid syntax
#########################################
    if _mess_check:
        s=''
        for x in e:
            s += str(x)+' '
        tprint("Message parsing error:", s)



def _parse_obj(obj):
    """Internal use only
       -> received objective, or None if invalid
"""
#########################################
# Check if received objective is in valid
# format, after CBOR decoding. Parse it.
#########################################
    if tname(obj) != 'list':
        _parse_diag("Objective is not a list")
        return None # not a list
    if len(obj) not in (_Ob_Val,_Ob_Val+1):
        _parse_diag("Objective has wrong length")
        return None # invalid length
    if tname(obj[_Ob_Nam]) not in ('int','str') or \
       tname(obj[_Ob_Flg]) != 'int' or \
       tname(obj[_Ob_LCt]) != 'int':
        _parse_diag("Objective has wrong types")
        return None # wrong type
    # no rules about the value field, so nothing to check
    try:
        # cGRASP: numeric objective number
        if tname(obj[_Ob_Nam]) == 'int':
            o = cobjective(int(obj[_Ob_Nam]))
            o.discoverable = True
            o.neg, o.synch, o.dry = _flags(obj[_Ob_Flg])
            o.loop_count = obj[_Ob_LCt]
            try:
                o.value = obj[_Ob_Val]
            except Exception:
                o.value = None
            return o

        # Legacy GRASP: string objective name (best-effort)
        # If the legacy `objective` class exists, use it; otherwise try
        # interpreting the string as an integer objective number.
        name = obj[_Ob_Nam]
        if 'objective' in globals() and callable(globals().get('objective')):
            o = globals()['objective'](name)  # type: ignore[call-arg]
            o.neg, o.synch, o.dry = _flags(obj[_Ob_Flg])
            o.loop_count = obj[_Ob_LCt]
            try:
                o.value = obj[_Ob_Val]
            except Exception:
                o.value = None
            return o

        o = cobjective(int(name))
        o.discoverable = True
        o.neg, o.synch, o.dry = _flags(obj[_Ob_Flg])
        o.loop_count = obj[_Ob_LCt]
        try:
            o.value = obj[_Ob_Val]
        except Exception:
            o.value = None
        return o

    except Exception:
        _parse_diag("Objective parse failed")
        return None

def _parse_opt(opt, _depth=0):
    """Internal use only
       -> received option, or None if invalid
"""
#########################################
# Check if received option is in valid
# format, after CBOR decoding. Parse it.
#########################################
    if _depth > 8:
        _parse_diag("O_DIVERT nesting too deep")
        return None
    if tname(opt) != 'list':
        _parse_diag("Option is not a list")
        return None # not a list
    elif not len(opt):
        _parse_diag("Option is empty")
        return None # zero length
    o = _option(opt[_Op_Opt])
    if opt[_Op_Opt] == O_DIVERT:
        if len(opt) < _Op_Con+1 or \
          tname(opt[_Op_Con]) != 'list':
            _parse_diag("Invalid O_DIVERT")
            return None
        else:
            # ttprint("O_DIVERT length",len(opt))
            # scan through embedded locators inside divert option
            for _raw_opt in opt[_Op_Con:]:
                # ttprint("Raw option",_raw_opt)
                eo = _parse_opt(_raw_opt, _depth + 1)
                # ttprint("Parsed option",eo)
                if eo:
                    o.embedded.append(eo)
                    # ttprint("Added",eo,"in parser")
                else:
                    _parse_diag("Invalid option inside O_DIVERT")
                    return None
            # 20220316 The next line was one tab too far in!
            return o
    elif opt[_Op_Opt] == O_ACCEPT:
        return o
    elif opt[_Op_Opt] == O_DECLINE:
        if len(opt) == _Op_Opt+1:
            return o
        elif len(opt) == _Op_Con+1 and tname(opt[_Op_Con]) == 'str':
            o.reason = opt[_Op_Con]
            return o
        else:
            _parse_diag("Invalid content in O_DECLINE")
            return None
    elif opt[_Op_Opt] in (O_IPv6_LOCATOR, O_IPv4_LOCATOR):
        if len(opt) == _Op_Port+1:
            if tname(opt[_Op_Con]) == 'bytes' and \
               tname(opt[_Op_Proto]) == 'int' and \
               tname(opt[_Op_Port]) in ('int','NoneType'):
                o.locator = opt[_Op_Con]
                o.protocol = opt[_Op_Proto]
                o.port = opt[_Op_Port]
                return o
            else:
                _parse_diag("IPv6 or IPv4 locator option has invalid format")
                return None
        else:
            _parse_diag("IPv6 or IPv4 locator option has wrong length")
            return None
    elif opt[_Op_Opt] in (O_FQDN_LOCATOR, O_URI_LOCATOR):
        if len(opt) == _Op_Port+1:
            if tname(opt[_Op_Con]) == 'str' and \
               (tname(opt[_Op_Proto]) == 'int' or tname(opt[_Op_Proto]) == 'NoneType') and \
               (tname(opt[_Op_Port]) == 'int' or tname(opt[_Op_Port]) == 'NoneType'):
                o.locator = opt[_Op_Con]
                o.protocol = opt[_Op_Proto]
                o.port = opt[_Op_Port]
                return o
            else:
                _parse_diag("FQDN or URI locator option has invalid format")
                return None
        else:
            _parse_diag("FQDN or URI locator option has wrong length")
            return None
    else:
        if tname(opt[_Op_Opt]) != 'str':
            # not an objective option
            _parse_diag("Unknown option type", opt[_Op_Opt])
        return None # unknown option


def _parse_msg(payload):
    """Internal use only
       -> received grasp.message, or None if invalid
"""
#########################################
# Check if received message is in valid
# format, after CBOR decoding. Parse it.
#########################################
    if tname(payload) != 'list':
        _parse_diag("Message is not a list")
        return None # not a list
    elif not len(payload):
        _parse_diag("Message is empty")
        return None # zero length
    m = _message(payload[_Pl_Msg])
    if payload[_Pl_Msg] == M_NOOP:
        return m
    elif payload[_Pl_Msg] == M_DISCOVERY:
        if len(payload) != _Pl_Dobj+1 or \
           tname(payload[_Pl_Ses]) != 'int' or \
           tname(payload[_Pl_Ini]) != 'bytes':
            _parse_diag("Invalid M_DISCOVERY format")
            return None
        else:
            o = _parse_obj(payload[_Pl_Dobj])
            if o:
                m.id_value = payload[_Pl_Ses]
                m.id_source = payload[_Pl_Ini]
                m.obj = o
                return m
            else:
                _parse_diag("No objective in M_DISCOVERY")
                return None
    elif payload[_Pl_Msg] == M_RESPONSE:
        if len(payload) < _Pl_Robj or \
           tname(payload[_Pl_Ses]) != 'int' or \
           tname(payload[_Pl_Ini]) != 'bytes' or \
           tname(payload[_Pl_TTL]) != 'int':
            _parse_diag("Invalid M_RESPONSE format")
            return None
        else:
            for pl in payload[_Pl_Rloc:]:
                o = _parse_opt(pl)
                if o:
                    m.id_value = payload[_Pl_Ses]
                    m.id_source = payload[_Pl_Ini]
                    m.ttl = payload[_Pl_TTL]
                    m.options.append(o)
                else:
                    # look for optional objective
                    m.obj = _parse_obj(pl)
            if not m.options:
                _parse_diag("No valid option in M_RESPONSE")
                return None
            else:
                return m
    elif payload[_Pl_Msg] == M_FLOOD:
        if len(payload) < _Pl_FCon+1 or \
           tname(payload[_Pl_Ses]) != 'int' or \
           tname(payload[_Pl_Ini]) != 'bytes' or \
           tname(payload[_Pl_TTL]) != 'int':
            _parse_diag("Invalid M_FLOOD format")
            return None
        else:
            m.id_value = payload[_Pl_Ses]
            m.id_source = payload[_Pl_Ini]
            m.ttl = payload[_Pl_TTL]
            m.flood_list = []
            # fetch embedded tagged objectives
            pp = _Pl_FCon
            while pp < len(payload):
                if len(payload[pp]) != _Fo_Floc+1:
                    _parse_diag("No tagged objective in M_FLOOD")
                    return None
                ob = _parse_obj(payload[pp][_Fo_Fobj])
                if not ob:
                    _parse_diag("Invalid objective in M_FLOOD")
                    return None
                if payload[pp][_Fo_Floc] != []:
                    op = _parse_opt(payload[pp][_Fo_Floc])
                    if not op:
                        _parse_diag("Invalid locator option in M_FLOOD")
                        return None
                else:
                    op = None
                m.flood_list.append(_flooded_objective(ob,op))
                pp += 1
            return m
    elif payload[_Pl_Msg] in (M_REQ_NEG, M_NEGOTIATE, M_SYNCH, M_REQ_SYN):
        if len(payload) != _Pl_Con+1 or \
           tname(payload[_Pl_Ses]) != 'int':
            _parse_diag("Invalid message format")
            return None
        else:
            o = _parse_obj(payload[_Pl_Con])
            if o:
                m.id_value = payload[_Pl_Ses]
                m.obj = o
                return m
            else:
                # _parse_obj emitted the diagnostic
                return None
    elif payload[_Pl_Msg] == M_END:
        if len(payload) != _Pl_Con+1 or \
           tname(payload[_Pl_Ses]) != 'int':
            _parse_diag("Invalid M_END format")
            return None
        else:
            o = _parse_opt(payload[_Pl_Con])
            if o:
                m.id_value = payload[_Pl_Ses]
                m.options.append(o)
                return m
            else:
                # _parse_option emitted the diagnostic
                return None
    elif payload[_Pl_Msg] == M_WAIT:
        if len(payload) != _Pl_Con+1 or \
           tname(payload[_Pl_Ses]) != 'int' or \
           tname(payload[_Pl_Con]) != 'int':
            _parse_diag("Invalid M_WAIT format")
            return None
        else:
            m.id_value = payload[_Pl_Ses]
            m.ttl = payload[_Pl_Con]
            return m
    elif payload[_Pl_Msg] == M_INVALID:
        if len(payload) < _Pl_Con or \
           tname(payload[_Pl_Ses]) != 'int':
            _parse_diag("Invalid M_INVALID format :-)")
            return None
        else:
            m.id_value = payload[_Pl_Ses]
            if len(payload) > _Pl_Con:
                m.content = payload[_Pl_Con:]
            return m
    else:
        # unknown message type
        _parse_diag("Unknown message type", payload[_Pl_Msg])
        return None

def _opt_to_asa_loc(opt, ifi, inDivert):
    """Internal use only"""
####################################################
# Service function for _mchandler, _drloop etc.
# opt is a grasp.option
# ->  list of asa_locator (empty if no valid locator)
####################################################

    if opt.otype == O_DIVERT:
        alocs = []
        for o in opt.embedded:
            if o.otype == O_IPv6_LOCATOR:
                # recursive call for embedded locator
                alocs += _opt_to_asa_loc(o, ifi, True)

# 20220316: was complete rubbish: alocs.append(opt, ifi, True)
#          but no run time error, so never executed due to defect
#          in _mchandler

        return alocs
    else:
        aloc = asa_locator(None, ifi, inDivert)
        aloc.protocol = opt.protocol
        aloc.port = opt.port
        if opt.otype == O_IPv6_LOCATOR:
            aloc.locator = ipaddress.IPv6Address(opt.locator)
            aloc.is_ipaddress = True
        elif opt.otype == O_IPv4_LOCATOR:
            aloc.locator = ipaddress.IPv4Address(opt.locator)
            aloc.is_ipaddress = True
        elif opt.otype == O_FQDN_LOCATOR:
            aloc.locator = opt.locator
            aloc.is_fqdn = True
        elif opt.otype == O_URI_LOCATOR:
            aloc.locator = opt.locator
            aloc.is_uri = True
        else:
            # no valid locator
            return []
    return [aloc]

def _try_mcsock(ifi):
    """Internal use only"""
####################################################
# Service function for _make_mcssock etc.           #
####################################################
    mcssock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    mcssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mcssock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, struct.pack('@I', ifi))
    if not _listen_self:
        # don't listen to yourself talking
        mcssock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
    mcssock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
    return mcssock

def _make_mcssock(ifi):
    """Internal use only"""
####################################################
# Create socket to send GRASP multicasts on a      #
# given interface                                  #
# (Discovery messages and Synchronisation flood    #
# messages) and handle them accordingly            #
####################################################

    _mcssocks.append([ifi, _try_mcsock(ifi)])

def _fixmcsock(i):
    """Internal use only"""
####################################################
# Fix socket to send GRASP multicasts on a         #
# given interface                                  #
# Called if socket fails when used.                #
####################################################

    _mcssocks[i][1].close()
    ifi = _mcssocks[i][0]
    while True:
        try:
            _mcssocks[i][1] = _try_mcsock(ifi)
            break
        except OSError:
            tprint("Waiting for interface")
            time.sleep(5) # wait for interface to come back up

    # Discovery responses are received over UDP in cGRASP, so there is no
    # per-interface TCP discovery-response listener to recreate here.

class _mclisten(threading.Thread):
    """Internal use only"""
####################################################
# Listen for GRASP link-local multicasts           #
# (Discovery messages and synchronisation Flood    #
# messages) and queue them for handling            #
#                                                  #
# This runs as a thread                            #
####################################################
    def __init__(self):
        threading.Thread.__init__(self, daemon=True)

    def run(self):
        """Run the link-local multicast listener until stopped."""
        global _mc_restart
        mcrsock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        mcrsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        mcrsock.bind(('',CGRASP_LISTEN_PORT))
        # join LL multicast group on all interfaces
        for x in _ll_zone_ids:
            mreq = ALL_GRASP_NEIGHBORS_6.packed + struct.pack('@I', x[0])
            while True:
                try:
                    mcrsock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
                    break
                except Exception: # failed, probably too soon during restart so wait & retry
                    time.sleep(2)

        mcrsock.settimeout(120)

        tprint("LL multicast listener is up")
        while True:
            try:
                ttprint("Listening for LL multicasts")
                rawmsg, send_addr = mcrsock.recvfrom(_multicast_size)
                if "%" in send_addr[0]:
                    a,b = send_addr[0].split('%')
                    saddr = ipaddress.IPv6Address(a)
                else:
                    saddr = ipaddress.IPv6Address(send_addr[0])
                sport = send_addr[1]
                ifn = send_addr[3]
                ttprint("Received multicast",rawmsg,"from",saddr,"port",
                        sport,"interface",ifn,"bytecount",len(rawmsg))
                if _listen_self or (not [ifn, saddr] in _ll_zone_ids):

                    # Because we listen to ourselves in testing
                    # and because we can't trust IPV6_MULTICAST_LOOP = 0

                    coap_token = None
                    if _use_coap_multicast:
                        try:
                            _cc, _cmid, _ctok, _cpayload = _coap_parse(rawmsg)
                            if _cpayload:
                                rawmsg = _cpayload
                                coap_token = _ctok
                        except Exception:
                            coap_token = None

                    try:
                        payload = cbor.loads(_decrypt_msg(rawmsg))
                    except Exception:
                        ttprint("Multicast: CBOR decode error") # test mode to suppress QUADS warnings
                        continue
                    msg = _parse_msg(payload)
                    if not msg:
                        # invalid message, cannot process it
                        ttprint(payload,saddr,sport,ifn)
                        ttprint("Multicast: Invalid message format")
                        continue
                    ttprint("Multicast: CBOR->Python:", payload)
                    if msg.mtype in (M_DISCOVERY, M_FLOOD):
                        if _relay_needed:
                            # ttprint("Send",msg.mtype,"from", ifn, "for relay")
                            # Note that Flood relay needs the payload
                            _relay(payload, msg, ifn)
                        try:
                            ttprint("Initiator:", str(ipaddress.IPv6Address(msg.id_source)))
                            # queue for the mc handler (include CoAP token if present)
                            _mcq.put([saddr, sport, ifn, msg, coap_token],block=False)
                        except Exception:
                            tprint("Multicast queue full: packet dropped")
                            pass
                    # note that unrecognized messages are simply ignored
            except OSError:
                tprint("No LL multicasts on interface for 2 minutes")
                if _mc_restart:
                    # Need to exit and restart if we can
                    _mc_restart = False
                    _mclisten().start()
                    break # restarted, so this one can exit
                else:
                    _mc_restart = True  # restart anyway next time
                                        # in case we missed a CPU wakeup


def _relay(payload, msg, ifi, *, relay_seen=False):
    """Internal use only"""
####################################################
# Relay GRASP link-local multicasts (Discovery and #
# Flood messages) to all other interfaces          #
#                                                  #
# NOTE WELL: uses raw payload, as well as parsed   #
# message, since we send the payload out again in  #
# the Flood case.                                  #
#                                                  #
# Lazy code: only controls loops using loop count  #
# and doesn't throttle rate. Note that we must not #
# throttle in line here because that would block   #
# the multicast listener - instead we need to queue#
# the relays for a separate thread that implements #
# the throttle.                                    #
####################################################

    r_shandle = _session_handle(msg.id_value, msg.id_source)

    if _coap_relay_state is not None:
        if msg.mtype == M_FLOOD and not relay_seen:
            outgoing = []
            outgoing_seen = set()
            for info in _ll_zone_ids:
                if info[0] != ifi and info[0] not in outgoing_seen:
                    outgoing_seen.add(info[0])
                    try:
                        outgoing.append(socket.if_indextoname(info[0]))
                    except Exception:
                        pass
            if not _coap_relay_state.remember_flood(
                    FloodKey(bytes(msg.id_source), msg.id_value), str(ifi), outgoing):
                return
        elif msg.mtype == M_DISCOVERY:
            try:
                incoming = socket.if_indextoname(ifi)
            except Exception:
                incoming = str(ifi)
            tx = _coap_relay_state.create_discovery(
                DiscoveryKey(bytes(msg.id_source), msg.id_value),
                incoming_interface=incoming, upstream_remote=None,
                upstream_token=b"", upstream_request_context=None)
            if tx is None:
                return

    # drop message if this is a looping relay
    sess = _get_session(r_shandle)
    if sess and _coap_relay_state is None:
        if sess.id_relayed:
            ttprint("Dropping a looping relayed multicast", msg.mtype)
            return
        else:
            # mark the session as relayed
            sess.id_relayed = True
            _update_session(sess)

    if msg.mtype == M_FLOOD:
        uobj = payload[_Pl_FCon][_Fo_Fobj] # first objective in unparsed flood
        uobj[_Ob_LCt] -= 1                 # decrement its loop count
        if uobj[_Ob_LCt] < 1:
            return # do nothing
        # ttprint("relaying", uobj[_Ob_Nam],"flood with loop ct", uobj[_Ob_LCt])
        if not sess:
            # insert session id for the relayed copies
            news = _session_instance(r_shandle.id_value,True,r_shandle.id_source)
            news.id_relayed = True
            _insert_session(news)
        msg_bytes = _encrypt_msg(cbor.dumps(payload))
        if _use_coap_std_multicast:
            try:
                from .coap_client import coap_post_many_sync

                path = "/".join(_coap_std_mc_uri_path)
                sent_interfaces = set()
                for i in range(len(_ll_zone_ids)):
                    ttprint("Flood relay for", uobj[_Ob_Nam])
                    outgoing_ifi = _ll_zone_ids[i][0]
                    if outgoing_ifi in sent_interfaces:
                        continue
                    sent_interfaces.add(outgoing_ifi)
                    if outgoing_ifi != ifi:  # will skip the relay source interface
                        try:
                            ifname = socket.if_indextoname(_ll_zone_ids[i][0])
                        except Exception:
                            ifname = None
                        if not ifname:
                            continue
                        if _coap_relay_state is not None and not _coap_relay_state.allow("flood", ifname):
                            continue
                        uri = f"coap://[{_coap_std_mc_group}%{ifname}]:{int(_coap_std_mc_port)}/{path}"
                        coap_post_many_sync([uri], msg_bytes, content_format=60,
                                            no_response=FLOOD_NO_RESPONSE_VALUE, grace=0.02)
            except Exception as ex:
                if _strict_coap or not _allow_legacy_multicast:
                    _audit_transport("errors", "standard CoAP flood relay: " + repr(ex))
                    return
                # Fall back to legacy UDP multicast below.
                wire_bytes = _coap_wrap_mc_request(msg_bytes)
                for i in range(len(_ll_zone_ids)):
                    ttprint("Flood relay for", uobj[_Ob_Nam])
                    if _ll_zone_ids[i][0] != ifi: # will skip the relay source interface
                        _mcssocks[i][1].sendto(wire_bytes,0,(str(ALL_GRASP_NEIGHBORS_6), CGRASP_LISTEN_PORT))
        else:
            wire_bytes = _coap_wrap_mc_request(msg_bytes)
            for i in range(len(_ll_zone_ids)):
                ttprint("Flood relay for", uobj[_Ob_Nam])
                if _ll_zone_ids[i][0] != ifi: # will skip the relay source interface
                    _mcssocks[i][1].sendto(wire_bytes,0,(str(ALL_GRASP_NEIGHBORS_6), CGRASP_LISTEN_PORT))
        _disactivate_flood(r_shandle).start() # will disactivate session ID later
    elif msg.mtype == M_DISCOVERY:
        msg.obj.loop_count -=1 # decrement loop count
        if msg.obj.loop_count < 1:
            return # do nothing
        # reuse discover function in relay mode, but kick it off
        # as a separate thread with fresh copy of objective
        _disc_relay(r_shandle, _oclone(msg.obj), ifi).start()


class _disactivate_flood(threading.Thread):
    """Internal use only"""
    def __init__(self, shandle):
        threading.Thread.__init__(self, daemon=True)
        self.shandle = shandle
    def run(self):
        """Close a flood session after the configured delay."""
        time.sleep(GRASP_DEF_TIMEOUT/500)
        ttprint("Disactivating flood session")
        _disactivate_session(self.shandle)

class _disc_relay(threading.Thread):
    """Internal use only"""
    def __init__(self, shandle, obj, ifi):
        threading.Thread.__init__(self, daemon=True)
        self.shandle = shandle
        self.obj = obj
        self.ifi = ifi
    def run(self):
        """Relay a discovery message across interfaces until it completes."""
        ttprint("Discovery relay for", self.obj.num, self.obj.loop_count)
        # set timeout to 1s per loop count 20170528
        discover(None, self.obj, _discTimeoutUnit*self.obj.loop_count, relay_ifi=self.ifi, relay_shandle=self.shandle)

def _init_drsocks(i):
    """Internal use only"""
####################################
# Initialise TCP sockets to receive#
# unicast Discovery responses      #
####################################

    # Can't use a comprehension because we need the actual
    # list index in order select the correct socket.
    _msg_bytes = _encrypt_msg(cbor.dumps([M_NOOP])) # No-op message
    for _ in range(10):
        try:
            _mcssocks[i][1].sendto(_msg_bytes,0,(str(ALL_GRASP_NEIGHBORS_6), CGRASP_LISTEN_PORT))
            _port = _mcssocks[i][1].getsockname()[1]
            _s =socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            _s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                # ttprint("Binding",_port)
                _s.bind(('',_port))
            except Exception: # Can't get the same port number, try again
                # ttprint("Couldn't bind")
                _s.close()
                _mcssocks[i][1].close()
                ifi = _mcssocks[i][0]
                _mcssocks[i][1] = _try_mcsock(ifi)
                continue
            _drlt = _drlisten(_s, _ll_zone_ids[i][0])
            tprint("Starting a discovery TCP listener for interface", _s.getsockname(), _ll_zone_ids[i][0])
            _drlt.start()
            return
        except OSError as ex:
            ttprint(ex)
            # Network down, most likely, wait and retry
            tprint("Retrying to start discovery listener")
            time.sleep(10)
    # If we're here, something is deeply suspect and we have to give up.
    raise RuntimeError("Cannot get free port for discovery TCP listener")


class _drlisten(threading.Thread):
    """Internal use only"""
####################################################
# Listen for discovery responses on a given socket #
#                                                  #
# Socket must be bound to a port already           #
# This runs as a thread and exits after timeout.   #
#                                                  #
# This thread is invoked for the Discover function #
# and must not be activated otherwise.             #
####################################################
    def __init__(self, sock, ifi):
        threading.Thread.__init__(self, daemon=True)
        self.sock = sock
        self.ifi = ifi
    def run(self):
        """Run the discovery-response listener for one interface."""
        tprint("Discovery response listener for interface",self.ifi,"is up")
        while True:
            self.sock.listen(5)
            try:
                ttprint("Listening for discovery response")
                asock, aaddr = self.sock.accept()
                rawmsg, send_addr = _recvraw(asock)
                asock.close()
                if '%' in aaddr[0]:
                    a,b = aaddr[0].split('%') # strip any Zone ID
                else:
                    a = aaddr[0]
                send_addr=ipaddress.IPv6Address(a)
                # ttprint("Received TCP", _decrypt_msg(rawmsg), "from", send_addr)
                try:
                    payload = cbor.loads(_decrypt_msg(rawmsg))
                    ttprint("Received response: CBOR->Python:", payload)
                    msg = _parse_msg(payload)
                    if not msg:
                        ttprint("Invalid Response message: packet dropped")
                    elif msg.mtype != M_RESPONSE:
                        ttprint("Not a Response message: packet dropped")
                    else:
                        # find the correct session queue
                        sid = msg.id_value  # session ID
                        sini = msg.id_source # session initiator
                        s=_get_session(_session_handle(sid,sini))
                        if s:
                            # (give up silently if no such session)
                            if s.id_dq:
                                # (give up silently if session has no queue)
                                # queue for the discovery response handler
                                try:
                                    ttprint("Queueing response")
                                    s.id_dq.put([send_addr,self.ifi,msg],block=False)
                                except Exception:
                                    tprint("Discovery response queue full or absent: packet dropped")
                except Exception:
                    tprint("Discovery response: CBOR decode error")
            except OSError as ex:
                tprint("Discovery response socket error", ex)
                pass     # keep trying anyway



class _mchandler(threading.Thread):
    """Internal use only"""
####################################################
# Multicast queue handler                          #
#                                                  #
# This runs forever as a thread.                   #
#                                                  #
# This version is lazy: Floods queue behind        #
# Discovery responses.                             #
####################################################
    def __init__(self):
        threading.Thread.__init__(self, daemon=True)

    def run(self):
        """Run the multicast queue handler until stopped."""
        tprint("Multicast queue handler up")
        while True:
            try:      # this is to catch unknown bug 20190724
                mc = _mcq.get()
                ttprint("Multicast handler got something", mc)
                from_addr = mc[0]
                from_port = mc[1]
                from_ifi = mc[2]
                msg = mc[3]
                coap_token = None
                if len(mc) > 4:
                    coap_token = mc[4]
                if (not _listen_self) and (msg.mtype == M_DISCOVERY) and \
                   (msg.id_value == _i_sent_it) and not _multi_asas:
                    # hack to ignore self-sent discoveries if multiple instances and
                    # running with _listen_self == True
                    ttprint("Dropping own discovery multicast")

                elif DULL and not from_addr.is_link_local:
                    ttprint("DULL dropping non-local packet")

                elif DULL and msg.mtype == M_DISCOVERY and msg.obj.loop_count != 1:
                    ttprint("DULL dropping discovery with bad loop count")

                elif DULL and msg.mtype == M_FLOOD and \
                     msg.flood_list[0].obj.loop_count != 1:
                    ttprint("DULL dropping flood with bad loop count")

                elif msg.mtype == M_DISCOVERY:
                    ttprint("Got multicast Discovery msg")

                    if _test_divert:
                        ttprint("mchandler: _test_divert",_test_divert)

                    # Is the objective registered in this node?
                    try:
                        onum = msg.obj.num
                        _found = False
                        _rapid = False
                        if not _test_divert:
                            _obj_lock.acquire()
                            for x in _obj_registry:
                                if x.objective.num == onum and x.discoverable:
                                    # Yes, we have it, can send unicast response
                                    # (including the objective, for rapid mode)
                                    _found = x.objective
                                    _rapid = x.rapid
                                    _ttl = x.ttl
                                    if x.locators:
                                        # we have a specified list of asa_locator(s)
                                        _alist = x.locators
                                    else:
                                        # normal objective - create an asa_locator
                                        if x.local or (_my_address == None):
                                            # either link-local address is required, or we
                                            # have no global address, may as well send link-local
                                            for y in _ll_zone_ids:
                                                if y[0] == from_ifi:
                                                    _a = y[1]
                                        else:
                                            _a = _my_address

                                        if _advertise_coap_unicast:
                                            # Advertise a CoAP URI locator rather than a TCP port.
                                            # Include RFC6874 zone-id (%25ifname) for link-local.
                                            host = str(_a) if _a is not None else "::1"
                                            if _a is not None and getattr(_a, "is_link_local", False):
                                                try:
                                                    ifname = socket.if_indextoname(from_ifi)
                                                except Exception:
                                                    ifname = None
                                                if ifname:
                                                    host = host + "%25" + ifname
                                            uri = f"coap://[{host}]:{int(_advertise_coap_unicast_port)}/{_advertise_coap_unicast_path.strip('/')}"
                                            _aloc = asa_locator(uri, None, False)
                                            _aloc.is_uri = True
                                            _aloc.is_ipaddress = False
                                            _aloc.is_fqdn = False
                                            _aloc.protocol = socket.IPPROTO_UDP
                                            _aloc.port = int(_advertise_coap_unicast_port)
                                        else:
                                            _aloc = asa_locator(_a, None, False)
                                            _aloc.protocol = x.protocol
                                            _aloc.port = x.port
                                            _aloc.is_ipaddress = True

                                        _alist = [_aloc]
                                    break
                            _obj_lock.release()

                        if _found:
                            # found it locally, respond immediately
                            _los = []
                            for _aloc in _alist:
                                # build locator option
                                try:
                                    if getattr(_aloc, "is_uri", False):
                                        _los.append([O_URI_LOCATOR, _aloc.locator, _aloc.protocol, _aloc.port])
                                    elif getattr(_aloc, "is_fqdn", False):
                                        _los.append([O_FQDN_LOCATOR, _aloc.locator, _aloc.protocol, _aloc.port])
                                    elif getattr(_aloc, "is_ipaddress", False):
                                        # Only supports IPv6 here.
                                        _los.append([O_IPv6_LOCATOR, _aloc.locator.packed, _aloc.protocol, _aloc.port])
                                    else:
                                        # Fallback: try to treat as IPv6 locator.
                                        _los.append([O_IPv6_LOCATOR, _aloc.locator.packed, _aloc.protocol, _aloc.port])
                                except Exception:
                                    # If a malformed locator was supplied, skip it.
                                    pass

                            # assemble response message with variable number of locators
                            # plus the objective, for rapid mode
                            if _rapid:
                                msg_bytes = _ass_message(M_RESPONSE, msg.id_value, msg.id_source,
                                                     _ttl, _los, _found)
                            else:
                                msg_bytes = _ass_message(M_RESPONSE, msg.id_value, msg.id_source,
                                                     _ttl, _los)

                            # Send unicast UDP response to the requester's source port.
                            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                            sock.settimeout(1) # discovery requester should always be waiting
                            try:
                                out_bytes = msg_bytes
                                if coap_token is not None:
                                    out_bytes = _coap_wrap_mc_response(msg_bytes, token=coap_token)
                                sock.sendto(out_bytes, 0, (str(from_addr), from_port, 0, from_ifi))
                                ttprint("Sent local response")
                            except OSError as ex:
                                tprint("Socket error when sending local discovery Response", ex)
                            sock.close()

                        elif not DULL:

                            # Not local - do we have it in the cache?
                            # We will come here too if _test_divert is set

                            # ttprint("Search discovery cache")

                            _disc_lock.acquire()

                            # ttprint("Acquired _disc_lock")

                            # Can't use a comprehension because we need the actual
                            # list entry in order to delete it.
                            ll = False
                            for i in range(len(_discovery_cache)):
                                x = _discovery_cache[i]
                                if x.objective.num == onum: # found the objective
                                    ll = x.asa_locators
                                    if ll:  # it has not expired
                                        del(_discovery_cache[i])
                                        _discovery_cache.append(x)   # make it Most Recently Used
                                    break   # quit the search
                            _disc_lock.release()
                            if ll:
                                # Build Divert option
                                ttprint("Build Divert option")
                                _ttl = 0
                                # 20220316 - fixed failure to use _option class here
                                divo = _option(O_DIVERT)
                                for y in ll:
                                    # ttprint("Discovery cache entry", y.is_ipaddress, y.locator, y.ifi, y.expire, int(time.monotonic()))
                                    if y.is_ipaddress:
                                        if (not y.locator.is_link_local) and \
                                           (y.expire > int(time.monotonic())): # not LL and not expired

                                            # build locator option (only supports IPv6, TCP)
                                            lo = [O_IPv6_LOCATOR, y.locator.packed, socket.IPPROTO_TCP, y.port]
                                            divo.embedded.append(lo)
                                            if _test_divert:
                                                break # to avoid duplicates during local testing
                                    elif y.is_fqdn:
                                        divo.embedded.append([O_FQDN_LOCATOR, y.locator, y.protocol, y.port])
                                    elif y.is_uri:
                                        divo.embedded.append([O_URI_LOCATOR, y.locator])
                                    # calculate worst case TTL
                                    if y.expire > 0:
                                        if _ttl > 0:
                                            _ttl = min(int((y.expire - time.monotonic())*1000),_ttl)
                                        else:
                                            _ttl = int((y.expire - time.monotonic())*1000)

                                if _ttl == 0:
                                    _ttl = _discCacheDefTimeOut
                                if len(divo.embedded):
                                    # Send unicast UDP divert response to the requester's source port.
                                    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                                    sock.settimeout(1) # discovery requester should always be waiting
                                    try:
                                        msg_bytes = _ass_message(M_RESPONSE, msg.id_value, msg.id_source,
                                                                 _ttl, divo)
                                        out_bytes = msg_bytes
                                        if coap_token is not None:
                                            out_bytes = _coap_wrap_mc_response(msg_bytes, token=coap_token)
                                        sock.sendto(out_bytes, 0, (str(from_addr), from_port, 0, from_ifi))
                                        ttprint("Sent divert response")
                                    except OSError as ex:
                                        tprint("Socket error when sending divert Response", ex)
                                    sock.close()
                            else:
                                # ttprint("Not in discovery cache")
                                pass
                        else:
                            tprint("DULL discovery failure")
                            pass
                    except OSError:
                        # invalid discovery format - do nothing
                        tprint("Discovery message has invalid content")
                elif msg.mtype == M_FLOOD:
                    ttprint("Got Flood message, TTL=", msg.ttl)

                    lobjs = msg.flood_list  # list of _flooded_objective

                    for lo in lobjs:
                        # construct asa_locator from locator option
                        if lo.loco:
                            _locs = _opt_to_asa_loc(lo.loco, from_ifi, False)
                            if len(_locs) == 1:
                                _loc = _locs[0] # got exactly one locator

                            else:
                                tprint("Anomalous locator in flood ignored")
                                _loc = asa_locator(None, None, False)
                        else:
                            ttprint("No locator in flooded objective")
                            _loc = asa_locator(None, None, False)
                        if msg.ttl > 0:
                            _loc.expire = int(time.monotonic() + msg.ttl/1000)
                            ttprint("Setting expiry",_loc.expire)
                        else:
                            _loc.expire = 0

                        # construct and store objective
                        obj = lo.obj
                        # ttprint(obj.num,"flood has loop ct",obj.loop_count,"from ifi",from_ifi)
                        obj = _detag_obj(obj)
                        if obj.synch: # must be a synch objective
                            _flood_lock.acquire()
                            # zap objective if already cached
                            # zap expired objectives as we go
                            for j in range(len(_flood_cache)):
                                if _flood_cache[j].objective.num == obj.num and \
                                   _flood_cache[j].source.locator == _loc.locator and \
                                   _flood_cache[j].source.port == _loc.port:
                                    # found it, zap old version
                                    _flood_cache[j] = None

                                elif _flood_cache[j].source.expire !=0 and \
                                     _flood_cache[j].source.expire < int(time.monotonic()):
                                    # expired entry, zap it
                                    # ttprint("MC handler expiring flood",_flood_cache[j].objective.num,
                                    #        _flood_cache[j].source.expire)
                                    _flood_cache[j] = None

                            # garbage collect
                            j=0
                            while j < len(_flood_cache):
                                if _flood_cache[j] == None:
                                    del _flood_cache[j]
                                else:
                                    j += 1

                            # if cache is full, delete oldest
                            if len(_flood_cache) >= _floodCacheLimit:
                                del(_flood_cache[0])
                            # concatenate new one in MRU position
                            _flood_cache.append(tagged_objective(obj,_loc))
                            _flood_lock.release()
                            # ttprint(obj.num,"flood appended")
                else:
                    # Some other message such as M_NOOP, drop it
                    pass
            except Exception as ex:
                tprint("Unexpected exception in _mchandler:", ex)
                traceback.print_exc()
                # and we just wait for the next multicast message



class _tcp_listen(threading.Thread):
    """Internal use only"""
#########################################################
# TCP listener thread for synch and negotiate requests  #
#########################################################
    def __init__(self, listen_sock):
        threading.Thread.__init__(self, daemon=True)
        self.listen_sock = listen_sock

    def run(self):


        """Run the TCP request listener until stopped."""
        self.listen_sock.listen(5)
        self.listen_sock.settimeout(None) # listeners will block

        # For ever, wait for incoming connections and queue them
        # for the listening ASA (if any).
        ttprint("A TCP request listener is up on port", self.listen_sock.getsockname()[1])
        found = True # this will change if objective becomes unregistered
        while found:
            try:
                asock, aaddr = self.listen_sock.accept()
                asock.set_inheritable(True)
                ttprint("Talking on",asock.getsockname())
                rawmsg, send_addr = _recvraw(asock)
                if '%' in aaddr[0]:
                    a,b = aaddr[0].split('%') # strip any Zone ID
                else:
                    a = aaddr[0]
                send_addr=ipaddress.IPv6Address(a)
                # ttprint("Received TCP", rawmsg, "from", send_addr,"bytecount",len(rawmsg))
                try:
                    payload = cbor.loads(_decrypt_msg(rawmsg))
                    ttprint("Received request: CBOR->Python:", payload)
                    msg = _parse_msg(payload)
                    if not msg:
                        tprint("Invalid Request message: packet dropped")
                        asock.close()
                    elif msg.mtype == M_INVALID:
                        tprint("Got M_INVALID", msg.id_value, msg.content)
                        asock.close()
                    elif not msg.mtype in (M_REQ_SYN, M_REQ_NEG):
                        ttprint("Not a Request message: packet dropped")
                        asock.close()
                    else:
                        # check whether ASA is listening
                        queued = False
                        found = False
                        _obj_lock.acquire()
                        for x in _obj_registry: # ??? once seemed to fail in reentrant case?
                            if x.objective.num == msg.obj.num:
                                found = True
                                ttprint("Listener found ",msg.obj.num," listening=",x.listening)
                                if x.listening:
                                    # check that flags match
                                    if not _objective_supports(x.objective, msg.obj):
                                        # oops, mismatch
                                        ttprint("Request mismatches capability")
                                        break
                                    # queue socket,sender,and message for the ASA
                                    try:
                                        x.listen_q.put([asock,send_addr,msg],block=False)
                                        queued = True
                                        ttprint("Request queued for ASA")
                                    except Exception:
                                        tprint("ASA queue error: packet dropped")
                        _obj_lock.release()
                        if not queued:
                            # no listener for this objective
                            asock.close()
                except Exception:
                    tprint("Listener: CBOR decode error")
                    asock.close()
            except OSError as ex:
                tprint("Request listener socket error", ex)
                pass     # go round again
        # if we get here, the objective has vanished
        ttprint("Listener exiting on port", self.listen_sock.getsockname()[1])
        self.listen_sock.close()
# end of TCP listener


def _queue_unicast_request(asock, send_addr, msg):
    """Internal use only.

    Enqueue an inbound unicast request (M_REQ_SYN or M_REQ_NEG) for delivery to
    a listening ASA.

    This is factored out of the TCP listener so alternate unicast transports
    (e.g., CoAP bridges) can inject request messages into the same queueing
    model used by listen_negotiate()/listen_synchronize().

    Returns:
        (found, queued)
          - found: True if the objective exists in the registry
          - queued: True if a listener was present and the request was queued
    """

    queued = False
    found = False
    try:
        mtype = msg.mtype
    except Exception:
        return False, False
    if mtype not in (M_REQ_SYN, M_REQ_NEG):
        return False, False

    _obj_lock.acquire()
    try:
        for x in _obj_registry:
            if x.objective.num == msg.obj.num:
                found = True
                ttprint("Listener found ", msg.obj.num, " listening=", x.listening)
                if x.listening:
                    # check that flags match
                    if not _objective_supports(x.objective, msg.obj):
                        ttprint("Request mismatches capability")
                        break
                    try:
                        x.listen_q.put([asock, send_addr, msg], block=False)
                        queued = True
                        ttprint("Request queued for ASA")
                    except Exception:
                        tprint("ASA queue error: packet dropped")
                break
    finally:
        _obj_lock.release()

    return found, queued

class _watcher(threading.Thread):
    """Internal use only"""
####################################################
# Keep an eye on the ACP for ever                  #
# (or for some time in test mode)                  #
#                                                  #
# In a production implementation, the ACP would    #
# monitor the active interfaces, add any new active#
# ones, and mark any old ones as inactive, updating#
# various data structures accordingly.             #
####################################################

    def __init__(self):
        threading.Thread.__init__(self, daemon=True)

    def run(self):
        """Watch for ACP/address changes until stopped."""
        global _my_address
        global _mc_restart
        global _said_no_route
        time.sleep(1)
        tprint("ACP watcher is up; thread count:",threading.active_count())
        i=0
        while True:
            _security_check()

            time.sleep(10)

            if test_mode and i<40:
                i += 1
                tprint("Watching the ACP in test mode; thread count:",threading.active_count())
# #                for x in _obj_registry:
# #                    if x.objective.value != 0:
# #                        tprint(x.objective.num, "synch value", x.objective.value)
# #                for x in _flood_cache:
# #                    tprint(x.name, "flood value", x.value)
                if i == 40:
                    tprint("Watcher going silent")

            # Watch for address change

            _new_locator = acp._get_my_address()
            if _new_locator == ipaddress.IPv6Address("::1"):
                # loopback address, looks like the CPU slept
                tprint("CPU wakeup, no address yet")
                # flag MC handler to restart on timeout
                _mc_restart = True
                # need to restart TCP listeners too

            elif _new_locator and (_new_locator != _my_address):
                tprint("IPv6 address changed to",_new_locator)
                _my_address = _new_locator
                _said_no_route = False
                # flag MC handler to restart on timeout
                _mc_restart = True

            elif _new_locator == None:
                if not _said_no_route:
                    tprint("No routeable IPv6 address, using link local")
                    _said_no_route = True
                _my_address = None
                # flag MC handler to restart on timeout
                _mc_restart = True


class _figger(threading.Thread):
    """Internal use only"""

########################################################
# Configger is an Autonomic Service Agent.
# It supports the proposed GRASP objective GraspConfig
# in order to receive and apply GRASP configuration
# information in an autonomic node.
#
# It is built into the GRASP core and should run
# indefinitely.
#########################################################

    def __init__(self):
        threading.Thread.__init__(self, daemon=True)

    def run(self):

        """Run the ASA configuration loop until stopped."""
        global _multicast_size, _unicast_size

        time.sleep(4)  # ensure that GRASP initialisation is done

        ###################################
        # Constants for reading dictionary
        ###################################

        class codepoints:
            """Code points for configuration dictionary"""
            def __init__(self):
                self.sender = 0
                self.sender_loop_count = 1
                self.grasp_version = 2
                self.max_multicast = 3
                self.max_unicast = 4

        cp = codepoints()

        tprint("ASA Configger is starting up.")


        ####################################
        # Register ASA
        ####################################

        err,asa_handle = register_asa("Configger")
        if err:
            raise Exception("Could not register ASA Configger, "+etext[err])


        ####################################
        # Define objective
        ####################################


        obj1 = cobjective("GraspConfig")
        obj1.synch = True


        ###################################
        # Check objective for ever
        ###################################

        while True:
            err, objs = get_flood(asa_handle, obj1)
            if err:
                tprint("Configger get-flood error:", etext[err])
            elif objs:
                reply = objs[0].objective # take the first one (really should analyze multiple replies)
# #                if cp.sender in reply.value:
# #                    ttprint("Received",reply.name, "from", ipaddress.IPv6Address(reply.value[cp.sender]))
# #                if cp.sender_loop_count in reply.value:
# #                    ttprint(reply.name,"hops", reply.value[cp.sender_loop_count]-reply.loop_count+1)
# #                if cp.grasp_version in reply.value:
# #                    ttprint("GRASP version", reply.value[cp.grasp_version])
# #                if cp.max_hops in reply.value:
# #                    ttprint("Maximum hops", reply.value[cp.max_hops])
                if cp.max_multicast in reply.value:
                    # configure multicast size
                    _msize = reply.value[cp.max_multicast]
                    if _msize != _multicast_size and _msize > GRASP_DEF_MAX_SIZE and _msize < 10*GRASP_DEF_MAX_SIZE:
                        tprint("Changing max multicast size to", _msize)
                        _multicast_size = _msize
                if cp.max_unicast in reply.value:
                    # configure unicast size
                    _usize = reply.value[cp.max_unicast]
                    if _usize != _unicast_size and _usize > GRASP_DEF_MAX_SIZE and _usize < 10*GRASP_DEF_MAX_SIZE:
                        tprint("Changing max unicast size to", _usize)
                        _unicast_size = _usize

            time.sleep(70)

def dump_all(partial=False):
    """
Utility function dump_all() prints various GRASP data
structures for interactive debugging. Not thread-safe.
"""
    if not partial:
        print("\nThread count:",threading.active_count(),"\n------------")
        print("\nMy address:", str(_my_address),"\n----------")
        print("\nSession locator:", str(_session_locator),"\n---------------")
        print("\nLink local zone index(es):\n-------------------------")
        for x in _ll_zone_ids:
            print(x)
        print("\nASA registry contents:\n---------------------")
        for x in _asa_registry:
            print(x.name,"handle:",x.handle)
    print("\nObjective registry contents:\n---------------------------")
    for x in _obj_registry:
        o= x.objective
        print(o.num,"ASA:",x.asa_id,"Listen:",x.listening,"Port", x.port,"Neg:",o.neg,
               "Synch:",o.synch,"Count:",o.loop_count,"Value:",o.value)
        if x.locators:
            print("Predefined locators:", x.locators)
    if not partial:
        print("\nDiscovery cache contents:\n------------------------")
        for x in _discovery_cache:
            print(x.objective.num,"locators:")
            for y in x.asa_locators:
                print(y.locator, y.protocol, y.port, "Diverted:",y.diverted,"Expiry:",y.expire)
            if x.received:
                print("Received",getattr(x.received, "name", ""),"rapid value",x.received.value)
    print("\nFlood cache contents:\n--------------------")
    for x in _flood_cache:
        print(x.objective.num,"count:",x.objective.loop_count,"value:", x.objective.value,
              "source:",x.source.locator, x.source.protocol, x.source.port, x.source.expire)
    if not partial:
        print("\nSession ID cache contents:\n-------------------------")
        for x in _session_id_cache:
            print("Handle:",'{:8}'.format(x.id_value),"Source:",x.id_source,"Active:",x.id_active,
                  "Relayed:",x.id_relayed)

def _security_check():
    """Internal use only """
    global _secure, _tls_required

    ####################################
    # Is there a secure ACP or QUADS?                 #
    ####################################

    astat = acp.status()
    ttprint("ACP status:", astat)
    if DULL:
        _secure = False  # Make sure of it!
        ttprint("WARNING: Insecure Discovery Unsolicited Link-Local (DULL) mode")
    else:
        _secure = astat or _crypto
        _tls_required = not _secure
        if _tls_required:
            # should be code to cause TLS wrapping of TCP...
            tprint("WARNING: ACP insecure, need TLS, not implemented")
    return

def _initialise_grasp():
    """Internal use only """
    # Called the first time register_asa() is called

    ####################################
    # Should we even be here?          #
    ####################################

    global _grasp_initialised
    if _grasp_initialised:
        return

    ####################################
    # Declare all global variables     #
    # (a necessary nuisance)           #
    ####################################
    global _tls_required
    global _secure
    global DULL
    global _rapid_supported
    global _mcq
    global _my_address
    global _session_locator
    global _ll_zone_ids
    global _said_no_route
    global _mcssocks
    global _relay_needed
    global _mc_restart
    global _i_sent_it
    global _multi_asas
    global test_mode
    global _mess_check
    global _listen_self
    global _test_divert
    global _make_invalid
    global _make_badmess

    ####################################
    ####################################
    #                                  #
    # Start of main initialisation     #
    #                                  #
    ####################################
    ####################################


    tprint("WARNING: This is prototype code for the GRASP protocol.")
    tprint("It is unsuitable for operational purposes and relies")
    tprint("on an underlying ACP for security. Use it at your own risk!")
    # print("For further details see http://xkcd.com/1742/")
    tprint("Python GRASP Version",_version,"released under the")
    tprint("Revised BSD license.")
    tprint("Will use port", CGRASP_LISTEN_PORT)
    tprint("Will use multicast address", ALL_GRASP_NEIGHBORS_6)

    if (not _skip_dialogue) or (test_mode == "ask"):

        ####################################
        # Run in test mode?                #
        ####################################

        test_mode = False          # Set this True for prolix diagnostic prints
                                   # and some special case tests.
                                   # Leave it False for "production" mode.
        try:
            _l = input("Test mode (many extra diagnostics)? Y/N:")
            if _l:
                if _l[0] == "Y" or _l[0] == "y":
                    test_mode = True
        except Exception:
            pass

        if test_mode:
            tprint("Running in test mode.")

    if (not _skip_dialogue) or (_mess_check == "ask"):

        ####################################
        # Strict checking ?                #
        ####################################

        _mess_check = True         # Set this True for detailed format
                                   # diagnostics for incoming messages
        try:
            _l = input("Diagnostics for inbound message parse errors? Y/N:")
            if _l:
                if _l[0] == "N" or _l[0] == "n":
                    _mess_check = False
        except Exception:
            pass

        if test_mode and not _mess_check:
            tprint("No parsing diagnostics.")

    if (not _skip_dialogue) or (_listen_self == "ask"):

        ####################################
        # Listen to own LL multicasts?     #
        ####################################

        _listen_self = True

        try:
            _l = input("Listen to own multicasts? Y/N:")
            if _l:
                if _l[0] == "N" or _l[0] == "n":
                    _listen_self = False
        except Exception:
            pass

        if test_mode and not _listen_self:
            tprint("Not listening to own LL multicasts.")

    if (not _skip_dialogue) or (_be_dull == "ask"):

        ####################################
        # DULL mode?                       #
        ####################################

        DULL = False

        try:
            _l = input("Insecure link-local mode (DULL)? Y/N:")
            if _l:
                if _l[0] == "Y" or _l[0] == "y":
                    DULL = True
        except Exception:
            pass
    else:
        DULL = _be_dull



    ####################################
    # Initialise QUADS (unless DULL)   #
    ####################################
    if not DULL:
        _quads_key_file = os.environ.get("CGRASP_QUADS_KEY_FILE", "").strip()
        if _quads_key_file:
            try:
                with open(_quads_key_file, "r", encoding="utf-8") as _kf:
                    _kdata = json.load(_kf)
                _ini_crypt(key=bytes.fromhex(_kdata["key"]),
                           iv=bytes.fromhex(_kdata["iv"]))
            except Exception as _kex:
                raise RuntimeError(
                    "Invalid CGRASP_QUADS_KEY_FILE: " + _quads_key_file
                ) from _kex
        elif os.environ.get("CGRASP_QUADS_REQUIRED") == "1":
            raise RuntimeError(
                "QUADS is required (CGRASP_QUADS_REQUIRED=1) but "
                "CGRASP_QUADS_KEY_FILE is not set")
        else:
            tprint("QUADS disabled (no CGRASP_QUADS_KEY_FILE); traffic is plaintext")
    else:
        tprint("Insecure Discovery Unsolicited Link-Local (DULL) mode")

    ####################################
    # Initialise global variables      #
    #                                  #
    # Reminder: any of these that get  #
    # written before read inside any   #
    # function or thread must be       #
    # declared 'global' inside that    #
    # function.                        #
    ####################################

    _secure = False             # Not secure yet
    _tls_required = True        # Assume no ACP for now
    _rapid_supported = False    # Default, can only be changed by Intent
    _i_sent_it = 0              # Initialise hack to detect own discoveries
    _multi_asas = False         # Initialise multiple ASA status

    _mcq = queue.Queue(_multQlimit) # Limits number of queued multicasts

    # Registries, caches and locks are owned by the default engine.  Rebind
    # the compatibility globals in case the module was reloaded or a caller
    # replaced them.
    _engine.attach()

    _ll_zone_ids = []          # Empty list of [IPv6 Zone (interface) index,LL address]
    _mcssocks = []             # Empty list of multicast sending sockets
                               # Each entry is [Zone Index, socket]

    _test_divert = False        # Flip this only inside test ASA, with care
    _make_invalid = False      # For testing M_INVALID, with care
    _make_badmess = False      # For testing bad message format, with care

    ####################################
    # Security check                   #
    ####################################

    _security_check()

    if DULL:
        tprint("Security status: DULL mode")
    elif _crypto:
        tprint("Security status: QUADS active")
    elif _secure:
        tprint("Security status: ACP secure")
    else:
        tprint("Security status: GRASP is insecure")

    tprint("Initialised global variables, registries and caches.")

    ####################################
    # What's my address?               #
    # What interfaces do I have?       #
    ####################################

    _my_address, _ll_zone_ids = acp._get_my_address(build_zone=True)
    _said_no_route = False # flag used by watcher

    if _my_address == None:
        tprint("Could not find a valid global IPv6 address, will generate a bogon for session disambiguation")
        # Note - this trick is not sanctioned in the spec, which says that
        # in such a case, a RFC7217-based link-local address must be used.
        _p = bytes.fromhex('20010db8f000baaaf000baaa')       # 96 bits of prefix
        _x = struct.pack('!L', _prng.randint(0, 2147483647)) # 32 bits of randomness
        _session_locator = ipaddress.IPv6Address(_p+_x)
    else:
        if not acp.is_ula(_my_address):
            tprint("WARNING: address is not ULA")
        _session_locator = _my_address

    tprint("My global scope address:", str(_my_address))
    tprint("Session locator:", str(_session_locator))
    tprint("Link local zone index(es):")
    for _x in _ll_zone_ids:
        tprint(_x)



    ####################################
    # Create sockets to send           #
    # LL multicasts                    #
    ####################################

    for _x in _ll_zone_ids:
        _make_mcssock(_x[0])

    # Those sockets are now waiting in _mcssocks[].
    # To send a packet:
    # _mcssocks[?][1].sendto(bytes.fromhex('f000baaa'),0,(str(ALL_GRASP_NEIGHBORS_6), CGRASP_LISTEN_PORT))


    # Discovery responses are received over UDP in cGRASP; no TCP listeners needed.

    ####################################
    # Start relay if needed            #
    ####################################

    global _coap_relay_state
    global _coap_engine
    _relay_needed = False
    relay_interface_count = len({info[0] for info in _ll_zone_ids})
    if relay_interface_count > 1 and not DULL:
        # start thread to relay incoming Discovery and
        # Synchronisation multicasts
        _relay_needed = True
        relay_names = []
        relay_indexes = set()
        for info in _ll_zone_ids:
            if info[0] in relay_indexes:
                continue
            relay_indexes.add(info[0])
            try:
                relay_names.append(socket.if_indextoname(info[0]))
            except Exception:
                pass
        if relay_names:
            config = _coap_relay_config_override or RelayConfig(tuple(relay_names))
            _coap_engine = CgraspEngine(config)
            _coap_engine.install()
        tprint("Multicast relay needed")
    else:
        _coap_relay_state = None
        _coap_engine = None
        tprint("Multicast relay not needed")

    ####################################
    # Start threads to listen for and  #
    # handle GRASP multicasts          #
    # (Discovery and Flood messages)   #
    # on all interfaces                #
    ####################################


    if not _use_coap_std_multicast:
        # Legacy raw UDP multicast path (ff02::13 / CGRASP_LISTEN_PORT)
        _mc_restart = False
        _mclisten().start()
        _mchandler().start()
        ttprint("Set up multicast listening")
    else:
        ttprint("Standard CoAP multicast enabled; legacy multicast threads disabled")


    ####################################
    # Start thread to keep an eye on   #
    # the ACP and need for TLS         #
    ####################################

    _watcher().start()
    ttprint("Set up ACP watcher")

    _grasp_initialised = True

    ####################################
    # Start configuration ASA          #
    ####################################

    _figger().start()

    # Auto-start aiocoap server endpoint for unicast-over-CoAP and/or standard multicast.
    if (_coap_server_autostart and _coap_transport_enabled) or _use_coap_std_multicast:
        _maybe_start_coap_transport()

    ####################################
    # GRASP initialisation complete!   #
    ####################################

    time.sleep(2) # to avoid printing glitch
    tprint("GRASP startup function exiting")

####################################
# Create globals needed for initialisation
####################################

_print_lock = threading.Lock() # printing might be needed before init!
test_mode = False              # referenced by skip_dialogue(), used by printing
_mess_check = False            # used by _parse_ functions
_listen_self = False           # referenced by skip_dialogue()
DULL = False                   # referenced by skip_dialogue()
_be_dull = False               # referenced by skip_dialogue()
_skip_dialogue = False         # referenced by skip_dialogue()
_dobubbles = False             # Don't bubble print by default
_bubbleQ = queue.Queue(100)    # Will be used if bubble printing

#------------------------------------------------------------
# The following are the GIF images used for the bubble printing
# mechanism. They are placed here only to avoid distraction
# elsewhere. Don't edit them! There's nothing significant below

_bigstring="""
R0lGODlhwgHIAOcAAAAAAAEBAQICAgMDAwQEBAUFBQYGBgcHBwgICAkJCQoKCgsLCwwMDA0NDQ4O
Dg8PDxAQEBERERISEhMTExQUFBUVFRYWFhcXFxgYGBkZGRoaGhsbGxwcHB0dHR4eHh8fHyAgICEh
ISIiIiMjIyQkJCUlJSYmJicnJygoKCkpKSoqKisrKywsLC0tLS4uLi8vLzAwMDExMTIyMjMzMzQ0
NDU1NTY2Njc3Nzg4ODk5OTo6Ojs7Ozw8PD09PT4+Pj8/P0BAQEFBQUJCQkNDQ0REREVFRUZGRkdH
R0hISElJSUpKSktLS0xMTE1NTU5OTk9PT1BQUFFRUVJSUlNTU1RUVFVVVVZWVldXV1hYWFlZWVpa
WltbW1xcXF1dXV5eXl9fX2BgYGFhYWJiYmNjY2RkZGVlZWZmZmdnZ2hoaGlpaWpqamtra2xsbG1t
bW5ubm9vb3BwcHFxcXJycnNzc3R0dHV1dXZ2dnd3d3h4eHl5eXp6ent7e3x8fH19fX5+fn9/f4CA
gIGBgYKCgoODg4SEhIWFhYaGhoeHh4iIiImJiYqKiouLi4yMjI2NjY6Ojo+Pj5CQkJGRkZKSkpOT
k5SUlJWVlZaWlpeXl5iYmJmZmZqampubm5ycnJ2dnZ6enp+fn6CgoKGhoaKioqOjo6SkpKWlpaam
pqenp6ioqKmpqaqqqqurq6ysrK2tra6urq+vr7CwsLGxsbKysrOzs7S0tLW1tba2tre3t7i4uLm5
ubq6uru7u7y8vL29vb6+vr+/v8DAwMHBwcLCwsPDw8TExMXFxcbGxsfHx8jIyMnJycrKysvLy8zM
zM3Nzc7Ozs/Pz9DQ0NHR0dLS0tPT09TU1NXV1dbW1tfX19jY2NnZ2dra2tvb29zc3N3d3d7e3t/f
3+Dg4OHh4eLi4uPj4+Tk5OXl5ebm5ufn5+jo6Onp6erq6uvr6+zs7O3t7e7u7u/v7/Dw8PHx8fLy
8vPz8/T09PX19fb29vf39/j4+Pn5+fr6+vv7+/z8/P39/f7+/v///yH+EUNyZWF0ZWQgd2l0aCBH
SU1QACH5BAEKAO8ALAAAAADCAcgAAAj+AN8JHEiwoMGDCBMqXMiwocOHECNKnEixosWLGDNq3Mix
o8ePIEOKHEmypMmTKFOqXMmypcuXMGPKnEmzps2bOHPq3Mmzp8+fQIMKHUq0qNGjSJMqXcq0qdOn
JAMEAEBVqtWrWAVo3cq1q9evYMOKHUu2rNmzaNOqXcu2rdu3cL8OGECgANSQVAEIWFBBw4cRKVi0
GEy4sOHDiBMrXsy4sePHkCNLnky5suXLmDNbZpGCxIcNFRoMyEvgbsW8BVA8qVPpFTFn1bR9E0e7
tu3buHPr3s27t+/fwIMLH068uPHjyJMrTw5umzVoxWZl0kNlhYK8ph1OBaDAxx9f5Oz+7evn75/5
8+jTq1/Pvr379/Djy59Pv779+/jz69/Pvz97f/3sY086xSwyBARU2ZXdQVMR0AEYtMSDnj/l+Wfh
hRhmqOGGHHboYYYVmocPL2+QYAAAByxIEFUglFEMPudR+OGMNNZo44045uhfiPpAM8cJVDWw4FQF
LGHKPOZRGKKOTDbp5JNQRhmfkubZk8sTCC5gmgAAQMCEMfxIKeaYZJZp5oYh5nNNGA8AkMBdVEUx
jD3/yHjmnXjmqeedFR6jxgFdPgUAATFUos+eiCaq6KI36kPLDAYEICgCahjD6KWYZqqpfdiwsQEA
GjTFZQSEYLPpqaimuqiM5TQCJAX+TVG1gSXjqGrrrbiOuY4oMATKFFUcYEJOrsQWa+yM65ASAwAR
NDVVsMMeK+201OKXbK8TOAsAtNV26+236V0LQAVJMMUlt+Cmq66x4lrAhLnbCrvuvPSmKi4GTsCL
br389puouBk8wdRo+/pr8MFkiqtBFEwREG+0CEcscZPicjBFIXoo5XDBE3fssYfidkAFxnlkfNTG
8n6s8soYiuuBFYToUbLJRRXwMMs455yfuB9cEXPJe9A81IkbpKzz0Ui7Jy4IVwwisx5Q51EU0UYn
bfXVS2PhdB5cQy00UFRDfPXYR4sbQhZbR801UWGT7bbOZqP9tNdQDwVo0WK/rXf+x+KKoIUgc3M9
s1B3V7334QiLO8Lfc8vcNeEA4I345ImT0uvigAuu9tc9FZ435aCvq/gWmXfteN1AeR766vOOLojp
m0udeuSGs247ta47PrPmQSFA++e3B1+s67DrzvlOvksu/PLsWg4ACaQXzztQydfO/PWoigt9IF3v
jsfa1P+O/fiqas/F6zPrXnLv4pPvvqbmA67HHvRHPT/7yr+v/6LaR5++/UELX/72R0A9xa97Xtud
AK1XwAbqynkkOB8C7SezBQLPgRiE0gFLlj4F/qR6F8ygCHW0wcZ50CcgHKEKn1TCDkbNgiuMIQkh
KEEOJvCFH2yfDHdIoxbesIL+ORwgD4e4IR9SUHYo1CERl9gyGqLPhDhMohCZSMX9GDFwMKyiFq3o
xAliMYgM3KIY4XPFE/YkhWNM43zKGMUzKlGNcGQPG4EoxTDGMY5zRKIbp3jHPuYxi30MpHn+CMYQ
CnKMhKyjIQ+5xUTu0Y6M1KIjeYLGSOKxizY8IiAtqcZJIu+NnBSjJ3VSyVAiEpNQpOMjF2nKIY4y
J6VspSRR6UJVUhKUsmTiK3ESy1zqkpY/1OMt+ehLVwJTk4Us5ix7FcEn1lKYnySmMmW4y5v0cpo7
rKZNronNGGqzJtzspgq/SZNwilOE5JyJOc+JwXTKZJ3sbKA7YwLPeBJwnjD+qac99YfPl+hzn+7r
p0v+CdDxCbQlBC3o9Q7KkoQqdHkMXYlDHxq8iKpkohS1nUVTgtGMrm6jKOmoR0EH0pOIdKSTK6lJ
TorSw6m0JCxtqd5eSpKYytRtNB2JTW86tpyKZKc8tZpPQwLUoCJtqCApqlHhdswvKnKpBm2qGYcJ
SaiSVKptpCorrZpSrNoymlXlKuKQ+hGlivVjZPWIWc/KN69Ck5S4ZCvl0tqRtco1YnTliF3verC8
bmSvfPWXXzUC2MDya7AZKaxh6YVYjCh2saJz6yYhu7fGXuSxlAWXZS2C2cx6a7MV6axnq7VB2HHw
rbC82WhnCkHS0S1oc2P+nwYqIY7Vkk1G6wjFCwBQgi44jW4UDIoDAPCAQFjDtm8jRyJKAAAYiIF7
gosu+H5iARSRYRhJQu7VrlGGChTAB2kARHShhofvoVYnBRBACRRBJ+1arR6rSMEAKpCFOvgBakGD
7eCEMhok1EIe7kWaP3TRBQEwIAdz6IPaajkUDHDHB7eoR3YD3DEZ3aMYUkDAAWpQhj3wQXPz2xxR
LhAAAszgEexI0pIo7K8KteMUNzAAAnZghvsab8HrK4rvIrCEXMRjSStmsbfsZB55GKMLEQDABYQw
Bz4EzXTde9xRNDAaCkQhFNm4h3qILORiBRkf4EAFGCwQgAbUIAxOPh3+iIGrFBH47gAr0IIjhIGO
INeHyzvCc5cxxA5kWCIML1BAAC6wAy/cwclQPt2Cj2cUDihAAANwwAiCUIZFtOIXyoiGNrzxjU57
+tPeAIc5tIym8vCDHeLg9KdXzepWu/rVsI61rGdN61rb+ta4zrWud83rXHtjG9NYRjBgIYk0GOEE
DoC0BGAghTfkQb823F0Cp+sUF2BgAaPJiwAQ0AAIeNvbEQg3BMTNAAuoARgYshM/fNEGEDzgAeGO
t7znTe962/ve+M63vvfN7377+98AD7jAB07wfkPAAQnINgACgAAKnGAIXqADHxQs3UTjOMfZicIQ
clADGHDmBChIQQr+VsACwbTgBSygwMK/0IsLhegcm7gBABhQAhvU4OY4zznOacDznvN8BkAHOg2C
TvSiG/3oSE+60pfO9KY7/elQj7rUp071qje9BjnwwRCSIIUvsMEOfPCDH2AL3GnbD3YqIkgf0mw8
wX2YDB8YgAY0sQ6Xm+cZebCAADhQhTh8uOKAD/x4o2Ze0wquvIgvr+AXz/jGO/7xkI+85CdP+cpb
fvLqwy/9+MD5+inaa7B9cgehnPaB/M+0evhDG4qQAAYwIRkWkpE8etGEusgADHn4cNl3z3ver7n3
wA++8IdP/OIb//jIT77yl8985QMexwB8muZMV3qC3Bi4f9ACCQD+kIJJmKNOdpYPlf5hjk2gQAAP
GMIa7nv6I97Q4u8f/efl3/z62//++M+//peP+hs/84fSp2aL9kzVVxC7E130Awc8kAAFQAXTACP7
ISP54AxmcAEAIAJRAHbuRzfS9j/AJ23ud1oguH8kWIImeIIo6HtRBoDEJ4IHWHbUV4AFETt5cF9N
8Ck2YAn7wB8Vwg6kMAMEgAA3MAbQlkorqD6n94ICmEn+B1wemIJQGIVSOIUceISNw4Ftd0QgOEH7
JYMGIW0etgYnQAAKwAfVMGF3dh74cA1qYIEckAR2oGBXOIdLeHYVd32fB32bQ4V82Id+GIWDt2bw
V0taOFVeOIP+JRMIbmAECoAAPMAL4Sd+5sEOp7ADB1AAMoBmoneFTOh7TkhBoGhCSUiIf1iKpniK
xic9g6dmhOiBpnWIDDE/gQAFn3ICj7BV/1Ee+zANa6AB25IEc0A/xUOHViiAmUd/gThtw4iKzNiM
zViMhreFUTZ60wOLDgEGJhAAD3AG4RAmevYeFZIOoCADBXAAMQAGfBA7Z5eHyJhJiSaCAdh2QCN6
hXd59niP+JiP+riP9vg9WhhieAhl0Zg+1igRLHAABIAFtnAfIRIPw4AFbcIBSCBxTyZ8T6hoLiRd
Kth/meeMHvmRf6iRZrdoofh5BUkRQqAABdACrSBhdSJ+IRL+DYEQAgLQADpABmkmPe/3gat4cVD0
ez45kiA5lESZgoJoeE54khhhBBUAACaQCLUyH0SGDp3QAwZQACuABYfWkQfYiZxojHnIjsGkk0JZ
lGZ5lvyHlEp5EhygjWYADjsIH1ymD7ogBgygZErgBjYGYhc5iEgZivK3loI5mEgRAgNQAFhwC2j4
Hy/5D/mgDHYQAgCwAGc2cdMImGUpfwNJmJzZmUdRAAXAAi25mOtRIftwDX7gAgCAACiQBXSwl6M4
gv5HjdPmmbZ5m8LllFA5JRUSDpTwAgZAACEQBXQAkAlkXjB4fdP3irjZnM6pE20SAWnwDXFZmkR2
DqogBCf+ggFCQJGrSH+7t5wd9JzkWZ400SYJcAbY1ZgTMpWkMAUL0CU6YAZ/sIkk2YlMeJHmuZ/8
2RJN6QBKQAwxkh7lUSHmIApHgCAQYAO4l45kqYxbyHv9OaEUehJcYgS6ICFbFiLoYApDkADEJQNo
8GyAeZRPyJdfVaEquqIZAQAD8AOfECbteR79kA6j8AQnwgAuAAbv4KBOOIrBJIqMxqJEWqQP4aIm
QAruMGEh4g/XQAlF0AAA0AAvsAUEAY9diYyseF5G2qVeehCjsQKNIDZE9gx8AAOAAgEwgBAoqpyn
hYVfGqdyihACEAAckAfrUCEhQg/MsAYiQBURkAMLEZT+90mQc3qoiOowD7AH0sCk6SALZGCBAAAr
DpGRMChliJqpcnoiFxAGjUqj0vAIRCABLpoBE8GJhqqpqhqno6EAXvCAVdILaFACDpMAILCquJqr
E+EwCAAGvmAe4HAKS4AgU6qrxnqsDdElToAM7UAMe2ADDhMAlIqs1FqtA8FwSpAJhPAEF8AlCGCt
4GqtCycBHKABJzIA4Zqu1JoXeZEi6vquurodAaAg8FqvuEoX9pqv+rqv/Nqv/vqvABuwAjuwBFuw
BnuwCJuwCruwDNuwDvuwEBuxEjuxFFuxFnuxGJuxGruxHNuxHvuxIBuyIjuyJFuyJnuyKJuyKruy
LNsqsi77sjAbszI7szRbszZ7szibszq7szzbsz77s0AbtEI7tERbtEYLEQEBADs="""

_bigstring2="""
R0lGODlhlgCbAIABAAAAAP///yH+D0lFVEYgR1JBU1AgMjAxNgAsAAAAAJYAmwAAAv6Mj6nL7Q+j
nLTai7PevPsPhuJIluaJpurKtu4Lx/JM1/aN5/qOAv4PDAJ4xIjwiEz+ijql8+lktqDUKlVKsmq3
SmyHCw4fvRex+ewjG9FstlrRjrffBrnd7b3r8cS9n4/zJ4iWM2goFniouHWz6GhV8yh5NTNpGSVz
qYmUuekJFPMpmvYyOlpqKuqSejrF+umqWjHIAvult7KZJZdr2TOXMomKGPzYCVa8aIN84ljI2KzY
VxV9yERtIo0FlW1N9tRNS9e1K04XkFRieJ4wVu7HDhf0Dh/fDjpibt8ruB9b748fwIC//hAUiOug
in4Kk+1pWPAhxGoSJ6ozaPHiwP6MITByzLfx4wePIkeSLHkrJEoNJ1duaOkyA8yYZVTKfEUqZUIP
OHNymImh5xCeNoP2NFlRJyukO5WmYnoHhFCodqQeJZr051WnvKia8hrHKk6wwLC+IgtI61izUdF6
cntG7Fm2VeFqsmsGry+6dbm24hsWsCzBaVlu9RtY7VzChY2uZUwIsS3IcSW/1RsmUVPLkSNlVbz5
WFvMmT2HfsmQRtGbQGt9Bn161WvUqUPNpr164W3DtYeNlps7Yt+O+mTHhr2b4nDixRF2BbnO+G/m
0V0f5/xc93XsiR0uF+FM+3To2pRn16gs3Hjy4dmfp2cMfHLS2y0Epz9fwn381Wwp7Ocv1HvmBdie
cwSWZ92B6UmnYH//NNjbgxDmp96E9XlnYXeiZViWahxq6OGHlWkmYmnPlMjMDihqsc2KmHzjIj7x
uKgQhx8pSNNXNDFwyY7+Necja8QESWSRRh6JZJJKLslkk04+CWUDBQAAOw=="""

#---------------The End ----------------------------------------------------
