#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors

"""########################################################
########################################################
# cPfxm is a demonstration Autonomic Service Agent.
# It is a compact cGRASP/CoAP version of pfxm3.
# It supports the IPv6 Edge Prefix Management objective
# 'PrefixManager', mapped here to private cGRASP objective
# number 899201, and its companion 'PrefixManager.Params',
# mapped to private cGRASP objective number 899202.
#
# As demonstration code it does not operate in real
# prefix-assigning nodes or perform real prefix assignments.
#
# See src/cgrasp/cgrasp.py for license, copyright, and disclaimer.
########################################################"""

import os
import sys
import threading
import time
import math
import ipaddress

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cgrasp import cgrasp as grasp


OBJ_PREFIX_MANAGER = 899201
OBJ_PREFIX_PARAMS = 899202

###################################
# Print current pool
###################################

def prefstr(plen, pref):
    return str(ipaddress.IPv6Address(pref)) + "/" + str(plen)


def dump_pool():
    """Print prefix pool"""
    grasp.tprint("Prefix pool contents:")
    pool_lock.acquire()
    if len(ppool) == 0:
        grasp.tprint("(empty)")
    else:
        for x in ppool:
            grasp.tprint(prefstr(x[0], x[1]))
    pool_lock.release()
    return


###################################
# Thread to flood PrefixManager.Params repeatedly
###################################

class flooder(threading.Thread):
    """Thread to flood PrefixManager.Params repeatedly"""
    def __init__(self):
        threading.Thread.__init__(self, daemon=True)

    def run(self):
        grasp.tprint("Flooding", obj2.num, "for ever")
        while True:
            time.sleep(60)
            grasp.flood(asa_nonce, 59000, grasp.tagged_objective(obj2, None))
            time.sleep(5)


####################################
# Main negotiator
####################################

class main_negotiator(threading.Thread):
    """Main negotiator"""

    def __init__(self):
        threading.Thread.__init__(self, daemon=True)

    def run(self):
        grasp.tprint("Ready to negotiate", obj1.num, "as listener, unless pool is empty")
        while True:
            if len(ppool) > 0:
                err, snonce, answer = grasp.listen_negotiate(asa_nonce, obj1)
                if err:
                    grasp.tprint("listen_negotiate error:", grasp.etext[err])
                    time.sleep(5)
                else:
                    negotiator(snonce, answer).start()
            else:
                time.sleep(5)


####################################
# Support function for negotiator
####################################

def endit(snonce, r):
    """Support function for negotiator"""
    grasp.tprint("Failed", r)
    err = grasp.end_negotiate(asa_nonce, snonce, False, reason=r)
    if err:
        grasp.tprint("end_negotiate error:", grasp.etext[err])
    return


####################################
# Thread to handle a PrefixManager negotiation
####################################

class negotiator(threading.Thread):
    """Thread to negotiate PrefixManager as server"""
    def __init__(self, snonce, nobj):
        threading.Thread.__init__(self, daemon=True)
        self.snonce = snonce
        self.nobj = nobj

    def run(self):
        nobj = self.nobj
        snonce = self.snonce
        try:
            req_ipv = int(nobj.value[ipv])
            req_plen = int(nobj.value[lgth])
        except:
            endit(snonce, "Invalid request format")
            return

        grasp.tprint("Got request for IPv" + str(req_ipv) + "; length=", req_plen)
        if nobj.dry:
            grasp.tprint("Dry run (not handled by this implementation)")

        if len(ppool) == 0:
            endit(snonce, "Prefix pool empty")
        elif req_ipv != 6:
            endit(snonce, "Only IPv6 is supported in cPfxm")
        elif req_plen < 32 or req_plen > subnet_max:
            endit(snonce, "Prefix length out of range")
        else:
            pref = get_from_pool(req_plen)
            if not pref:
                while (not pref) and (req_plen < subnet_max):
                    req_plen += 1
                    pref = get_from_pool(req_plen)
            if pref:
                nobj.value = [6, req_plen, pref]
                grasp.tprint("Starting negotiation")
                grasp.tprint("Offering", prefstr(req_plen, pref))
                err, temp, nobj = grasp.negotiate_step(asa_nonce, snonce, nobj, 5000)
                grasp.ttprint("Step gave:", err, temp, nobj)
                if (not err) and temp == None:
                    grasp.tprint("Negotiation succeeded")
                elif not err:
                    insert_pool(req_plen, pref)
                    endit(snonce, "Insufficient resource")
                else:
                    insert_pool(req_plen, pref)
                    if err == grasp.errors.loopExhausted:
                        endit(snonce, "Loop count exhausted")
                    else:
                        grasp.tprint("Failed:", grasp.etext[err])
            else:
                endit(snonce, "No prefix available")


###################################
# Thread to delegate prefixes to clients.
# This version is a simulation.
###################################

delegated = []

class delegator(threading.Thread):
    """Thread to delegate prefixes"""
    def __init__(self):
        threading.Thread.__init__(self, daemon=True)

    def run(self):
        grasp.tprint("Prefix delegator running")
        while True:
            time.sleep(10)
            p = get_from_pool(subnet_length)
            if p == None:
                nudge_pool(subnet_length)
            else:
                delegated.append([subnet_length, p])
            _l = len(delegated)
            if _l == 1:
                grasp.tprint("1 prefix was delegated")
            if _l > 1:
                grasp.tprint(_l, "prefixes were delegated")


###################################
# Functions for prefix manipulation
###################################

bytemasks = [b'\x00', b'\x80', b'\xc0', b'\xe0', b'\xf0', b'\xf8', b'\xfc', b'\xfe', b'\xff']

def make_mask(plen):
    """-> bytes object that is a mask of plen bits"""
    mask = b''
    for i in range(0, plen//8):
        mask += b'\xff'
    mask += bytemasks[plen%8]
    while len(mask) < 16:
        mask += b'\x00'
    return mask


def mask_prefix(plen, prefix):
    """-> packed prefix masked to length plen"""
    m = make_mask(plen)
    r = b''
    for i in range(0, 16):
        r += bytes([(prefix[i] & m[i]) % 256])
    return r


bitmasks = [1, 128, 64, 32, 16, 8, 4, 2]
bitvals = (1, 2, 4, 8, 16, 32, 64, 128)

def split_prefix(plen, prefix):
    """-> plen+1, prefix1, plen+1, prefix2"""
    lb = 127
    for i in range(15, -1, -1):
        if prefix[i] == 0:
            lb -= 8
        else:
            for j in bitvals:
                if not j & prefix[i]:
                    lb -= 1
                else:
                    break
            break
    if plen > 127 or plen <= lb:
        grasp.tprint("Cannot split prefix", prefstr(plen, prefix))
        raise RuntimeError("Unsplittable prefix")
    new_plen = plen + 1
    new_pref = b''
    j = plen//8
    for i in range(0, j):
        new_pref += bytes([prefix[i]])
    new_pref += bytes([prefix[j] | bitmasks[new_plen%8]])
    while len(new_pref) < 16:
        new_pref += b'\x00'
    return new_plen, prefix, new_plen, new_pref


####################################
# Functions to manage prefix pool
####################################

ppool = []
pool_lock = threading.Lock()
need = 0

def create_pool():
    """makes a prefix pool, called only in origin"""
    ini_pref = [32, bytes.fromhex('20010db8000000000000000000000000')]
    try:
        _ = input("Choose IPv6 prefix for pool? Y/N:")
        if _[0] == "Y" or _[0] == "y":
            ini_pref = None
    except:
        pass
    if ini_pref == None:
        pl = 0
        while pl < 3 or pl > 127:
            try:
                _ = input("IPv6 prefix length for pool (3..127):")
                pl = eval(_)
            except:
                pass
        pp = bytes.fromhex('20010db8000000000000000000000000')
        try:
            _ = input("Manual prefix entry? Y/N:")
            if _[0] == "Y" or _[0] == "y":
                pp = None
                while pp == None:
                    _ = input("Enter IPv6 prefix:>")
                    try:
                        pp = ipaddress.IPv6Address(_).packed
                    except:
                        print("Invalid")
        except:
            pass
        ini_pref = [pl, pp]
    pool_lock.acquire()
    ppool.append(ini_pref)
    pool_lock.release()
    return


def get_from_pool(plen):
    """-> packed IPv6 prefix of requested length, or None"""
    pool_lock.acquire()
    for i in range(len(ppool)-1, -1, -1):
        if ppool[i][0] == plen:
            r = ppool[i][1]
            del ppool[i]
            pool_lock.release()
            return r
        elif ppool[i][0] < plen:
            nl, p1, _, p2 = split_prefix(ppool[i][0], ppool[i][1])
            del ppool[i]
            pool_lock.release()
            insert_pool(nl, p1)
            if nl == plen:
                return p2
            else:
                insert_pool(nl, p2)
                return get_from_pool(plen)
    pool_lock.release()
    return None


def insert_pool(plen, prefix):
    """inserts IPv6 prefix in pool in canonical order"""
    pool_lock.acquire()
    if len(ppool) > 0:
        for i in range(len(ppool)):
            if ppool[i][0] < plen:
                continue
            elif ppool[i][0] == plen:
                while i < len(ppool):
                    if prefix == ppool[i][1]:
                        grasp.tprint("Blocked insertion of duplicate prefix",
                                     prefstr(plen, prefix))
                        pool_lock.release()
                        return
                    if (prefix < ppool[i][1]) and (ppool[i][0] == plen) \
                       or (ppool[i][0] > plen):
                        ppool.insert(i, [plen, prefix])
                        pool_lock.release()
                        return
                    i += 1
            else:
                ppool.insert(i, [plen, prefix])
                pool_lock.release()
                return
    ppool.append([plen, prefix])
    pool_lock.release()
    return


def sum_pool():
    """ -> estimate of IPv6 pool size in /'subnet_unit's"""
    spool = 0
    pool_lock.acquire()
    for i in range(len(ppool)):
        spool += 2**(subnet_unit-ppool[i][0])
    pool_lock.release()
    return spool


def nudge_pool(l):
    """signal need for prefixes of length l"""
    global need
    need += 2**(subnet_length-l)


####################################
# Thread to compress pool
####################################

class compress(threading.Thread):
    """Thread to compress pool"""
    def __init__(self):
        threading.Thread.__init__(self, daemon=True)

    def run(self):
        while True:
            pool_lock.acquire()
            if len(ppool) > 1:
                l1 = ppool[0][0]
                p1 = ppool[0][1]
                for i in range(1, len(ppool)):
                    l2 = ppool[i][0]
                    p2 = ppool[i][1]
                    if l1 == l2:
                        nl = l1 - 1
                        np = mask_prefix(nl, p1)
                        if np == mask_prefix(nl, p2):
                            del ppool[i]
                            del ppool[i-1]
                            pool_lock.release()
                            insert_pool(nl, np)
                            pool_lock.acquire()
                            break
                    l1 = l2
                    p1 = p2
            pool_lock.release()
            time.sleep(5)


grasp.tprint("==========================")
grasp.tprint("ASA cPfxm is starting up.")
grasp.tprint("==========================")
grasp.tprint("cPfxm is a demonstration Autonomic Service Agent.")
grasp.tprint("It supports the IP Edge Prefix Management")
grasp.tprint("objective 'PrefixManager' and its companion")
grasp.tprint("'PrefixManager.Params', using cGRASP over CoAP.")
grasp.tprint("==========================")

grasp.skip_dialogue(testing=False, selfing=False, diagnosing=True, be_dull=True)
grasp.enable_coap_transport(
    bind=os.environ.get("CGRASP_BIND", "::"),
    port=int(os.environ.get("CGRASP_COAP_PORT", "5683")),
    strict_coap=False,
    standard_multicast=True,
)

time.sleep(8)

####################################
# Set some control variables to default values
####################################

origin = False
subnet_default = 64
subnet_max = 96
subnet_min = 48
subnet_length = subnet_default

####################################
# Input mode etc. from user
####################################

print("Startup dialogue: press Enter for defaults")

try:
    _ = input("Act as origin? Y/N:")
    if _[0] == "Y" or _[0] == "y":
        origin = True
except:
    pass

if origin:
    grasp.tprint("This ASA will provide an initial prefix pool.")
    grasp.tprint("Also, it will supply default parameters for other ASAs.")
    try:
        _ = input("Enter longest allowed IPv6 subnet request:")
        subnet_length = int(eval(_))
    except:
        pass
    if subnet_length > subnet_max:
        subnet_length = subnet_max
    if subnet_length < subnet_min:
        subnet_length = subnet_min
    grasp.tprint("Using allowed IPv6 subnet length", subnet_length)
    subnet_unit = subnet_default
    create_pool()
    dump_pool()
    btext = "cPfxm Origin"
else:
    grasp.tprint("This ASA will start with an empty prefix pool.")
    try:
        _ = input("Enter subnet length to be delegated:")
        subnet_length = int(eval(_))
    except:
        pass
    if subnet_length > subnet_max:
        subnet_length = subnet_max
    if subnet_length < subnet_min:
        subnet_length = subnet_min
    grasp.tprint("Using subnet length", subnet_length)
    subnet_unit = subnet_length
    btext = "cPfxm Delegator"

####################################
# Register ASA/objectives
####################################

_err, asa_nonce = grasp.register_asa("cPfxm")
if not _err:
    grasp.tprint("ASA cPfxm registered OK")
else:
    grasp.tprint("Fatal error:", grasp.etext[_err])
    exit()

obj1 = grasp.cobjective(OBJ_PREFIX_MANAGER)
obj1.loop_count = 4
obj1.neg = True
obj1.value = None

ipv = 0
lgth = 1
pfx = 2

_err = grasp.register_obj(asa_nonce, obj1, discoverable=True)
if not _err:
    grasp.tprint("Objective", obj1.num, "registered OK")
else:
    grasp.tprint("Fatal error:", grasp.etext[_err])
    exit()

obj2 = grasp.cobjective(OBJ_PREFIX_PARAMS)
obj2.loop_count = 4
obj2.synch = True

if origin:
    _err = grasp.register_obj(asa_nonce, obj2, discoverable=True)
    if not _err:
        grasp.tprint("Objective", obj2.num, "registered OK")
    else:
        grasp.tprint("Fatal error:", grasp.etext[_err])
        exit()

####################################
# Start pretty printing
####################################

grasp.init_bubble_text(btext)

####################################
# If origin, flood and answer synch
####################################

if origin:
    obj2.value = [[["role", "RSG"], ["prefix_length", 34]],
                  [["role", "ASG"], ["prefix_length", 44]],
                  [["role", "CSG"], ["prefix_length", 56]]]

    flooder().start()
    grasp.tprint("Flooding", obj2.num, "for ever")

    _err = grasp.listen_synchronize(asa_nonce, obj2)
    if not _err:
        grasp.tprint("Listening for synch requests for", obj2.num)
    else:
        grasp.tprint("Error in listen_synchronize:", grasp.etext[_err])

###################################
# Negotiate obj1 as listener
###################################

main_negotiator().start()

###################################
# Get parameters (if not origin)
###################################

if not origin:
    grasp.tprint("Attempting to obtain prefix management parameters")
    err, param_obj = grasp.synchronize(asa_nonce, obj2, None, 5000)
    if not err:
        grasp.tprint("Results for", param_obj.num, ":", param_obj.value)
    else:
        grasp.tprint("Error obtaining parameters:", grasp.etext[err])

    need = 32
    delegator().start()

###################################
# Start garbage collector
###################################

compress().start()

###################################
# Negotiate obj1 as requester for ever
###################################

want_obj = grasp.cobjective(OBJ_PREFIX_MANAGER)
want_obj.neg = True

good_peer = None
while True:
    shortfall = need - sum_pool()
    if shortfall > 0:
        if shortfall < 1:
            want_p = subnet_length - 1
        else:
            want_p = subnet_length - 2 - int(math.log(shortfall, 2))
        if want_p < subnet_min:
            want_p = subnet_min
        grasp.tprint("IPv6 prefix pool is low, will ask for /" + str(want_p))
        want_obj.value = [6, want_p, None]
        err, ll = grasp.discover(asa_nonce, want_obj, 3000, flush=True)
        if err:
            grasp.tprint("Discovery error:", grasp.etext[err])
        elif ll == []:
            grasp.tprint("No peer discovered")
            good_peer = None
        else:
            if len(ll) == 1:
                peer = ll[0]
                grasp.tprint("Trying the only peer")
            elif good_peer in ll:
                peer = good_peer
                grasp.tprint("Trying previous peer")
            else:
                next_peer = grasp._prng.randint(0, len(ll)-1)
                peer = ll[next_peer]
                grasp.tprint("Trying peer", next_peer, "out of", len(ll))
            err, snonce, answer = grasp.req_negotiate(asa_nonce, want_obj, peer, 5000)
            if not err:
                if snonce:
                    if answer.value[lgth] < want_p + 1:
                        grasp.end_negotiate(asa_nonce, snonce, True)
                        insert_pool(answer.value[lgth], answer.value[pfx])
                        need = 0
                        good_peer = peer
                        grasp.tprint("Obtained", prefstr(answer.value[lgth], answer.value[pfx]))
                    else:
                        grasp.end_negotiate(asa_nonce, snonce, False, "Insufficient offer")
                        grasp.tprint("Refused prefix of length", answer.value[lgth])
            else:
                if err == grasp.errors.declined:
                    grasp.tprint("Peer declined:", answer)
                else:
                    grasp.tprint("req_negotiate error:", grasp.etext[err])

    grasp.tprint("IPv6 pool size", int(sum_pool()), "/" + str(subnet_unit) + "s")
    time.sleep(10)
