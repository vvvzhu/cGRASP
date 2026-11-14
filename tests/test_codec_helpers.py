# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""Unit tests for cgrasp2 codec helpers that do not need engine startup."""

from __future__ import annotations

import ipaddress

import cbor2

from cgrasp import cgrasp as cgrasp2
def test_cobjective_defaults_and_flagword():
    objective = cgrasp2.cobjective(42)
    assert objective.num == 42
    assert objective.loop_count == cgrasp2.GRASP_DEF_LOOPCT
    assert objective.value is None

    objective.discoverable = True
    objective.neg = True
    objective.loop_count = 3
    assert cgrasp2._flagword(objective) == cgrasp2.B_DISC | cgrasp2.B_NEG
    assert cgrasp2._flags(cgrasp2.B_NEG | cgrasp2.B_SYNCH) == (True, True, False)


def test_oclone_is_independent():
    objective = cgrasp2.cobjective(7)
    objective.value = "value"
    clone = cgrasp2._oclone(objective)
    clone.value = "changed"
    assert objective.value == "value"
    assert clone is not objective


def test_assemble_and_parse_objective_round_trip():
    objective = cgrasp2.cobjective(42)
    objective.neg = True
    objective.loop_count = 4
    objective.value = "payload"

    raw = cgrasp2._ass_obj(objective)
    assert raw[0] == 42
    assert raw[2] == 4

    parsed = cgrasp2._parse_obj(raw)
    assert parsed is not None
    assert parsed.num == 42
    assert parsed.neg is True
    assert parsed.loop_count == 4
    assert parsed.value == "payload"


def test_assemble_and_parse_discovery_message():
    objective = cgrasp2.cobjective(42)
    objective.discoverable = True
    payload = cgrasp2._ass_message(
        cgrasp2.M_DISCOVERY, 1234, b"\xfe" + b"\x00" * 15, objective)

    decoded = cbor2.loads(payload)
    message = cgrasp2._parse_msg(decoded)
    assert message is not None
    assert message.mtype == cgrasp2.M_DISCOVERY
    assert message.id_value == 1234
    assert message.obj.num == 42


def test_assemble_and_parse_locator_option():
    locator = cgrasp2.asa_locator(ipaddress.IPv6Address("fe80::1"), 0, False)
    locator.is_ipaddress = True
    locator.protocol = 17
    locator.port = 5683

    option = cgrasp2._option(cgrasp2.O_IPv6_LOCATOR)
    option.locator = locator.locator.packed
    option.protocol = 17
    option.port = 5683

    raw = cgrasp2._ass_opt(option)
    parsed = cgrasp2._parse_opt(raw)
    assert parsed is not None
    assert parsed.otype == cgrasp2.O_IPv6_LOCATOR
    assert parsed.locator == ipaddress.IPv6Address("fe80::1").packed
    assert parsed.protocol == 17
    assert parsed.port == 5683


def test_parse_obj_ignores_malformed_input():
    assert cgrasp2._parse_obj(None) is None
    assert cgrasp2._parse_obj([]) is None
    assert cgrasp2._parse_obj(["name", "flags", 1]) is None


def test_parse_opt_ignores_malformed_input():
    assert cgrasp2._parse_opt([]) is None
    assert cgrasp2._parse_opt("not-a-list") is None


def test_detag_object_value():
    objective = cgrasp2.cobjective(1)
    objective.value = cbor2.CBORTag(24, b"\x01\x02")
    detagged = cgrasp2._detag_obj(objective)
    assert detagged.value == b"\x01\x02"

    objective.value = "plain"
    assert cgrasp2._detag_obj(objective).value == "plain"


def test_hexit_bytes():
    assert cgrasp2._hexit(b"\x01\x02") == b"0102"


def test_parse_msg_rejects_malformed_payload():
    assert cgrasp2._parse_msg(None) is None
    assert cgrasp2._parse_msg([]) is None
    assert cgrasp2._parse_msg([999]) is None


def test_assemble_and_parse_response_message():
    locator = cgrasp2._option(cgrasp2.O_IPv6_LOCATOR)
    locator.locator = b"\xfe" + b"\x00" * 15
    locator.protocol = 17
    locator.port = 5683
    payload = cgrasp2._ass_message(
        cgrasp2.M_RESPONSE, 77, b"\xfe" + b"\x00" * 15, 1234, [locator])
    message = cgrasp2._parse_msg(cbor2.loads(payload))
    assert message is not None
    assert message.mtype == cgrasp2.M_RESPONSE
    assert message.ttl == 1234
    assert message.options


def test_assemble_and_parse_end_message():
    option = cgrasp2._option(cgrasp2.O_ACCEPT)
    payload = cgrasp2._ass_message(cgrasp2.M_END, 55, None, option)
    message = cgrasp2._parse_msg(cbor2.loads(payload))
    assert message is not None
    assert message.mtype == cgrasp2.M_END
    assert message.options[0].otype == cgrasp2.O_ACCEPT


def test_assemble_decline_option():
    option = cgrasp2._option(cgrasp2.O_DECLINE)
    option.reason = "not now"
    raw = cgrasp2._ass_opt(option)
    parsed = cgrasp2._parse_opt(raw)
    assert parsed is not None
    assert parsed.otype == cgrasp2.O_DECLINE
    assert parsed.reason == "not now"


def test_hexit_list_is_recursive():
    values = [b"\x01", [b"\x02"]]
    cgrasp2._hexit(values)
    assert values == [b"01", [b"02"]]


def test_session_instance_fields():
    session = cgrasp2._session_instance(9, True, b"\xfe" * 16)
    assert session.id_value == 9
    assert session.id_active is True
    assert session.id_source == b"\xfe" * 16
    assert session.id_relayed is False


def test_session_cache_insert_lookup_update(monkeypatch):
    import threading

    monkeypatch.setattr(cgrasp2, "_sess_lock", threading.RLock())
    monkeypatch.setattr(cgrasp2, "_session_id_cache", [])

    session = cgrasp2._session_instance(11, True, None)
    assert cgrasp2._insert_session(session) is True
    assert cgrasp2._get_session(cgrasp2._session_handle(11, None)) is session

    session.id_active = False
    assert cgrasp2._update_session(session) is True
    assert cgrasp2._get_session(cgrasp2._session_handle(11, None)) is False


def test_check_asa_obj_rejects_unknown_handle(monkeypatch):
    import threading

    monkeypatch.setattr(cgrasp2, "_obj_lock", threading.RLock())
    monkeypatch.setattr(cgrasp2, "_obj_registry", [])

    objective = cgrasp2.cobjective(1)
    objective.neg = True
    assert cgrasp2._check_asa_obj(object(), objective, False) == cgrasp2.errors.noASA


def test_rejects_objective_with_neg_and_synch():
    objective = cgrasp2.cobjective(1)
    objective.neg = True
    objective.synch = True
    assert cgrasp2._check_asa_obj(object(), objective, False) == cgrasp2.errors.notBoth
