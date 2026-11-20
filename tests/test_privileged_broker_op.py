"""Wire-format opt-in addition for the root-side fixed-operation broker."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentinelx_protocol.messages import RequestMessage, parse_message


def test_new_operation_round_trip():
    request = RequestMessage(
        id="broker-1",
        op="privileged_broker",
        payload={"operation": "audit-check", "ticket": "a" * 64},
    )
    parsed = parse_message(request.model_dump())
    assert isinstance(parsed, RequestMessage)
    assert parsed.op == "privileged_broker"
    assert parsed.payload == request.payload


def test_existing_script_run_operation_untouched():
    old = RequestMessage(
        id="script-1",
        op="script_run",
        payload={"interpreter": "python3", "content": "print(1)"},
    )
    assert parse_message(old.model_dump()).op == "script_run"


def test_unknown_privileged_operation_name_still_rejected():
    with pytest.raises(ValidationError):
        RequestMessage(id="x", op="privileged_root_shell", payload={})
