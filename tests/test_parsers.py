# tests/test_parsers.py
import enlogic_core as core

def test_parse_outlet_number():
    assert core.parse_outlet_number({"OutletNumber": 7}, None) == 7
    assert core.parse_outlet_number({"Name": "Outlet 12"}, None) == 12
    assert core.parse_outlet_number({}, "/redfish/v1/.../Outlets/OUTLET5") == 5
    assert core.parse_outlet_number({"Name": "weird"}, None) is None

def test_parse_outlet_state_and_lock():
    o = {"PowerState": "On", "PowerControlLocked": True}
    assert core.parse_outlet_state(o) == "on"
    assert core.parse_outlet_locked(o) is True
    o2 = {"Status": {"State": "off", "Locked": False}}
    assert core.parse_outlet_state(o2) == "off"
    assert core.parse_outlet_locked(o2) is False
