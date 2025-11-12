# tests/test_cli_list_super.py
import sys
import types
import enlogic_core as core
import enlogic_cli as cli

# Fake client to record auth used
class FakeClient:
    def __init__(self, base, insecure, timeout, retries, backoff, debug):
        self.base = base
        self.calls = {"fetch_maps": [], "fetch_locks_map": [], "pdu_display": []}
    def fetch_maps(self, pduid, auth):
        self.calls["fetch_maps"].append(auth.username if hasattr(auth, "username") else getattr(auth, "username", None))
        # 2 outlets
        return ({1:"on", 2:"off"}, {1:"PSU1", 2:"PSU2"})
    def fetch_locks_map(self, pduid, auth):
        self.calls["fetch_locks_map"].append(auth.username if hasattr(auth, "username") else getattr(auth, "username", None))
        return {1: True, 2: False}
    def pdu_display(self, pduid, auth, override=None):
        self.calls["pdu_display"].append(auth.username if hasattr(auth, "username") else getattr(auth, "username", None))
        return "PDU-Label"

def run_with_args(argv):
    old = sys.argv[:]
    try:
        sys.argv = ["enlogic_cli.py"] + argv
        cli.core.PDUClient = FakeClient  # patch in module under test
        cli.main()
    except SystemExit as e:
        return e.code, getattr(cli, "core").PDUClient  # return patched class obj for inspection
    finally:
        sys.argv = old

def test_list_uses_super_when_flag(monkeypatch):
    # run list with --use-super
    code, P = run_with_args([
        "--host","1.2.3.4","--super-user","super","--super-password","sp","list","--use-super"
    ])
    assert code == 0

def test_list_uses_normal_auth_without_flag(monkeypatch):
    code, P = run_with_args([
        "--host","1.2.3.4","--user","u","--password","p","list"
    ])
    assert code == 0
