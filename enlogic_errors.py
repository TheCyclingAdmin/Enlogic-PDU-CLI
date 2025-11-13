from __future__ import annotations
import sys
import requests
from requests import exceptions as rx

class ExitCode:
    OK = 0
    USAGE = 2
    CONFIG = 3
    AUTH = 4
    NETWORK = 5
    DEVICE = 6
    PARTIAL = 7
    IO = 8
    TIMEOUT = 9
    UNEXPECTED = 10

def exit_with(code: int, msg: str | None = None) -> None:
    if msg:
        print(msg, file=sys.stderr)
    sys.exit(code)

def map_request_error(exc) -> int:
    if isinstance(exc, rx.Timeout): return ExitCode.TIMEOUT
    if isinstance(exc, rx.SSLError): return ExitCode.NETWORK
    if isinstance(exc, rx.HTTPError):
        try:
            status = exc.response.status_code  # type: ignore[attr-defined]
            if status in (401,403): return ExitCode.AUTH
            return ExitCode.DEVICE
        except Exception:
            return ExitCode.DEVICE
    if isinstance(exc, requests.exceptions.RequestException): return ExitCode.NETWORK
    return ExitCode.UNEXPECTED
