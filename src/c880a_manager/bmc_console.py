"""Bounded BMC GUI session broker for the authenticated console gateway.

The BMC GUI session cookie, CSRF value, and stored credentials stay server-side.
The vendor viewer receives its short-lived KVM token through the authenticated
gateway; the upstream BMC origin and cookie are never returned to the browser.
"""

from __future__ import annotations

import ipaddress
import json
import re
import ssl
from typing import Any

import httpx
from websockets.asyncio.client import ClientConnection, connect


_MAX_JSON_BYTES = 64 * 1024
_KVM_TOKEN_PATH = "/api/kvm/token"
_VIEWER_CONFIG_PATH = "/api/settings/media/h5viewercfg"
_VIEWER_API_PATHS = frozenset({
    _KVM_TOKEN_PATH,
    _VIEWER_CONFIG_PATH,
    "/api/configuration/runtime",
    "/api/configuration/project",
    "/api/settings/media/adviser",
})
_STATIC_PATH = re.compile(r"^/(?:viewer\.html|viewer\.min\.(?:js|css)|(?:app|libs|templates|locales|images|fonts|bower)/[A-Za-z0-9_./-]+)$")
_MAX_ASSET_BYTES = 8 * 1024 * 1024
_USER_AGENT = "C880A-Manager/0.1"


class BmcConsoleError(Exception):
    """A BMC GUI operation failed without exposing response data or secrets."""


class BmcGuiSession:
    """One short-lived, fixed-origin BMC GUI session.

    ``verify=False`` is only for a server whose untrusted certificate was
    explicitly accepted during onboarding; normal operation validates TLS.
    """

    def __init__(self, host: str, *, port: int = 443, verify: bool | str = True,
                 transport: httpx.BaseTransport | None = None) -> None:
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError("BMC host must be an IP address") from exc
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("BMC port must be between 1 and 65535")
        authority = f"[{address}]" if address.version == 6 else str(address)
        self._origin = f"https://{authority}" + (f":{port}" if port != 443 else "")
        self._verify = verify
        self._client = httpx.Client(
            base_url=self._origin + "/", verify=verify, transport=transport,
            trust_env=False, follow_redirects=False,
            headers={"User-Agent": _USER_AGENT},
            timeout=httpx.Timeout(12.0, connect=5.0),
        )
        self._csrf: str | None = None

    def __enter__(self) -> BmcGuiSession:
        return self

    def __exit__(self, _type: Any, _value: Any, _traceback: Any) -> None:
        self.close()

    def _json_request(self, method: str, path: str, *, data: dict[str, str] | None = None,
                      authenticated: bool = False) -> dict[str, Any]:
        # Callers select fixed paths only. Never forward a browser-provided URL.
        headers = {"Accept": "application/json"}
        if authenticated:
            if not self._csrf:
                raise BmcConsoleError("BMC GUI session is not open")
            headers["X-CSRFToken"] = self._csrf
        try:
            with self._client.stream(method, path, data=data, headers=headers) as response:
                if response.status_code != 200:
                    raise BmcConsoleError(f"BMC GUI request failed ({response.status_code})")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > _MAX_JSON_BYTES:
                        raise BmcConsoleError("BMC GUI response exceeded size limit")
            payload = json.loads(body)
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            raise BmcConsoleError("BMC GUI request failed") from exc
        if not isinstance(payload, dict):
            raise BmcConsoleError("Unexpected BMC GUI response")
        return payload

    def login(self, username: str, password: str) -> None:
        if self._csrf is not None:
            raise BmcConsoleError("BMC GUI session is already open")
        payload = self._json_request("POST", "/api/session",
                                     data={"username": username, "password": password})
        csrf = payload.get("CSRFToken")
        if not isinstance(csrf, str) or not csrf or not self._client.cookies.get("QSESSIONID"):
            self._client.cookies.clear()
            raise BmcConsoleError("BMC GUI did not establish a session")
        self._csrf = csrf

    def kvm_ready(self) -> bool:
        token = self._json_request("GET", _KVM_TOKEN_PATH, authenticated=True)
        config = self._json_request("GET", _VIEWER_CONFIG_PATH, authenticated=True)
        return (isinstance(token.get("token"), str) and bool(token["token"])
                and isinstance(token.get("session"), str) and bool(token["session"])
                and bool(config.get("kvm_service_status")))

    def kvm_slot_available(self) -> bool:
        """Mirror the BMC launcher service check before opening a viewer."""
        if not self._csrf:
            raise BmcConsoleError("BMC GUI session is not open")
        try:
            with self._client.stream("GET", "/api/settings/services",
                                     headers={"X-CSRFToken": self._csrf}) as response:
                if response.status_code != 200:
                    raise BmcConsoleError(f"BMC KVM service check failed ({response.status_code})")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > _MAX_JSON_BYTES:
                        raise BmcConsoleError("BMC KVM service response exceeded size limit")
            services = json.loads(body)
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            raise BmcConsoleError("BMC KVM service check failed") from exc
        if not isinstance(services, list):
            raise BmcConsoleError("Unexpected BMC KVM service response")
        for service in services:
            if isinstance(service, dict) and service.get("service_name") == "kvm":
                count = service.get("viewer_count")
                return isinstance(count, int) and count == 0
        raise BmcConsoleError("BMC KVM service status is missing")

    def kvm_reconnect_enabled(self) -> bool:
        """Use the same advertised feature flag as the BMC's native launcher."""
        if not self._csrf:
            raise BmcConsoleError("BMC GUI session is not open")
        try:
            with self._client.stream(
                "GET", "/api/configuration/project",
                headers={"X-CSRFToken": self._csrf},
            ) as response:
                if response.status_code != 200:
                    raise BmcConsoleError(
                        f"BMC viewer feature check failed ({response.status_code})"
                    )
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > _MAX_JSON_BYTES:
                        raise BmcConsoleError("BMC viewer feature response exceeded size limit")
            features = json.loads(body)
        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            raise BmcConsoleError("BMC viewer feature check failed") from exc
        if not isinstance(features, (dict, list)):
            raise BmcConsoleError("Unexpected BMC viewer feature response")
        # The vendor GUI checks this feature in its serialized project data.
        return "KVM_SESSION_RECONNECT" in json.dumps(features)

    def fetch_viewer(self, path: str) -> tuple[bytes, str]:
        """Fetch a fixed-origin viewer resource, with no browser URL forwarding.

        Only GET resources needed by the vendor viewer are eligible. The
        caller must still authenticate every incoming browser request.
        """
        if not self._csrf:
            raise BmcConsoleError("BMC GUI session is not open")
        if path not in _VIEWER_API_PATHS and (not _STATIC_PATH.fullmatch(path)
                                               or ".." in path.split("/")):
            raise BmcConsoleError("Viewer resource is not permitted")
        try:
            with self._client.stream("GET", path,
                                     headers={"X-CSRFToken": self._csrf}) as response:
                if response.status_code != 200:
                    raise BmcConsoleError(f"Viewer resource failed ({response.status_code})")
                content_type = response.headers.get("content-type", "application/octet-stream").split(";", 1)[0]
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > _MAX_ASSET_BYTES:
                        raise BmcConsoleError("Viewer resource exceeded size limit")
            return bytes(body), content_type
        except httpx.HTTPError as exc:
            raise BmcConsoleError("Viewer resource request failed") from exc

    async def connect_kvm(self) -> ClientConnection:
        """Open the BMC video socket; the caller must close it promptly.

        The BMC cookie remains inside this process. Never pass it, or the
        returned connection, to a management-browser response.
        """
        if not self._csrf:
            raise BmcConsoleError("BMC GUI session is not open")
        session_cookie = self._client.cookies.get("QSESSIONID")
        if not session_cookie:
            raise BmcConsoleError("BMC GUI session cookie is missing")
        if self._verify is False:
            # Only reached for an explicit per-server onboarding exception.
            tls = ssl.create_default_context()
            tls.check_hostname = False
            tls.verify_mode = ssl.CERT_NONE
        else:
            tls = ssl.create_default_context(cafile=self._verify if isinstance(self._verify, str) else None)
        try:
            return await connect(
                self._origin.replace("https://", "wss://", 1) + "/kvm",
                origin=self._origin,
                additional_headers={"Cookie": f"QSESSIONID={session_cookie}"},
                subprotocols=["binary", "base64"], compression=None,
                user_agent_header=_USER_AGENT,
                ssl=tls, proxy=None, open_timeout=8, close_timeout=3,
                # The native browser viewer sends no WebSocket control pings.
                # The library's 20s ping + 20s timeout drops this BMC at ~40s.
                # The manager session and console lease still bound this socket.
                ping_interval=None,
                max_size=8 * 1024 * 1024, max_queue=4,
            )
        except Exception as exc:
            raise BmcConsoleError("BMC KVM socket handshake failed") from exc

    def close(self) -> None:
        if self._csrf is not None:
            try:
                # Best-effort release of the BMC session created by this broker.
                self._client.delete("/api/session", headers={"X-CSRFToken": self._csrf})
            except httpx.HTTPError:
                pass
            self._csrf = None
        self._client.cookies.clear()
        self._client.close()
