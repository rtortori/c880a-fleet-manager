"""Isolated-origin HTTP/WebSocket relay for one onboarded BMC console.

This runs on a separate port so the BMC viewer's root-relative resources and
same-origin WebSockets cannot collide with the fleet manager API. A browser
can create a BMC GUI session only by POSTing the manager's CSRF token from
the configured manager origin; every subsequent request rechecks that manager
session and the server's active state.
"""

from __future__ import annotations

import argparse
import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
import hmac
import logging
import math
import os
from pathlib import Path
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI, HTTPException, Request, WebSocket
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, HTMLResponse, Response
from starlette.websockets import WebSocketDisconnect
import uvicorn

from .bmc_console import BmcConsoleError, BmcGuiSession
from .deployment import listener_address
from .manager import COOKIE
from .storage import Store


STATIC = Path(__file__).parent / "static"
LOG = logging.getLogger("c880a.console_gateway")
_MAX_BROWSER_MESSAGE = 8 * 1024 * 1024
_MAX_CONSOLE_IDLE_MINUTES = 15
_LAUNCHER = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>C880A virtual console</title><script src="/console-features.js"></script>
<script src="/console-launcher.js"></script><script src="/console-idle.js" defer></script>
<link rel="stylesheet" href="/console-gateway.css"></head><body>
<header><strong>C880A virtual console</strong><span id="console-idle-status" role="status">Connecting…</span>
<button id="console-keep-open" type="button" hidden>Keep console open</button></header>
<p id="console-idle-warning" role="alert" hidden>Console will close soon due to inactivity. Use the console or choose Keep console open.</p>
<p id="console-expired" role="alert" hidden>Console session ended. Close this window and reopen it from the manager.</p>
<iframe id="console-viewer" title="Virtual KVM" src="/viewer.html" allow="fullscreen"></iframe>
</body></html>"""


@dataclass
class ConsoleLease:
    gui: BmcGuiSession
    created: float
    last_activity: float
    kvm_reconnect_enabled: bool


class ConsoleRuntime:
    def __init__(self, store: Store, server_id: str, manager_origin: str,
                 console_origin: str, bmc_ca: str | None = None) -> None:
        self.store = store
        self.server_id = server_id
        self.manager_origin = self._origin(manager_origin)
        self.console_origin = self._origin(console_origin)
        self.bmc_ca = bmc_ca
        self.leases: dict[str, ConsoleLease] = {}
        self.lock = threading.RLock()

    @staticmethod
    def _origin(raw: str) -> str:
        try:
            parsed = urlsplit(raw)
            host, port = parsed.hostname, parsed.port
        except ValueError:
            raise ValueError("Expected a plain HTTP(S) origin") from None
        if parsed.scheme not in ("http", "https") or not host or parsed.path not in ("", "/") or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise ValueError("Expected a plain HTTP(S) origin")
        authority = f"[{host}]" if ":" in host else host
        default_port = 443 if parsed.scheme == "https" else 80
        if port is not None and port != default_port:
            authority += f":{port}"
        return f"{parsed.scheme}://{authority}"

    def manager_origin_matches(self, raw: str | None) -> bool:
        try:
            return self._origin(raw or "") == self.manager_origin
        except ValueError:
            return False

    def manager_session(self, token: str | None, *, touch: bool = True) -> dict[str, Any]:
        session = self.store.session(token, touch=touch) if token else None
        server = self.store.get_server(self.server_id)
        if not session or not server or server["state"] != "active":
            raise HTTPException(401, "Console access requires an active manager session and server")
        if session["role"] != "admin":
            raise HTTPException(403, "Admin role required for console access")
        if session["must_change_password"]:
            raise HTTPException(403, "Change the initial password before opening a console")
        return session

    def launch(self, session_hash: str) -> None:
        server = self.store.get_server(self.server_id)
        if not server or server["state"] != "active":
            raise BmcConsoleError("Server is not active")
        verify: bool | str = False if server["insecure_bmc"] else self.bmc_ca or True
        gui = (BmcGuiSession(server["bmc_host"], verify=verify) if server["bmc_port"] == 443
               else BmcGuiSession(server["bmc_host"], port=server["bmc_port"], verify=verify))
        try:
            gui.login(server["username"], self.store.decrypt(server))
            if not gui.kvm_slot_available():
                raise BmcConsoleError("BMC already has an active KVM viewer")
            reconnect_enabled = gui.kvm_reconnect_enabled()
        except Exception:
            gui.close()
            raise
        with self.lock:
            previous = self.leases.pop(session_hash, None)
            opened_at = time.monotonic()
            self.leases[session_hash] = ConsoleLease(gui, opened_at, opened_at,
                                                     reconnect_enabled)
        if previous:
            previous.gui.close()

    def idle_seconds(self) -> int:
        # Clamp persisted values too; direct DB edits must not create an
        # unbounded BMC GUI session.
        minutes = self.store.setting("console_idle_minutes", 15)
        return max(1, min(minutes, _MAX_CONSOLE_IDLE_MINUTES)) * 60

    def active_lease(self, session_hash: str) -> tuple[ConsoleLease, float]:
        idle_seconds = self.idle_seconds()
        with self.lock:
            item = self.leases.get(session_hash)
            remaining = idle_seconds - (time.monotonic() - item.last_activity) if item else 0
            if item and remaining > 0:
                return item, remaining
            if item:
                self.leases.pop(session_hash, None)
        if item:
            item.gui.close()
        raise HTTPException(401, "Console session expired; reopen it from the manager")

    def remaining(self, session_hash: str) -> float:
        return self.active_lease(session_hash)[1]

    def lease(self, session_hash: str) -> BmcGuiSession:
        return self.active_lease(session_hash)[0].gui

    def note_activity(self, session_hash: str) -> None:
        idle_seconds = self.idle_seconds()
        with self.lock:
            item = self.leases.get(session_hash)
            now = time.monotonic()
            if item and now - item.last_activity < idle_seconds:
                item.last_activity = now
                return
            if item:
                self.leases.pop(session_hash, None)
        if item:
            item.gui.close()
        raise HTTPException(401, "Console session expired; reopen it from the manager")

    def prune(self) -> None:
        now = time.monotonic()
        idle_seconds = self.idle_seconds()
        server = self.store.get_server(self.server_id)
        active_server = bool(server and server["state"] == "active")
        with self.lock:
            candidates = list(self.leases.items())
        expired = []
        for key, item in candidates:
            if not active_server or now - item.last_activity >= idle_seconds:
                expired.append((key, item))
                continue
            session = self.store.session_by_hash(key)
            if not session or session["role"] != "admin" or session["must_change_password"]:
                expired.append((key, item))
        with self.lock:
            leases = []
            for key, item in expired:
                if self.leases.get(key) is item:
                    self.leases.pop(key)
                    leases.append(item)
        for item in leases:
            item.gui.close()

    def revoke(self, session_hash: str) -> None:
        """Release the BMC GUI session as soon as manager access is revoked."""
        with self.lock:
            lease = self.leases.pop(session_hash, None)
        if lease:
            lease.gui.close()

    def close_all(self) -> None:
        with self.lock:
            leases = list(self.leases.values())
            self.leases.clear()
        for item in leases:
            item.gui.close()


def create_console_app(store: Store, server_id: str, manager_origin: str,
                       console_origin: str, bmc_ca: str | None = None) -> FastAPI:
    runtime = ConsoleRuntime(store, server_id, manager_origin, console_origin, bmc_ca)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        async def clean_expired() -> None:
            while True:
                await asyncio.sleep(5)
                await run_in_threadpool(runtime.prune)

        cleaner = asyncio.create_task(clean_expired())
        try:
            yield
        finally:
            cleaner.cancel()
            await asyncio.gather(cleaner, return_exceptions=True)
            await run_in_threadpool(runtime.close_all)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.console_runtime = runtime

    @app.middleware("http")
    async def secure_headers(request: Request, call_next):
        response = await call_next(request)
        socket_origin = runtime.console_origin.replace("https://", "wss://", 1)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data: blob:; worker-src 'self' blob:; "
            f"connect-src 'self' {socket_origin}; frame-src 'self'; "
            "frame-ancestors 'self'; object-src 'none'; base-uri 'none'; form-action 'none'"
        )
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=86400"
        return response

    def authorized(request: Request) -> tuple[dict[str, Any], BmcGuiSession]:
        # Vendor asset loads and automatic status traffic must not extend the
        # manager login or the console idle lease.
        session = runtime.manager_session(request.cookies.get(COOKIE), touch=False)
        return session, runtime.lease(session["token_hash"])

    @app.post("/launch")
    async def launch(request: Request):
        if not runtime.manager_origin_matches(request.headers.get("origin")):
            raise HTTPException(403, "Console launch origin rejected")
        session = runtime.manager_session(request.cookies.get(COOKIE))
        body = await request.body()
        if len(body) > 1024 or request.headers.get("content-type", "").split(";", 1)[0] != "application/x-www-form-urlencoded":
            raise HTTPException(400, "Invalid console launch form")
        try:
            values = parse_qs(body.decode("ascii"), strict_parsing=True)
        except (UnicodeDecodeError, ValueError) as exc:
            raise HTTPException(400, "Invalid console launch form") from exc
        csrf = values.get("csrf", [])
        if len(csrf) != 1 or not hmac.compare_digest(csrf[0], session["csrf"]):
            raise HTTPException(403, "Invalid CSRF token")
        try:
            await run_in_threadpool(runtime.launch, session["token_hash"])
        except BmcConsoleError as exc:
            raise HTTPException(502, str(exc)) from exc
        store.audit(session["user_id"], "console_open", server_id)
        return HTMLResponse(_LAUNCHER)

    @app.get("/console-launcher.js")
    async def launcher_script(request: Request):
        authorized(request)
        return FileResponse(STATIC / "console-launcher.js", media_type="text/javascript")

    @app.get("/console-idle.js")
    async def idle_script(request: Request):
        authorized(request)
        return FileResponse(STATIC / "console-idle.js", media_type="text/javascript")

    @app.get("/console/status")
    async def console_status(request: Request):
        session = runtime.manager_session(request.cookies.get(COOKIE), touch=False)
        return {"remaining_seconds": max(0, math.ceil(runtime.remaining(session["token_hash"]))),
                "idle_minutes": runtime.idle_seconds() // 60}

    @app.post("/console/activity")
    async def console_activity(request: Request):
        if (request.headers.get("origin") != runtime.console_origin
                or request.headers.get("x-console-activity") != "1"):
            raise HTTPException(403, "Console activity origin rejected")
        token = request.cookies.get(COOKIE)
        session = runtime.manager_session(token, touch=False)
        runtime.remaining(session["token_hash"])
        # Recheck expiry while touching the login; an expired login cannot be
        # revived by a console request.
        runtime.manager_session(token, touch=True)
        runtime.note_activity(session["token_hash"])
        return Response(status_code=204)

    @app.get("/console-features.js")
    async def console_features(request: Request):
        session = runtime.manager_session(request.cookies.get(COOKIE), touch=False)
        reconnect = runtime.active_lease(session["token_hash"])[0].kvm_reconnect_enabled
        # Only a server-derived boolean crosses this boundary, never a token.
        value = "true" if reconnect else "false"
        return Response(
            f"window.CONSOLE_FLAGS = Object.freeze({{kvmReconnect: {value}}});",
            media_type="text/javascript",
        )

    @app.get("/console-bridge.js")
    async def bridge_script(request: Request):
        authorized(request)
        return FileResponse(STATIC / "console-bridge.js", media_type="text/javascript")

    @app.get("/console-gateway.css")
    async def gateway_style(request: Request):
        authorized(request)
        return FileResponse(STATIC / "console-gateway.css", media_type="text/css")

    @app.websocket("/kvm")
    async def kvm_socket(browser: WebSocket):
        if browser.headers.get("origin") != runtime.console_origin:
            LOG.info("kvm rejected: browser origin")
            await browser.close(code=1008)
            return
        manager_token = browser.cookies.get(COOKIE)
        try:
            session = runtime.manager_session(manager_token, touch=False)
            gui = runtime.lease(session["token_hash"])
            upstream = await gui.connect_kvm()
        except HTTPException:
            LOG.info("kvm rejected: manager session or console lease")
            await browser.close(code=1008)
            return
        except BmcConsoleError:
            LOG.info("kvm rejected: BMC socket handshake")
            await browser.close(code=1008)
            return
        offered = {part.strip() for part in browser.headers.get("sec-websocket-protocol", "").split(",")}
        protocol = upstream.subprotocol if upstream.subprotocol in offered else None
        await browser.accept(subprotocol=protocol)
        LOG.info("kvm connected: protocol=%s", protocol or "none")

        async def to_bmc() -> None:
            while True:
                message = await browser.receive()
                if message["type"] == "websocket.disconnect":
                    return
                payload = message.get("bytes") if message.get("bytes") is not None else message.get("text")
                if payload is None or len(payload) > _MAX_BROWSER_MESSAGE:
                    return
                await upstream.send(payload)

        async def to_browser() -> None:
            async for payload in upstream:
                if isinstance(payload, bytes):
                    await browser.send_bytes(payload)
                else:
                    await browser.send_text(payload)

        async def watch_access() -> None:
            while True:
                await asyncio.sleep(2)
                try:
                    runtime.manager_session(manager_token, touch=False)
                    runtime.lease(session["token_hash"])
                except HTTPException:
                    await run_in_threadpool(runtime.revoke, session["token_hash"])
                    raise

        task_names = ("browser_to_bmc", "bmc_to_browser", "access_watch")
        tasks = [asyncio.create_task(coroutine(), name=name)
                 for coroutine, name in zip((to_bmc, to_browser, watch_access), task_names)]
        try:
            done, _pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                error = task.exception() if not task.cancelled() else None
                LOG.info("kvm relay ended: task=%s error=%s upstream_close=%s",
                         task.get_name(), type(error).__name__ if error else "none",
                         upstream.close_code)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await upstream.close()
            try:
                await browser.close()
            except (RuntimeError, WebSocketDisconnect):
                pass

    @app.get("/{asset_path:path}")
    async def viewer_asset(asset_path: str, request: Request):
        _session, gui = authorized(request)
        path = "/" + asset_path
        try:
            body, content_type = await run_in_threadpool(gui.fetch_viewer, path)
        except BmcConsoleError as exc:
            raise HTTPException(404, str(exc)) from exc
        if path == "/viewer.html":
            marker = b"</head>"
            if marker not in body:
                raise HTTPException(502, "BMC viewer HTML shape changed")
            body = body.replace(marker, b'<script src="/console-bridge.js"></script></head>', 1)
        return Response(body, media_type=content_type)

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Per-server C880A console gateway")
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--server-id", required=True)
    parser.add_argument("--manager-origin", required=True)
    parser.add_argument("--advertise-host", default="localhost")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    parser.add_argument("--bmc-ca")
    args = parser.parse_args()
    try:
        args.bind = listener_address(args.bind)
    except ValueError as exc:
        parser.error(str(exc))
    log_fd = os.open(args.data_dir / "console-gateway.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.fchmod(log_fd, 0o600)
    handler = logging.StreamHandler(os.fdopen(log_fd, "a", encoding="utf-8"))
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    LOG.addHandler(handler)
    LOG.setLevel(logging.INFO)
    if not args.tls_cert or not args.tls_key:
        parser.error("An HTTPS certificate and key are required for the console")
    scheme = "https"
    manager_origin = ConsoleRuntime._origin(args.manager_origin)
    if not manager_origin.startswith("https://"):
        parser.error("Manager origin must use HTTPS")
    host = args.advertise_host
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    origin = ConsoleRuntime._origin(f"{scheme}://{host}:{args.port}")
    if urlsplit(origin).hostname != urlsplit(manager_origin).hostname:
        parser.error("Console and manager must use the same hostname for session cookies")
    app = create_console_app(Store(args.data_dir), args.server_id, manager_origin,
                             origin, args.bmc_ca)
    uvicorn.run(app, host=args.bind, port=args.port, ssl_certfile=args.tls_cert,
                ssl_keyfile=args.tls_key, proxy_headers=False)


if __name__ == "__main__":
    main()
