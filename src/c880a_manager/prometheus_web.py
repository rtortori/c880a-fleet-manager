"""Bounded read-only access to the pinned engine through the manager session.

No browser header, destination, credential, or administrative path is forwarded.
The private transport remains mutual TLS even for packaged static assets.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
from html import escape
import re
import secrets
from urllib.parse import quote

import anyio
import httpx
from fastapi import HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, Response, StreamingResponse

from .prometheus_service import ManagedPrometheus, PrometheusError


PAGES = {"", "query", "graph", "targets", "service-discovery", "status", "rules",
         "alerts", "tsdb-status"}
READ_APIS = {"query", "query_range", "query_exemplars", "format_query", "parse_query",
             "labels", "series", "scrape_pools", "targets", "targets/metadata", "metadata",
             "status/runtimeinfo", "status/buildinfo", "status/tsdb", "status/tsdb/blocks",
             "status/walreplay", "features", "notifications", "notifications/live", "alerts", "rules",
             "search/metric_names", "search/label_names", "search/label_values"}
QUERY_POST_APIS = {"query", "query_range", "query_exemplars", "format_query", "parse_query",
                   "labels", "series", "search/metric_names", "search/label_names", "search/label_values"}
_LABEL_VALUES = re.compile(r"api/v1/label/[A-Za-z_][A-Za-z0-9_]*/values\Z")
_ASSET = re.compile(r"assets/[A-Za-z0-9_/-]+(?:\.[A-Za-z0-9_-]+)*\.(?:js|css|svg|png|ico|woff2?|ttf|txt)\Z")
MAX_REQUEST = 128 * 1024
MAX_QUERY = 64 * 1024
MAX_RESPONSE = 32 * 1024 * 1024
NOTIFICATION_CHECK_SECONDS = 1
NOTIFICATION_HEARTBEAT_SECONDS = 15
NOTIFICATION_OPEN_SECONDS = 10


def allowed_path(path: str, method: str) -> bool:
    # Reject encoded separators/dot segments even after the framework's decode.
    if len(path) > 1024 or any(ord(char) < 32 or ord(char) == 127 for char in path) or any(char in path for char in ("%", "\\", ":")) or any(
            segment in (".", "..", "") for segment in path.split("/") if path):
        return False
    api = path.removeprefix("api/v1/") if path.startswith("api/v1/") else None
    if method == "POST":
        return api in QUERY_POST_APIS
    if method != "GET":
        return False
    return (path in PAGES or path in {"favicon.svg", "favicon.ico"} or
            bool(_ASSET.fullmatch(path)) or api in READ_APIS or bool(_LABEL_VALUES.fullmatch(path)))


def login_location(target: str) -> str:
    return "/?prometheus_return=" + quote(target, safe="") + "#/servers"


def state_page(title: str, message: str, *, admin: bool, target: str,
               retry: bool = False, status: int = 503) -> HTMLResponse:
    actions = '<a class="button outline" href="/#/servers">Back to manager</a>'
    if retry:
        actions += f'<a class="button outline" href="{escape(target, quote=True)}">Retry</a>'
    if admin:
        actions += '<a class="button primary" href="/#/configuration/prometheus">Open Configuration</a>'
    return HTMLResponse('<!doctype html><html lang="en" data-theme="dark"><head>'
                        '<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
                        '<title>Prometheus · Fleet Operations</title><link rel="stylesheet" href="/app.css">'
                        '</head><body><main class="panel prometheus-state"><h1 tabindex="-1">' + escape(title) +
                        '</h1><p>' + escape(message) + '</p><div class="prometheus-actions">' + actions +
                        '</div></main><script src="/prometheus-session.js"></script></body></html>', status_code=status)


def engine_response(managed: ManagedPrometheus, path: str, method: str,
                    query: str, body: bytes = b"") -> Response:
    if path == "api/v1/notifications/live":
        raise HTTPException(403, "This endpoint requires an authenticated notification stream")
    if not allowed_path(path, method):
        raise HTTPException(403, "This Prometheus endpoint is not available through the manager")
    if len(query.encode()) > MAX_QUERY or len(body) > MAX_REQUEST:
        raise HTTPException(413, "Prometheus request exceeds the limit")
    active = managed.active()
    try:
        with managed.client(active, timeout=20) as client:
            # Build a fixed relative URL; query text can never change its host.
            url = client.base_url.join(path).copy_with(query=query.encode())
            headers = {"Accept-Encoding": "identity"}
            if method == "POST":
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            with client.stream(method, url, content=body, headers=headers,
                               extensions={"sni_hostname": active["deployment"]["manager_host"]}) as upstream:
                if 300 <= upstream.status_code < 400:
                    # Root/legacy graph redirects are handled by the manager;
                    # never forward an engine-controlled Location or cookie.
                    raise HTTPException(502, "Unexpected Prometheus redirect")
                chunks, size = [], 0
                for chunk in upstream.iter_bytes():
                    size += len(chunk)
                    if size > MAX_RESPONSE:
                        raise HTTPException(413, "Prometheus response exceeds the limit; narrow the query")
                    chunks.append(chunk)
                content = b"".join(chunks)
                media = upstream.headers.get("content-type", "application/octet-stream")
                response = Response(content, status_code=upstream.status_code,
                                    headers={"Content-Type": media})
    except (PrometheusError, httpx.HTTPError, OSError, ValueError):
        raise HTTPException(503, "Prometheus is unavailable. Check its state in Configuration.") from None
    if media.startswith("text/html") and upstream.status_code == 200:
        nonce = secrets.token_urlsafe(24)
        text = content.decode("utf-8")
        text = re.sub(r'<script\b(?![^>]*\bsrc=)([^>]*)>',
                      lambda match: f'<script nonce="{nonce}"{match[1]}>', text)
        text = text.replace("<head>", '<head><script src="/prometheus-session.js"></script>', 1)
        response = HTMLResponse(text, headers={"Content-Security-Policy":
            f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; worker-src 'self' blob:; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"})
    return response


async def notification_response(managed, request, authorize, slots):
    """Forward only the pinned read-only SSE route, with live session checks."""
    if request.url.query:
        raise HTTPException(400, "Notification stream does not accept query parameters")
    if not slots.acquire(blocking=False):
        raise HTTPException(429, "Prometheus notifications are busy; retry shortly")
    client = upstream = None
    async def close():
        # A disconnected ASGI stream cancels its scope; shield socket cleanup.
        with anyio.CancelScope(shield=True):
            try:
                if upstream is not None:
                    await upstream.aclose()
            finally:
                if client is not None:
                    await client.aclose()
    try:
        active = managed.active()
        client = managed.async_client(active, timeout=httpx.Timeout(10, read=None))
        upstream = await asyncio.wait_for(client.send(client.build_request("GET", "api/v1/notifications/live",
            headers={"Accept-Encoding":"identity"},
            extensions={"sni_hostname":active["deployment"]["manager_host"]}), stream=True),
            timeout=NOTIFICATION_OPEN_SECONDS)
        if (upstream.status_code != 200 or
                upstream.headers.get("content-type", "").split(";")[0] != "text/event-stream"):
            raise HTTPException(503, "Prometheus notifications are unavailable; retry shortly")
    except BaseException as exc:
        try:
            await close()
        finally:
            slots.release()
        if isinstance(exc, (PrometheusError, httpx.HTTPError, OSError, ValueError)):
            raise HTTPException(503, "Prometheus notifications are unavailable; retry shortly") from None
        raise

    async def frames():
        pending = None
        try:
            chunks = upstream.aiter_bytes()
            total = 0
            heartbeat = asyncio.get_running_loop().time()
            line_complete = True
            # Flush downstream headers even when the native stream is idle.
            # The pinned GUI parses every blank-delimited frame as JSON,
            # including a comment-only frame. Do not create an empty event.
            yield b": connected\n"
            while True:
                try:
                    await run_in_threadpool(authorize)
                except HTTPException:
                    return
                if await request.is_disconnected():
                    return
                if pending is None:
                    pending = asyncio.create_task(anext(chunks))
                ready, _ = await asyncio.wait({pending}, timeout=NOTIFICATION_CHECK_SECONDS)
                if ready:
                    try:
                        chunk = pending.result()
                    except (StopAsyncIteration, httpx.HTTPError):
                        return
                    pending = None
                    total += len(chunk)
                    if total > MAX_RESPONSE:
                        return
                    # Recheck before sending a chunk that arrived during wait.
                    try:
                        await run_in_threadpool(authorize)
                    except HTTPException:
                        return
                    if chunk:
                        line_complete = chunk.endswith(b"\n")
                    yield chunk
                now = asyncio.get_running_loop().time()
                if line_complete and now - heartbeat >= NOTIFICATION_HEARTBEAT_SECONDS:
                    # Never insert a comment inside a split native data line.
                    yield b": keep-alive\n"
                    heartbeat = now
        finally:
            try:
                with anyio.CancelScope(shield=True):
                    if pending is not None:
                        pending.cancel()
                        with suppress(asyncio.CancelledError, StopAsyncIteration, httpx.HTTPError):
                            await pending
                    await close()
            finally:
                slots.release()
    return StreamingResponse(frames(), media_type="text/event-stream",
                             headers={"Cache-Control":"no-store","X-Accel-Buffering":"no"})
