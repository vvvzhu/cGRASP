# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""
CoAP server wrapper based on aiocoap.

Key points:
- aiocoap server expects a ResourceSite (resource.Site) with Resource objects.
- This module provides a small, cGRASP-friendly interface:
    - CoapServer(start/stop)
    - register(path, handler)
Handlers receive (method, payload, request) and return (code, payload, content_format).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Awaitable, Callable, List, Optional, Tuple, Union

import aiocoap
from aiocoap import resource

CoapHandlerResult = Union[
    Tuple[aiocoap.Code, bytes, Optional[int]],
    # Optional extensions:
    # - observe: if set, copied to resp.opt.observe
    # - no_response: if set, copied to resp.opt.no_response
    Tuple[aiocoap.Code, bytes, Optional[int], Optional[int]],
    Tuple[aiocoap.Code, bytes, Optional[int], Optional[int], Optional[int]],
]
CoapHandler = Callable[[str, bytes, aiocoap.Message], Awaitable[CoapHandlerResult]]

CGRASP_CONTENT_FORMAT = 60
# draft -03 recommends 2.04 Changed for successful POSTs, but this prototype
# carries the cGRASP reply in the response payload and historically uses 2.05
# Content. A 2.04 trial did not resolve the separately tracked large-response
# truncation and would add an unrelated wire change. Keep this compatibility
# exception centralized until the blockwise design is fixed and revalidated.
CGRASP_UNICAST_SUCCESS_CODE = aiocoap.Code.CONTENT


def default_bind(port: int = 5683) -> Tuple[str, int]:
    """Return the default bind address (loopback unless overridden).

    Listening on the any-address requires aiocoap's ``udp6`` transport; the
    Windows fallback rejects it.  Loopback is therefore the safe default.
    Set ``CGRASP_BIND`` to override (for example ``::`` on a Linux relay or a
    concrete link-local address on a constrained node).
    """

    override = os.environ.get("CGRASP_BIND", "").strip()
    if override:
        return override, int(port)
    return "::1", int(port)


class HandlerResource(resource.Resource):
    """A generic Resource that dispatches to an async handler."""

    def __init__(self, handler: CoapHandler):
        super().__init__()
        self._handler = handler

    async def needs_blockwise_assembly(self, request):
        # Some transports advertise a payload size that is larger than the
        # practical UDP receive path used in these tests. Keep responses inside
        # a conservative Block2 size so large cGRASP payloads are reassembled by
        # aiocoap instead of being sent as one oversized datagram.
        """Return True when the request needs blockwise reassembly."""
        try:
            request.remote.maximum_payload_size = min(
                int(request.remote.maximum_payload_size),
                1024,
            )
            request.remote.maximum_block_size_exp = min(
                int(request.remote.maximum_block_size_exp),
                6,
            )
        except Exception:
            pass
        return await super().needs_blockwise_assembly(request)

    async def _call(self, method: str, request: aiocoap.Message) -> aiocoap.Message:
        payload = request.payload or b""
        result = await self._handler(method, payload, request)
        code: aiocoap.Code
        out_payload: bytes
        content_format: Optional[int]
        observe: Optional[int] = None
        no_response: Optional[int] = None

        if isinstance(result, tuple) and len(result) == 3:
            code, out_payload, content_format = result
        elif isinstance(result, tuple) and len(result) == 4:
            code, out_payload, content_format, observe = result
        elif isinstance(result, tuple) and len(result) == 5:
            code, out_payload, content_format, observe, no_response = result
        else:
            raise ValueError("Invalid CoAP handler result")

        resp = aiocoap.Message(code=code, payload=out_payload or b"")
        if content_format is not None:
            resp.opt.content_format = content_format
        if observe is not None:
            resp.opt.observe = int(observe)
        if no_response is not None:
            resp.opt.no_response = int(no_response)
        return resp

    async def render_get(self, request: aiocoap.Message) -> aiocoap.Message:
        """Handle a CoAP GET request."""
        return await self._call("GET", request)

    async def render_post(self, request: aiocoap.Message) -> aiocoap.Message:
        """Handle a CoAP POST request."""
        return await self._call("POST", request)

    async def render_put(self, request: aiocoap.Message) -> aiocoap.Message:
        """Handle a CoAP PUT request."""
        return await self._call("PUT", request)

    async def render_delete(self, request: aiocoap.Message) -> aiocoap.Message:
        """Handle a CoAP DELETE request."""
        return await self._call("DELETE", request)

    # RFC8132
    async def render_fetch(self, request: aiocoap.Message) -> aiocoap.Message:
        """Handle a CoAP FETCH request."""
        return await self._call("FETCH", request)


@dataclass
class CoapServer:
    """
    Simple CoAP server with path-based handlers.

    Example:
        async def on_msg(method, payload, request):
            return (aiocoap.Code.CONTENT, b"ok", 0)

        srv = CoapServer(bind=("::", 5683))
        srv.register((".well-known", "grasp-coap"), on_msg)
        await srv.start()
    """

    bind: Tuple[str, int] = default_bind()
    # Passed through to aiocoap.Context.create_server_context(multicast=...).
    # Elements may be (multicast_address, interface_name) or interface_name.
    multicast: List[Union[Tuple[str, str], str]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self._site = resource.Site()
        self._ctx: Optional[aiocoap.Context] = None
        if self.multicast is None:
            self.multicast = []

    def register(self, path: Union[str, Tuple[str, ...]], handler: CoapHandler) -> None:
        """
        Register a handler on a path.
        - path can be ".well-known/grasp-coap" or (".well-known","grasp-coap")
        """
        if isinstance(path, str):
            parts = tuple(p for p in path.strip("/").split("/") if p)
        else:
            parts = path
        if not parts:
            raise ValueError("path must not be empty")
        self._site.add_resource(parts, HandlerResource(handler))

    def register_pipe(self, path: Union[str, Tuple[str, ...]], handler: Callable) -> None:
        """Register a multi-response Pipe handler.

        Private aiocoap client details remain in ``coap_multicast_adapter``;
        server-side ``render_to_pipe`` is a documented stable resource API.
        """
        from .coap_multicast_adapter import PipeHandlerResource
        if isinstance(path, str):
            parts = tuple(p for p in path.strip("/").split("/") if p)
        else:
            parts = path
        if not parts:
            raise ValueError("path must not be empty")
        self._site.add_resource(parts, PipeHandlerResource(handler))

    async def start(self) -> None:
        """Start the CoAP server on the configured bind address."""
        if self._ctx is not None:
            return
        try:
            self._ctx = await aiocoap.Context.create_server_context(
                self._site,
                bind=self.bind,
                multicast=self.multicast or [],
            )
        except ValueError as exc:
            # aiocoap's simplesocketserver fallback (Windows) rejects the
            # any-address.  Retry on loopback so the endpoint still works for
            # local demos and tests; callers that need a specific interface
            # should pass an explicit bind address.
            if self.bind[0] in ("::", "0.0.0.0") and "any-address" in str(exc):
                host = "::1" if ":" in self.bind[0] else "127.0.0.1"
                logging.getLogger(__name__).warning(
                    "bind %r rejected by aiocoap; falling back to %r",
                    self.bind, (host, self.bind[1]))
                self._ctx = await aiocoap.Context.create_server_context(
                    self._site,
                    bind=(host, self.bind[1]),
                    multicast=self.multicast or [],
                )
            else:
                raise

    async def stop(self) -> None:
        """Stop the CoAP server and release its resources."""
        if self._ctx is None:
            return
        await self._ctx.shutdown()
        self._ctx = None


# ---- cGRASP-friendly defaults ----

def make_default_cgrasp_server(
    on_message: Callable[[bytes, aiocoap.Message], Awaitable[bytes]],
    bind: Tuple[str, int] = default_bind(),
    base_path: str = ".well-known/grasp-coap",
) -> CoapServer:
    """
    Create a server with one endpoint (default: POST coap://<host>:5683/.well-known/grasp-coap)

    on_message(payload_bytes, request_message) -> response_payload_bytes
    """

    async def handler(method: str, payload: bytes, request: aiocoap.Message) -> CoapHandlerResult:
        """Dispatch an incoming aiocoap request to the configured handler."""
        if method != "POST":
            return (aiocoap.Code.METHOD_NOT_ALLOWED, b"POST only", 0)

        try:
            resp = await on_message(payload, request)
            # cGRASP/GRASP payloads are CBOR (optionally encrypted) bytes.
            return (CGRASP_UNICAST_SUCCESS_CODE, resp or b"", CGRASP_CONTENT_FORMAT)
        except Exception:
            # Do not leak internal exception text to remote clients.
            logging.getLogger(__name__).exception("cGRASP request handler failed")
            return (aiocoap.Code.INTERNAL_SERVER_ERROR, b"internal error", 0)

    srv = CoapServer(bind=bind)
    srv.register(base_path, handler)
    return srv
