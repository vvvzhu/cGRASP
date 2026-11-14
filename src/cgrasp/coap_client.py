# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""
CoAP client wrapper based on aiocoap.

Provides:
- CoapClient (reuses aiocoap Context)
- async request/get/post
- optional sync helpers for non-async code
"""

from __future__ import annotations

import asyncio
import os
import threading
from dataclasses import dataclass
from typing import Callable, Hashable, List, Optional, Sequence, Tuple, Union

import aiocoap
from aiocoap.optiontypes import BlockOption

from .coap_multicast_adapter import CoapResponse, MulticastExchange, make_multicast_request


def _consume_future(_fut) -> None:
    """Consume a Future's result to avoid 'Future exception was never retrieved'."""
    try:
        _fut.result()
    except Exception:
        pass


@dataclass
class CoapClient:
    """Synchronous facade over an aiocoap client context."""
    _ctx: Optional[aiocoap.Context] = None

    async def start(self) -> None:
        """Start the aiocoap context and background event loop."""
        if self._ctx is None:
            self._ctx = await aiocoap.Context.create_client_context()

    async def close(self) -> None:
        """Stop the background loop and close the aiocoap context."""
        if self._ctx is not None:
            await self._ctx.shutdown()
            self._ctx = None

    async def request(
        self,
        method: str,
        uri: str,
        payload: Union[bytes, str, None] = None,
        timeout: Optional[float] = None,
        content_format: Optional[int] = 0,
        block2_size_exp: Optional[int] = None,
    ) -> aiocoap.Message:
        """Send a CoAP request and return the decoded response."""
        await self.start()

        if payload is None:
            raw = b""
        elif isinstance(payload, bytes):
            raw = payload
        else:
            raw = payload.encode("utf-8")

        # aiocoap versions vary in whether they expose RFC8132 FETCH.
        fetch_code = getattr(aiocoap.Code, "FETCH", None)
        code = {
            "GET": aiocoap.Code.GET,
            "FETCH": fetch_code,
            "POST": aiocoap.Code.POST,
            "PUT": aiocoap.Code.PUT,
            "DELETE": aiocoap.Code.DELETE,
        }.get(method.upper())
        if code is None and method.upper() == "FETCH":
            # Fallback: POST works for our multicast solicitation usage.
            code = aiocoap.Code.POST
        if code is None:
            raise ValueError(f"Unsupported method: {method}")

        msg = aiocoap.Message(code=code, uri=uri, payload=raw)
        if content_format is not None:
            msg.opt.content_format = content_format
        if block2_size_exp is not None:
            msg.opt.block2 = BlockOption.BlockwiseTuple(0, 0, int(block2_size_exp))

        req = self._ctx.request(msg)  # type: ignore[union-attr]
        if timeout is None:
            return await req.response
        return await asyncio.wait_for(req.response, timeout=timeout)

    async def get(self, uri: str, timeout: Optional[float] = None) -> bytes:
        """Send a CoAP GET request."""
        resp = await self.request("GET", uri, payload=b"", timeout=timeout)
        return resp.payload or b""

    async def post(
        self,
        uri: str,
        payload: Union[bytes, str],
        timeout: Optional[float] = None,
        content_format: Optional[int] = 0,
        block2_size_exp: Optional[int] = None,
    ) -> bytes:
        """Send a CoAP POST request."""
        resp = await self.request(
            "POST",
            uri,
            payload=payload,
            timeout=timeout,
            content_format=content_format,
            block2_size_exp=block2_size_exp,
        )
        return resp.payload or b""

    async def post_multicast_collect(
        self,
        uris: List[str],
        payload: Union[bytes, str],
        *,
        timeout: float = 5.0,
        content_format: Optional[int] = 0,
        max_responses: Optional[int] = None,
    ) -> List[CoapResponse]:
        """Send a multicast FETCH (typically to multiple interfaces) and collect multiple responses.

        aiocoap's default request() to a multicast address behaves like anycast (first reply wins).
        To implement "one request, many replies" we intentionally create an *Observe*-style
        request (Observe=0) and require responders to include an Observe option in their
        responses. This keeps the request alive for multiple replies.

        Returns a list of aiocoap.Message responses.
        """

        await self.start()

        if payload is None:
            raw = b""
        elif isinstance(payload, bytes):
            raw = payload
        else:
            raw = payload.encode("utf-8")

        loop = asyncio.get_running_loop()
        deadline = loop.time() + float(timeout)
        out: List[CoapResponse] = []

        async def _collect_one(uri: str) -> None:
            # Use FETCH (RFC8132) so request semantics are clearly "retrieve" while still
            # allowing a request payload (the GRASP M_DISCOVERY bytes).
            fetch_code = getattr(aiocoap.Code, "FETCH", None)
            if fetch_code is None:
                # Fallback for older aiocoap versions.
                fetch_code = aiocoap.Code.POST
            msg = aiocoap.Message(code=fetch_code, uri=uri, payload=raw)
            # Multicast requests must be NON.
            try:
                msg.mtype = aiocoap.NON
            except Exception:
                pass
            # Use Observe to keep token open for multiple replies.
            msg.opt.observe = 0
            # Ask servers to suppress 4.xx/5.xx responses (RFC7967 No-Response).
            # This avoids getting a response from every node that has no matching objective.
            try:
                msg.opt.no_response = 0x18
            except Exception:
                pass
            if content_format is not None:
                msg.opt.content_format = content_format

            req = self._ctx.request(msg)  # type: ignore[union-attr]
            seen = set()

            # Always collect the initial response.
            while True:
                if max_responses is not None and len(out) >= int(max_responses):
                    return
                remaining = deadline - loop.time()
                if remaining <= 0:
                    return
                try:
                    resp0 = await asyncio.wait_for(req.response, timeout=remaining)
                except asyncio.TimeoutError:
                    return
                except Exception:
                    return
                else:
                    try:
                        ra = getattr(resp0, "remote", None)
                        sockaddr = getattr(ra, "sockaddr", None)
                    except Exception:
                        sockaddr = None
                    k = (tuple(sockaddr) if sockaddr is not None else (), resp0.payload or b"")
                    if k not in seen:
                        seen.add(k)
                        out.append(resp0)
                break

            # Optional: try to keep collecting via observation (works only if aiocoap
            # establishes an observation for this request).
            try:
                obs = getattr(req, "observation", None)
                if obs is None:
                    return
                it = obs.__aiter__()
            except Exception:
                return

            while True:
                if max_responses is not None and len(out) >= int(max_responses):
                    break
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    resp = await asyncio.wait_for(it.__anext__(), timeout=remaining)
                except asyncio.TimeoutError:
                    break
                except StopAsyncIteration:
                    break
                except Exception:
                    break
                else:
                    try:
                        ra = getattr(resp, "remote", None)
                        sockaddr = getattr(ra, "sockaddr", None)
                    except Exception:
                        sockaddr = None
                    k = (tuple(sockaddr) if sockaddr is not None else (), resp.payload or b"")
                    if k in seen:
                        continue
                    seen.add(k)
                    out.append(resp)

        tasks = [asyncio.create_task(_collect_one(u)) for u in (uris or [])]
        if tasks:
            try:
                await asyncio.wait(tasks, timeout=float(timeout) + 0.25)
            finally:
                for t in tasks:
                    if not t.done():
                        t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

        return out

    async def fetch_multicast_collect(
        self, uris: List[str], payload: bytes, *, hard_timeout: float = 5.0,
        quiet_timeout: Optional[float] = None, max_responses: Optional[int] = None,
        on_exchange_created: Optional[Callable[[str, MulticastExchange], None]] = None,
        on_exchange_started: Optional[Callable[[str, bytes, MulticastExchange], None]] = None,
        on_response: Optional[Callable[[CoapResponse], None]] = None,
    ) -> List[CoapResponse]:
        """Collect ordinary Content responses without Observe or No-Response.

        ``quiet_timeout`` is global across all outgoing interfaces. Once any
        interface has produced a response, the caller should not have to wait
        for every other no-response interface to reach its hard timeout; this is
        essential for loop topologies where one branch responds and another is
        correctly duplicate-suppressed.
        """
        await self.start()
        out: List[CoapResponse] = []
        response_event = asyncio.Event()

        async def collect(uri: str) -> None:
            """Collect responses for one multicast URI."""
            request = make_multicast_request(uri, payload)
            deduplicate = os.environ.get("CGRASP_TEST_ALLOW_DUPLICATE_RESPONSES") != "1"
            exchange = MulticastExchange(
                self._ctx, request, uri, hard_timeout, quiet_timeout,
                deduplicate=deduplicate,
            )
            if on_exchange_created is not None:
                on_exchange_created(uri, exchange)
            await exchange.start()
            try:
                # TokenManager assigns the token synchronously in start(). No
                # network callback can run until this coroutine yields again,
                # so the relay can register its branch before accepting
                # responses.
                if on_exchange_started is not None and not exchange.snapshot()["closed"]:
                    on_exchange_started(uri, bytes(request.token or b""), exchange)
                async for response in exchange:
                    if response.code != aiocoap.Code.CONTENT:
                        continue
                    out.append(response)
                    if on_response is not None:
                        on_response(response)
                    response_event.set()
                    if max_responses is not None and len(out) >= max_responses:
                        return
            finally:
                await exchange.close()

        tasks = [asyncio.create_task(collect(uri)) for uri in uris]
        loop = asyncio.get_running_loop()
        deadline = loop.time() + float(hard_timeout)
        last_response_at: Optional[float] = None
        seen_count = 0
        try:
            while tasks and not all(task.done() for task in tasks):
                if max_responses is not None and len(out) >= max_responses:
                    break
                if len(out) != seen_count:
                    seen_count = len(out)
                    last_response_at = loop.time()
                now = loop.time()
                if last_response_at is not None and quiet_timeout is not None and \
                   now >= last_response_at + float(quiet_timeout):
                    break
                remaining = deadline - now
                if remaining <= 0:
                    break
                wait_for = min(remaining, 0.05)
                if last_response_at is not None and quiet_timeout is not None:
                    wait_for = min(wait_for, max(0.0, last_response_at + float(quiet_timeout) - now))
                try:
                    response_event.clear()
                    await asyncio.wait_for(response_event.wait(), timeout=max(wait_for, 0.001))
                except asyncio.TimeoutError:
                    pass
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            task_results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in task_results:
            if isinstance(result, Exception) and not isinstance(
                    result, asyncio.CancelledError):
                raise result
        return out

    async def request_many(
        self,
        method: str,
        uris: List[str],
        payload: Union[bytes, str, None],
        *,
        content_format: Optional[int] = 0,
        no_response: Optional[int] = 0x1A,
        uri_query: Optional[Sequence[str]] = None,
        grace: float = 0.05,
    ) -> None:
        """Send NON requests to multiple URIs without waiting for responses.

        Intended for multicast notifications or solicitations where responses are
        suppressed using RFC7967 No-Response, or where responders reply out-of-band.
        """

        await self.start()

        if payload is None:
            raw = b""
        elif isinstance(payload, bytes):
            raw = payload
        else:
            raw = payload.encode("utf-8")

        code = {
            "GET": aiocoap.Code.GET,
            "FETCH": getattr(aiocoap.Code, "FETCH", None),
            "POST": aiocoap.Code.POST,
            "PUT": aiocoap.Code.PUT,
            "DELETE": aiocoap.Code.DELETE,
        }.get(method.upper())
        if code is None:
            raise ValueError(f"Unsupported method: {method}")

        pending = []
        for uri in (uris or []):
            try:
                msg = aiocoap.Message(code=code, uri=uri, payload=raw)
                try:
                    msg.mtype = aiocoap.NON
                except Exception:
                    pass
                if content_format is not None:
                    msg.opt.content_format = content_format
                if uri_query:
                    try:
                        msg.opt.uri_query = tuple(str(x) for x in uri_query)
                    except Exception:
                        pass
                if no_response is not None:
                    try:
                        msg.opt.no_response = int(no_response)
                    except Exception:
                        pass

                req = self._ctx.request(msg)  # type: ignore[union-attr]
                try:
                    req.response.add_done_callback(_consume_future)
                except Exception:
                    pass
                pending.append(req)
            except Exception:
                continue

        if grace and grace > 0:
            try:
                await asyncio.sleep(float(grace))
            except Exception:
                pass

        for req in pending:
            try:
                if req.response.done():
                    _consume_future(req.response)
            except Exception:
                continue

    async def post_many(
        self,
        uris: List[str],
        payload: Union[bytes, str],
        *,
        content_format: Optional[int] = 0,
        no_response: Optional[int] = 0x1A,
        confirmable: bool = False,
        grace: float = 0.05,
    ) -> None:
        """Send POSTs to multiple URIs without waiting for responses.

        Intended for multicast notifications (Flood) where responders should
        not reply.
        """

        await self.start()

        if payload is None:
            raw = b""
        elif isinstance(payload, bytes):
            raw = payload
        else:
            raw = payload.encode("utf-8")

        pending = []
        for uri in (uris or []):
            try:
                msg = aiocoap.Message(code=aiocoap.Code.POST, uri=uri, payload=raw)
                try:
                    msg.mtype = aiocoap.CON if confirmable else aiocoap.NON
                except Exception:
                    pass
                if content_format is not None:
                    msg.opt.content_format = content_format
                if no_response is not None:
                    msg.opt.no_response = int(no_response)
                # Fire-and-forget: do not await response, but do attach a
                # callback to consume exceptions (e.g., during shutdown).
                req = self._ctx.request(msg)  # type: ignore[union-attr]
                try:
                    req.response.add_done_callback(_consume_future)
                except Exception:
                    pass
                pending.append(req)
            except Exception:
                continue

        # Give the event loop a moment to push packets out before shutdown.
        if grace and grace > 0:
            try:
                await asyncio.sleep(float(grace))
            except Exception:
                pass

        # Best-effort: also consume any responses that already completed.
        for req in pending:
            try:
                if req.response.done():
                    _consume_future(req.response)
            except Exception:
                continue


class _BackgroundLoop:
    """Run an asyncio loop in a dedicated thread for sync callers.

    This allows us to keep long-lived aiocoap Context objects (ClientContext)
    alive and reused across multiple sync calls.
    """

    def __init__(self) -> None:
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()

    def ensure_started(self) -> None:
        """Start the background loop once, if needed."""
        if self._thread is not None:
            return

        def _main() -> None:
            loop = asyncio.new_event_loop()
            self._loop = loop
            asyncio.set_event_loop(loop)
            self._ready.set()
            loop.run_forever()
            try:
                loop.close()
            except Exception:
                pass

        self._thread = threading.Thread(target=_main, name="coap-clientctx-pool", daemon=True)
        self._thread.start()
        self._ready.wait(timeout=5.0)

    @property
    def loop(self) -> asyncio.AbstractEventLoop:
        """Run the asyncio event loop until stopped."""
        self.ensure_started()
        assert self._loop is not None
        return self._loop

    def run(self, coro, *, timeout: Optional[float] = None):
        """Submit a coroutine to the background loop and wait for its result."""
        fut = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return fut.result(timeout=timeout)


class CoapClientContextPool:
    """Pool CoapClient instances keyed by an arbitrary hashable key.

    Typical key for cGRASP: (session_id, peer_base_uri) to achieve:
    - same session-id => same outgoing socket/context
    - different peer or different direction => different key/context
    """

    def __init__(self) -> None:
        self._bg = _BackgroundLoop()
        self._lock = threading.Lock()
        self._clients: dict[Hashable, CoapClient] = {}

    def _get(self, key: Hashable) -> CoapClient:
        with self._lock:
            client = self._clients.get(key)
            if client is None:
                client = CoapClient()
                self._clients[key] = client
            return client

    def post_sync(
        self,
        key: Hashable,
        uri: str,
        payload: Union[bytes, str],
        *,
        timeout: Optional[float] = None,
        content_format: Optional[int] = 0,
        block2_size_exp: Optional[int] = None,
    ) -> bytes:
        """POST synchronously using a pooled CoAP context."""
        client = self._get(key)

        async def _do() -> bytes:
            return await client.post(
                uri,
                payload,
                timeout=timeout,
                content_format=content_format,
                block2_size_exp=block2_size_exp,
            )

        wait_budget = None if timeout is None else float(timeout) + 2.0
        return self._bg.run(_do(), timeout=wait_budget)

    def close_key_sync(self, key: Hashable) -> None:
        """Close a pooled CoAP context by key."""
        with self._lock:
            client = self._clients.pop(key, None)
        if client is None:
            return

        async def _do() -> None:
            await client.close()

        try:
            self._bg.run(_do(), timeout=2.0)
        except Exception:
            pass


_DEFAULT_POOL = CoapClientContextPool()


def coap_post_pooled_sync(
    key: Hashable,
    uri: str,
    payload: Union[bytes, str],
    *,
    timeout: Optional[float] = None,
    content_format: Optional[int] = 0,
    block2_size_exp: Optional[int] = None,
) -> bytes:
    """Sync POST using a pooled ClientContext selected by `key`."""

    return _DEFAULT_POOL.post_sync(
        key,
        uri,
        payload,
        timeout=timeout,
        content_format=content_format,
        block2_size_exp=block2_size_exp,
    )


def coap_pool_close_key(key: Hashable) -> None:
    """Close and forget the pooled client for `key` (best-effort)."""

    _DEFAULT_POOL.close_key_sync(key)


def _run(coro):
    """Run coroutine from sync code (simple helper)."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    else:
        # If already in an event loop, user must await; raise a clear error.
        raise RuntimeError("Already running in an event loop; use 'await' instead of sync helper.")


def coap_get_sync(uri: str, timeout: Optional[float] = None) -> bytes:
    """Perform a synchronous CoAP GET."""
    client = CoapClient()
    async def _do():
        try:
            return await client.get(uri, timeout=timeout)
        finally:
            await client.close()
    return _run(_do())


def coap_post_sync(
    uri: str,
    payload: Union[bytes, str],
    timeout: Optional[float] = None,
    content_format: Optional[int] = 0,
) -> bytes:
    """Perform a synchronous CoAP POST."""
    client = CoapClient()
    async def _do():
        try:
            return await client.post(uri, payload, timeout=timeout, content_format=content_format)
        finally:
            await client.close()
    return _run(_do())


def coap_post_multicast_collect_sync(
    uris: List[str],
    payload: Union[bytes, str],
    *,
    timeout: float = 5.0,
    content_format: Optional[int] = 0,
    max_responses: Optional[int] = None,
) -> List[Tuple[Tuple, bytes]]:
    """Sync helper: multicast POST to all given URIs and collect multiple replies.

    Returns a list of (remote_sockaddr, payload_bytes).
    """

    client = CoapClient()

    async def _do():
        try:
            resps = await client.post_multicast_collect(
                list(uris),
                payload,
                timeout=float(timeout),
                content_format=content_format,
                max_responses=max_responses,
            )
            out: List[Tuple[Tuple, bytes]] = []
            for r in resps:
                try:
                    ra = getattr(r, "remote", None)
                    sockaddr = getattr(ra, "sockaddr", None)
                except Exception:
                    sockaddr = None
                if sockaddr is None:
                    sockaddr = ()
                out.append((tuple(sockaddr), r.payload or b""))
            return out
        finally:
            await client.close()

    return _run(_do())


def coap_fetch_multicast_collect_sync(
    uris: List[str], payload: bytes, *, hard_timeout: float = 5.0,
    quiet_timeout: Optional[float] = None, max_responses: Optional[int] = None,
    on_exchange_created: Optional[Callable[[str, MulticastExchange], None]] = None,
    on_exchange_started: Optional[Callable[[str, bytes, MulticastExchange], None]] = None,
    on_response: Optional[Callable[[Tuple[Tuple, bytes, bytes, Optional[int], int, str]], None]] = None,
) -> List[Tuple[Tuple, bytes, bytes, Optional[int], int, str]]:
    """Collect all ordinary responses to NON multicast FETCH requests."""
    client = CoapClient()

    def response_tuple(response: CoapResponse):
        """Convert a CoapResponse to the public tuple form."""
        remote = getattr(response, "remote", None)
        sockaddr = getattr(remote, "sockaddr", None) or ()
        return (tuple(sockaddr), response.payload or b"",
                bytes(response.token or b""), response.mid,
                int(response.code), str(response.interface))

    def forward_response(response: CoapResponse) -> None:
        """Forward a converted response to the optional callback."""
        if on_response is not None:
            on_response(response_tuple(response))

    async def _do():
        try:
            responses = await client.fetch_multicast_collect(
                list(uris), payload, hard_timeout=hard_timeout,
                quiet_timeout=quiet_timeout, max_responses=max_responses,
                on_exchange_created=on_exchange_created,
                on_exchange_started=on_exchange_started,
                on_response=forward_response if on_response is not None else None)
            return [response_tuple(response) for response in responses]
        finally:
            await client.close()

    return _run(_do())


def coap_request_many_sync(
    uris: List[str],
    method: str,
    payload: Union[bytes, str, None],
    *,
    content_format: Optional[int] = 0,
    no_response: Optional[int] = 0x1A,
    uri_query: Optional[Sequence[str]] = None,
    grace: float = 0.05,
) -> None:
    """Sync helper: send NON requests to multiple URIs without waiting for replies."""

    client = CoapClient()

    async def _do():
        try:
            await client.request_many(
                method,
                list(uris),
                payload,
                content_format=content_format,
                no_response=no_response,
                uri_query=uri_query,
                grace=grace,
            )
        finally:
            await client.close()

    _run(_do())


def coap_post_many_sync(
    uris: List[str],
    payload: Union[bytes, str],
    *,
    content_format: Optional[int] = 0,
    no_response: Optional[int] = 0x1A,
    grace: float = 0.05,
) -> None:
    """Sync helper: send POST to multiple URIs without waiting for replies."""

    client = CoapClient()

    async def _do():
        try:
            await client.post_many(
                list(uris),
                payload,
                content_format=content_format,
                no_response=no_response,
                grace=grace,
            )
        finally:
            await client.close()

    _run(_do())
