# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
"""aiocoap-specific multicast request/response adapter.

aiocoap 0.4.x intentionally treats ``Context.request(multicast)`` as anycast.
This module contains the private TokenManager integration needed to keep a
multicast token open for several ordinary 2.05 responses. No caller needs to
access aiocoap private objects directly.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from importlib import metadata
from typing import AsyncIterator, Callable

import aiocoap
from aiocoap import resource


SUPPORTED_AIOCOAP_VERSIONS = ("0.4.17",)
STREAMING_RESPONSE_PAYLOAD_LIMIT = 1024


class StreamingResponsePayloadTooLarge(ValueError):
    """A repeated-response representation cannot be identified across Block2."""

    def __init__(self, actual: int, limit: int):
        super().__init__(
            f"streaming CoAP response payload is {actual} bytes; "
            f"single-message limit is {limit} bytes"
        )
        self.actual = actual
        self.limit = limit


def aiocoap_adapter_version() -> str:
    """Return the required aiocoap adapter version string."""
    try:
        return metadata.version("aiocoap")
    except metadata.PackageNotFoundError:
        return str(getattr(aiocoap, "__version__", "unknown"))


def assert_supported_aiocoap() -> str:
    """Fail clearly when private TokenManager assumptions are unsupported."""
    version = aiocoap_adapter_version()
    if version not in SUPPORTED_AIOCOAP_VERSIONS:
        raise RuntimeError(
            f"Unsupported aiocoap version {version}; multicast adapter supports "
            + ", ".join(SUPPORTED_AIOCOAP_VERSIONS)
        )
    return version


def assert_aiocoap_private_contract() -> str:
    """Validate every private symbol used by the multicast adapter."""
    version = assert_supported_aiocoap()
    from aiocoap import messagemanager, protocol

    token_manager = getattr(protocol, "TokenManager", None)
    message_manager = getattr(messagemanager, "MessageManager", None)
    missing = []
    if token_manager is None:
        missing.append("protocol.TokenManager")
    else:
        for name in ("request", "process_response"):
            if not callable(getattr(token_manager, name, None)):
                missing.append(f"protocol.TokenManager.{name}")
    if message_manager is None:
        missing.append("messagemanager.MessageManager")
    elif not callable(getattr(message_manager, "dispatch_message", None)):
        missing.append("messagemanager.MessageManager.dispatch_message")
    if missing:
        raise RuntimeError(
            "aiocoap private adapter contract is missing: " + ", ".join(missing))
    return version


_receive_dispatch_original = None


def install_receive_dispatch_hook(*, observer: Callable, should_drop: Callable,
                                  on_drop: Callable) -> None:
    """Install the test-only MessageManager receive hook behind the adapter."""
    global _receive_dispatch_original
    assert_aiocoap_private_contract()
    if _receive_dispatch_original is not None:
        return
    from aiocoap import messagemanager

    original = messagemanager.MessageManager.dispatch_message

    def dispatch(manager, message):
        """Dispatch a multicast response to the matching exchange."""
        observer(message)
        if should_drop(message):
            on_drop(message)
            return None
        return original(manager, message)

    _receive_dispatch_original = original
    messagemanager.MessageManager.dispatch_message = dispatch


@dataclass(frozen=True)
class CoapResponse:
    """Response object used by the multicast adapter."""
    remote: object
    token: bytes
    mid: int | None
    code: object
    payload: bytes
    message: aiocoap.Message
    interface: str


class _MulticastPipe:
    """Pipe-like object that re-arms aiocoap's multicast TokenManager key."""

    def __init__(self, request: aiocoap.Message, queue: asyncio.Queue):
        self.request = request
        self.queue = queue
        self.manager = None
        self.closed = False
        self._interest_end = []
        self._event_callbacks = []
        self.responses_received = 0
        self.late_responses_dropped = 0

    def on_interest_end(self, callback):
        """Handle the end of multicast interest from aiocoap."""
        if self.closed:
            callback()
        else:
            self._interest_end.append(callback)

    def on_event(self, callback, is_interest=True):
        """Handle a TokenManager event."""
        self._event_callbacks.append(callback)

        def remove():
            """Remove an exchange from the adapter registry."""
            with contextlib.suppress(ValueError):
                self._event_callbacks.remove(callback)
        return remove

    def add_response(self, response, is_last=False):
        """Add a response to the exchange queue."""
        if self.closed:
            self.late_responses_dropped += 1
            return
        self.responses_received += 1
        self.queue.put_nowait((response, None))
        event = type("Event", (), {"message": response, "exception": None, "is_last": False})()
        self._event_callbacks = [callback for callback in self._event_callbacks if callback(event)]
        # TokenManager pops multicast requests before delivering each normal
        # response. Re-arm the exact key so further responders are accepted.
        if self.manager is not None:
            self.manager.outgoing_requests[(self.request.token, None)] = self

    def add_exception(self, exception):
        """Record an exception for the exchange."""
        if not self.closed:
            self.queue.put_nowait((None, exception))

    def finish(self):
        """Mark the exchange stream as finished."""
        if self.closed:
            return
        self.closed = True
        callbacks, self._interest_end = self._interest_end, []
        for callback in callbacks:
            callback()


class MulticastExchange:
    """Exchange state for one multicast request."""
    def __init__(self, context, request: aiocoap.Message, interface: str,
                 hard_timeout: float, quiet_timeout: float | None = None,
                 deduplicate: bool = True):
        self.context = context
        self.request = request
        self.interface = interface
        self.hard_timeout = float(hard_timeout)
        self.quiet_timeout = None if quiet_timeout is None else float(quiet_timeout)
        self._queue: asyncio.Queue = asyncio.Queue()
        self._closed_event = asyncio.Event()
        self._pipe = _MulticastPipe(request, self._queue)
        self._deadline = 0.0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._last_new: float | None = None
        self._started = False
        self._closed = False
        self._seen: set[tuple] = set()
        self.deduplicate = bool(deduplicate)

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *_exc):
        await self.close()

    async def start(self) -> None:
        """Start the exchange and register it with the adapter."""
        if self._started or self._closed:
            return
        assert_aiocoap_private_contract()
        self._started = True
        loop = asyncio.get_running_loop()
        self._loop = loop
        self._deadline = loop.time() + self.hard_timeout
        manager = await self.context.find_remote_and_interface(self.request)
        if self._closed:
            return
        if not hasattr(manager, "outgoing_requests"):
            raise RuntimeError("aiocoap transport has no TokenManager multicast support")
        self._pipe.manager = manager
        manager.request(self._pipe)

    def snapshot(self) -> dict:
        """Return a diagnostic snapshot of the exchange."""
        manager = self._pipe.manager
        token_registered = False
        if manager is not None:
            token_registered = manager.outgoing_requests.get(
                (self.request.token, None)) is self._pipe
        return {
            "aiocoap_version": aiocoap_adapter_version(),
            "started": self._started,
            "closed": self._closed,
            "interface": self.interface,
            "token_registered": token_registered,
            "pending_responses": self._queue.qsize(),
            "unique_responses": len(self._seen),
            "responses_received": self._pipe.responses_received,
            "late_responses_dropped": self._pipe.late_responses_dropped,
        }

    def __aiter__(self) -> AsyncIterator[CoapResponse]:
        return self._iterate()

    async def _iterate(self):
        if not self._started:
            await self.start()
        loop = asyncio.get_running_loop()
        while not self._closed:
            deadline = self._deadline
            if self._last_new is not None and self.quiet_timeout is not None:
                deadline = min(deadline, self._last_new + self.quiet_timeout)
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            response_waiter = asyncio.create_task(self._queue.get())
            close_waiter = asyncio.create_task(self._closed_event.wait())
            try:
                done, pending = await asyncio.wait(
                    (response_waiter, close_waiter), timeout=remaining,
                    return_when=asyncio.FIRST_COMPLETED,
                )
            finally:
                pending = {
                    task for task in (response_waiter, close_waiter)
                    if not task.done()
                }
                for task in pending:
                    task.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
            if not done or close_waiter in done:
                break
            message, error = response_waiter.result()
            if error is not None:
                raise error
            remote = getattr(message, "remote", None)
            sockaddr = getattr(remote, "sockaddr", None)
            key = (tuple(sockaddr) if sockaddr else repr(remote), message.mid, message.token,
                   int(message.code), message.payload or b"")
            if self.deduplicate and key in self._seen:
                continue
            self._seen.add(key)
            self._last_new = loop.time()
            yield CoapResponse(remote, bytes(message.token or b""), message.mid,
                               message.code, message.payload or b"", message,
                               self.interface)
        await self.close()

    async def close(self) -> None:
        """Close the exchange and release resources."""
        self._close_now()

    def request_close(self) -> None:
        """Request idempotent closure on the exchange's owning event loop."""
        loop = self._loop
        if loop is None or not loop.is_running():
            self._close_now()
            return
        try:
            if asyncio.get_running_loop() is loop:
                self._close_now()
                return
        except RuntimeError:
            pass
        try:
            loop.call_soon_threadsafe(self._close_now)
        except RuntimeError:
            self._close_now()

    def _close_now(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._closed_event.set()
        self._pipe.finish()
        manager = self._pipe.manager
        if manager is not None:
            key = (self.request.token, None)
            if manager.outgoing_requests.get(key) is self._pipe:
                manager.outgoing_requests.pop(key, None)
        while not self._queue.empty():
            with contextlib.suppress(asyncio.QueueEmpty):
                self._queue.get_nowait()


class PipeHandlerResource(resource.Resource):
    """Stable server-side Pipe resource for zero, one or many responses."""

    def __init__(self, handler: Callable):
        super().__init__()
        self.handler = handler

    async def needs_blockwise_assembly(self, request):
        """Keep Pipe responses within a conservative UDP Block2 size.

        The unified cGRASP resource is a Pipe resource whenever standard
        multicast is enabled.  Without this counterpart to
        ``coap_server.HandlerResource``, aiocoap attempts to put a large
        immediate Synchronization reply into one UDP datagram: the receiver
        then sees only the first practical datagram fragment and has no Block2
        option with which to request the remainder.
        """
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

    async def render_to_pipe(self, pipe) -> None:
        """Render the exchange result into an aiocoap pipe."""
        request = pipe.request

        # ``render_to_pipe`` overrides Resource's implementation, so invoke
        # this explicitly to apply the same conservative transport limit used
        # by ordinary resources.
        await self.needs_blockwise_assembly(request)

        # Multicast cGRASP handlers may emit several independent responses.
        # Pass their real server Pipe through so each response is transmitted
        # immediately; buffering here would reintroduce one quiet/hard-window
        # delay per relay hop. A Block2 continuation cannot identify which of
        # several representations from one relay/token it is continuing, so
        # fail explicitly rather than transmit a truncated or mixed response.
        if getattr(request.remote, "is_multicast_locally", False):
            try:
                limit = min(
                    int(request.remote.maximum_payload_size),
                    STREAMING_RESPONSE_PAYLOAD_LIMIT,
                )
            except Exception:
                limit = STREAMING_RESPONSE_PAYLOAD_LIMIT
            await self.handler(request, _BoundedStreamingResponsePipe(pipe, limit))
            return

        # ``resource.Resource._render_to_pipe`` normally owns Block2 caching,
        # but it cannot be used here because this resource deliberately allows
        # more than one response.  A continuation request is necessarily for
        # the one-response representation that was cached after the initial
        # request, so do not invoke the application handler a second time.
        block2 = getattr(request.opt, "block2", None)
        if block2 is not None and block2.block_number > 0:
            response = await self._block2.extract_or_insert(
                request,
                lambda: self._missing_cached_response(),
            )
            pipe.add_response(response, is_last=True)
            return

        buffered = _BufferedResponsePipe(request)
        await self.handler(request, buffered)
        if not buffered.responses:
            if buffered.finished:
                finish_pipe_silently(pipe)
            return

        # RFC 7959 represents a single response as one cached body.  Do not
        # force that model onto multicast/relay fan-in where several distinct
        # responses share a request token; those responses remain streamed as
        # supplied by the handler.
        if len(buffered.responses) == 1:
            response, is_last = buffered.responses[0]

            async def build_response():
                """Build an aiocoap response from the exchange."""
                return response

            response = await self._block2.extract_or_insert(request, build_response)
            pipe.add_response(response, is_last=is_last)
            return

        for response, is_last in buffered.responses:
            pipe.add_response(response, is_last=is_last)

    async def _missing_cached_response(self):
        # ``Block2Cache`` calls this only if its continuation lookup logic
        # changes. Raising gives the peer a protocol error instead of silently
        # re-running a side-effecting cGRASP operation.
        raise RuntimeError("missing cached Block2 response")


class _BufferedResponsePipe:
    """Minimal producer-side Pipe facade used to apply Block2 to one reply."""

    def __init__(self, request):
        self.request = request
        self.responses = []
        self.finished = False

    def add_response(self, response, is_last=False):
        """Add a response to the pipe."""
        self.responses.append((response, bool(is_last)))

    def _end(self):
        self.finished = True


class _BoundedStreamingResponsePipe:
    """Delegate a Pipe while rejecting ambiguous multi-response Block2 data."""

    def __init__(self, pipe, payload_limit: int):
        self._pipe = pipe
        self.request = pipe.request
        self.payload_limit = int(payload_limit)

    def __getattr__(self, name):
        return getattr(self._pipe, name)

    def add_response(self, response, is_last=False):
        """Add a response to the exchange queue."""
        fallback = response if isinstance(response, bytes) else b""
        payload = getattr(response, "payload", fallback)
        actual = len(payload or b"")
        if actual > self.payload_limit:
            raise StreamingResponsePayloadTooLarge(actual, self.payload_limit)
        return self._pipe.add_response(response, is_last=is_last)


def finish_pipe_silently(pipe) -> None:
    """End server interest without emitting a multicast error response."""
    end = getattr(pipe, "_end", None)
    if end is None:
        raise RuntimeError("aiocoap Pipe no longer supports silent completion")
    end()


def make_multicast_request(uri: str, payload: bytes, *, token: bytes | None = None,
                           no_response: int | None = None) -> aiocoap.Message:
    """Build a NON CoAP multicast request."""
    message = aiocoap.Message(code=aiocoap.Code.FETCH, uri=uri, payload=payload)
    message.mtype = aiocoap.NON
    message.opt.content_format = 60
    if token is not None:
        message.token = token
    if no_response is not None:
        message.opt.no_response = int(no_response)
    return message
