# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2025-2026 The cGRASP contributors
from __future__ import annotations

import asyncio
import socket
import unittest

import aiocoap

from cgrasp.coap_client import CoapClient, coap_pool_close_key, coap_post_pooled_sync
from cgrasp.coap_multicast_adapter import MulticastExchange, make_multicast_request
from cgrasp.coap_server import CoapServer


def _free_loopback_port() -> int:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.bind(("::1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


class CoapBlockwiseTests(unittest.IsolatedAsyncioTestCase):
    async def test_large_post_response_is_fully_reassembled(self):
        try:
            port = _free_loopback_port()
        except PermissionError:
            self.skipTest("sandbox does not permit creating IPv6 UDP sockets")
        expected = b"B" * 16384

        async def handler(method, _payload, _request):
            self.assertEqual(method, "POST")
            return aiocoap.Code.CONTENT, expected, 60

        server = CoapServer(bind=("::1", port))
        server.register(".well-known/blockwise", handler)
        client = CoapClient()
        await server.start()
        try:
            response = await client.request(
                "POST",
                f"coap://[::1]:{port}/.well-known/blockwise",
                payload=b"request",
                timeout=8,
                content_format=60,
                block2_size_exp=6,
            )
        finally:
            await client.close()
            await server.stop()

        self.assertEqual(
            response.payload,
            expected,
            msg=(
                f"payload={len(response.payload or b'')} code={response.code} "
                f"block2={response.opt.block2}"
            ),
        )

    async def test_pooled_sync_client_reassembles_large_response(self):
        try:
            port = _free_loopback_port()
        except PermissionError:
            self.skipTest("sandbox does not permit creating IPv6 UDP sockets")
        expected = b"P" * 16384
        pool_key = ("test-blockwise", port)

        async def handler(_method, _payload, _request):
            return aiocoap.Code.CONTENT, expected, 60

        server = CoapServer(bind=("::1", port))
        server.register(".well-known/pooled-blockwise", handler)
        await server.start()
        try:
            received = await asyncio.to_thread(
                coap_post_pooled_sync,
                pool_key,
                f"coap://[::1]:{port}/.well-known/pooled-blockwise",
                b"request",
                timeout=8,
                content_format=60,
            )
        finally:
            coap_pool_close_key(pool_key)
            await server.stop()

        self.assertEqual(len(received), len(expected))
        self.assertEqual(received, expected)

    async def test_pipe_resource_reassembles_large_response(self):
        try:
            port = _free_loopback_port()
        except PermissionError:
            self.skipTest("sandbox does not permit creating IPv6 UDP sockets")
        expected = b"R" * 16384
        calls = 0

        async def handler(_request, pipe):
            nonlocal calls
            calls += 1
            response = aiocoap.Message(code=aiocoap.Code.CONTENT, payload=expected)
            response.opt.content_format = 60
            pipe.add_response(response, is_last=True)

        server = CoapServer(bind=("::1", port))
        server.register_pipe(".well-known/pipe-blockwise", handler)
        client = CoapClient()
        await server.start()
        try:
            response = await client.request(
                "POST",
                f"coap://[::1]:{port}/.well-known/pipe-blockwise",
                payload=b"request",
                timeout=8,
                content_format=60,
                block2_size_exp=6,
            )
        finally:
            await client.close()
            await server.stop()

        self.assertEqual(response.payload, expected)
        self.assertEqual(calls, 1, "Block2 continuation must use the cached response")

    async def test_pipe_responses_from_one_endpoint_keep_token_open(self):
        """Exercise the private client adapter against a real aiocoap context.

        Relay fan-in needs this exact property: two ordinary Content replies
        from one relay endpoint with the request's single token must both reach
        the collector.  This deliberately uses loopback unicast so it tests
        token lifecycle without requiring host multicast routing.
        """
        try:
            port = _free_loopback_port()
        except PermissionError:
            self.skipTest("sandbox does not permit creating IPv6 UDP sockets")

        async def handler(_request, pipe):
            pipe.add_response(aiocoap.Message(code=aiocoap.Code.CONTENT, payload=b"first"))
            pipe.add_response(
                aiocoap.Message(code=aiocoap.Code.CONTENT, payload=b"second"),
                is_last=True,
            )

        server = CoapServer(bind=("::1", port))
        server.register_pipe(".well-known/multi", handler)
        client = CoapClient()
        await server.start()
        try:
            await client.start()
            request = make_multicast_request(
                f"coap://[::1]:{port}/.well-known/multi", b"request"
            )
            exchange = MulticastExchange(client._ctx, request, "loopback", 3)
            received = []
            async with exchange:
                async for response in exchange:
                    received.append(response)
        finally:
            await client.close()
            await server.stop()

        self.assertEqual([response.payload for response in received], [b"first", b"second"])
        self.assertEqual({response.token for response in received}, {request.token})
        # The multicast adapter wraps responses in aiocoap's connection object,
        # which does not expose ``sockaddr`` on every aiocoap version.  Assert
        # the peer when the transport provides it, without depending on that
        # private attribute.
        for response in received:
            sockaddr = getattr(response.remote, "sockaddr", None)
            if sockaddr:
                self.assertEqual(sockaddr[0], "::1")

