"""Offline public payload/negative oracles; no socket listeners are created."""

import importlib.util
import io
import json
import socket
import struct
import time
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch


def fixture(name):
    path = Path(__file__).resolve().parents[2] / "fixtures/interop" / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = fixture("mihomo_probe")
echo = fixture("mihomo_echo")
ORIGIN = "192.0.2.20"
PEER = "192.0.2.10"
DOMAIN = "origin.fixture.invalid"
REPLY = b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", 24502)


class Stream:
    def __init__(self, *, reject=False):
        self.incoming = bytearray()
        self.sent = []
        self.reject = reject

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def sendall(self, data):
        self.sent.append(data)
        if data == b"\x05\x01\x00":
            self.incoming.extend(b"\x05\x00")
        elif data.startswith(b"\x05\x03"):
            self.incoming.extend(REPLY)
        elif data.startswith(b"\x05\x01"):
            if self.reject:
                self.incoming.extend(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
            else:
                self.incoming.extend(REPLY)
                self.incoming.extend(socket.inet_aton(PEER) + data[10:])
        else:
            self.incoming.extend(socket.inet_aton(PEER) + data)

    def recv(self, size):
        data = bytes(self.incoming[:size])
        del self.incoming[:size]
        return data


class Datagram:
    def __init__(self, *, response_domain=False, disabled=False):
        self.response_domain = response_domain
        self.disabled = disabled
        self.sent, self.incoming = [], []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def settimeout(self, timeout):
        pass

    def connect(self, address):
        if address != ("127.0.0.1", 24502):
            raise AssertionError("unexpected relay")

    def send(self, packet):
        self.sent.append(packet)
        payload = packet[7 + packet[4] :] if packet[3] == 3 else packet[10:]
        target = (
            b"\x03" + bytes([len(DOMAIN)]) + DOMAIN.encode()
            if self.response_domain
            else b"\x01" + socket.inet_aton(ORIGIN)
        )
        self.incoming.append(
            b"\x00\x00\x00"
            + target
            + struct.pack("!H", 24500)
            + socket.inet_aton(PEER)
            + payload
        )
        return len(packet)

    def recv(self, size):
        if self.disabled:
            raise TimeoutError("synthetic no UDP response")
        return self.incoming.pop(0)


class ProbeTests(unittest.TestCase):
    def test_domain_udp_is_sent_without_local_resolution_and_accepts_ip_or_domain_reply(
        self,
    ):
        for response_domain in (False, True):
            with self.subTest(response_domain=response_domain):
                udp = Datagram(response_domain=response_domain)
                with (
                    patch.object(
                        socket, "create_connection", side_effect=[Stream(), Stream()]
                    ),
                    patch.object(socket, "socket", return_value=udp),
                    patch.object(socket, "getaddrinfo", side_effect=AssertionError),
                ):
                    result = probe.probe(ORIGIN, PEER, udp_target=DOMAIN)
                self.assertEqual(result["status"], "PASS")
                self.assertTrue(result["origin_observed_peer_source"])
                self.assertEqual(udp.sent[0][3], 3)
                self.assertEqual(udp.sent[0][5 : 5 + len(DOMAIN)], DOMAIN.encode())

    def test_hop_keeps_the_same_stream_and_udp_association_for_four_fresh_rounds(self):
        tcp, association, udp = Stream(), Stream(), Datagram()
        clock = [0.0]

        def sleep(duration):
            clock[0] += duration

        with (
            patch.object(
                socket, "create_connection", side_effect=[tcp, association]
            ) as connect,
            patch.object(socket, "socket", return_value=udp),
            patch.object(time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(time, "sleep", side_effect=sleep),
        ):
            result = probe.probe(ORIGIN, PEER, hold_seconds=16.5, interval_seconds=5.5)
        self.assertEqual(connect.call_count, 2)
        self.assertEqual(result["tcp_bytes_each_direction"], 4096)
        self.assertEqual(result["udp_packets_each_direction"], 8)
        self.assertEqual(clock[0], 16.5)
        self.assertEqual(len({packet[10:] for packet in udp.sent}), 8)

    def test_missing_client_identity_requires_business_rejection_and_zero_origin_delta(
        self,
    ):
        stats = {"tcp_frames": 0, "tcp_bytes": 0, "udp_packets": 0, "udp_bytes": 0}
        with (
            patch.object(socket, "create_connection", return_value=Stream(reject=True)),
            patch.object(
                urllib.request,
                "urlopen",
                side_effect=[io.BytesIO(json.dumps(stats).encode()) for _ in range(2)],
            ),
        ):
            result = probe.probe(ORIGIN, PEER, expected="tls-client-auth-rejection")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["origin_business_delta"], stats)
        self.assertEqual(
            result["negative_reason"], "TLS client authentication was rejected"
        )

    def test_ss_identity_rejection_proves_tcp_and_an_actual_udp_attempt(self):
        stats = {"tcp_frames": 0, "tcp_bytes": 0, "udp_packets": 0, "udp_bytes": 0}
        udp = Datagram(disabled=True)
        with (
            patch.object(
                socket, "create_connection", side_effect=[Stream(reject=True), Stream()]
            ),
            patch.object(socket, "socket", return_value=udp),
            patch.object(
                urllib.request,
                "urlopen",
                side_effect=[io.BytesIO(json.dumps(stats).encode()) for _ in range(2)],
            ),
        ):
            result = probe.probe(ORIGIN, PEER, expected="ss-identity-rejection")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(
            result["negative_reason"], "SS identity authentication was rejected"
        )
        self.assertEqual(result["udp_attempted_packets"], 1)
        self.assertEqual(result["origin_business_delta"], stats)
        self.assertEqual(len(udp.sent), 1)
        self.assertEqual(len(udp.sent[0][10:]), 64)

    def test_disabled_udp_requires_live_tcp_before_and_after_and_zero_udp_at_origin(
        self,
    ):
        before = {"tcp_frames": 0, "tcp_bytes": 0, "udp_packets": 0, "udp_bytes": 0}
        after = {"tcp_frames": 2, "tcp_bytes": 2048, "udp_packets": 0, "udp_bytes": 0}
        with (
            patch.object(socket, "create_connection", side_effect=[Stream(), Stream()]),
            patch.object(socket, "socket", return_value=Datagram(disabled=True)),
            patch.object(
                urllib.request,
                "urlopen",
                side_effect=[
                    io.BytesIO(json.dumps(stats).encode()) for stats in (before, after)
                ],
            ),
        ):
            result = probe.probe(ORIGIN, PEER, expected="udp-disabled")
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["tcp_bytes_each_direction"], 2048)
        self.assertEqual(result["udp_packets_each_direction"], 0)
        self.assertEqual(result["origin_business_delta"]["udp_packets"], 0)

    def test_negative_does_not_turn_a_missing_consumer_into_authentication_pass(self):
        stats = {"tcp_frames": 0, "tcp_bytes": 0, "udp_packets": 0, "udp_bytes": 0}
        with (
            patch.object(
                socket, "create_connection", side_effect=ConnectionRefusedError
            ),
            patch.object(
                urllib.request,
                "urlopen",
                return_value=io.BytesIO(json.dumps(stats).encode()),
            ),
            self.assertRaises(ConnectionRefusedError),
        ):
            probe.probe(ORIGIN, PEER, expected="tls-client-auth-rejection")

    def test_negative_is_not_pass_when_complete_business_reached_the_origin(self):
        before = {"tcp_frames": 0, "tcp_bytes": 0, "udp_packets": 0, "udp_bytes": 0}
        after = {"tcp_frames": 1, "tcp_bytes": 1024, "udp_packets": 0, "udp_bytes": 0}
        with (
            patch.object(socket, "create_connection", return_value=Stream(reject=True)),
            patch.object(
                urllib.request,
                "urlopen",
                side_effect=[
                    io.BytesIO(json.dumps(stats).encode()) for stats in (before, after)
                ],
            ),
            self.assertRaisesRegex(ValueError, "still reached the origin"),
        ):
            probe.probe(ORIGIN, PEER, expected="tls-client-auth-rejection")

    def test_udp_disabled_requires_the_peer_to_remain_live_after_the_timeout(self):
        class DeadAfterFirstExchange(Stream):
            def sendall(self, data):
                if data.startswith(b"\x05"):
                    super().sendall(data)

        stats = {"tcp_frames": 0, "tcp_bytes": 0, "udp_packets": 0, "udp_bytes": 0}
        with (
            patch.object(
                socket,
                "create_connection",
                side_effect=[DeadAfterFirstExchange(), Stream()],
            ),
            patch.object(socket, "socket", return_value=Datagram(disabled=True)),
            patch.object(
                urllib.request,
                "urlopen",
                return_value=io.BytesIO(json.dumps(stats).encode()),
            ),
            self.assertRaisesRegex(ValueError, "truncated"),
        ):
            probe.probe(ORIGIN, PEER, expected="udp-disabled")

    def test_tcp_origin_uses_one_stream_for_multiple_complete_frames(self):
        class OriginStream:
            def __init__(self):
                self.incoming = bytearray(
                    b"\x00\x00\x00\x03one\x00\x00\x00\x03two\x00\x00\x00\x08partial"
                )
                self.sent = bytearray()

            def settimeout(self, timeout):
                pass

            def recv(self, size):
                data = bytes(self.incoming[:size])
                del self.incoming[:size]
                return data

            def sendall(self, data):
                self.sent.extend(data)

        stream = OriginStream()
        handler = object.__new__(echo.TCP)
        handler.request, handler.client_address = stream, (PEER, 12345)
        before = echo.stats_snapshot()
        handler.handle()
        after = echo.stats_snapshot()
        self.assertEqual(after["tcp_frames"] - before["tcp_frames"], 2)
        self.assertEqual(after["tcp_bytes"] - before["tcp_bytes"], 6)
        self.assertEqual(
            bytes(stream.sent),
            socket.inet_aton(PEER)
            + b"\x00\x00\x00\x03one"
            + socket.inet_aton(PEER)
            + b"\x00\x00\x00\x03two",
        )

    def test_origin_statistics_are_available_through_read_only_http(self):
        class HttpStream:
            def __init__(self):
                self.response = bytearray()

            def makefile(self, mode, *args):
                return io.BytesIO(b"GET /stats HTTP/1.0\r\n\r\n")

            def sendall(self, data):
                self.response.extend(data)

            def settimeout(self, timeout):
                pass

        stream = HttpStream()
        echo.Statistics(stream, (PEER, 12345), object())
        body = bytes(stream.response).split(b"\r\n\r\n", 1)[1]
        self.assertEqual(json.loads(body), echo.stats_snapshot())


if __name__ == "__main__":
    unittest.main()
