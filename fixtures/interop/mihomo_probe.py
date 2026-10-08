"""Vole public SOCKS5 payload, held-session and rejection probes; no retries."""

import json
import math
import socket
import struct
import time
import urllib.request

PORT = 24500
SOCKS_PORT = 24502


class TruncatedResponse(ValueError):
    pass


class SocksRequestRejected(ValueError):
    pass


def exact(stream, size):
    output = bytearray()
    while len(output) < size:
        part = stream.recv(size - len(output))
        if not part:
            raise TruncatedResponse("truncated interoperability response")
        output.extend(part)
    return bytes(output)


def socks(stream, command, host, port, initial=b""):
    stream.sendall(b"\x05\x01\x00")
    if exact(stream, 2) != b"\x05\x00":
        raise ValueError("SOCKS5 negotiation failed")
    stream.sendall(
        bytes([5, command, 0, 1])
        + socket.inet_aton(host)
        + struct.pack("!H", port)
        + initial
    )
    header = exact(stream, 4)
    if header[0] != 5 or header[2:] != b"\x00\x01":
        raise ValueError("SOCKS5 IPv4 request failed")
    bound = socket.inet_ntoa(exact(stream, 4)), struct.unpack("!H", exact(stream, 2))[0]
    if 1 <= header[1] <= 8:
        raise SocksRequestRejected("SOCKS5 outbound request rejected")
    if header[1] != 0:
        raise ValueError("SOCKS5 reply status is invalid")
    return bound


def origin_stats(origin):
    with urllib.request.urlopen(f"http://{origin}:24503/stats", timeout=5) as response:
        data = response.read(4097)
    if len(data) > 4096:
        raise ValueError("TCP origin statistics exceeded bounds")
    counters = json.loads(data)
    if set(counters) != {"tcp_frames", "tcp_bytes", "udp_packets", "udp_bytes"} or any(
        type(value) is not int or value < 0 for value in counters.values()
    ):
        raise ValueError("TCP origin statistics schema is invalid")
    return counters


def stats_delta(before, after):
    delta = {key: after[key] - before[key] for key in before}
    if any(value < 0 for value in delta.values()):
        raise ValueError("TCP origin statistics decreased during the probe")
    return delta


def tcp_response(tcp, witness, payload):
    if exact(tcp, 4) != witness:
        raise ValueError("TCP origin did not observe the declared peer")
    if struct.unpack("!I", exact(tcp, 4))[0] != len(payload):
        raise ValueError("TCP response length differs")
    if exact(tcp, len(payload)) != payload:
        raise ValueError("TCP bidirectional payload differs")


def client_auth_rejection(origin, witness, expected):
    before = origin_stats(origin)
    payload = bytes(range(256)) * 4
    with socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=15) as tcp:
        # Negotiation/readiness failures and timeouts are infrastructure errors,
        # not proof of TLS/SS authentication being required.
        try:
            socks(tcp, 1, origin, PORT, struct.pack("!I", len(payload)) + payload)
        except SocksRequestRejected:
            pass
        else:
            try:
                tcp_response(tcp, witness, payload)
            except (TruncatedResponse, ConnectionResetError):
                pass
            else:
                raise ValueError(
                    "TCP client authentication unexpectedly accepted business"
                )
    ss_identity = expected == "ss-identity-rejection"
    if ss_identity:
        ingress = ("127.0.0.1", SOCKS_PORT)
        with (
            socket.create_connection(ingress, timeout=15) as association,
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp,
        ):
            relay = socks(association, 3, "0.0.0.0", 0)
            if relay != ingress:
                raise ValueError("SOCKS5 relay is not the declared loopback ingress")
            udp.settimeout(5)
            udp.connect(relay)
            payload = bytes(index % 251 for index in range(64))
            packet = (
                b"\x00\x00\x00\x01"
                + socket.inet_aton(origin)
                + struct.pack("!H", PORT)
                + payload
            )
            if udp.send(packet) != len(packet):
                raise ValueError("partial UDP submission")
            try:
                udp.recv(65536)
            except TimeoutError:
                pass
            else:
                raise ValueError(
                    "UDP identity authentication unexpectedly returned business"
                )
    delta = stats_delta(before, origin_stats(origin))
    if any(delta.values()):
        raise ValueError("TCP rejected client authentication still reached the origin")
    return {
        "status": "PASS",
        "expected": expected,
        "negative_reason": "SS identity authentication was rejected"
        if ss_identity
        else "TLS client authentication was rejected",
        "origin_business_delta": delta,
        "tcp_bytes_each_direction": 0,
        "udp_packets_each_direction": 0,
        "udp_attempted_packets": int(ss_identity),
    }


def udp_address(target):
    try:
        return b"\x01" + socket.inet_aton(target)
    except OSError:
        encoded = target.encode("ascii")
        if not 0 < len(encoded) <= 255 or any(value <= 32 for value in encoded):
            raise ValueError("UDP target domain is invalid") from None
        return b"\x03" + bytes([len(encoded)]) + encoded


def udp_response(response, origin, target, witness, payload):
    if response[:3] != b"\x00\x00\x00" or len(response) < 4:
        raise ValueError("UDP response has invalid SOCKS framing")
    if response[3] == 1 and len(response) >= 10:
        source, offset = socket.inet_ntoa(response[4:8]), 8
    elif response[3] == 3 and len(response) >= 5 + response[4] + 2:
        source = response[5 : 5 + response[4]].decode("ascii")
        offset = 5 + response[4]
    else:
        raise ValueError("UDP response has invalid source endpoint")
    port = struct.unpack("!H", response[offset : offset + 2])[0]
    if (
        source.lower() not in {origin.lower(), target.lower()}
        or port != PORT
        or response[offset + 2 :] != witness + payload
    ):
        raise ValueError("UDP origin source or bidirectional payload differs")


def probe(
    origin, peer, expected="pass", udp_target=None, hold_seconds=0, interval_seconds=5.5
):
    if (
        not math.isfinite(hold_seconds)
        or not 0 <= hold_seconds <= 60
        or not math.isfinite(interval_seconds)
        or interval_seconds <= 0
    ):
        raise ValueError("UDP hold interval is invalid")
    ingress = ("127.0.0.1", SOCKS_PORT)
    witness = socket.inet_aton(peer)
    if expected in ("tls-client-auth-rejection", "ss-identity-rejection"):
        return client_auth_rejection(origin, witness, expected)
    if expected not in ("pass", "udp-disabled"):
        raise ValueError("UDP expected outcome is unknown")
    if expected == "udp-disabled" and hold_seconds:
        raise ValueError("UDP disabled negative does not support a hold interval")
    before = origin_stats(origin) if expected == "udp-disabled" else None
    rounds = math.floor(hold_seconds / interval_seconds) + 1
    with (
        socket.create_connection(ingress, timeout=15) as tcp,
        socket.create_connection(ingress, timeout=15) as association,
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp,
    ):
        payload = bytes(range(256)) * 4
        # Client-first payload is legal SOCKS5 pipelining. In particular, do not
        # manufacture an empty SS2022 first write while waiting for a server.
        socks(tcp, 1, origin, PORT, struct.pack("!I", len(payload)) + payload)
        relay = socks(association, 3, "0.0.0.0", 0)
        if relay != ingress:
            raise ValueError("SOCKS5 relay is not the declared loopback ingress")
        udp.settimeout(5 if expected == "udp-disabled" else 15)
        udp.connect(relay)
        target = udp_target or origin
        header = b"\x00\x00\x00" + udp_address(target) + struct.pack("!H", PORT)
        started = time.monotonic()
        for iteration in range(rounds):
            if iteration:
                delay = started + iteration * interval_seconds - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                payload = struct.pack("!I", iteration) + bytes(range(4, 256))
                payload += bytes(range(256)) * 3
                tcp.sendall(struct.pack("!I", len(payload)) + payload)
            tcp_response(tcp, witness, payload)
            for size in (64, 1200):
                udp_payload = struct.pack("!I", iteration) + bytes(
                    index % 251 for index in range(4, size)
                )
                packet = header + udp_payload
                if udp.send(packet) != len(packet):
                    raise ValueError("partial UDP submission")
                if expected == "udp-disabled":
                    try:
                        udp.recv(65536)
                    except TimeoutError:
                        pass
                    else:
                        raise ValueError(
                            "UDP disabled peer unexpectedly returned business"
                        )
                    # A fresh successful exchange on the same stream rules out
                    # treating a dead runtime/peer as disabled UDP negotiation.
                    control = b"\x00\x00\x00\x01" + payload[4:]
                    tcp.sendall(struct.pack("!I", len(control)) + control)
                    tcp_response(tcp, witness, control)
                    delta = stats_delta(before, origin_stats(origin))
                    if delta["udp_packets"] or delta["udp_bytes"]:
                        raise ValueError(
                            "UDP disabled business still reached the origin"
                        )
                    if delta["tcp_frames"] < 2 or delta["tcp_bytes"] < 2048:
                        raise ValueError(
                            "TCP origin statistics did not witness live business"
                        )
                    return {
                        "status": "PASS",
                        "expected": "udp-disabled",
                        "negative_reason": "UDP was disabled by the authenticated peer",
                        "tcp_bytes_each_direction": 2048,
                        "udp_packets_each_direction": 0,
                        "udp_attempted_packets": 1,
                        "origin_observed_peer_source": True,
                        "origin_business_delta": delta,
                        "tcp_exchange": "client-first",
                    }
                response = udp.recv(65536)
                udp_response(response, origin, target, witness, udp_payload)
        remaining = started + hold_seconds - time.monotonic()
        if remaining > 0:
            time.sleep(remaining)
    return {
        "status": "PASS",
        "tcp_bytes_each_direction": 1024 * rounds,
        "udp_packets_each_direction": 2 * rounds,
        "udp_payload_sizes": [64, 1200],
        "origin_observed_peer_source": True,
        "tcp_exchange": "client-first",
        "hold_seconds": hold_seconds,
    }
