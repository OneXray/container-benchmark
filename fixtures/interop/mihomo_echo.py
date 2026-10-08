"""Independent TCP/UDP payload and peer-source oracle, in an owned Vole container."""

import http.server
import json
import os
import socket
import socketserver
import ssl
import struct
import sys
import threading

PORT = 24500
MAX_PAYLOAD = 4096
_STATS_LOCK = threading.Lock()
_STATS = {"tcp_frames": 0, "tcp_bytes": 0, "udp_packets": 0, "udp_bytes": 0}


def stats_snapshot():
    with _STATS_LOCK:
        return dict(_STATS)


def record_business(protocol, size):
    with _STATS_LOCK:
        _STATS["tcp_frames" if protocol == "tcp" else "udp_packets"] += 1
        _STATS[protocol + "_bytes"] += size


class Statistics(http.server.BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.request.settimeout(5)

    def do_GET(self):
        if self.path != "/stats":
            self.send_error(404)
            return
        payload = json.dumps(stats_snapshot(), separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


def exact(stream, size):
    output = bytearray()
    while len(output) < size:
        part = stream.recv(size - len(output))
        if not part:
            raise ValueError("truncated fixture payload")
        output.extend(part)
    return bytes(output)


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        try:
            while True:
                size = struct.unpack("!I", exact(self.request, 4))[0]
                if not 0 < size <= MAX_PAYLOAD:
                    raise ValueError("fixture payload bound")
                payload = exact(self.request, size)
                record_business("tcp", size)
                self.request.sendall(
                    socket.inet_aton(self.client_address[0])
                    + struct.pack("!I", size)
                    + payload
                )
        except (OSError, ValueError):
            # A TCP readiness connection is not a business exchange.
            return


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        payload, stream = self.request
        if not 0 < len(payload) <= MAX_PAYLOAD:
            return
        record_business("udp", len(payload))
        stream.sendto(
            socket.inet_aton(self.client_address[0]) + payload,
            self.client_address,
        )


def cover():
    """Standard TLS 1.3 cover only; no proxy/ShadowTLS decoder lives here."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain("/work/peer/cert.pem", "/work/peer/key.pem")
    context.set_ecdh_curve("X25519")
    context.set_alpn_protocols(["h2", "http/1.1"])
    slots = threading.BoundedSemaphore(16)

    def handle(raw):
        try:
            raw.settimeout(15)
            with context.wrap_socket(raw, server_side=True) as tls:
                tls.recv(1)
        except OSError:
            raw.close()
        finally:
            slots.release()

    with socket.socket(socket.AF_INET) as listener:
        listener.bind(("0.0.0.0", 24501))
        listener.listen(16)
        while True:
            raw, _ = listener.accept()
            if not slots.acquire(blocking=False):
                raw.close()
                continue
            threading.Thread(target=handle, args=(raw,), daemon=True).start()


def main():
    if sys.platform != "linux" or os.environ.get("VOLE_INTEROP_ISOLATED") != "1":
        raise RuntimeError("owned Linux origin required")
    with (
        socketserver.ThreadingTCPServer(("0.0.0.0", PORT), TCP) as tcp,
        socketserver.UDPServer(("0.0.0.0", PORT), UDP) as udp,
        http.server.HTTPServer(("0.0.0.0", 24503), Statistics) as statistics,
    ):
        tcp.daemon_threads = True
        threading.Thread(target=cover, daemon=True).start()
        threading.Thread(target=statistics.serve_forever, daemon=True).start()
        worker = threading.Thread(target=tcp.serve_forever, daemon=True)
        worker.start()
        udp.serve_forever()


if __name__ == "__main__":
    main()
