#!/usr/bin/env python3
"""Local regression check for CONNECT forwarding and GHCR fault control."""

from __future__ import annotations

import json
import socket
import socketserver
import threading

from fault_proxy import ProxyServer


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            data = self.request.recv(4096)
            if not data:
                return
            self.request.sendall(data)


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _http_json(port: int, method: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
    body = json.dumps(payload or {}, separators=(",", ":")).encode("utf-8")
    request = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{port}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + body
    with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
        client.settimeout(2)
        client.sendall(request)
        response = bytearray()
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
    head, response_body = bytes(response).split(b"\r\n\r\n", 1)
    status = int(head.split(b"\r\n", 1)[0].split()[1])
    return status, json.loads(response_body)


def _connect(port: int) -> tuple[socket.socket, int]:
    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    client.settimeout(2)
    client.sendall(
        b"CONNECT ghcr.io:443 HTTP/1.1\r\n"
        b"Host: ghcr.io:443\r\n"
        b"Connection: keep-alive\r\n\r\n"
    )
    response = bytearray()
    while b"\r\n\r\n" not in response:
        response.extend(client.recv(4096))
    head = bytes(response).split(b"\r\n\r\n", 1)[0]
    return client, int(head.split(b"\r\n", 1)[0].split()[1])


def _round_trip(port: int, payload: bytes) -> socket.socket:
    client, status = _connect(port)
    assert status == 200, f"expected CONNECT 200, got {status}"
    client.sendall(payload)
    assert client.recv(len(payload)) == payload, "tunnel did not forward data unchanged"
    return client


def main() -> None:
    with EchoServer(("127.0.0.1", 0), EchoHandler) as upstream:
        upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
        upstream_thread.start()
        with ProxyServer(
            ("127.0.0.1", 0),
            connect_timeout=1,
            idle_timeout=5,
            # This test-only override keeps the CONNECT authority ghcr.io:443 while
            # routing its upstream socket to a loopback echo server.
            test_upstream_overrides={"ghcr.io": ("127.0.0.1", upstream.server_address[1])},
        ) as proxy:
            proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
            proxy_thread.start()
            proxy_port = proxy.server_address[1]

            existing = _round_trip(proxy_port, b"normal tunnel")
            status, state = _http_json(proxy_port, "POST", "/control", {"mode": "block"})
            assert status == 200 and state["mode"] == "block", "block control failed"
            assert existing.recv(1) == b"", "mode change did not terminate the active GHCR tunnel"
            existing.close()

            blocked, status = _connect(proxy_port)
            blocked.close()
            assert status == 503, f"expected block response 503, got {status}"

            status, state = _http_json(proxy_port, "POST", "/control", {"mode": "normal"})
            assert status == 200 and state["mode"] == "normal", "recovery control failed"
            recovered = _round_trip(proxy_port, b"recovered tunnel")

            status, state = _http_json(proxy_port, "POST", "/control", {"flush": True})
            assert status == 200 and state["closed"] >= 1, "flush did not close an active tunnel"
            assert recovered.recv(1) == b"", "flush did not terminate the active GHCR tunnel"
            recovered.close()

            status, state = _http_json(
                proxy_port, "POST", "/control", {"mode": "delay", "delay_ms": 25}
            )
            assert status == 200 and state["delay_ms"] == 25, "delay control failed"
            delayed = _round_trip(proxy_port, b"delayed tunnel")
            delayed.close()
            status, state = _http_json(proxy_port, "POST", "/control", {"mode": "normal"})
            assert status == 200 and state["mode"] == "normal", "normal mode recovery failed"

            status, stats = _http_json(proxy_port, "GET", "/stats")
            host_stats = stats["hosts"]["ghcr.io"]
            assert status == 200 and stats["mode"] == "normal", "stats/recovery state is incorrect"
            assert stats["generation"] >= 5, "mode generation did not advance"
            assert host_stats["connections"] >= 2, "successful tunnels were not counted"
            assert host_stats["blocked"] >= 1, "blocked CONNECT was not counted"
            assert host_stats["closed_by_control"] >= 2, "forced tunnel closures were not counted"
            assert host_stats["bytes_in"] >= len(b"normal tunnel") + len(b"recovered tunnel")
            assert host_stats["bytes_out"] >= len(b"normal tunnel") + len(b"recovered tunnel")
            assert host_stats["setup_delay_count"] == 1, "CONNECT setup delay was not counted once"
            assert host_stats["setup_delay_ms_total"] == 25, "CONNECT setup delay duration was miscounted"

            proxy.shutdown()
            upstream.shutdown()
            proxy_thread.join(timeout=2)
            upstream_thread.join(timeout=2)
            print("fault proxy self-check passed")


if __name__ == "__main__":
    main()
