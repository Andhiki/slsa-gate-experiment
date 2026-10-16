#!/usr/bin/env python3
"""Small CONNECT proxy for the isolated SLSA fault-injection pilot."""

from __future__ import annotations

import argparse
import http
import ipaddress
import json
import select
import socket
import socketserver
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


TARGET_HOST = "ghcr.io"
MAX_HEADER_BYTES = 32 * 1024
MAX_CONTROL_BODY = 8 * 1024
MAX_DELAY_MS = 60_000
MAX_TUNNEL_BUFFER = 1024 * 1024


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _host_key(host: str) -> str:
    return host.rstrip(".").lower()


def _is_loopback_peer(peer: Any) -> bool:
    try:
        return ipaddress.ip_address(str(peer[0]).split("%", 1)[0]).is_loopback
    except (ValueError, IndexError, TypeError):
        return False


def _parse_authority(authority: str) -> tuple[str, int]:
    if not authority or any(ch.isspace() for ch in authority) or "@" in authority:
        raise ValueError("invalid CONNECT authority")
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0 or end + 1 >= len(authority) or authority[end + 1] != ":":
            raise ValueError("CONNECT authority must include a port")
        host, port_text = authority[1:end], authority[end + 2 :]
    else:
        if authority.count(":") != 1:
            raise ValueError("CONNECT authority must be host:port")
        host, port_text = authority.rsplit(":", 1)
    if not host or len(host) > 253 or not port_text.isdecimal():
        raise ValueError("invalid CONNECT host or port")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("invalid CONNECT port")
    return host, port


def _request(client: socket.socket) -> tuple[str, str, str, dict[str, str], bytes, bytes]:
    data = bytearray()
    marker = b"\r\n\r\n"
    while marker not in data:
        if len(data) >= MAX_HEADER_BYTES:
            raise ValueError("request headers too large")
        chunk = client.recv(min(4096, MAX_HEADER_BYTES + 4 - len(data)))
        if not chunk:
            raise ValueError("connection closed before request headers")
        data.extend(chunk)

    head, extra = bytes(data).split(marker, 1)
    if len(head) > MAX_HEADER_BYTES:
        raise ValueError("request headers too large")
    lines = head.split(b"\r\n")
    try:
        method, target, version = lines[0].decode("ascii").split(" ")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("invalid request line") from exc
    if version not in ("HTTP/1.0", "HTTP/1.1"):
        raise ValueError("unsupported HTTP version")

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or b":" not in line:
            raise ValueError("invalid HTTP header")
        name, value = line.split(b":", 1)
        try:
            key = name.decode("ascii").strip().lower()
            text_value = value.decode("latin-1").strip()
        except UnicodeDecodeError as exc:
            raise ValueError("invalid HTTP header") from exc
        if not key or key in headers:
            raise ValueError("duplicate or empty HTTP header")
        headers[key] = text_value

    if "transfer-encoding" in headers:
        raise ValueError("transfer encoding is unsupported")
    length_text = headers.get("content-length", "0")
    if not length_text.isdecimal():
        raise ValueError("invalid content length")
    length = int(length_text)
    if length > MAX_CONTROL_BODY:
        raise ValueError("request body too large")
    body = bytearray(extra[:length])
    while len(body) < length:
        chunk = client.recv(length - len(body))
        if not chunk:
            raise ValueError("connection closed in request body")
        body.extend(chunk)
    tunnel_data = extra if method == "CONNECT" else b""
    return method, target, version, headers, bytes(body), tunnel_data


def _send_response(
    client: socket.socket,
    status: int,
    body: bytes = b"",
    content_type: str = "application/json",
    extra_headers: tuple[tuple[str, str], ...] = (),
) -> None:
    reason = http.HTTPStatus(status).phrase
    headers = [
        f"HTTP/1.1 {status} {reason}\r\n",
        f"Content-Length: {len(body)}\r\n",
        f"Content-Type: {content_type}\r\n",
        "Connection: close\r\n",
    ]
    headers.extend(f"{name}: {value}\r\n" for name, value in extra_headers)
    client.sendall("".join(headers).encode("ascii") + b"\r\n" + body)


@dataclass(eq=False)
class Tunnel:
    host: str
    client: socket.socket
    upstream: socket.socket
    generation: int
    forced_closed: bool = False


class ProxyState:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.mode = "normal"
        self.delay_ms = 0
        self.generation = 0
        self.active: set[Tunnel] = set()
        self.counters: dict[str, dict[str, int]] = defaultdict(
            lambda: {
                "connections": 0,
                "blocked": 0,
                "closed": 0,
                "closed_by_control": 0,
                "ended": 0,
                "bytes_in": 0,
                "bytes_out": 0,
                "setup_delay_count": 0,
                "setup_delay_ms_total": 0,
            }
        )

    def snapshot(self) -> tuple[str, int, int]:
        with self.lock:
            return self.mode, self.delay_ms, self.generation

    def record_delay(self, host: str, delay_ms: int) -> None:
        with self.lock:
            stats = self.counters[host]
            stats["setup_delay_count"] += 1
            stats["setup_delay_ms_total"] += delay_ms

    def _close_target_tunnels(self) -> int:
        closed = 0
        for tunnel in tuple(self.active):
            if tunnel.host == TARGET_HOST and not tunnel.forced_closed:
                tunnel.forced_closed = True
                stats = self.counters[tunnel.host]
                stats["closed"] += 1
                stats["closed_by_control"] += 1
                closed += 1
                for sock in (tunnel.client, tunnel.upstream):
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
        return closed

    def control(self, body: bytes) -> tuple[int, dict[str, Any]]:
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return 400, {"error": "body must be JSON"}
        if not isinstance(payload, dict) or set(payload) - {"mode", "delay_ms", "flush"}:
            return 400, {"error": "expected mode, delay_ms, or flush"}

        mode = payload.get("mode")
        delay_ms = payload.get("delay_ms")
        flush = payload.get("flush", False)
        if mode is not None and mode not in ("normal", "delay", "block"):
            return 400, {"error": "mode must be normal, delay, or block"}
        if delay_ms is not None and (
            isinstance(delay_ms, bool)
            or not isinstance(delay_ms, int)
            or not 0 <= delay_ms <= MAX_DELAY_MS
        ):
            return 400, {"error": f"delay_ms must be an integer from 0 to {MAX_DELAY_MS}"}
        if not isinstance(flush, bool):
            return 400, {"error": "flush must be a boolean"}

        with self.lock:
            changed = (mode is not None and mode != self.mode) or (
                delay_ms is not None and delay_ms != self.delay_ms
            )
            if mode is not None:
                self.mode = mode
            if delay_ms is not None:
                self.delay_ms = delay_ms
            closed = 0
            if changed or flush:
                self.generation += 1
            if changed or flush:
                closed = self._close_target_tunnels()
            result = {
                "mode": self.mode,
                "delay_ms": self.delay_ms,
                "generation": self.generation,
                "closed": closed,
            }
        return 200, result

    def block_current(self, host: str) -> bool:
        if host != TARGET_HOST:
            return False
        with self.lock:
            if self.mode == "block":
                self.counters[host]["blocked"] += 1
                return True
            return False

    def activate(self, host: str, client: socket.socket, upstream: socket.socket) -> Tunnel | None:
        with self.lock:
            if host == TARGET_HOST and self.mode == "block":
                self.counters[host]["blocked"] += 1
                return None
            tunnel = Tunnel(host, client, upstream, self.generation)
            self.active.add(tunnel)
            self.counters[host]["connections"] += 1
            return tunnel

    def add_bytes(self, host: str, direction: str, count: int) -> None:
        with self.lock:
            self.counters[host][direction] += count

    def finish(self, tunnel: Tunnel) -> None:
        with self.lock:
            self.active.discard(tunnel)
            self.counters[tunnel.host]["ended"] += 1

    def stats(self) -> dict[str, Any]:
        with self.lock:
            active_by_host: dict[str, int] = defaultdict(int)
            for tunnel in self.active:
                active_by_host[tunnel.host] += 1
            hosts = {
                host: {**values, "active": active_by_host.get(host, 0)}
                for host, values in sorted(self.counters.items())
            }
            return {
                "mode": self.mode,
                "delay_ms": self.delay_ms,
                "generation": self.generation,
                "active": len(self.active),
                "hosts": hosts,
            }


class ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = False
    request_queue_size = 64

    def __init__(
        self,
        address: tuple[str, int],
        *,
        connect_timeout: float = 5.0,
        idle_timeout: float = 300.0,
        test_upstream_overrides: dict[str, tuple[str, int]] | None = None,
    ) -> None:
        self.state = ProxyState()
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout
        self.test_upstream_overrides = {
            _host_key(host): destination for host, destination in (test_upstream_overrides or {}).items()
        }
        super().__init__(address, ProxyHandler)

    def open_upstream(self, host: str, port: int) -> socket.socket:
        override = self.test_upstream_overrides.get(host)
        connect_host, connect_port = override if override is not None else (host, port)
        if override is not None:
            addresses = socket.getaddrinfo(connect_host, connect_port, type=socket.SOCK_STREAM)
            if not addresses or any(
                not ipaddress.ip_address(item[4][0].split("%", 1)[0]).is_loopback for item in addresses
            ):
                raise PermissionError("test upstream override must resolve only to loopback")
        else:
            if port != 443:
                raise PermissionError("only upstream port 443 is allowed")
            addresses = socket.getaddrinfo(connect_host, connect_port, type=socket.SOCK_STREAM)
            if not addresses:
                raise OSError("host has no addresses")
            for item in addresses:
                address_ip = ipaddress.ip_address(item[4][0].split("%", 1)[0])
                if not address_ip.is_global:
                    raise PermissionError("private or non-public upstream address is not allowed")

        last_error: OSError | None = None
        for family, socktype, proto, _canonname, sockaddr in addresses:
            upstream = socket.socket(family, socktype, proto)
            upstream.settimeout(self.connect_timeout)
            try:
                upstream.connect(sockaddr)
                return upstream
            except OSError as exc:
                last_error = exc
                upstream.close()
        if last_error:
            raise last_error
        raise OSError("no usable upstream address")


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client: socket.socket = self.request
        client.settimeout(10.0)
        try:
            method, target, _version, _headers, body, tunnel_data = _request(client)
            if method == "CONNECT":
                self._connect(target, tunnel_data)
            else:
                self._control_or_stats(method, target, body)
        except (OSError, ValueError) as exc:
            status = 431 if str(exc) == "request headers too large" else 400
            self._error(status, str(exc))
        finally:
            try:
                client.close()
            except OSError:
                pass

    def _error(self, status: int, message: str) -> None:
        try:
            _send_response(self.request, status, _json_bytes({"error": message}))
        except OSError:
            pass

    def _control_or_stats(self, method: str, target: str, body: bytes) -> None:
        path = urlsplit(target).path
        if path not in ("/stats", "/control"):
            self._error(404, "unknown endpoint")
            return
        if not _is_loopback_peer(self.client_address):
            self._error(403, "control API is available from loopback only")
            return
        if path == "/stats" and method == "GET":
            status, payload = 200, self.server.state.stats()
        elif path == "/control" and method == "POST":
            status, payload = self.server.state.control(body)
        else:
            status, payload = 405, {"error": "use GET /stats or POST /control"}
        _send_response(self.request, status, _json_bytes(payload))

    def _connect(self, authority: str, tunnel_data: bytes) -> None:
        try:
            raw_host, port = _parse_authority(authority)
        except ValueError as exc:
            self._error(400, str(exc))
            return
        host = _host_key(raw_host)
        if self.server.state.block_current(host):
            self._error(503, "target blocked by fault proxy")
            return

        mode, delay_ms, _generation = self.server.state.snapshot()
        if host == TARGET_HOST and mode == "delay" and delay_ms:
            time.sleep(delay_ms / 1000)
            self.server.state.record_delay(host, delay_ms)
        if self.server.state.block_current(host):
            self._error(503, "target blocked by fault proxy")
            return

        try:
            upstream = self.server.open_upstream(host, port)
        except PermissionError as exc:
            self._error(403, str(exc))
            return
        except OSError:
            self._error(502, "upstream connection failed")
            return

        tunnel = self.server.state.activate(host, self.request, upstream)
        if tunnel is None:
            upstream.close()
            self._error(503, "target blocked by fault proxy")
            return
        try:
            self.request.settimeout(10.0)
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n")
            self._relay(tunnel, tunnel_data)
        except OSError:
            pass
        finally:
            self.server.state.finish(tunnel)
            for sock in (upstream, self.request):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass

    def _relay(self, tunnel: Tunnel, early_data: bytes) -> None:
        client, upstream = tunnel.client, tunnel.upstream
        client.setblocking(False)
        upstream.setblocking(False)
        buffers = {client: bytearray(), upstream: bytearray()}
        read_open = {client: True, upstream: True}
        if early_data:
            buffers[upstream].extend(early_data)
        last_activity = time.monotonic()

        while any(read_open.values()) or any(buffers.values()):
            if time.monotonic() - last_activity > self.server.idle_timeout:
                return
            readable = []
            for sock in (client, upstream):
                destination = upstream if sock is client else client
                if read_open[sock] and len(buffers[destination]) < MAX_TUNNEL_BUFFER:
                    readable.append(sock)
            writable = [sock for sock in (client, upstream) if buffers[sock]]
            try:
                ready_read, ready_write, _ = select.select(readable, writable, [], 1.0)
            except (OSError, ValueError):
                return

            for sock in ready_read:
                destination = upstream if sock is client else client
                try:
                    data = sock.recv(min(65536, MAX_TUNNEL_BUFFER - len(buffers[destination])))
                except BlockingIOError:
                    continue
                except OSError:
                    return
                if not data:
                    read_open[sock] = False
                    if not buffers[destination]:
                        try:
                            destination.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                else:
                    buffers[destination].extend(data)
                    last_activity = time.monotonic()

            for sock in ready_write:
                try:
                    count = sock.send(buffers[sock])
                except BlockingIOError:
                    continue
                except OSError:
                    return
                if count:
                    del buffers[sock][:count]
                    direction = "bytes_in" if sock is upstream else "bytes_out"
                    self.server.state.add_bytes(tunnel.host, direction, count)
                    last_activity = time.monotonic()
                    source = client if sock is upstream else upstream
                    if not read_open[source] and not buffers[sock]:
                        try:
                            sock.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Fault-injection CONNECT proxy for the SLSA pilot")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=3128)
    args = parser.parse_args()
    with ProxyServer((args.host, args.port)) as server:
        print(f"fault proxy listening on {args.host}:{args.port}", flush=True)
        try:
            server.serve_forever(poll_interval=0.5)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
