#!/usr/bin/env python3
import json
import os
import socket

SPEC = os.environ.get("SENTINEL_IPC", "unix:/tmp/sentinel.sock")

def connect(spec: str) -> socket.socket:
    if spec.startswith("/") and ":" not in spec:
        spec = "unix:" + spec

    if spec.startswith("unix:"):
        path = spec[len("unix:"):]
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(path)
        return s

    if spec.startswith("tcp:"):
        hostport = spec[len("tcp:"):]
        host, port = hostport.rsplit(":", 1)
        return socket.create_connection((host, int(port)), timeout=2)

    raise ValueError(f"Unsupported SENTINEL_IPC spec: {spec}")

def recv_line(sock: socket.socket) -> str:
    buf = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            break
        buf.extend(chunk)
        if chunk == b"\n":
            break
    return buf.decode("utf-8", "replace").strip()

def send(msg: dict):
    line = (json.dumps(msg) + "\n").encode("utf-8")
    s.sendall(line)
    ack = recv_line(s)
    print("ack:", ack)

print(f"[plugin-demo] connecting via SENTINEL_IPC={SPEC}")
s = connect(SPEC)

send({"type":"Register","payload":{"plugin_id":"example.python"}})
send({
    "type":"PushMetrics",
    "payload":{"metrics":[{"source":"example.python","label":"Demo Metric","value":"42"}]}
})

s.close()
