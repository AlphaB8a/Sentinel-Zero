#!/usr/bin/env python3
"""
Internal defensive canary client for authorized environments only.

Safety guardrails:
- Targets private/loopback addresses by default.
- Requires explicit --allow-public-ip to target non-private addresses.
"""

import argparse
import ipaddress
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def recv_line(sock: socket.socket, timeout_s: float) -> str:
    sock.settimeout(timeout_s)
    buf = bytearray()
    while True:
        try:
            chunk = sock.recv(1)
        except socket.timeout:
            break
        if not chunk:
            break
        buf.extend(chunk)
        if chunk == b"\n":
            break
    return buf.decode("utf-8", "replace").strip()


def send_and_ack(host: str, port: int, line: str, timeout_s: float) -> dict:
    started = time.perf_counter()
    with socket.create_connection((host, port), timeout=timeout_s) as s:
        s.sendall(line.encode("utf-8"))
        ack = recv_line(s, timeout_s)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return {"ack": ack, "elapsed_ms": round(elapsed_ms, 3)}


def scenario_valid_register(host: str, port: int, timeout_s: float) -> dict:
    payload = {"type": "Register", "payload": {"plugin_id": "canary.valid"}}
    out = send_and_ack(host, port, json.dumps(payload) + "\n", timeout_s)
    out["status_ok"] = '"status":"ok"' in out["ack"]
    return out


def scenario_invalid_json(host: str, port: int, timeout_s: float) -> dict:
    out = send_and_ack(host, port, "{not-json}\n", timeout_s)
    out["bad_request"] = '"status":"bad_request"' in out["ack"]
    return out


def scenario_overlong(host: str, port: int, timeout_s: float, overlong_chars: int) -> dict:
    payload = {
        "type": "Register",
        "payload": {"plugin_id": "X" * overlong_chars},
    }
    out = send_and_ack(host, port, json.dumps(payload) + "\n", timeout_s)
    out["line_too_long"] = "line_too_long" in out["ack"]
    return out


def scenario_slowloris(host: str, port: int, timeout_s: float, delay_s: float) -> dict:
    result = {
        "closed_before_newline": False,
        "send_error": None,
        "post_delay_ack": "",
    }
    with socket.create_connection((host, port), timeout=timeout_s) as s:
        s.settimeout(timeout_s)
        s.sendall(b'{"type":"Register","payload":{"plugin_id":"canary.slow')
        time.sleep(delay_s)
        try:
            s.sendall(b'"}}\n')
            result["post_delay_ack"] = recv_line(s, timeout_s)
        except OSError as exc:
            result["send_error"] = str(exc)
        # Empty ack after delayed write is expected if server disconnected.
        result["closed_before_newline"] = (
            result["post_delay_ack"] == "" or result["send_error"] is not None
        )
    return result


def scenario_message_limit(host: str, port: int, timeout_s: float, tries: int) -> dict:
    counts = {"ok": 0, "bad_request": 0, "message_limit_exceeded": 0, "empty": 0}
    with socket.create_connection((host, port), timeout=timeout_s) as s:
        s.settimeout(timeout_s)
        for i in range(tries):
            payload = {"type": "Register", "payload": {"plugin_id": f"canary.msg.{i}"}}
            s.sendall((json.dumps(payload) + "\n").encode("utf-8"))
            ack = recv_line(s, timeout_s)
            if not ack:
                counts["empty"] += 1
                break
            if '"status":"ok"' in ack:
                counts["ok"] += 1
            if '"status":"bad_request"' in ack:
                counts["bad_request"] += 1
            if "message_limit_exceeded" in ack:
                counts["message_limit_exceeded"] += 1
                break
    return counts


def flood_worker(host: str, port: int, timeout_s: float, idx: int) -> dict:
    try:
        with socket.create_connection((host, port), timeout=timeout_s) as s:
            s.settimeout(timeout_s)
            payload = {"type": "Register", "payload": {"plugin_id": f"canary.flood.{idx}"}}
            s.sendall((json.dumps(payload) + "\n").encode("utf-8"))
            ack = recv_line(s, timeout_s)
            return {
                "connected": True,
                "ack_ok": '"status":"ok"' in ack,
                "ack_bad_request": '"status":"bad_request"' in ack,
                "ack_empty": ack == "",
            }
    except OSError:
        return {
            "connected": False,
            "ack_ok": False,
            "ack_bad_request": False,
            "ack_empty": True,
        }


def scenario_connection_flood(
    host: str, port: int, timeout_s: float, workers: int, attempts: int
) -> dict:
    totals = {
        "attempts": attempts,
        "connected": 0,
        "connect_failed": 0,
        "ack_ok": 0,
        "ack_bad_request": 0,
        "ack_empty": 0,
    }
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(flood_worker, host, port, timeout_s, i) for i in range(attempts)]
        for fut in as_completed(futures):
            res = fut.result()
            if res["connected"]:
                totals["connected"] += 1
            else:
                totals["connect_failed"] += 1
            if res["ack_ok"]:
                totals["ack_ok"] += 1
            if res["ack_bad_request"]:
                totals["ack_bad_request"] += 1
            if res["ack_empty"]:
                totals["ack_empty"] += 1
    return totals


def scenario_throughput(host: str, port: int, timeout_s: float, count: int) -> dict:
    started = time.perf_counter()
    ok = 0
    for i in range(count):
        payload = {"type": "Register", "payload": {"plugin_id": f"canary.tp.{i}"}}
        out = send_and_ack(host, port, json.dumps(payload) + "\n", timeout_s)
        if '"status":"ok"' in out["ack"]:
            ok += 1
    elapsed = time.perf_counter() - started
    return {
        "messages": count,
        "ok": ok,
        "elapsed_s": round(elapsed, 3),
        "throughput_msgs_per_s": round((count / elapsed) if elapsed > 0 else 0.0, 3),
    }


def resolve_target_ip(host: str) -> str:
    # Keep behavior explicit: resolve once and use the resolved IPv4 for policy checks.
    return socket.gethostbyname(host)


def enforce_private_target(host: str, allow_public_ip: bool) -> tuple[str, bool]:
    resolved = resolve_target_ip(host)
    ip_obj = ipaddress.ip_address(resolved)
    is_private_or_local = (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
    )
    if not allow_public_ip and not is_private_or_local:
        raise SystemExit(
            f"refusing non-private target {host} ({resolved}); pass --allow-public-ip only in explicitly authorized tests"
        )
    return resolved, is_private_or_local


def main() -> None:
    parser = argparse.ArgumentParser(description="Safe hostile simulation client")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--timeout-s", type=float, default=2.0)
    parser.add_argument("--slowloris-delay-s", type=float, default=2.0)
    parser.add_argument("--overlong-chars", type=int, default=4000)
    parser.add_argument("--msg-limit-tries", type=int, default=40)
    parser.add_argument("--flood-workers", type=int, default=64)
    parser.add_argument("--flood-attempts", type=int, default=200)
    parser.add_argument("--throughput-count", type=int, default=120)
    parser.add_argument(
        "--allow-public-ip",
        action="store_true",
        help="Allow targeting a non-private IP (disabled by default for safety).",
    )
    args = parser.parse_args()
    resolved_ip, is_private_or_local = enforce_private_target(
        args.host, args.allow_public_ip
    )

    result = {
        "target": {
            "host": args.host,
            "resolved_ip": resolved_ip,
            "port": args.port,
            "is_private_or_local": is_private_or_local,
        },
        "scenarios": {},
        "started_epoch_s": int(time.time()),
    }

    result["scenarios"]["valid_register"] = scenario_valid_register(
        args.host, args.port, args.timeout_s
    )
    result["scenarios"]["invalid_json"] = scenario_invalid_json(
        args.host, args.port, args.timeout_s
    )
    result["scenarios"]["overlong_line"] = scenario_overlong(
        args.host, args.port, args.timeout_s, args.overlong_chars
    )
    result["scenarios"]["slowloris_timeout"] = scenario_slowloris(
        args.host, args.port, args.timeout_s, args.slowloris_delay_s
    )
    result["scenarios"]["message_limit"] = scenario_message_limit(
        args.host, args.port, args.timeout_s, args.msg_limit_tries
    )
    result["scenarios"]["connection_flood"] = scenario_connection_flood(
        args.host, args.port, args.timeout_s, args.flood_workers, args.flood_attempts
    )
    result["scenarios"]["throughput"] = scenario_throughput(
        args.host, args.port, args.timeout_s, args.throughput_count
    )
    result["ended_epoch_s"] = int(time.time())

    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
