#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType


def load_adapter(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("sg_gateway_infosec_adapter", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load adapter: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def exercise(module: ModuleType, control: str, events: str) -> dict[str, bool]:
    client = module.SGInfoSecClient(
        control_socket=control,
        events_socket=events,
        timeout=0.5,
    )
    ipv4 = "203.0.113.44"
    ipv6 = "2001:db8::44"

    initially_blocked = client.is_blocked(
        scope="admin-login", ip=ipv4, route_id="login_post"
    )
    require(not initially_blocked, "fresh IPv4 address is already blocked")

    for index in range(1, 5):
        require(
            client.emit_auth_failure(
                scope="admin-login",
                ip=ipv4,
                route="login_post",
                subject="admin",
            ),
            f"IPv4 event {index} was rejected",
        )
        require(
            not client.is_blocked(
                scope="admin-login", ip=ipv4, route_id="login_post"
            ),
            f"IPv4 address blocked before threshold at event {index}",
        )

    require(
        client.emit_auth_failure(
            scope="admin-login",
            ip=ipv4,
            route="login_post",
            subject="admin",
        ),
        "fifth IPv4 event was rejected",
    )
    blocked_after_five = client.is_blocked(
        scope="admin-login", ip=ipv4, route_id="login_post"
    )
    require(blocked_after_five, "fifth IPv4 event did not create a decision")

    api_blocked = client.is_blocked(
        scope="admin-api", ip=ipv4, route_id="api_status"
    )
    require(not api_blocked, "admin-login decision leaked into admin-api scope")

    for index in range(1, 6):
        require(
            client.emit_auth_failure(
                scope="admin-login",
                ip=ipv6,
                route="login_post",
                subject="admin",
            ),
            f"IPv6 event {index} was rejected",
        )
    ipv6_blocked = client.is_blocked(
        scope="admin-login", ip=ipv6, route_id="login_post"
    )
    require(ipv6_blocked, "IPv6 threshold did not create an independent decision")

    return {
        "initially_blocked": initially_blocked,
        "blocked_after_five": blocked_after_five,
        "api_blocked": api_blocked,
        "ipv6_blocked": ipv6_blocked,
    }


def verify_fail_open(module: ModuleType, control: str, events: str) -> None:
    client = module.SGInfoSecClient(
        control_socket=control,
        events_socket=events,
        timeout=0.05,
    )
    require(
        not client.is_blocked(
            scope="admin-login", ip="203.0.113.45", route_id="login_post"
        ),
        "missing daemon did not fail open",
    )
    require(
        not client.emit_auth_failure(
            scope="admin-login",
            ip="203.0.113.45",
            route="login_post",
            subject="admin",
        ),
        "missing daemon reported an accepted event",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--adapter", type=Path, required=True)
    parser.add_argument("--control", required=True)
    parser.add_argument("--events", required=True)
    parser.add_argument("--fail-open-only", action="store_true")
    args = parser.parse_args()

    try:
        module = load_adapter(args.adapter)
        if args.fail_open_only:
            verify_fail_open(module, args.control, args.events)
            print(json.dumps({"fail_open": True}, separators=(",", ":")))
        else:
            print(
                json.dumps(
                    exercise(module, args.control, args.events),
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        return 0
    except Exception as exc:
        print(f"SG-Gateway adapter smoke: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
