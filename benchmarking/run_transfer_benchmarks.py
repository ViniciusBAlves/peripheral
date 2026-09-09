#!/usr/bin/env python3
"""Run bidirectional MQTT QoS 1 payload benchmarks over BLE L2CAP."""

from __future__ import annotations

import sys

from run_benchmarks import main


if __name__ == "__main__":
    # A 5 KiB CoC SDU keeps sustained transfers below signaling-credit limits.
    # A caller-provided --mtu appears later and can still override this default.
    raise SystemExit(main(["--transfer-mode", "--mtu", "5120", *sys.argv[1:]]))
