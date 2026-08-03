#!/usr/bin/env python3
"""Run bidirectional MQTT QoS 1 payload benchmarks over BLE L2CAP."""

from __future__ import annotations

import sys

from run_benchmarks import main


if __name__ == "__main__":
    raise SystemExit(main(["--transfer-mode", *sys.argv[1:]]))
