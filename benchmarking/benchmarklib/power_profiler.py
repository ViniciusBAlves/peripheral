from __future__ import annotations

import csv
import gzip
import statistics
import threading
import time
from dataclasses import dataclass
from pathlib import Path


NATIVE_SAMPLE_RATE_HZ = 100_000
WINDOW_BITS = {
    # DK P0.03/P0.04/P0.28/P0.29 are wired to PPK2 D7/D6/D5/D4.
    "total_execution": 7,
    "handshake": 6,
    "client_kem": 5,
    "client_signature": 4,
}


def _open_ppk(device: str):
    try:
        from ppk2_api.ppk2_api import PPK2_API
    except ImportError as error:
        raise RuntimeError(
            "PPK2 support requires: python -m pip install ppk2-api==0.9.2"
        ) from error
    ppk = PPK2_API(device, timeout=0.1)
    # ppk2-api 0.9.2 changes this to 9600 after opening. Current Nordic
    # Power Profiler uses 115200 for the PPK2 command/data CDC interface.
    ppk.ser.baudrate = 115200
    return ppk


@dataclass
class _Window:
    start: int
    end: int
    sample_count: int
    current_sum_ua: float
    peak_current_ua: float


def _combine_windows(windows: list[_Window]) -> _Window:
    """Combine disjoint GPIO pulses without charging the gaps between them."""
    if not windows:
        raise ValueError("at least one power window is required")
    return _Window(
        start=min(window.start for window in windows),
        end=max(window.end for window in windows),
        sample_count=sum(window.sample_count for window in windows),
        current_sum_ua=sum(window.current_sum_ua for window in windows),
        peak_current_ua=max(window.peak_current_ua for window in windows),
    )


class PowerProfilerSession:
    """Keep the PPK2 source and measurement CDC alive for the complete run."""

    def __init__(self, device: str, vdd_mv: int, output_samples_per_second: int):
        self.device = device
        self.vdd_mv = vdd_mv
        self.output_rate = output_samples_per_second
        self.ppk = None
        self.powered = False

    def open(self) -> None:
        self.ppk = _open_ppk(self.device)
        try:
            self.ppk.stop_measuring()
            self.ppk.toggle_DUT_power("OFF")
            time.sleep(0.1)
            self.ppk.ser.reset_input_buffer()
            if not self.ppk.get_modifiers():
                raise RuntimeError(
                    f"could not read PPK2 calibration data from {self.device}"
                )
            self.ppk.use_source_meter()
            self.ppk.set_source_voltage(self.vdd_mv)
        except BaseException:
            try:
                self.ppk.toggle_DUT_power("OFF")
            finally:
                self.ppk.ser.close()
                self.ppk = None
            raise

    def power_on(self, boot_seconds: float = 0.5) -> None:
        if self.ppk is None:
            raise RuntimeError("PPK2 session is not open")
        self.ppk.toggle_DUT_power("ON")
        self.powered = True
        time.sleep(boot_seconds)

    def probe_current(self) -> tuple[float, float]:
        if self.ppk is None:
            raise RuntimeError("PPK2 session is not open")
        if not self.powered:
            raise RuntimeError("PPK2 DUT power is off")
        samples: list[float] = []
        self.ppk.start_measuring()
        try:
            deadline = time.monotonic() + 0.5
            while time.monotonic() < deadline:
                raw = self.ppk.get_data()
                if raw:
                    current, _ = self.ppk.get_samples(raw)
                    samples.extend(current)
                else:
                    time.sleep(0.002)
        finally:
            self.ppk.stop_measuring()
        if not samples:
            raise RuntimeError("PPK2 returned no current samples")
        absolute = [abs(value) for value in samples]
        return statistics.fmean(absolute), max(absolute)

    def capture(self) -> "PowerProfilerCapture":
        if self.ppk is None:
            raise RuntimeError("PPK2 session is not open")
        return PowerProfilerCapture(
            self.device, self.vdd_mv, self.output_rate, ppk=self.ppk
        )

    def power_cycle(self, off_seconds: float = 0.25,
                    boot_seconds: float = 1.0) -> None:
        if self.ppk is None:
            raise RuntimeError("PPK2 session is not open")
        self.ppk.stop_measuring()
        self.ppk.toggle_DUT_power("OFF")
        self.powered = False
        time.sleep(off_seconds)
        self.ppk.toggle_DUT_power("ON")
        self.powered = True
        time.sleep(boot_seconds)

    def close(self) -> None:
        if self.ppk is None:
            return
        try:
            self.ppk.stop_measuring()
        finally:
            try:
                self.ppk.toggle_DUT_power("OFF")
                self.powered = False
            finally:
                self.ppk.ser.close()
                self.ppk = None


class PowerProfilerCapture:
    """Capture PPK2 current and synchronous digital markers for one attempt."""

    def __init__(
        self, device: str, vdd_mv: int, output_samples_per_second: int, *, ppk=None
    ):
        if vdd_mv <= 0:
            raise ValueError("PPK2 VDD must be positive")
        if not 1 <= output_samples_per_second <= NATIVE_SAMPLE_RATE_HZ:
            raise ValueError("PPK2 output sample rate must be between 1 and 100000")
        self.device = device
        self.vdd_mv = vdd_mv
        self.output_rate = output_samples_per_second
        self._ppk = ppk
        self._owns_ppk = ppk is None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._error: Exception | None = None
        self._sample_index = 0
        self._trace: list[tuple[float, float, int]] = []
        self._active: dict[str, dict[str, float | int]] = {}
        self._completed: dict[str, list[_Window]] = {
            name: [] for name in WINDOW_BITS
        }
        self._last_mask = 0

    def start(self) -> None:
        if self._ppk is None:
            self._ppk = _open_ppk(self.device)
            self._ppk.stop_measuring()
            time.sleep(0.1)
            self._ppk.ser.reset_input_buffer()
            if not self._ppk.get_modifiers():
                raise RuntimeError(
                    f"could not read PPK2 calibration data from {self.device}"
                )
            self._ppk.use_source_meter()
            self._ppk.set_source_voltage(self.vdd_mv)
            self._ppk.toggle_DUT_power("ON")
        self._ppk.start_measuring()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def _capture_loop(self) -> None:
        assert self._ppk is not None
        downsample_step = NATIVE_SAMPLE_RATE_HZ / self.output_rate
        next_trace_sample = 0.0
        try:
            while not self._stop.is_set():
                raw = self._ppk.get_data()
                if not raw:
                    time.sleep(0.002)
                    continue
                currents, masks = self._ppk.get_samples(raw)
                for current_ua, mask in zip(currents, masks):
                    index = self._sample_index
                    self._process_sample(index, float(current_ua), int(mask))
                    if index >= next_trace_sample:
                        self._trace.append(
                            (index / NATIVE_SAMPLE_RATE_HZ, float(current_ua), int(mask))
                        )
                        next_trace_sample += downsample_step
                    self._sample_index += 1
        except Exception as error:  # surfaced by stop(), in the runner thread
            self._error = error

    def _process_sample(self, index: int, current_ua: float, mask: int) -> None:
        for name, bit in WINDOW_BITS.items():
            high = bool(mask & (1 << bit))
            was_high = bool(self._last_mask & (1 << bit))
            if high and not was_high:
                self._active[name] = {
                    "start": index, "count": 0, "sum": 0.0, "peak": current_ua,
                }
            state = self._active.get(name)
            if high and state is not None:
                state["count"] = int(state["count"]) + 1
                state["sum"] = float(state["sum"]) + current_ua
                state["peak"] = max(float(state["peak"]), current_ua)
            if not high and was_high and state is not None:
                self._completed[name].append(_Window(
                    start=int(state["start"]), end=index,
                    sample_count=int(state["count"]),
                    current_sum_ua=float(state["sum"]),
                    peak_current_ua=float(state["peak"]),
                ))
                del self._active[name]
        self._last_mask = mask

    def stop(self, trace_path: Path) -> dict[str, object]:
        # Allow the final low GPIO edge already emitted by the board to reach
        # the USB CDC receive buffer before stopping the polling thread.
        time.sleep(0.05)
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3.0)
        if self._ppk is not None:
            try:
                self._ppk.stop_measuring()
            except Exception as error:
                if self._error is None:
                    self._error = error
            finally:
                if self._owns_ppk:
                    try:
                        self._ppk.toggle_DUT_power("OFF")
                    finally:
                        self._ppk.ser.close()
        if self._owns_ppk:
            self._ppk = None
        self._write_trace(trace_path)
        if self._error is not None:
            return self._empty_result("error", str(self._error))
        return self._measurements()

    def _write_trace(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with gzip.open(path, "wt", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(("time_s", "current_ua", "digital_mask"))
            for timestamp, current, mask in self._trace:
                writer.writerow((f"{timestamp:.6f}", f"{current:.6f}", mask))

    def _empty_result(self, status: str, message: str = "") -> dict[str, object]:
        result: dict[str, object] = {
            "power_status": status,
            "power_profiler_sample_count": self._sample_index,
            "power_profiler_window_count": len(self._completed["total_execution"]),
            "power_profiler_vdd_mv": self.vdd_mv,
            "power_profiler_output_samples_per_second": self.output_rate,
        }
        if message:
            result["power_error"] = message
        return result

    def _measurements(self) -> dict[str, object]:
        totals = self._completed["total_execution"]
        if not totals:
            return self._empty_result("incomplete")
        total = totals[-1]
        selected: dict[str, _Window] = {"total_execution": total}
        for name in WINDOW_BITS:
            if name == "total_execution":
                continue
            contained = [
                window for window in self._completed[name]
                if total.start <= window.start and window.end <= total.end
            ]
            if contained:
                selected[name] = _combine_windows(contained)
        result = self._empty_result(
            "success" if len(selected) == len(WINDOW_BITS) else "incomplete"
        )
        for name, window in selected.items():
            duration_s = window.sample_count / NATIVE_SAMPLE_RATE_HZ
            avg_current_ua = window.current_sum_ua / window.sample_count
            charge_uc = window.current_sum_ua / NATIVE_SAMPLE_RATE_HZ
            result.update({
                f"{name}_duration_ms": f"{duration_s * 1000.0:.3f}",
                f"{name}_charge_uc": f"{charge_uc:.6f}",
                f"{name}_energy_uj": f"{charge_uc * self.vdd_mv / 1000.0:.6f}",
                f"{name}_avg_current_ua": f"{avg_current_ua:.3f}",
                f"{name}_peak_current_ua": f"{window.peak_current_ua:.3f}",
            })
        return result
