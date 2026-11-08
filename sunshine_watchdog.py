#!/usr/bin/env python3
"""
sunshine_watchdog.py - Sunshine + macOS display watchdog.

Checks:
  1. Sunshine process.
  2. Local Sunshine serverinfo API (47989).
  3. Local Sunshine Web UI (47990).
  4. Tailscale reachability (diagnostic only; does NOT restart Sunshine).
  5. Active macOS displays through CoreGraphics (no third-party dependencies).
  6. Optional stream.py panel health endpoint.

Display recovery:
  - Detects display topology / pixel-size changes.
  - Waits for the display configuration to settle.
  - Restarts Sunshine once after a stable display change, so capture can
    reopen against the new display mode.
  - Detects the absence of active displays separately. Restarting Sunshine
    cannot create a macOS display, so this is logged and rate-limited.

Moonlight client-side 503:
  This host-side watchdog cannot directly see an error shown on a separate
  Moonlight client. Keep the client-side detector: it provides useful
  end-to-end evidence that video capture/encoding failed even when the
  Sunshine API is alive.

Only Python standard library is used. On macOS, CoreGraphics is accessed
through ctypes. Run as the same user / launch context as the workflow where
possible. Root is only needed if your existing launchctl-asuser setup requires it.
"""

import ctypes
import ctypes.util
import json
import os
import re
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import deque


# ============================================================
# CONFIG
# ============================================================

SUNSHINE_BIN = os.environ.get(
    "WD_SUNSHINE_BIN",
    "/Applications/Sunshine.app/Contents/MacOS/sunshine",
)
PROC_PATTERN = os.environ.get(
    "WD_PROC_PATTERN",
    "Sunshine.app/Contents/MacOS/sunshine",
)
GUI_UID = os.environ.get("WD_GUI_UID", "501")
SUNSHINE_LOG = os.environ.get(
    "WD_SUNSHINE_LOG",
    "/Users/runner/.config/sunshine/sunshine.log",
)

CHECK_INTERVAL = max(2, int(os.environ.get("WD_CHECK_INTERVAL", "10")))
PROBE_TIMEOUT = max(1, int(os.environ.get("WD_PROBE_TIMEOUT", "5")))
FAIL_LIMIT = max(1, int(os.environ.get("WD_FAIL_LIMIT", "6")))
START_GRACE = max(0, int(os.environ.get("WD_START_GRACE", "60")))
RECOVERY_WAIT = max(5, int(os.environ.get("WD_RECOVERY_WAIT", "60")))

MAX_RESTARTS = max(1, int(os.environ.get("WD_MAX_RESTARTS", "5")))
RESTART_WINDOW = max(60, int(os.environ.get("WD_RESTART_WINDOW", "600")))
LIMIT_PAUSE = max(10, int(os.environ.get("WD_LIMIT_PAUSE", "120")))

STUCK_BUSY_MINUTES = max(0, int(os.environ.get("WD_STUCK_BUSY_MINUTES", "0")))

# Display monitoring
DISPLAY_WATCH = os.environ.get("WD_DISPLAY_WATCH", "1") == "1"
DISPLAY_CHANGE_RESTART = os.environ.get("WD_DISPLAY_CHANGE_RESTART", "1") == "1"
DISPLAY_SETTLE_SECONDS = max(
    5, int(os.environ.get("WD_DISPLAY_SETTLE_SECONDS", "20"))
)
DISPLAY_NO_DISPLAY_LIMIT = max(
    1, int(os.environ.get("WD_DISPLAY_NO_DISPLAY_LIMIT", "3"))
)
DISPLAY_RESTART_COOLDOWN = max(
    30, int(os.environ.get("WD_DISPLAY_RESTART_COOLDOWN", "90"))
)
# Optional user-supplied command to re-apply / recreate a virtual display.
# Leave empty unless the workflow has a known-good display recovery command.
DISPLAY_RECOVERY_CMD = os.environ.get("WD_DISPLAY_RECOVERY_CMD", "").strip()
DISPLAY_RECOVERY_COOLDOWN = max(
    60, int(os.environ.get("WD_DISPLAY_RECOVERY_COOLDOWN", "300"))
)

# Optional stream.py panel
PANEL_WATCH = os.environ.get("WD_PANEL_WATCH", "0") == "1"
PANEL_CMD = os.environ.get("WD_PANEL_CMD", "")
PANEL_HEALTH = os.environ.get(
    "WD_PANEL_HEALTH",
    "http://127.0.0.1:5902/health",
)

LOG_FILE = os.environ.get("WD_LOG_FILE", "/tmp/sunshine_watchdog.log")

SERVERINFO_LOCAL = "http://127.0.0.1:47989/serverinfo"
WEBUI_LOCAL = "https://127.0.0.1:47990/"

RUNNING = True


# ============================================================
# LOGGING
# ============================================================

def log(message):
    line = f"[{time.strftime('%H:%M:%S')}] [watchdog] {message}"
    print(line, flush=True)
    try:
        log_dir = os.path.dirname(LOG_FILE)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ============================================================
# HTTP PROBES
# ============================================================

def http_probe(url, timeout=PROBE_TIMEOUT):
    """Return (answered, status, body). HTTP errors still mean endpoint answered."""
    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "Sunshine-Watchdog/2.0"},
        )
        # Sunshine's local HTTPS UI commonly uses a self-signed certificate.
        import ssl
        context = ssl._create_unverified_context()
        with urllib.request.urlopen(request, timeout=timeout, context=context) as r:
            return True, r.status, r.read(16384)
    except urllib.error.HTTPError as exc:
        return True, exc.code, b""
    except Exception:
        return False, 0, b""


def serverinfo_ok(url):
    answered, status, body = http_probe(url)
    ok = answered and status == 200 and b"<root" in body
    state = ""
    if ok:
        match = re.search(rb"<state>(.*?)</state>", body, re.IGNORECASE)
        state = match.group(1).decode("utf-8", "replace") if match else ""
    return ok, state


# ============================================================
# PROCESS / TAILSCALE
# ============================================================

def sunshine_running():
    try:
        result = subprocess.run(
            ["pgrep", "-f", PROC_PATTERN],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def tailscale_ip():
    try:
        result = subprocess.run(
            ["tailscale", "ip", "-4"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        lines = result.stdout.strip().splitlines()
        return lines[0] if lines else None
    except Exception:
        return None


# ============================================================
# macOS DISPLAY MONITOR
# ============================================================

class DisplayMonitor:
    """
    Uses CoreGraphics to obtain active display IDs and pixel dimensions.
    Signature changes when a display is added/removed or its pixel mode changes.

    No `system_profiler` polling is used: it is comparatively slow and can
    return changing / incomplete text while macOS is reconfiguring displays.
    """

    class _CGRect(ctypes.Structure):
        _fields_ = [
            ("origin_x", ctypes.c_double),
            ("origin_y", ctypes.c_double),
            ("size_width", ctypes.c_double),
            ("size_height", ctypes.c_double),
        ]

    def __init__(self):
        self.cg = None
        self.error = None
        try:
            path = ctypes.util.find_library("CoreGraphics")
            if not path:
                path = (
                    "/System/Library/Frameworks/"
                    "CoreGraphics.framework/CoreGraphics"
                )
            self.cg = ctypes.CDLL(path)

            self.cg.CGGetActiveDisplayList.argtypes = [
                ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_uint32),
                ctypes.POINTER(ctypes.c_uint32),
            ]
            self.cg.CGGetActiveDisplayList.restype = ctypes.c_int32

            self.cg.CGDisplayIsOnline.argtypes = [ctypes.c_uint32]
            self.cg.CGDisplayIsOnline.restype = ctypes.c_bool
            self.cg.CGDisplayIsActive.argtypes = [ctypes.c_uint32]
            self.cg.CGDisplayIsActive.restype = ctypes.c_bool
            self.cg.CGDisplayPixelsWide.argtypes = [ctypes.c_uint32]
            self.cg.CGDisplayPixelsWide.restype = ctypes.size_t
            self.cg.CGDisplayPixelsHigh.argtypes = [ctypes.c_uint32]
            self.cg.CGDisplayPixelsHigh.restype = ctypes.size_t
            self.cg.CGDisplayBounds.argtypes = [ctypes.c_uint32]
            self.cg.CGDisplayBounds.restype = self._CGRect
        except Exception as exc:
            self.cg = None
            self.error = f"{type(exc).__name__}: {exc}"

    def snapshot(self):
        if self.cg is None:
            return None, self.error or "CoreGraphics unavailable"

        count = ctypes.c_uint32(0)
        result = self.cg.CGGetActiveDisplayList(0, None, ctypes.byref(count))
        if result != 0:
            return None, f"CGGetActiveDisplayList(count) returned {result}"

        if count.value == 0:
            return tuple(), None

        display_ids = (ctypes.c_uint32 * count.value)()
        actual = ctypes.c_uint32(0)
        result = self.cg.CGGetActiveDisplayList(
            count.value, display_ids, ctypes.byref(actual)
        )
        if result != 0:
            return None, f"CGGetActiveDisplayList(list) returned {result}"

        displays = []
        for index in range(actual.value):
            display_id = int(display_ids[index])
            try:
                online = bool(self.cg.CGDisplayIsOnline(display_id))
                active = bool(self.cg.CGDisplayIsActive(display_id))
                width = int(self.cg.CGDisplayPixelsWide(display_id))
                height = int(self.cg.CGDisplayPixelsHigh(display_id))
                bounds = self.cg.CGDisplayBounds(display_id)
                if online and active:
                    displays.append((
                        display_id,
                        width,
                        height,
                        round(bounds.origin_x),
                        round(bounds.origin_y),
                        round(bounds.size_width),
                        round(bounds.size_height),
                    ))
            except Exception as exc:
                return None, f"display {display_id}: {type(exc).__name__}: {exc}"

        return tuple(sorted(displays)), None


def format_display_signature(signature):
    if signature is None:
        return "unavailable"
    if not signature:
        return "no active displays"
    return ", ".join(
        f"id={d[0]} {d[1]}x{d[2]} at ({d[3]},{d[4]})"
        for d in signature
    )


# ============================================================
# OPTIONAL PANEL
# ============================================================

def panel_ok():
    answered, status, _ = http_probe(PANEL_HEALTH)
    return answered and status == 200


# ============================================================
# ACTIONS
# ============================================================

def sudo_prefix():
    return [] if os.geteuid() == 0 else ["sudo"]


def tail_sunshine_log(lines=25):
    try:
        if os.path.exists(SUNSHINE_LOG):
            with open(
                SUNSHINE_LOG, "r", encoding="utf-8", errors="replace"
            ) as f:
                tail = f.readlines()[-lines:]
            log("---- sunshine.log (tail) ----")
            for line in tail:
                print("    " + line.rstrip(), flush=True)
    except Exception as exc:
        log(f"cannot read Sunshine log: {exc}")


def restart_sunshine(reason):
    log(f"RESTART Sunshine - reason: {reason}")
    tail_sunshine_log()

    try:
        subprocess.run(
            sudo_prefix() + ["pkill", "-9", "-f", PROC_PATTERN],
            capture_output=True,
            timeout=15,
        )
    except Exception as exc:
        log(f"warning: pkill failed: {exc}")

    # Wait for the old process to disappear.
    for _ in range(15):
        if not sunshine_running():
            break
        time.sleep(1)
    time.sleep(2)

    try:
        subprocess.Popen(
            sudo_prefix() + [
                "launchctl", "asuser", GUI_UID, SUNSHINE_BIN
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception as exc:
        log(f"ERROR: could not launch Sunshine: {type(exc).__name__}: {exc}")
        return False

    log("Sunshine launched; waiting for local API...")
    started = time.monotonic()
    while time.monotonic() - started < RECOVERY_WAIT:
        if sunshine_running():
            ok, _ = serverinfo_ok(SERVERINFO_LOCAL)
            if ok:
                elapsed = time.monotonic() - started
                log(f"Sunshine process and API recovered after {elapsed:.0f}s.")
                return True
        time.sleep(3)

    log(f"Sunshine did not recover within {RECOVERY_WAIT}s.")
    tail_sunshine_log()
    return False


def restart_panel(reason):
    if not PANEL_CMD:
        log(f"panel down ({reason}) but WD_PANEL_CMD is not set - skipping.")
        return False

    log(f"RESTART panel - reason: {reason}")
    try:
        subprocess.run(
            sudo_prefix() + ["pkill", "-9", "-f", "stream.py"],
            capture_output=True,
            timeout=15,
        )
        time.sleep(2)
        subprocess.Popen(
            sudo_prefix() + [
                "launchctl", "asuser", GUI_UID, "/usr/bin/env"
            ] + PANEL_CMD.split(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return True
    except Exception as exc:
        log(f"ERROR restarting panel: {type(exc).__name__}: {exc}")
        return False


# ============================================================
# MAIN LOOP
# ============================================================

def stop(signum, frame):
    global RUNNING
    RUNNING = False
    log("Stop signal received.")


def main():
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    log("=" * 64)
    log("Sunshine + macOS Display watchdog started")
    log(
        f"interval={CHECK_INTERVAL}s timeout={PROBE_TIMEOUT}s "
        f"fail_limit={FAIL_LIMIT} grace={START_GRACE}s "
        f"display_watch={DISPLAY_WATCH} "
        f"display_change_restart={DISPLAY_CHANGE_RESTART} "
        f"display_settle={DISPLAY_SETTLE_SECONDS}s "
        f"display_recovery_cmd={'set' if DISPLAY_RECOVERY_CMD else 'off'} "
        f"panel_watch={PANEL_WATCH}"
    )
    log("=" * 64)

    display_monitor = DisplayMonitor() if DISPLAY_WATCH else None
    previous_display_signature = None
    display_baseline_set = False
    display_changed_at = None
    display_no_active_count = 0
    display_outage_recovery_attempted = False
    display_unavailable_logged = False
    last_display_restart = 0.0
    last_display_recovery_command = 0.0

    restarts = deque()
    core_fails = 0
    down_since = None
    busy_since = None
    panel_fails = 0

    ts_ip = None
    ts_checked = 0.0
    ts_was_ok = None

    grace_until = time.monotonic() + START_GRACE

    while RUNNING:
        time.sleep(CHECK_INTERVAL)
        if not RUNNING:
            break

        now = time.monotonic()

        # Keep the startup grace, but continue observing display changes.
        in_grace = now < grace_until

        # Tailscale is diagnostic / network health only. It must not restart
        # a healthy local Sunshine instance.
        if now - ts_checked >= 60:
            ts_ip = tailscale_ip()
            ts_checked = now

        # ----------------------------------------------------
        # DISPLAY CHECK
        # ----------------------------------------------------
        display_restart_reason = None

        if display_monitor is not None:
            signature, display_error = display_monitor.snapshot()

            if signature is None:
                if not display_unavailable_logged:
                    log(f"display monitor unavailable: {display_error}")
                    display_unavailable_logged = True
            else:
                display_unavailable_logged = False

                if len(signature) == 0:
                    display_no_active_count += 1
                    if display_no_active_count == 1:
                        display_outage_recovery_attempted = False
                        log("DISPLAY WARNING: no active macOS displays detected.")
                    elif display_no_active_count == DISPLAY_NO_DISPLAY_LIMIT:
                        log(
                            "DISPLAY ERROR: no active display for "
                            f"{display_no_active_count} checks."
                        )
                    if (
                        display_no_active_count >= DISPLAY_NO_DISPLAY_LIMIT
                        and DISPLAY_RECOVERY_CMD
                        and not display_outage_recovery_attempted
                        and now - last_display_recovery_command
                            >= DISPLAY_RECOVERY_COOLDOWN
                    ):
                        display_outage_recovery_attempted = True
                        last_display_recovery_command = now
                        log("DISPLAY RECOVERY: running WD_DISPLAY_RECOVERY_CMD.")
                        try:
                            result = subprocess.run(
                                DISPLAY_RECOVERY_CMD,
                                shell=True,
                                capture_output=True,
                                text=True,
                                timeout=30,
                            )
                            log(
                                "display recovery command exit="
                                f"{result.returncode}"
                            )
                            if result.stdout.strip():
                                log("display recovery stdout: " +
                                    result.stdout.strip()[-1500:])
                            if result.stderr.strip():
                                log("display recovery stderr: " +
                                    result.stderr.strip()[-1500:])
                        except Exception as exc:
                            log(
                                "display recovery command failed: "
                                f"{type(exc).__name__}: {exc}"
                            )
                else:
                    if display_no_active_count:
                        log(
                            "DISPLAY recovered: active display(s) detected "
                            f"after {display_no_active_count} failed check(s)."
                        )
                        # Even if the same display ID/mode returned, force a
                        # settle + Sunshine restart so capture reopens it.
                        display_changed_at = now
                    display_no_active_count = 0
                    display_outage_recovery_attempted = False

                    if not display_baseline_set:
                        previous_display_signature = signature
                        display_baseline_set = True
                        log(
                            "Display baseline: "
                            + format_display_signature(signature)
                        )
                    elif signature != previous_display_signature:
                        previous_display_signature = signature
                        display_changed_at = now
                        log(
                            "DISPLAY CHANGE detected: "
                            + format_display_signature(signature)
                        )

                # Restart only after the new display mode has remained stable.
                if (
                    DISPLAY_CHANGE_RESTART
                    and display_changed_at is not None
                    and signature
                    and now - display_changed_at >= DISPLAY_SETTLE_SECONDS
                    and now - last_display_restart >= DISPLAY_RESTART_COOLDOWN
                    and not in_grace
                ):
                    display_restart_reason = (
                        "display configuration changed and settled: "
                        + format_display_signature(signature)
                    )
                    display_changed_at = None

        # During initial launch grace, establish display baseline but don't
        # run service recovery checks yet.
        if in_grace:
            continue

        # ----------------------------------------------------
        # SUNSHINE LOCAL HEALTH
        # ----------------------------------------------------
        problems = []
        proc_alive = sunshine_running()

        if not proc_alive:
            problems.append("process not running")

        local_ok, state = serverinfo_ok(SERVERINFO_LOCAL)
        if not local_ok:
            problems.append("local serverinfo (47989) not answering")

        web_answered, web_status, _ = http_probe(WEBUI_LOCAL)
        if not web_answered:
            problems.append("local web UI (47990) not answering")

        # Tailscale probe is intentionally non-critical.
        if ts_ip:
            ts_ok, _ = serverinfo_ok(f"http://{ts_ip}:47989/serverinfo")
            if ts_ok != ts_was_ok:
                if ts_ok:
                    log(f"Tailscale endpoint recovered: {ts_ip}:47989")
                else:
                    log(
                        f"NETWORK WARNING: Sunshine is not reachable via "
                        f"Tailscale ({ts_ip}:47989); local service checks "
                        "will continue independently."
                    )
                ts_was_ok = ts_ok

        # Optional BUSY-state timeout.
        if STUCK_BUSY_MINUTES > 0 and local_ok and "BUSY" in state.upper():
            busy_since = busy_since or now
            if now - busy_since > STUCK_BUSY_MINUTES * 60:
                problems.append(
                    f"state BUSY for more than {STUCK_BUSY_MINUTES} min"
                )
        else:
            busy_since = None

        # Optional panel watchdog.
        if PANEL_WATCH:
            if panel_ok():
                if panel_fails:
                    log("panel health recovered.")
                panel_fails = 0
            else:
                panel_fails += 1
                log(f"panel unhealthy {panel_fails}/3")
                if panel_fails >= 3:
                    restart_panel("health check failed 3 times")
                    panel_fails = 0

        # ----------------------------------------------------
        # DISPLAY-CHANGE RECOVERY
        # ----------------------------------------------------
        if display_restart_reason:
            if not sunshine_running():
                log(
                    "Display changed, but Sunshine is already down; "
                    "the normal process recovery will handle it."
                )
            else:
                restarts = deque(
                    t for t in restarts if now - t < RESTART_WINDOW
                )
                if len(restarts) < MAX_RESTARTS:
                    restart_sunshine(display_restart_reason)
                    restarts.append(time.monotonic())
                    last_display_restart = time.monotonic()
                    core_fails = 0
                    down_since = None
                    busy_since = None
                    grace_until = time.monotonic() + START_GRACE
                    continue
                else:
                    log(
                        "Display changed, but restart limit is reached; "
                        "skipping display-triggered restart."
                    )

        # ----------------------------------------------------
        # CORE RECOVERY DECISION
        # ----------------------------------------------------
        if not problems:
            if down_since is not None:
                log(
                    f"Sunshine healthy again "
                    f"(was unhealthy for {now - down_since:.0f}s)."
                )
            core_fails = 0
            down_since = None
            continue

        core_fails += 1
        down_since = down_since or now
        log(f"unhealthy {core_fails}/{FAIL_LIMIT}: " + "; ".join(problems))

        # A dead process is an immediate recovery condition.
        need_restart = (not proc_alive) or core_fails >= FAIL_LIMIT
        if not need_restart:
            continue

        # Restart storm protection.
        restarts = deque(t for t in restarts if now - t < RESTART_WINDOW)
        if len(restarts) >= MAX_RESTARTS:
            log(
                f"restart limit reached ({MAX_RESTARTS} per "
                f"{RESTART_WINDOW}s) - pausing {LIMIT_PAUSE}s."
            )
            time.sleep(LIMIT_PAUSE)
            restarts.clear()
            grace_until = time.monotonic() + START_GRACE
            continue

        restart_sunshine("; ".join(problems))
        restarts.append(time.monotonic())
        core_fails = 0
        down_since = None
        busy_since = None
        grace_until = time.monotonic() + START_GRACE

    log("Watchdog stopped.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        log(f"FATAL: {type(exc).__name__}: {exc}")
        sys.exit(1)
