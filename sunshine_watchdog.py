#!/usr/bin/env python3
"""
Sunshine + macOS Display Watchdog

Мониторинг:
  - Sunshine process
  - Sunshine API :47989
  - Sunshine Web UI :47990
  - Tailscale endpoint
  - Moonlight client endpoints через Tailscale
  - macOS active displays через CoreGraphics
  - Display resolution / topology changes
  - Optional stream.py panel

Recovery:
  - Sunshine crash recovery
  - Sunshine API recovery
  - Moonlight client-path recovery
  - Display change recovery
  - Optional display recovery command
  - Restart storm protection

Python standard library only.
"""

import ctypes
import ctypes.util
import os
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import ssl
from collections import deque


# ============================================================
# CONFIGURATION
# ============================================================

SUNSHINE_BIN = os.environ.get(
    "WD_SUNSHINE_BIN",
    "/Applications/Sunshine.app/Contents/MacOS/sunshine"
)

PROC_PATTERN = os.environ.get(
    "WD_PROC_PATTERN",
    "Sunshine.app/Contents/MacOS/sunshine"
)

GUI_UID = os.environ.get("WD_GUI_UID", "501")

SUNSHINE_LOG = os.environ.get(
    "WD_SUNSHINE_LOG",
    "/Users/runner/.config/sunshine/sunshine.log"
)

CHECK_INTERVAL = max(
    2, int(os.environ.get("WD_CHECK_INTERVAL", "10"))
)

PROBE_TIMEOUT = max(
    1, int(os.environ.get("WD_PROBE_TIMEOUT", "5"))
)

FAIL_LIMIT = max(
    1, int(os.environ.get("WD_FAIL_LIMIT", "6"))
)

START_GRACE = max(
    0, int(os.environ.get("WD_START_GRACE", "60"))
)

RECOVERY_WAIT = max(
    5, int(os.environ.get("WD_RECOVERY_WAIT", "60"))
)

MAX_RESTARTS = max(
    1, int(os.environ.get("WD_MAX_RESTARTS", "5"))
)

RESTART_WINDOW = max(
    60, int(os.environ.get("WD_RESTART_WINDOW", "600"))
)

LIMIT_PAUSE = max(
    10, int(os.environ.get("WD_LIMIT_PAUSE", "120"))
)

STUCK_BUSY_MINUTES = max(
    0, int(os.environ.get("WD_STUCK_BUSY_MINUTES", "0"))
)


# ============================================================
# DISPLAY WATCHDOG CONFIGURATION
# ============================================================

DISPLAY_WATCH = (
    os.environ.get("WD_DISPLAY_WATCH", "1") == "1"
)

DISPLAY_CHANGE_RESTART = (
    os.environ.get("WD_DISPLAY_CHANGE_RESTART", "1") == "1"
)

DISPLAY_SETTLE_SECONDS = max(
    5, int(os.environ.get("WD_DISPLAY_SETTLE_SECONDS", "20"))
)

DISPLAY_NO_DISPLAY_LIMIT = max(
    1, int(os.environ.get("WD_DISPLAY_NO_DISPLAY_LIMIT", "3"))
)

DISPLAY_RESTART_COOLDOWN = max(
    30, int(os.environ.get("WD_DISPLAY_RESTART_COOLDOWN", "90"))
)

DISPLAY_RECOVERY_CMD = os.environ.get(
    "WD_DISPLAY_RECOVERY_CMD", ""
).strip()

DISPLAY_RECOVERY_COOLDOWN = max(
    60, int(os.environ.get("WD_DISPLAY_RECOVERY_COOLDOWN", "300"))
)


# ============================================================
# PANEL CONFIGURATION
# ============================================================

PANEL_WATCH = (
    os.environ.get("WD_PANEL_WATCH", "0") == "1"
)

PANEL_CMD = os.environ.get("WD_PANEL_CMD", "")

PANEL_HEALTH = os.environ.get(
    "WD_PANEL_HEALTH",
    "http://127.0.0.1:5902/health"
)


# ============================================================
# MOONLIGHT CLIENT-PATH WATCHDOG
# ============================================================

# Проверяем TCP endpoints Sunshine, которыми пользуется Moonlight.
# Проверка идёт по Tailscale IP, а не только через localhost.

CLIENT_WATCH = (
    os.environ.get("WD_CLIENT_WATCH", "1") == "1"
)

CLIENT_CHECK_INTERVAL = max(
    10, int(os.environ.get("WD_CLIENT_CHECK_INTERVAL", "30"))
)

CLIENT_PROBE_TIMEOUT = max(
    1, int(os.environ.get("WD_CLIENT_PROBE_TIMEOUT", "3"))
)

CLIENT_FAIL_LIMIT = max(
    1, int(os.environ.get("WD_CLIENT_FAIL_LIMIT", "2"))
)

CLIENT_PORTS = tuple(
    int(port.strip())
    for port in os.environ.get(
        "WD_CLIENT_PORTS",
        "47984,47989,48010"
    ).split(",")
    if port.strip()
)


# ============================================================
# GENERAL
# ============================================================

LOG_FILE = os.environ.get(
    "WD_LOG_FILE",
    "/tmp/sunshine_watchdog.log"
)

SERVERINFO_LOCAL = "http://127.0.0.1:47989/serverinfo"

WEBUI_LOCAL = "https://127.0.0.1:47990/"

SSL_CTX = ssl._create_unverified_context()

RUNNING = True


# ============================================================
# LOGGING
# ============================================================

def log(message):
    line = (
        f"[{time.strftime('%H:%M:%S')}] "
        f"[watchdog] {message}"
    )

    print(line, flush=True)

    try:
        directory = os.path.dirname(LOG_FILE)

        if directory:
            os.makedirs(directory, exist_ok=True)

        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    except Exception:
        pass


# ============================================================
# HTTP PROBES
# ============================================================

def http_probe(url, timeout=PROBE_TIMEOUT):
    """
    Returns:
        (answered, status, body)

    HTTP errors such as 401/403/302 still count as
    an answering HTTP server.
    """

    try:
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Sunshine-Watchdog/2.0"
            }
        )

        with urllib.request.urlopen(
            request,
            timeout=timeout,
            context=SSL_CTX
        ) as response:

            return (
                True,
                response.status,
                response.read(16384)
            )

    except urllib.error.HTTPError as exc:
        return True, exc.code, b""

    except Exception:
        return False, 0, b""


def serverinfo_ok(url):
    answered, status, body = http_probe(url)

    ok = (
        answered
        and status == 200
        and b"<root" in body
    )

    state = ""

    if ok:
        match = re.search(
            rb"<state>(.*?)</state>",
            body,
            re.IGNORECASE
        )

        if match:
            state = match.group(1).decode(
                "utf-8", "replace"
            )

    return ok, state


# ============================================================
# SUNSHINE PROCESS
# ============================================================

def sunshine_running():
    try:
        result = subprocess.run(
            ["pgrep", "-f", PROC_PATTERN],
            capture_output=True,
            timeout=10
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
            timeout=10
        )

        lines = result.stdout.strip().splitlines()

        return lines[0] if lines else None

    except Exception:
        return None


def moonlight_client_path_ok(host):
    """
    Проверяет TCP endpoints Sunshine по Tailscale IP.

    47984 - Sunshine HTTPS control endpoint
    47989 - Sunshine serverinfo endpoint
    48010 - Sunshine RTSP endpoint

    Это проверка доступности сетевых точек подключения Moonlight,
    а не запуск полноценной игровой/desktop streaming-сессии.
    """

    if not host:
        return False, ["Tailscale IP unavailable"]

    failed = []

    for port in CLIENT_PORTS:
        try:
            with socket.create_connection(
                (host, port),
                timeout=CLIENT_PROBE_TIMEOUT
            ):
                pass

        except Exception as exc:
            failed.append(
                f"{port} ({type(exc).__name__}: {exc})"
            )

    return len(failed) == 0, failed


# ============================================================
# MACOS DISPLAY MONITOR
# ============================================================

class DisplayMonitor:

    class CGRect(ctypes.Structure):
        _fields_ = [
            ("origin_x", ctypes.c_double),
            ("origin_y", ctypes.c_double),
            ("size_width", ctypes.c_double),
            ("size_height", ctypes.c_double)
        ]

    def __init__(self):

        self.cg = None
        self.error = None

        try:

            path = ctypes.util.find_library(
                "CoreGraphics"
            )

            if not path:
                path = (
                    "/System/Library/Frameworks/"
                    "CoreGraphics.framework/CoreGraphics"
                )

            self.cg = ctypes.CDLL(path)

            self.cg.CGGetActiveDisplayList.argtypes = [
                ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_uint32),
                ctypes.POINTER(ctypes.c_uint32)
            ]

            self.cg.CGGetActiveDisplayList.restype = (
                ctypes.c_int32
            )

            self.cg.CGDisplayIsOnline.argtypes = [
                ctypes.c_uint32
            ]

            self.cg.CGDisplayIsOnline.restype = (
                ctypes.c_bool
            )

            self.cg.CGDisplayIsActive.argtypes = [
                ctypes.c_uint32
            ]

            self.cg.CGDisplayIsActive.restype = (
                ctypes.c_bool
            )

            self.cg.CGDisplayPixelsWide.argtypes = [
                ctypes.c_uint32
            ]

            self.cg.CGDisplayPixelsWide.restype = (
                ctypes.c_size_t
            )

            self.cg.CGDisplayPixelsHigh.argtypes = [
                ctypes.c_uint32
            ]

            self.cg.CGDisplayPixelsHigh.restype = (
                ctypes.c_size_t
            )

            self.cg.CGDisplayBounds.argtypes = [
                ctypes.c_uint32
            ]

            self.cg.CGDisplayBounds.restype = (
                self.CGRect
            )

        except Exception as exc:

            self.cg = None

            self.error = (
                f"{type(exc).__name__}: {exc}"
            )

    def snapshot(self):

        if self.cg is None:
            return None, (
                self.error or "CoreGraphics unavailable"
            )

        count = ctypes.c_uint32(0)

        result = self.cg.CGGetActiveDisplayList(
            0,
            None,
            ctypes.byref(count)
        )

        if result != 0:
            return None, (
                f"CGGetActiveDisplayList returned {result}"
            )

        if count.value == 0:
            return tuple(), None

        display_ids = (
            ctypes.c_uint32 * count.value
        )()

        actual = ctypes.c_uint32(0)

        result = self.cg.CGGetActiveDisplayList(
            count.value,
            display_ids,
            ctypes.byref(actual)
        )

        if result != 0:
            return None, (
                f"CGGetActiveDisplayList returned {result}"
            )

        displays = []

        for index in range(actual.value):

            display_id = int(display_ids[index])

            try:

                online = bool(
                    self.cg.CGDisplayIsOnline(display_id)
                )

                active = bool(
                    self.cg.CGDisplayIsActive(display_id)
                )

                width = int(
                    self.cg.CGDisplayPixelsWide(display_id)
                )

                height = int(
                    self.cg.CGDisplayPixelsHigh(display_id)
                )

                bounds = self.cg.CGDisplayBounds(
                    display_id
                )

                if online and active:

                    displays.append((
                        display_id,
                        width,
                        height,
                        round(bounds.origin_x),
                        round(bounds.origin_y),
                        round(bounds.size_width),
                        round(bounds.size_height)
                    ))

            except Exception as exc:

                return None, (
                    f"display {display_id}: "
                    f"{type(exc).__name__}: {exc}"
                )

        return tuple(sorted(displays)), None


def format_display_signature(signature):

    if signature is None:
        return "unavailable"

    if not signature:
        return "no active displays"

    return ", ".join(
        (
            f"id={display[0]} "
            f"{display[1]}x{display[2]} "
            f"at ({display[3]},{display[4]})"
        )
        for display in signature
    )


# ============================================================
# PANEL HEALTH
# ============================================================

def panel_ok():

    answered, status, _ = http_probe(
        PANEL_HEALTH
    )

    return answered and status == 200


# ============================================================
# ACTIONS
# ============================================================

def sudo_prefix():

    return (
        []
        if os.geteuid() == 0
        else ["sudo"]
    )


def tail_sunshine_log(lines=25):

    try:

        if os.path.exists(SUNSHINE_LOG):

            with open(
                SUNSHINE_LOG,
                "r",
                encoding="utf-8",
                errors="replace"
            ) as f:

                tail = f.readlines()[-lines:]

            log("---- sunshine.log (tail) ----")

            for line in tail:
                print(
                    "    " + line.rstrip(),
                    flush=True
                )

    except Exception as exc:

        log(
            f"cannot read Sunshine log: {exc}"
        )


# ============================================================
# SUNSHINE RECOVERY
# ============================================================

def restart_sunshine(reason):

    log(
        f"RESTART Sunshine - reason: {reason}"
    )

    tail_sunshine_log()

    try:

        subprocess.run(
            sudo_prefix() + [
                "pkill",
                "-9",
                "-f",
                PROC_PATTERN
            ],
            capture_output=True,
            timeout=15
        )

    except Exception as exc:

        log(f"warning: pkill failed: {exc}")

    for _ in range(15):

        if not sunshine_running():
            break

        time.sleep(1)

    time.sleep(2)

    try:

        subprocess.Popen(
            sudo_prefix() + [
                "launchctl",
                "asuser",
                GUI_UID,
                SUNSHINE_BIN
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )

    except Exception as exc:

        log(
            f"ERROR launching Sunshine: "
            f"{type(exc).__name__}: {exc}"
        )

        return False

    log(
        "Sunshine launched; waiting for local API..."
    )

    started = time.monotonic()

    while (
        time.monotonic() - started
        < RECOVERY_WAIT
    ):

        if sunshine_running():

            ok, _ = serverinfo_ok(
                SERVERINFO_LOCAL
            )

            if ok:

                elapsed = (
                    time.monotonic() - started
                )

                log(
                    f"Sunshine process and API "
                    f"recovered after {elapsed:.0f}s."
                )

                return True

        time.sleep(3)

    log(
        f"Sunshine did not recover within "
        f"{RECOVERY_WAIT}s."
    )

    tail_sunshine_log()

    return False


# ============================================================
# PANEL RECOVERY
# ============================================================

def restart_panel(reason):

    if not PANEL_CMD:

        log(
            f"panel down ({reason}) but "
            "WD_PANEL_CMD is not set - skipping."
        )

        return False

    log(f"RESTART panel - reason: {reason}")

    try:

        subprocess.run(
            sudo_prefix() + [
                "pkill",
                "-9",
                "-f",
                "stream.py"
            ],
            capture_output=True,
            timeout=15
        )

        time.sleep(2)

        subprocess.Popen(
            sudo_prefix() + [
                "launchctl",
                "asuser",
                GUI_UID,
                "/usr/bin/env"
            ] + PANEL_CMD.split(),

            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )

        return True

    except Exception as exc:

        log(
            f"ERROR restarting panel: "
            f"{type(exc).__name__}: {exc}"
        )

        return False


# ============================================================
# DISPLAY RECOVERY COMMAND
# ============================================================

def recover_display():

    if not DISPLAY_RECOVERY_CMD:
        return False

    log(
        "DISPLAY RECOVERY: running "
        "WD_DISPLAY_RECOVERY_CMD"
    )

    try:

        result = subprocess.run(
            DISPLAY_RECOVERY_CMD,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )

        log(
            f"display recovery command "
            f"exit={result.returncode}"
        )

        if result.stdout.strip():

            log(
                "display recovery stdout: "
                + result.stdout.strip()[-1500:]
            )

        if result.stderr.strip():

            log(
                "display recovery stderr: "
                + result.stderr.strip()[-1500:]
            )

        return result.returncode == 0

    except Exception as exc:

        log(
            f"display recovery command failed: "
            f"{type(exc).__name__}: {exc}"
        )

        return False


# ============================================================
# SIGNAL HANDLING
# ============================================================

def stop(signum, frame):

    global RUNNING

    RUNNING = False

    log("Stop signal received.")


# ============================================================
# MAIN LOOP
# ============================================================

def main():

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    log("=" * 64)

    log(
        "Sunshine + macOS Display watchdog started"
    )

    log(
        f"interval={CHECK_INTERVAL}s "
        f"timeout={PROBE_TIMEOUT}s "
        f"fail_limit={FAIL_LIMIT} "
        f"grace={START_GRACE}s "
        f"display_watch={DISPLAY_WATCH} "
        f"display_change_restart={DISPLAY_CHANGE_RESTART} "
        f"display_settle={DISPLAY_SETTLE_SECONDS}s "
        f"display_recovery_cmd="
        f"{'set' if DISPLAY_RECOVERY_CMD else 'off'} "
        f"panel_watch={PANEL_WATCH} "
        f"client_watch={CLIENT_WATCH} "
        f"client_interval={CLIENT_CHECK_INTERVAL}s "
        f"client_fail_limit={CLIENT_FAIL_LIMIT} "
        f"client_ports={','.join(str(p) for p in CLIENT_PORTS)}"
    )

    log("=" * 64)

    display_monitor = (
        DisplayMonitor()
        if DISPLAY_WATCH
        else None
    )

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

    client_checked_at = 0.0
    client_fails = 0
    client_path_was_ok = None
    client_restart_trigger = False

    grace_until = (
        time.monotonic() + START_GRACE
    )

    while RUNNING:

        time.sleep(CHECK_INTERVAL)

        if not RUNNING:
            break

        now = time.monotonic()

        in_grace = now < grace_until

        # ----------------------------------------------------
        # TAILSCALE
        # ----------------------------------------------------

        if now - ts_checked >= 60:

            ts_ip = tailscale_ip()

            ts_checked = now

        # ----------------------------------------------------
        # DISPLAY MONITOR
        # ----------------------------------------------------

        display_restart_reason = None

        if display_monitor is not None:

            signature, display_error = (
                display_monitor.snapshot()
            )

            if signature is None:

                if not display_unavailable_logged:

                    log(
                        f"display monitor unavailable: "
                        f"{display_error}"
                    )

                    display_unavailable_logged = True

            else:

                display_unavailable_logged = False

                if len(signature) == 0:

                    display_no_active_count += 1

                    if display_no_active_count == 1:

                        display_outage_recovery_attempted = False

                        log(
                            "DISPLAY WARNING: no active "
                            "macOS displays detected."
                        )

                    elif (
                        display_no_active_count
                        == DISPLAY_NO_DISPLAY_LIMIT
                    ):

                        log(
                            "DISPLAY ERROR: no active display "
                            f"for {display_no_active_count} checks."
                        )

                    if (
                        display_no_active_count
                        >= DISPLAY_NO_DISPLAY_LIMIT
                        and DISPLAY_RECOVERY_CMD
                        and not display_outage_recovery_attempted
                        and (
                            now - last_display_recovery_command
                            >= DISPLAY_RECOVERY_COOLDOWN
                        )
                    ):

                        display_outage_recovery_attempted = True

                        last_display_recovery_command = now

                        recover_display()

                else:

                    if display_no_active_count:

                        log(
                            "DISPLAY recovered: active "
                            "display(s) detected after "
                            f"{display_no_active_count} "
                            "failed check(s)."
                        )

                        display_changed_at = now

                    display_no_active_count = 0

                    display_outage_recovery_attempted = False

                    if not display_baseline_set:

                        previous_display_signature = signature

                        display_baseline_set = True

                        log(
                            "Display baseline: "
                            + format_display_signature(
                                signature
                            )
                        )

                    elif (
                        signature
                        != previous_display_signature
                    ):

                        previous_display_signature = signature

                        display_changed_at = now

                        log(
                            "DISPLAY CHANGE detected: "
                            + format_display_signature(
                                signature
                            )
                        )

                if (
                    DISPLAY_CHANGE_RESTART
                    and display_changed_at is not None
                    and signature
                    and (
                        now - display_changed_at
                        >= DISPLAY_SETTLE_SECONDS
                    )
                    and (
                        now - last_display_restart
                        >= DISPLAY_RESTART_COOLDOWN
                    )
                    and not in_grace
                ):

                    display_restart_reason = (
                        "display configuration changed "
                        "and settled: "
                        + format_display_signature(
                            signature
                        )
                    )

                    display_changed_at = None

        # ----------------------------------------------------
        # STARTUP GRACE
        # ----------------------------------------------------

        if in_grace:
            continue

        # ----------------------------------------------------
        # SUNSHINE HEALTH
        # ----------------------------------------------------

        problems = []

        proc_alive = sunshine_running()

        if not proc_alive:

            problems.append(
                "process not running"
            )

        local_ok, state = serverinfo_ok(
            SERVERINFO_LOCAL
        )

        if not local_ok:

            problems.append(
                "local serverinfo (47989) not answering"
            )

        web_answered, web_status, _ = http_probe(
            WEBUI_LOCAL
        )

        if not web_answered:

            problems.append(
                "local web UI (47990) not answering"
            )

        # ----------------------------------------------------
        # TAILSCALE DIAGNOSTIC ONLY
        # ----------------------------------------------------

        if ts_ip:

            ts_ok, _ = serverinfo_ok(
                f"http://{ts_ip}:47989/serverinfo"
            )

            if ts_ok != ts_was_ok:

                if ts_ok:

                    log(
                        f"Tailscale endpoint recovered: "
                        f"{ts_ip}:47989"
                    )

                else:

                    log(
                        "NETWORK WARNING: Sunshine is not "
                        f"reachable via Tailscale ({ts_ip}:47989). "
                        "Local service checks continue independently."
                    )

                ts_was_ok = ts_ok

        # ----------------------------------------------------
        # MOONLIGHT CLIENT-PATH CHECK
        # ----------------------------------------------------

        client_restart_trigger = False

        if (
            CLIENT_WATCH
            and ts_ip
            and now - client_checked_at >= CLIENT_CHECK_INTERVAL
        ):

            client_checked_at = now

            client_ok, client_failed_ports = (
                moonlight_client_path_ok(ts_ip)
            )

            if client_ok:

                if client_fails:
                    log(
                        "Moonlight client path recovered "
                        f"after {client_fails} failed check(s)."
                    )

                elif client_path_was_ok is not True:
                    log(
                        "Moonlight client path OK via "
                        f"Tailscale ({ts_ip}); "
                        f"TCP ports: {','.join(str(p) for p in CLIENT_PORTS)}"
                    )

                client_fails = 0
                client_path_was_ok = True

            else:

                client_fails += 1
                client_path_was_ok = False

                log(
                    f"MOONLIGHT CLIENT PATH UNHEALTHY "
                    f"{client_fails}/{CLIENT_FAIL_LIMIT} "
                    f"via {ts_ip}: "
                    + ", ".join(client_failed_ports)
                )

                if client_fails >= CLIENT_FAIL_LIMIT:
                    client_restart_trigger = True

        if client_restart_trigger:
            problems.append(
                "Moonlight client endpoints unavailable "
                f"({client_fails}/{CLIENT_FAIL_LIMIT})"
            )

        # ----------------------------------------------------
        # BUSY STATE
        # ----------------------------------------------------

        if (
            STUCK_BUSY_MINUTES > 0
            and local_ok
            and "BUSY" in state.upper()
        ):

            busy_since = busy_since or now

            if (
                now - busy_since
                > STUCK_BUSY_MINUTES * 60
            ):

                problems.append(
                    f"state BUSY for more than "
                    f"{STUCK_BUSY_MINUTES} min"
                )

        else:

            busy_since = None

        # ----------------------------------------------------
        # OPTIONAL PANEL
        # ----------------------------------------------------

        if PANEL_WATCH:

            if panel_ok():

                if panel_fails:

                    log("panel health recovered.")

                panel_fails = 0

            else:

                panel_fails += 1

                log(
                    f"panel unhealthy {panel_fails}/3"
                )

                if panel_fails >= 3:

                    restart_panel(
                        "health check failed 3 times"
                    )

                    panel_fails = 0

        # ----------------------------------------------------
        # DISPLAY CHANGE RECOVERY
        # ----------------------------------------------------

        if display_restart_reason:

            if not sunshine_running():

                log(
                    "Display changed, but Sunshine is "
                    "already down; normal recovery will "
                    "handle it."
                )

            else:

                restarts = deque(
                    t for t in restarts
                    if now - t < RESTART_WINDOW
                )

                if len(restarts) < MAX_RESTARTS:

                    restart_sunshine(
                        display_restart_reason
                    )

                    restarts.append(
                        time.monotonic()
                    )

                    last_display_restart = (
                        time.monotonic()
                    )

                    core_fails = 0

                    client_fails = 0
                    client_path_was_ok = None
                    client_checked_at = time.monotonic()

                    down_since = None

                    busy_since = None

                    grace_until = (
                        time.monotonic() + START_GRACE
                    )

                    continue

                else:

                    log(
                        "Display changed, but restart "
                        "limit is reached; skipping "
                        "display-triggered restart."
                    )

        # ----------------------------------------------------
        # NORMAL HEALTHY STATE
        # ----------------------------------------------------

        if not problems:

            if down_since is not None:

                log(
                    "Sunshine healthy again "
                    f"(was unhealthy for "
                    f"{now - down_since:.0f}s)."
                )

            core_fails = 0

            down_since = None

            continue

        # ----------------------------------------------------
        # UNHEALTHY STATE
        # ----------------------------------------------------

        core_fails += 1

        down_since = down_since or now

        log(
            f"unhealthy {core_fails}/{FAIL_LIMIT}: "
            + "; ".join(problems)
        )

        need_restart = (
            not proc_alive
            or core_fails >= FAIL_LIMIT
            or client_restart_trigger
        )

        if not need_restart:
            continue

        # ----------------------------------------------------
        # RESTART STORM PROTECTION
        # ----------------------------------------------------

        restarts = deque(
            t for t in restarts
            if now - t < RESTART_WINDOW
        )

        if len(restarts) >= MAX_RESTARTS:

            log(
                f"restart limit reached "
                f"({MAX_RESTARTS} per "
                f"{RESTART_WINDOW}s) - "
                f"pausing {LIMIT_PAUSE}s."
            )

            time.sleep(LIMIT_PAUSE)

            restarts.clear()

            grace_until = (
                time.monotonic() + START_GRACE
            )

            continue

        # ----------------------------------------------------
        # RESTART SUNSHINE
        # ----------------------------------------------------

        restart_sunshine(
            "; ".join(problems)
        )

        restarts.append(
            time.monotonic()
        )

        core_fails = 0

        client_fails = 0
        client_path_was_ok = None
        client_checked_at = time.monotonic()

        down_since = None

        busy_since = None

        grace_until = (
            time.monotonic() + START_GRACE
        )

    log("Watchdog stopped.")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except Exception as exc:

        log(
            f"FATAL: {type(exc).__name__}: {exc}"
        )

        sys.exit(1)
