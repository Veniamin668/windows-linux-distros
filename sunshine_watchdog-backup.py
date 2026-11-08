#!/usr/bin/env python3
"""
sunshine_watchdog.py - фоновый сторож Sunshine на macOS раннере.

Что проверяет каждые CHECK_INTERVAL секунд:
  1. процесс Sunshine жив (pgrep)
  2. http://127.0.0.1:47989/serverinfo   - то, что опрашивает Moonlight
  3. https://127.0.0.1:47990/            - веб-интерфейс (любой HTTP-ответ = жив)
  4. http://<tailscale-ip>:47989/serverinfo - виден ли хост с Tailscale-адреса
  5. (опц.) панель stream.py: http://127.0.0.1:5902/health

Когда перезапускает Sunshine:
  * процесс умер                                   - сразу
  * любая из проверок 2-4 не проходит FAIL_LIMIT подряд (по умолчанию 6 x 10с = 60с)
  * (опц.) состояние BUSY держится дольше STUCK_BUSY_MINUTES (по умолчанию выключено)

Защита от "перезапуск-шторма": не больше MAX_RESTARTS за RESTART_WINDOW секунд,
после лимита - пауза LIMIT_PAUSE секунд.

Только стандартная библиотека. Запускать от root (sudo) - тогда launchctl asuser
работает без пароля. stream.py не трогает (кроме перезапуска при падении, если включено).
"""
import os
import re
import signal
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request


# ============================================================
# CONFIG (все через env, значения по умолчанию подходят для твоего воркфлоу)
# ============================================================

SUNSHINE_BIN = os.environ.get(
    "WD_SUNSHINE_BIN",
    "/Applications/Sunshine.app/Contents/MacOS/sunshine",
)
PROC_PATTERN = os.environ.get("WD_PROC_PATTERN", "Sunshine.app/Contents/MacOS/sunshine")
GUI_UID = os.environ.get("WD_GUI_UID", "501")
SUNSHINE_LOG = os.environ.get("WD_SUNSHINE_LOG", "/Users/runner/.config/sunshine/sunshine.log")

CHECK_INTERVAL = int(os.environ.get("WD_CHECK_INTERVAL", "10"))
PROBE_TIMEOUT = int(os.environ.get("WD_PROBE_TIMEOUT", "5"))
FAIL_LIMIT = int(os.environ.get("WD_FAIL_LIMIT", "6"))          # 6 x 10с = минута
START_GRACE = int(os.environ.get("WD_START_GRACE", "60"))        # ждать после старта/рестарта
RECOVERY_WAIT = int(os.environ.get("WD_RECOVERY_WAIT", "60"))

MAX_RESTARTS = int(os.environ.get("WD_MAX_RESTARTS", "5"))
RESTART_WINDOW = int(os.environ.get("WD_RESTART_WINDOW", "600"))
LIMIT_PAUSE = int(os.environ.get("WD_LIMIT_PAUSE", "120"))

STUCK_BUSY_MINUTES = int(os.environ.get("WD_STUCK_BUSY_MINUTES", "0"))   # 0 = выключено

# панель stream.py (опционально)
PANEL_WATCH = os.environ.get("WD_PANEL_WATCH", "0") == "1"
PANEL_CMD = os.environ.get("WD_PANEL_CMD", "")   # напр. "python3 ./stream.py"
PANEL_HEALTH = os.environ.get("WD_PANEL_HEALTH", "http://127.0.0.1:5902/health")

LOG_FILE = os.environ.get("WD_LOG_FILE", "/tmp/sunshine_watchdog.log")

SERVERINFO_LOCAL = "http://127.0.0.1:47989/serverinfo"
WEBUI_LOCAL = "https://127.0.0.1:47990/"

SSL_CTX = ssl._create_unverified_context()
RUNNING = True


# ============================================================
# LOGGING
# ============================================================

def log(message):
    line = f"[{time.strftime('%H:%M:%S')}] [watchdog] {message}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ============================================================
# PROBES
# ============================================================

def http_probe(url, timeout=PROBE_TIMEOUT):
    """-> (answered, status, body). answered=True даже при 401/403/302."""
    try:
        with urllib.request.urlopen(url, timeout=timeout, context=SSL_CTX) as r:
            return True, r.status, r.read(8192)
    except urllib.error.HTTPError as e:
        return True, e.code, b""
    except Exception:
        return False, 0, b""


def serverinfo_ok(url):
    answered, status, body = http_probe(url)
    ok = answered and status == 200 and b"<root" in body
    state = ""
    if ok:
        m = re.search(rb"<state>(.*?)</state>", body)
        state = m.group(1).decode("utf-8", "replace") if m else ""
    return ok, state


def sunshine_running():
    try:
        return subprocess.run(
            ["pgrep", "-f", PROC_PATTERN],
            capture_output=True,
            timeout=10,
        ).returncode == 0
    except Exception:
        return False


def tailscale_ip():
    try:
        out = subprocess.run(
            ["tailscale", "ip", "-4"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip().splitlines()
        return out[0] if out else None
    except Exception:
        return None


def panel_ok():
    answered, status, _ = http_probe(PANEL_HEALTH)
    return answered and status == 200


# ============================================================
# ACTIONS
# ============================================================

def sudo_prefix():
    return [] if os.geteuid() == 0 else ["sudo"]


def tail_sunshine_log(lines=15):
    try:
        if os.path.exists(SUNSHINE_LOG):
            with open(SUNSHINE_LOG, "r", encoding="utf-8", errors="replace") as f:
                tail = f.readlines()[-lines:]
            log("---- sunshine.log (tail) ----")
            for line in tail:
                print("    " + line.rstrip(), flush=True)
    except Exception as e:
        log(f"cannot read sunshine log: {e}")


def restart_sunshine(reason):
    log(f"RESTART Sunshine - reason: {reason}")
    tail_sunshine_log()

    subprocess.run(sudo_prefix() + ["pkill", "-9", "-f", PROC_PATTERN], capture_output=True)

    # дождаться освобождения процесса
    for _ in range(10):
        if not sunshine_running():
            break
        time.sleep(1)
    time.sleep(2)

    subprocess.Popen(
        sudo_prefix() + ["launchctl", "asuser", GUI_UID, SUNSHINE_BIN],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    log("Sunshine launched, waiting for Moonlight endpoint...")

    started = time.monotonic()
    while time.monotonic() - started < RECOVERY_WAIT:
        ok, _ = serverinfo_ok(SERVERINFO_LOCAL)
        if ok:
            log(f"Sunshine is back after {time.monotonic() - started:.0f}s.")
            return True
        time.sleep(3)

    log(f"Sunshine did not answer within {RECOVERY_WAIT}s after restart.")
    return False


def restart_panel(reason):
    if not PANEL_CMD:
        log(f"panel down ({reason}) but WD_PANEL_CMD is not set - skipping.")
        return

    log(f"RESTART panel - reason: {reason}")
    subprocess.run(sudo_prefix() + ["pkill", "-9", "-f", "stream.py"], capture_output=True)
    time.sleep(2)
    subprocess.Popen(
        sudo_prefix() + ["launchctl", "asuser", GUI_UID, "/usr/bin/env"] + PANEL_CMD.split(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


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

    log("=" * 56)
    log("Sunshine watchdog started")
    log(f"interval={CHECK_INTERVAL}s timeout={PROBE_TIMEOUT}s fail_limit={FAIL_LIMIT} "
        f"grace={START_GRACE}s stuck_busy={STUCK_BUSY_MINUTES}min panel_watch={PANEL_WATCH}")
    log("=" * 56)

    restarts = []                # времена перезапусков
    fails = 0
    down_since = None
    busy_since = None
    panel_fails = 0
    ts_ip = None
    ts_checked = 0.0
    grace_until = time.monotonic() + START_GRACE

    while RUNNING:
        time.sleep(CHECK_INTERVAL)
        now = time.monotonic()

        if now < grace_until:
            continue

        # Tailscale IP обновляем раз в минуту
        if now - ts_checked > 60:
            ts_ip = tailscale_ip()
            ts_checked = now

        problems = []
        proc_alive = sunshine_running()

        if not proc_alive:
            problems.append("process not running")

        local_ok, state = serverinfo_ok(SERVERINFO_LOCAL)
        if not local_ok:
            problems.append("serverinfo (47989) not answering")

        answered, _, _ = http_probe(WEBUI_LOCAL)
        if not answered:
            problems.append("web UI (47990) not answering")

        if ts_ip:
            ts_ok, _ = serverinfo_ok(f"http://{ts_ip}:47989/serverinfo")
            if not ts_ok:
                problems.append(f"serverinfo via Tailscale {ts_ip} not answering")

        # --- опционально: "залипшее" BUSY-состояние ---
        if STUCK_BUSY_MINUTES > 0 and local_ok and "BUSY" in state.upper():
            busy_since = busy_since or now
            if now - busy_since > STUCK_BUSY_MINUTES * 60:
                problems.append(f"state BUSY for more than {STUCK_BUSY_MINUTES} min")
        else:
            busy_since = None

        # --- панель stream.py (опционально) ---
        if PANEL_WATCH:
            if panel_ok():
                panel_fails = 0
            else:
                panel_fails += 1
                if panel_fails >= 3:
                    restart_panel("health check failed 3 times")
                    panel_fails = 0
                    grace_until = max(grace_until, time.monotonic() + 30)

        # --- решение ---
        if not problems:
            if down_since is not None:
                log(f"healthy again (was unhealthy for {now - down_since:.0f}s).")
            fails = 0
            down_since = None
            continue

        fails += 1
        down_since = down_since or now
        log(f"unhealthy {fails}/{FAIL_LIMIT}: " + "; ".join(problems))

        need_restart = (not proc_alive) or fails >= FAIL_LIMIT
        if not need_restart:
            continue

        # лимит перезапусков
        restarts = [t for t in restarts if now - t < RESTART_WINDOW]
        if len(restarts) >= MAX_RESTARTS:
            log(f"restart limit reached ({MAX_RESTARTS} per {RESTART_WINDOW}s) - pausing {LIMIT_PAUSE}s.")
            time.sleep(LIMIT_PAUSE)
            restarts.clear()
            continue

        restart_sunshine("; ".join(problems))
        restarts.append(time.monotonic())
        fails = 0
        down_since = None
        busy_since = None
        grace_until = time.monotonic() + 15

    log("Watchdog stopped.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        log(f"FATAL: {type(exc).__name__}: {exc}")
        sys.exit(1)
