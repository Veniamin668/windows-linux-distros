
import http.server
import json
import os
import re
import ssl
import socketserver
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar
import base64
import hmac
import time
import threading
from html.parser import HTMLParser


# ============================================================
# CONFIGURATION
# ============================================================

HOST = os.environ.get("PAIR_HOST", "0.0.0.0")
PORT = int(os.environ.get("PAIR_PORT", "5902"))

SUNSHINE_API = os.environ.get(
    "SUNSHINE_API", "https://127.0.0.1:47990"
).rstrip("/")

SUNSHINE_USER = os.environ.get("SUNSHINE_USER", "")
SUNSHINE_PASSWORD = os.environ.get("SUNSHINE_PASSWORD", "")
WEB_TOKEN = os.environ.get("PAIR_WEB_TOKEN", "")

SSL_CONTEXT = ssl._create_unverified_context()

POLL_INTERVAL = 3
REQUEST_TIMEOUT = 20
PAIR_LOCK = threading.Lock()


# ============================================================
# WEB PAGE
# ============================================================

PAGE = r"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Moonlight Pairing</title>
<style>
*{box-sizing:border-box}
body{
  margin:0;min-height:100vh;display:grid;place-items:center;
  background:#101218;color:#f1f3f8;
  font-family:system-ui,-apple-system,Segoe UI,sans-serif
}
main{
  width:min(430px,calc(100% - 30px));padding:28px;
  border:1px solid #303541;border-radius:18px;background:#191d26;
  box-shadow:0 18px 60px #0005
}
h1{font-size:25px;margin:0 0 8px}
p{color:#aeb6c5;font-size:14px;line-height:1.5}
label{display:block;margin:18px 0 7px;font-size:14px}
input{
  width:100%;padding:13px;border:1px solid #3b4250;
  border-radius:9px;background:#10141c;color:white;font-size:16px
}
button{
  width:100%;margin-top:22px;padding:14px;border:0;border-radius:9px;
  background:#3478f6;color:white;font-size:16px;font-weight:700;
  cursor:pointer
}
button:disabled{opacity:.6;cursor:wait}
#status{margin-top:16px;white-space:pre-wrap;overflow-wrap:anywhere}
</style>
</head>
<body>
<main>
<h1>Moonlight Pairing</h1>
<p>Введи PIN, показанный в Moonlight, и имя устройства.</p>
<form id="pairForm">
<label for="pin">PIN</label>
<input id="pin" name="pin" inputmode="numeric"
       pattern="[0-9]{4}" maxlength="4" placeholder="1234" required>
<label for="name">Имя устройства</label>
<input id="name" name="name" maxlength="100"
       value="Moonlight Client" required>
<button id="submit" type="submit">Подтвердить сопряжение</button>
</form>
<div id="status" role="status"></div>
</main>
<script>
const form = document.getElementById('pairForm');
const button = document.getElementById('submit');
const statusBox = document.getElementById('status');

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  button.disabled = true;
  statusBox.textContent = 'Отправка запроса...';

  try {
    const response = await fetch('/api/pair', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Panel-Token': '__PANEL_TOKEN__'
      },
      body: JSON.stringify({
        pin: document.getElementById('pin').value.trim(),
        name: document.getElementById('name').value.trim()
      })
    });

    const result = await response.json();
    statusBox.textContent = result.message ||
      (result.ok ? 'Запрос обработан.' : 'Не удалось выполнить pairing.');

    if (result.ok) {
      document.getElementById('pin').value = '';
    }
  } catch (error) {
    statusBox.textContent = 'Ошибка соединения: ' + error.message;
  } finally {
    button.disabled = false;
  }
});
</script>
</body>
</html>
"""


# ============================================================
# SUNSHINE CLIENT
# ============================================================

class SunshineClient:
    def __init__(self):
        self.cookies = http.cookiejar.CookieJar()

        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies),
            urllib.request.HTTPSHandler(context=SSL_CONTEXT),
        )

        self.auth_header = self.make_auth_header()

    @staticmethod
    def make_auth_header():
        credentials = f"{SUNSHINE_USER}:{SUNSHINE_PASSWORD}"
        encoded = base64.b64encode(
            credentials.encode("utf-8")
        ).decode("ascii")
        return "Basic " + encoded

    def request(self, path, method="GET", data=None,
                auth=True, timeout=REQUEST_TIMEOUT):
        url = SUNSHINE_API + path

        headers = {
            "Accept": "application/json, text/html, */*",
            "User-Agent": "SunshinePairingHelper/1.0",
        }

        if auth:
            headers["Authorization"] = self.auth_header

        body = None

        if data is not None:
            body = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(
            url,
            data=body,
            headers=headers,
            method=method,
        )

        try:
            with self.opener.open(request, timeout=timeout) as response:
                content = response.read().decode(
                    "utf-8", errors="replace"
                )

                return (
                    response.status,
                    response.geturl(),
                    content,
                )

        except urllib.error.HTTPError as error:
            content = error.read().decode(
                "utf-8", errors="replace"
            )
            location = error.headers.get("Location", "")

            print(
                f"[Sunshine] HTTP {error.code}; "
                f"URL={url}; "
                f"Location={location or '(none)'}; "
                f"response={content[:500]!r}",
                flush=True,
            )

            return (
                error.code,
                location or url,
                content,
            )

        except Exception as error:
            print(
                f"[Sunshine] Request failed: {error}",
                flush=True,
            )
            return 0, url, str(error)

    @staticmethod
    def parse_json(content):
        try:
            result = json.loads(content)
            return result if isinstance(result, dict) else {}
        except (json.JSONDecodeError, TypeError):
            return {}

    # --------------------------------------------------------
    # Initial setup and authentication
    # --------------------------------------------------------

    def check_auth(self):
        status, url, content = self.request(
            "/api/apps",
            method="GET",
            auth=True,
        )

        if status != 200:
            print(
                f"[Sunshine] Auth check failed: HTTP {status}; "
                f"URL={url}",
                flush=True,
            )
            return False

        result = self.parse_json(content)

        if result.get("status") is False:
            return False

        print("[Sunshine] Admin authentication successful.", flush=True)
        return True

    def ensure_setup(self):
        if not SUNSHINE_USER or not SUNSHINE_PASSWORD:
            print(
                "[Sunshine] SUNSHINE_USER or SUNSHINE_PASSWORD "
                "is missing.",
                flush=True,
            )
            return False

        # Existing Sunshine instance: just authenticate.
        if self.check_auth():
            return True

        # Detect first-run Welcome page.
        status, url, content = self.request(
            "/welcome",
            method="GET",
            auth=False,
        )

        if status == 200 and "/welcome" in url.lower():
            print(
                "[Sunshine] Fresh instance detected. "
                "Creating the initial administrator...",
                flush=True,
            )

            setup_status, setup_url, setup_content = self.request(
                "/api/password",
                method="POST",
                auth=False,
                data={
                    "newUsername": SUNSHINE_USER,
                    "newPassword": SUNSHINE_PASSWORD,
                    "confirmNewPassword": SUNSHINE_PASSWORD,
                },
            )

            print(
                f"[Sunshine] Setup response: HTTP {setup_status}; "
                f"URL={setup_url}; "
                f"body={setup_content[:700]!r}",
                flush=True,
            )

            # Verify using an authenticated API request.
            if self.check_auth():
                print(
                    "[Sunshine] Initial setup completed successfully.",
                    flush=True,
                )
                return True

            print(
                "[Sunshine] Initial setup did not authenticate. "
                "Check the setup response above.",
                flush=True,
            )
            return False

        print(
            f"[Sunshine] Could not authenticate or identify "
            f"the Welcome page. HTTP {status}; URL={url}",
            flush=True,
        )
        return False

    # --------------------------------------------------------
    # Refresh Sunshine pairing page
    # --------------------------------------------------------

    def refresh_pin_page(self):
        """HTTP-equivalent of reopening Sunshine's /pin page."""
        status, url, content = self.request("/pin")

        if status == 200 and "/welcome" not in url.lower():
            print(
                f"[Sunshine] /pin refreshed: {url}",
                flush=True,
            )
        else:
            print(
                f"[Sunshine] /pin refresh: HTTP {status}; "
                f"URL={url}",
                flush=True,
            )

        return status, url, content

    # --------------------------------------------------------
    # Detect an internally generated pairing ID, if supported
    # --------------------------------------------------------

    def get_pending_pairings(self):
        status, url, content = self.request(
            "/api/pin",
            method="GET",
        )

        print(
            f"[Sunshine] Pending pairing lookup: "
            f"HTTP {status}; URL={url}; "
            f"response={content[:700]!r}",
            flush=True,
        )

        if status != 200:
            return None

        result = self.parse_json(content)

        # Recognize list fields only when the API actually returns
        # a list. If the endpoint is unsupported or returns HTML,
        # return None so the legacy API can be tried.
        for field in ("pairings", "pending", "requests"):
            if field in result and isinstance(result[field], list):
                return result[field]

        # Some API variants may return a single pending request.
        if any(key in result for key in ("pairing_id", "pairingId")):
            return [result]

        return None

    @staticmethod
    def extract_pairing_id(item):
        if not isinstance(item, dict):
            return None

        for field in ("pairing_id", "pairingId", "id"):
            value = item.get(field)

            if isinstance(value, (str, int)) and str(value).strip():
                return str(value).strip()

        return None

    # --------------------------------------------------------
    # Pairing
    # --------------------------------------------------------

    def pair(self, pin, name):
        # Refresh the Sunshine page first, preserving the cookie jar.
        self.refresh_pin_page()

        pending = self.get_pending_pairings()

        if pending is not None:
            if len(pending) == 0:
                print(
                    "[Pairing] No pending pairing entries found. "
                    "Trying the legacy API.",
                    flush=True,
                )
            elif len(pending) == 1:
                pairing_id = self.extract_pairing_id(pending[0])

                if pairing_id is not None:
                    print(
                        "[Pairing] Sunshine generated a pairing ID; "
                        "using it automatically.",
                        flush=True,
                    )

                    status, url, content = self.request(
                        "/api/pin",
                        method="POST",
                        data={
                            "pairing_id": pairing_id,
                            "pin": pin,
                            "name": name,
                        },
                        timeout=120,
                    )

                    print(
                        f"[Pairing] New API: HTTP {status}; "
                        f"URL={url}; response={content[:1000]!r}",
                        flush=True,
                    )

                    result = self.parse_json(content)

                    if status == 200 and result.get("status") is True:
                        self.refresh_pin_page()
                        return True, "Сопряжение подтверждено Sunshine."

                    self.refresh_pin_page()
                    return False, (
                        f"Sunshine не подтвердил сопряжение "
                        f"(HTTP {status}). Проверь PIN и логи Actions."
                    )

                print(
                    "[Pairing] Pending list has no recognized ID field; "
                    "trying the legacy API.",
                    flush=True,
                )

            else:
                print(
                    f"[Pairing] Found {len(pending)} pending requests. "
                    "Refusing to choose one randomly.",
                    flush=True,
                )
                self.refresh_pin_page()
                return False, (
                    "Sunshine ожидает несколько запросов. "
                    "Оставь один клиент Moonlight на экране PIN."
                )

        # Legacy API: PIN and device name only.
        status, url, content = self.request(
            "/api/pin",
            method="POST",
            data={"pin": pin, "name": name},
            timeout=120,
        )

        print(
            f"[Pairing] Legacy API: HTTP {status}; "
            f"URL={url}; response={content[:1000]!r}",
            flush=True,
        )

        result = self.parse_json(content)

        if status == 200 and result.get("status") is True:
            self.refresh_pin_page()
            return True, "Сопряжение подтверждено Sunshine."

        self.refresh_pin_page()

        return False, (
            f"Sunshine вернул HTTP {status}. "
            "Посмотри логи Actions: там указан URL редиректа "
            "и ответ API."
        )


SUNSHINE = SunshineClient()


# ============================================================
# WEB HANDLER
# ============================================================

class PairHandler(http.server.BaseHTTPRequestHandler):
    server_version = "PairingPanel/2.0"

    def send_json(self, status, payload):
        body = json.dumps(
            payload, ensure_ascii=False
        ).encode("utf-8")

        self.send_response(status)
        self.send_header(
            "Content-Type", "application/json; charset=utf-8"
        )
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return

        if self.path == "/health":
            self.send_json(200, {"ok": True})
            return

        if self.path not in ("/", "/index.html"):
            self.send_error(404)
            return

        # The browser sends the panel token in the POST header.
        # Do not create a form field for it.
        page = PAGE.replace("__PANEL_TOKEN__", WEB_TOKEN)
        body = page.encode("utf-8")

        self.send_response(200)
        self.send_header(
            "Content-Type", "text/html; charset=utf-8"
        )
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/api/pair":
            self.send_error(404)
            return

        if not WEB_TOKEN:
            self.send_json(503, {
                "ok": False,
                "message": "PAIR_WEB_TOKEN не настроен на сервере.",
            })
            return

        supplied_token = self.headers.get("X-Panel-Token", "")

        if not hmac.compare_digest(supplied_token, WEB_TOKEN):
            self.send_json(403, {
                "ok": False,
                "message": "Неверный токен панели.",
            })
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))

            if length <= 0 or length > 8192:
                raise ValueError("Invalid request size")

            payload = json.loads(
                self.rfile.read(length).decode("utf-8")
            )

            if not isinstance(payload, dict):
                raise ValueError("JSON object required")

        except Exception:
            self.send_json(400, {
                "ok": False,
                "message": "Некорректное тело запроса.",
            })
            return

        pin = str(payload.get("pin", "")).strip()
        name = str(payload.get("name", "")).strip()

        if not re.fullmatch(r"[0-9]{4}", pin):
            self.send_json(400, {
                "ok": False,
                "message": "PIN должен содержать ровно 4 цифры.",
            })
            return

        if not name or len(name) > 100:
            self.send_json(400, {
                "ok": False,
                "message": "Укажи имя устройства до 100 символов.",
            })
            return

        if not SUNSHINE_USER or not SUNSHINE_PASSWORD:
            self.send_json(503, {
                "ok": False,
                "message": "Не заданы SUNSHINE_USER / SUNSHINE_PASSWORD.",
            })
            return

        if not PAIR_LOCK.acquire(blocking=False):
            self.send_json(409, {
                "ok": False,
                "message": "Другой запрос pairing уже обрабатывается.",
            })
            return

        try:
            ok, message = SUNSHINE.pair(pin, name)

            self.send_json(200 if ok else 502, {
                "ok": ok,
                "message": message,
            })
        finally:
            PAIR_LOCK.release()

    def log_message(self, fmt, *args):
        print("[Panel] " + (fmt % args), flush=True)


# ============================================================
# MAIN
# ============================================================

def main():
    if not SUNSHINE_USER or not SUNSHINE_PASSWORD:
        raise SystemExit(
            "Set SUNSHINE_USER and SUNSHINE_PASSWORD environment variables."
        )

    if not WEB_TOKEN:
        raise SystemExit(
            "Set PAIR_WEB_TOKEN environment variable."
        )

    print("=" * 60, flush=True)
    print("SUNSHINE MOONLIGHT PAIRING PANEL", flush=True)
    print("=" * 60, flush=True)

    print(
        f"[Sunshine] Admin URL: {SUNSHINE_API}/pin",
        flush=True,
    )

    # Wait briefly for Sunshine to start before initializing it.
    setup_ok = False

    for attempt in range(1, 16):
        print(
            f"[Sunshine] Setup/auth check {attempt}/15",
            flush=True,
        )

        if SUNSHINE.ensure_setup():
            setup_ok = True
            break

        time.sleep(POLL_INTERVAL)

    if not setup_ok:
        raise SystemExit(
            "Sunshine initial setup/authentication failed. "
            "See the Sunshine logs above."
        )

    with socketserver.ThreadingTCPServer(
        (HOST, PORT), PairHandler
    ) as server:
        server.allow_reuse_address = True
        server.daemon_threads = True

        print(
            f"[Panel] Listening on http://{HOST}:{PORT}/",
            flush=True,
        )

        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("[Panel] Shutting down.", flush=True)
        finally:
            server.server_close()


if __name__ == "__main__":
    main()
