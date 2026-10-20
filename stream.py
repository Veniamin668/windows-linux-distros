import atexit
import base64
import http.cookiejar
import hmac
import http.server
import json
import os
import re
import socketserver
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from playwright.sync_api import sync_playwright


# ============================================================
# CONFIGURATION
# ============================================================

HOST = os.environ.get("PAIR_HOST", "0.0.0.0")
PORT = int(os.environ.get("PAIR_PORT", "5902"))

SUNSHINE_API = os.environ.get(
    "SUNSHINE_API",
    "https://127.0.0.1:47990",
).rstrip("/")

SUNSHINE_USER = os.environ.get("SUNSHINE_USER", "")
SUNSHINE_PASSWORD = os.environ.get("SUNSHINE_PASSWORD", "")
WEB_TOKEN = os.environ.get("PAIR_WEB_TOKEN", "")

SSL_CONTEXT = ssl._create_unverified_context()

POLL_INTERVAL = 3
REQUEST_TIMEOUT = 20
PAIR_LOCK = threading.Lock()


# ============================================================
# LOGGING
# ============================================================

def log(message):
    print(
        f"[{time.strftime('%H:%M:%S')}] {message}",
        flush=True,
    )


def safe_url(url):
    """Return a URL without query parameters."""
    try:
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    except Exception:
        return "<invalid-url>"


def safe_response_text(content, limit=1000):
    """Avoid logging PINs, passwords, tokens, or authorization data."""
    if not content:
        return "<empty>"

    result = str(content)

    result = re.sub(
        r'(?i)("?(?:password|token|authorization|pin)"?\s*[:=]\s*)'
        r'("[^"]*"|[^,\s}&]+)',
        r'\1<redacted>',
        result,
    )

    if len(result) > limit:
        result = result[:limit] + "... <truncated>"

    return repr(result)


# ============================================================
# PAIRING PANEL
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
<input id="pin" name="pin" type="text" inputmode="numeric"
       pattern="[0-9]{4}" maxlength="4" placeholder="1234" required>

<label for="name">Имя устройства</label>
<input id="name" name="name" type="text" maxlength="100"
       value="Moonlight Client" required>

<button id="submit" type="submit">Подтвердить сопряжение</button>
</form>

<div id="status" role="status" aria-live="polite"></div>
</main>

<script>
const form = document.getElementById('pairForm');
const button = document.getElementById('submit');
const statusBox = document.getElementById('status');

form.addEventListener('submit', async (event) => {
  event.preventDefault();

  if (button.disabled) return;

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

    let result;

    try {
      result = await response.json();
    } catch {
      throw new Error('Сервер вернул некорректный ответ.');
    }

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
# SUNSHINE BROWSER
# ============================================================

class SunshineBrowser:
    """
    Keeps one Chromium instance alive and uses the real Sunshine
    /pin page for pairing.

    Important:
    - The Welcome setup flow is preserved.
    - Pairing uses Sunshine's own form and JavaScript.
    - No direct Python POST to Sunshine /api/pin.
    - Do not refresh /pin after submitting a PIN.
    """

    def __init__(self):
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None

    # --------------------------------------------------------
    # START / INITIALIZATION
    # --------------------------------------------------------

    def start(self):
        if self.browser is not None and self.page is not None:
            try:
                if self.browser.is_connected():
                    return self.page
            except Exception:
                pass

            self.close()

        log("[Browser] Starting headless Chromium...")

        self.playwright = sync_playwright().start()

        try:
            self.browser = self.playwright.chromium.launch(
                headless=True,
            )

            self.context = self.browser.new_context(
                ignore_https_errors=True,
                http_credentials={
                    "username": SUNSHINE_USER,
                    "password": SUNSHINE_PASSWORD,
                },
            )

            self.page = self.context.new_page()
            self.page.set_default_timeout(15000)

            self.page.goto(
                SUNSHINE_API + "/",
                wait_until="domcontentloaded",
                timeout=45000,
            )

            # Keep the existing first-time Welcome setup.
            if self.is_welcome():
                self.configure_welcome()

            log("[Browser] Opening Sunshine PIN page...")

            self.page.goto(
                SUNSHINE_API + "/pin",
                wait_until="domcontentloaded",
                timeout=45000,
            )

            if self.is_welcome():
                raise RuntimeError(
                    "Sunshine redirected to /welcome after setup."
                )

            self._wait_for_pin_form()

            log("[Browser] Sunshine PIN page is ready.")
            return self.page

        except Exception:
            log("[Browser] Initialization failed.")
            self.close()
            raise

    def is_welcome(self):
        if self.page is None:
            return False

        try:
            path = urllib.parse.urlparse(self.page.url).path
            return path.rstrip("/").lower() == "/welcome"
        except Exception:
            return False

    def _wait_for_pin_form(self):
        """
        Sunshine currently uses:
            form#form
            input#pin-input
            input#name-input
            button[type=submit] with text Send
        """
        self.page.locator("#pin-input").wait_for(
            state="visible",
            timeout=30000,
        )

        self.page.locator("#name-input").wait_for(
            state="visible",
            timeout=15000,
        )

        self.page.locator(
            "form#form button[type='submit']"
        ).wait_for(
            state="visible",
            timeout=15000,
        )

    # --------------------------------------------------------
    # WELCOME SETUP
    # --------------------------------------------------------

    def configure_welcome(self):
        # Original Welcome setup behavior preserved.
        log("[Welcome] Initial Sunshine setup detected.")

        self.page.locator("input:visible").first.wait_for(
            state="visible",
            timeout=30000,
        )

        visible_inputs = self.page.locator("input:visible")
        password_inputs = self.page.locator(
            "input[type='password']:visible"
        )

        if password_inputs.count() < 2:
            raise RuntimeError(
                "Welcome form must contain two visible password fields."
            )

        username_field = None

        for selector in (
            "input[name='username']:visible",
            "input[name='user']:visible",
            "input[autocomplete='username']:visible",
            "input[type='text']:visible",
            "input[type='email']:visible",
        ):
            candidate = self.page.locator(selector)

            if candidate.count() > 0:
                username_field = candidate.first
                break

        if username_field is None:
            for index in range(visible_inputs.count()):
                candidate = visible_inputs.nth(index)

                input_type = (
                    candidate.get_attribute("type") or "text"
                ).lower()

                if input_type not in (
                    "password",
                    "submit",
                    "button",
                    "hidden",
                    "checkbox",
                    "radio",
                ):
                    username_field = candidate
                    break

        if username_field is None:
            raise RuntimeError(
                "Could not find the Welcome username field."
            )

        username_field.fill(SUNSHINE_USER)
        password_inputs.nth(0).fill(SUNSHINE_PASSWORD)
        password_inputs.nth(1).fill(SUNSHINE_PASSWORD)

        login_button = self.page.get_by_role(
            "button",
            name="Login",
            exact=True,
        )

        if login_button.count() == 0:
            login_button = self.page.locator(
                "button:visible, input[type='submit']:visible"
            ).filter(
                has_text=re.compile(
                    r"^\s*Login\s*$",
                    re.IGNORECASE,
                )
            )

        if login_button.count() == 0:
            raise RuntimeError(
                "Sunshine Welcome Login button was not found."
            )

        log("[Welcome] Submitting initial administrator setup.")

        login_button.first.click()

        try:
            self.page.wait_for_load_state(
                "domcontentloaded",
                timeout=15000,
            )
        except Exception:
            pass

        self.page.wait_for_timeout(2000)

        log(
            f"[Welcome] Setup form submitted; current page="
            f"{safe_url(self.page.url)}"
        )

    # --------------------------------------------------------
    # PAIRING FORM
    # --------------------------------------------------------

    def pair(self, pin, name):
        page = self.start()

        log("[Pairing] Starting Sunshine pairing.")

        current_path = (
            urllib.parse.urlparse(page.url).path.rstrip("/").lower()
        )

        if current_path != "/pin":
            log("[Pairing] Opening Sunshine /pin page.")

            page.goto(
                SUNSHINE_API + "/pin",
                wait_until="domcontentloaded",
                timeout=45000,
            )

        if self.is_welcome():
            raise RuntimeError(
                "Sunshine redirected to Welcome during pairing."
            )

        self._wait_for_pin_form()

        # Exact selectors used by the current Sunshine PIN page.
        pin_field = page.locator("#pin-input")
        name_field = page.locator("#name-input")

        # Prefer the actual Sunshine form's submit button.
        submit_button = page.locator(
            "form#form button[type='submit']"
        )

        if submit_button.count() == 0:
            # Fallback for Sunshine versions that change the form ID.
            submit_button = page.locator(
                "button[type='submit']:visible"
            )

        if submit_button.count() == 0:
            raise RuntimeError(
                "Could not find Sunshine's PIN form submit button."
            )

        # Fill the actual Sunshine form.
        pin_field.fill(pin)
        name_field.fill(name)

        # Ensure the form has accepted both values before clicking.
        entered_pin_length = pin_field.evaluate(
            "(element) => String(element.value || '').length"
        )
        entered_name_length = name_field.evaluate(
            "(element) => String(element.value || '').length"
        )

        if entered_pin_length != 4:
            raise RuntimeError(
                "Sunshine PIN field did not accept exactly four digits."
            )

        if entered_name_length != len(name):
            raise RuntimeError(
                "Sunshine device-name field did not accept the full name."
            )

        button = submit_button.first
        button.wait_for(state="visible", timeout=10000)

        # Sunshine's button can be disabled while its form is invalid.
        if not button.is_enabled():
            raise RuntimeError(
                "Sunshine's Send button is disabled after filling the form."
            )

        log("[Pairing] Submitting Sunshine's own PIN form.")

        started = time.monotonic()

        try:
            # The Sunshine SPA intercepts the form and sends POST /api/pin.
            # Wait for that response instead of navigating away or refreshing.
            with page.expect_response(
                lambda response: (
                    urllib.parse.urlparse(response.url).path.rstrip("/")
                    .lower() == "/api/pin"
                    and response.request.method.upper() == "POST"
                ),
                timeout=120000,
            ) as response_context:
                button.click(timeout=15000)

            response = response_context.value
            elapsed = time.monotonic() - started

            try:
                response_text = response.text()
            except Exception:
                response_text = ""

            log(
                f"[Pairing] Sunshine returned HTTP {response.status} "
                f"after {elapsed:.2f}s."
            )

            log(
                "[Pairing] Sunshine response: "
                + safe_response_text(response_text)
            )

            result = SunshineClient.parse_json(response_text)

            if response.status == 200 and result.get("status") is True:
                log(
                    "[Pairing] Sunshine accepted the PIN request. "
                    "Moonlight handshake completion is not guaranteed "
                    "by the HTTP response alone."
                )

                return True, (
                    "Sunshine принял PIN-запрос. Если Moonlight всё ещё "
                    "показывает ошибку, проверь состояние Moonlight и "
                    "логи Sunshine: ответ API сам по себе не гарантирует "
                    "завершение всего handshake."
                )

            log("[Pairing] Sunshine did not accept the PIN request.")

            return False, (
                f"Sunshine вернул HTTP {response.status}. "
                "Проверь PIN и состояние Moonlight."
            )

        except Exception as error:
            log(
                f"[Pairing] Submission failed: "
                f"{type(error).__name__}: {error}"
            )

            # Do not navigate or refresh here. A pending pairing request
            # must not be interrupted by an automatic page reload.
            return False, (
                "Не удалось получить ожидаемый ответ от Sunshine. "
                "Проверь, что Moonlight показывает актуальный PIN, "
                "и посмотри логи Actions."
            )

    # --------------------------------------------------------
    # CLEANUP
    # --------------------------------------------------------

    def close(self):
        if self.context is not None:
            try:
                self.context.close()
            except Exception:
                pass
            self.context = None

        if self.browser is not None:
            try:
                self.browser.close()
            except Exception:
                pass
            self.browser = None

        if self.playwright is not None:
            try:
                self.playwright.stop()
            except Exception:
                pass
            self.playwright = None

        self.page = None


SUNSHINE_BROWSER = SunshineBrowser()
atexit.register(SUNSHINE_BROWSER.close)


# ============================================================
# SUNSHINE HTTP CLIENT
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

    def request(
        self,
        path,
        method="GET",
        data=None,
        auth=True,
        timeout=REQUEST_TIMEOUT,
    ):
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

        started = time.monotonic()

        try:
            with self.opener.open(
                request,
                timeout=timeout,
            ) as response:
                content = response.read().decode(
                    "utf-8",
                    errors="replace",
                )

                log(
                    f"[SunshineHTTP] {method} {safe_url(url)} "
                    f"HTTP {response.status} "
                    f"({time.monotonic() - started:.2f}s)"
                )

                return (
                    response.status,
                    response.geturl(),
                    content,
                )

        except urllib.error.HTTPError as error:
            content = error.read().decode(
                "utf-8",
                errors="replace",
            )

            log(
                f"[SunshineHTTP] {method} {safe_url(url)} "
                f"HTTP {error.code}; "
                f"response={safe_response_text(content, 500)}"
            )

            return (
                error.code,
                error.geturl(),
                content,
            )

        except Exception as error:
            log(
                f"[SunshineHTTP] Request failed for {safe_url(url)}: "
                f"{type(error).__name__}: {error}"
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
    # AUTHENTICATION
    # --------------------------------------------------------

    def check_auth(self):
        status, url, content = self.request(
            "/api/apps",
            method="GET",
            auth=True,
        )

        if status != 200:
            log(
                f"[Sunshine] Authentication check failed: "
                f"HTTP {status}; URL={safe_url(url)}"
            )
            return False

        result = self.parse_json(content)

        if (
            not result
            and content.strip().lower().startswith(
                ("<!doctype html", "<html")
            )
        ):
            log("[Sunshine] API returned HTML instead of JSON.")
            return False

        if result.get("status") is False:
            log("[Sunshine] API reported authentication failure.")
            return False

        return True

    # --------------------------------------------------------
    # INITIAL SETUP
    # --------------------------------------------------------

    def ensure_setup(self):
        if not SUNSHINE_USER or not SUNSHINE_PASSWORD:
            log("[Sunshine] SUNSHINE_USER or SUNSHINE_PASSWORD is missing.")
            return False

        try:
            page = SUNSHINE_BROWSER.start()

            if page is None or SUNSHINE_BROWSER.is_welcome():
                log("[Sunshine] Browser is still on Welcome.")
                return False

        except Exception as error:
            log(
                f"[Sunshine] Browser initialization failed: "
                f"{type(error).__name__}: {error}"
            )
            return False

        if not self.check_auth():
            log("[Sunshine] Admin API authentication check failed.")
            return False

        status, url, _ = self.request(
            "/pin",
            method="GET",
            auth=True,
        )

        final_path = (
            urllib.parse.urlparse(url).path.rstrip("/").lower()
        )

        if status != 200 or final_path == "/welcome":
            log(
                f"[Sunshine] PIN page check failed: "
                f"HTTP {status}; URL={safe_url(url)}"
            )
            return False

        log("[Sunshine] Setup and authentication completed.")
        return True

    def refresh_pin_page(self):
        status, url, content = self.request(
            "/pin",
            method="GET",
            auth=True,
        )

        final_path = (
            urllib.parse.urlparse(url).path.rstrip("/").lower()
        )

        if status != 200 or final_path == "/welcome":
            log(
                f"[Sunshine] PIN page check failed: "
                f"HTTP {status}; URL={safe_url(url)}"
            )

        return status, url, content

    # --------------------------------------------------------
    # PAIRING
    # --------------------------------------------------------

    def pair(self, pin, name):
        log("[Pairing] Running Sunshine availability check.")

        status, url, _ = self.refresh_pin_page()

        final_path = (
            urllib.parse.urlparse(url).path.rstrip("/").lower()
        )

        if status != 200 or final_path == "/welcome":
            return False, (
                "Sunshine недоступен на PIN-странице. "
                "Проверь первоначальную настройку."
            )

        try:
            return SUNSHINE_BROWSER.pair(pin, name)

        except Exception as error:
            log(
                f"[Pairing] Browser pairing error: "
                f"{type(error).__name__}: {error}"
            )

            return False, (
                "Ошибка выполнения формы Sunshine. "
                "Проверь логи Actions."
            )


SUNSHINE = SunshineClient()


# ============================================================
# WEB HANDLER
# ============================================================

class PairHandler(http.server.BaseHTTPRequestHandler):
    server_version = "PairingPanel/2.0"

    def send_json(self, status, payload):
        body = json.dumps(
            payload,
            ensure_ascii=False,
        ).encode("utf-8")

        self.send_response(status)
        self.send_header(
            "Content-Type",
            "application/json; charset=utf-8",
        )
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

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

        # Prevent the token from breaking JavaScript if it contains
        # characters meaningful in HTML or JavaScript.
        safe_token = json.dumps(WEB_TOKEN)[1:-1]
        page = PAGE.replace("__PANEL_TOKEN__", safe_token)
        body = page.encode("utf-8")

        self.send_response(200)
        self.send_header(
            "Content-Type",
            "text/html; charset=utf-8",
        )
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

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
            log("[Panel] Pairing request rejected: invalid panel token.")

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
            log("[Panel] Invalid request body.")

            self.send_json(400, {
                "ok": False,
                "message": "Некорректное тело запроса.",
            })
            return

        pin = str(payload.get("pin", "")).strip()
        name = str(payload.get("name", "")).strip()

        # Never print the submitted PIN or credentials.
        log(
            f"[Panel] Pairing request received; "
            f"PIN length={len(pin)}; name length={len(name)}."
        )

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
            log("[Panel] Another pairing request is already active.")

            self.send_json(409, {
                "ok": False,
                "message": "Другой запрос pairing уже обрабатывается.",
            })
            return

        started = time.monotonic()

        try:
            log("[Panel] Starting pairing flow.")

            ok, message = SUNSHINE.pair(pin, name)

            log(
                f"[Panel] Pairing finished: ok={ok}; "
                f"elapsed={time.monotonic() - started:.2f}s"
            )

            self.send_json(200 if ok else 502, {
                "ok": ok,
                "message": message,
            })

        except Exception as error:
            log(
                f"[Panel] Pairing error: "
                f"{type(error).__name__}: {error}"
            )

            self.send_json(500, {
                "ok": False,
                "message": (
                    "Внутренняя ошибка pairing. Проверь логи Actions."
                ),
            })

        finally:
            PAIR_LOCK.release()

    def log_message(self, fmt, *args):
        # Keep normal HTTP access logs concise.
        log("[PanelHTTP] " + (fmt % args))


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

    log("=" * 56)
    log("SUNSHINE MOONLIGHT PAIRING PANEL")
    log("=" * 56)
    log(f"[Config] Panel: http://{HOST}:{PORT}/")
    log(f"[Config] Sunshine PIN page: {SUNSHINE_API}/pin")
    log("[Config] Headless Chromium enabled.")
    log("[Config] PINs and credentials are not logged.")

    setup_ok = False

    for attempt in range(1, 16):
        log(f"[Sunshine] Setup/authentication check {attempt}/15")

        if SUNSHINE.ensure_setup():
            setup_ok = True
            break

        if attempt < 15:
            log(
                f"[Sunshine] Check failed; retrying in "
                f"{POLL_INTERVAL}s."
            )
            time.sleep(POLL_INTERVAL)

    if not setup_ok:
        SUNSHINE_BROWSER.close()

        raise SystemExit(
            "Sunshine initial setup/authentication failed. "
            "Check the preceding logs."
        )

    # IMPORTANT:
    # Keep TCPServer so synchronous Playwright remains on the same
    # thread where its instance was created.
    class PairingServer(socketserver.TCPServer):
        allow_reuse_address = True

    try:
        with PairingServer((HOST, PORT), PairHandler) as server:
            log(f"[Panel] Listening on http://{HOST}:{PORT}/")
            log("[Panel] Ready.")

            server.serve_forever()

    except KeyboardInterrupt:
        log("[Panel] Shutting down.")

    finally:
        SUNSHINE_BROWSER.close()


if __name__ == "__main__":
    main()
