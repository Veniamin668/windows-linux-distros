import atexit
import base64
import http.cookiejar
import http.server
import hmac
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
# HIDDEN SUNSHINE BROWSER
# ============================================================

class SunshineBrowser:
    def __init__(self):
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None

    def start(self):
        if self.browser is not None and self.page is not None:
            if not self.browser.is_connected():
                self.close()
            else:
                return self.page

        print("[Browser] Starting headless Chromium...", flush=True)

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

            print("[Browser] Opening Sunshine...", flush=True)

            self.page.goto(
                SUNSHINE_API + "/",
                wait_until="domcontentloaded",
                timeout=45000,
            )

            print(
                f"[Browser] Initial URL: {self.page.url}",
                flush=True,
            )

            # Welcome logic remains unchanged.
            if self.is_welcome():
                self.configure_welcome()

            print("[Browser] Opening PIN page...", flush=True)

            self.page.goto(
                SUNSHINE_API + "/pin",
                wait_until="domcontentloaded",
                timeout=45000,
            )

            print(
                f"[Browser] PIN page URL: {self.page.url}",
                flush=True,
            )

            if self.is_welcome():
                raise RuntimeError(
                    "Sunshine redirected to /welcome after setup."
                )

            print(
                "[Browser] PIN page opened. Chromium remains running.",
                flush=True,
            )

            return self.page

        except Exception:
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

    def configure_welcome(self):
        # Original Welcome flow preserved.
        print(
            "[Browser] Welcome detected. Filling administrator form...",
            flush=True,
        )

        self.page.locator("input:visible").first.wait_for(
            state="visible",
            timeout=30000,
        )

        visible_inputs = self.page.locator("input:visible")
        password_inputs = self.page.locator(
            "input[type='password']:visible"
        )

        password_count = password_inputs.count()

        if password_count < 2:
            raise RuntimeError(
                "Welcome form must contain two visible password fields; "
                f"found {password_count}."
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

        print(
            "[Browser] Username and both password fields filled.",
            flush=True,
        )

        login_button = self.page.get_by_role(
            "button",
            name="Login",
            exact=True,
        )

        if login_button.count() == 0:
            login_button = self.page.locator(
                "button:visible, input[type='submit']:visible"
            ).filter(
                has_text=re.compile(r"^\s*Login\s*$", re.IGNORECASE)
            )

        if login_button.count() == 0:
            login_button = self.page.locator(
                "input[type='button']:visible"
            ).filter(
                has=self.page.locator("text=Login")
            )

        if login_button.count() == 0:
            raise RuntimeError(
                "Sunshine Welcome Login button was not found."
            )

        login_button.first.click()

        try:
            self.page.wait_for_load_state(
                "domcontentloaded",
                timeout=15000,
            )
        except Exception:
            pass

        self.page.wait_for_timeout(2000)

        print(
            f"[Browser] After Login click: {self.page.url}",
            flush=True,
        )

    # --------------------------------------------------------
    # PIN PAGE HELPERS
    # --------------------------------------------------------

    @staticmethod
    def _input_description(locator):
        values = []

        for attribute in (
            "name",
            "id",
            "placeholder",
            "aria-label",
            "autocomplete",
        ):
            try:
                value = locator.get_attribute(attribute)

                if value:
                    values.append(value)
            except Exception:
                pass

        try:
            input_type = locator.get_attribute("type")

            if input_type:
                values.append(input_type)
        except Exception:
            pass

        return " ".join(values).lower()

    def _find_pin_field(self):
        selectors = (
            "input[name='pin']:visible",
            "input#pin:visible",
            "input[autocomplete='one-time-code']:visible",
            "input[inputmode='numeric']:visible",
            "input[placeholder*='PIN' i]:visible",
            "input[aria-label*='PIN' i]:visible",
            "input[name*='pin' i]:visible",
            "input[id*='pin' i]:visible",
        )

        for selector in selectors:
            candidate = self.page.locator(selector)

            if candidate.count() > 0:
                return candidate.first

        inputs = self.page.locator(
            "input:visible:not([type='hidden'])"
        )

        for index in range(inputs.count()):
            candidate = inputs.nth(index)
            description = self._input_description(candidate)

            if "password" in description:
                continue

            if "pin" in description or "numeric" in description:
                return candidate

        return None

    def _find_name_field(self, pin_field):
        selectors = (
            "input[name='name']:visible",
            "input#name:visible",
            "input[name*='device' i]:visible",
            "input[id*='device' i]:visible",
            "input[placeholder*='name' i]:visible",
            "input[aria-label*='name' i]:visible",
            "input[name*='name' i]:visible",
        )

        for selector in selectors:
            candidates = self.page.locator(selector)

            for index in range(candidates.count()):
                candidate = candidates.nth(index)

                try:
                    same_element = candidate.evaluate(
                        "(element, other) => element === other",
                        pin_field,
                    )

                    if same_element:
                        continue
                except Exception:
                    pass

                return candidate

        inputs = self.page.locator(
            "input:visible:not([type='hidden'])"
        )

        for index in range(inputs.count()):
            candidate = inputs.nth(index)
            description = self._input_description(candidate)

            if "password" in description:
                continue

            try:
                same_element = candidate.evaluate(
                    "(element, other) => element === other",
                    pin_field,
                )

                if same_element:
                    continue
            except Exception:
                pass

            if "name" in description or "device" in description:
                return candidate

        for index in range(inputs.count()):
            candidate = inputs.nth(index)

            try:
                same_element = candidate.evaluate(
                    "(element, other) => element === other",
                    pin_field,
                )

                if same_element:
                    continue

                input_type = (
                    candidate.get_attribute("type") or "text"
                ).lower()

                if input_type in (
                    "text",
                    "search",
                    "tel",
                    "number",
                    "email",
                ):
                    return candidate

            except Exception:
                continue

        return None

    def _find_submit_button(self):
        for pattern in (
            r"pair",
            r"submit",
            r"connect",
            r"confirm",
            r"сопряж",
            r"подтверд",
            r"подключ",
        ):
            candidate = self.page.get_by_role(
                "button",
                name=re.compile(pattern, re.IGNORECASE),
            )

            for index in range(candidate.count()):
                button = candidate.nth(index)

                try:
                    if button.is_visible() and button.is_enabled():
                        return button
                except Exception:
                    continue

        for selector in (
            "form:visible button[type='submit']",
            "form:visible input[type='submit']",
            "button:visible",
        ):
            candidates = self.page.locator(selector)

            for index in range(candidates.count()):
                candidate = candidates.nth(index)

                try:
                    if candidate.is_visible() and candidate.is_enabled():
                        return candidate
                except Exception:
                    continue

        return None

    def pair(self, pin, name):
        page = self.start()

        current_path = urllib.parse.urlparse(page.url).path.rstrip("/")

        if current_path.lower() != "/pin":
            print(
                "[Browser] Returning to Sunshine /pin...",
                flush=True,
            )

            page.goto(
                SUNSHINE_API + "/pin",
                wait_until="domcontentloaded",
                timeout=45000,
            )

        if self.is_welcome():
            raise RuntimeError(
                "Sunshine redirected to Welcome during pairing."
            )

        print(
            "[Browser] Preparing the actual Sunshine PIN form...",
            flush=True,
        )

        pin_field = self._find_pin_field()

        if pin_field is None:
            raise RuntimeError(
                "Could not find a visible PIN input on Sunshine /pin. "
                "Inspect the page's HTML and input selectors."
            )

        name_field = self._find_name_field(pin_field)

        if name_field is None:
            raise RuntimeError(
                "Could not find a visible device-name input on Sunshine /pin. "
                "The current page may not contain a name field."
            )

        submit_button = self._find_submit_button()

        if submit_button is None:
            raise RuntimeError(
                "Could not find an enabled pairing submit button on /pin."
            )

        pin_field.fill(pin)
        name_field.fill(name)

        print(
            "[Browser] PIN and device name filled.",
            flush=True,
        )

        print(
            "[Browser] Submitting the actual Sunshine page form...",
            flush=True,
        )

        try:
            with page.expect_response(
                lambda response: (
                    urllib.parse.urlparse(response.url).path.rstrip("/").lower()
                    == "/api/pin"
                    and response.request.method.upper() == "POST"
                ),
                timeout=120000,
            ) as response_info:
                submit_button.click()

            response = response_info.value
            response_status = response.status

            try:
                response_content = response.text()
            except Exception:
                response_content = ""

            print(
                f"[Pairing] Sunshine page submission: "
                f"HTTP {response_status}; "
                f"response={response_content[:1000]!r}",
                flush=True,
            )

            result = SunshineClient.parse_json(response_content)

            try:
                current_path = (
                    urllib.parse.urlparse(page.url).path.rstrip("/").lower()
                )

                if current_path != "/pin":
                    page.goto(
                        SUNSHINE_API + "/pin",
                        wait_until="domcontentloaded",
                        timeout=45000,
                    )
            except Exception as navigation_error:
                print(
                    f"[Browser] Could not restore /pin: {navigation_error}",
                    flush=True,
                )

            if response_status == 200 and result.get("status") is True:
                print(
                    "[Pairing] Sunshine confirmed pairing successfully.",
                    flush=True,
                )

                return True, "Сопряжение подтверждено Sunshine."

            return False, (
                f"Sunshine вернул HTTP {response_status}. "
                "Проверь PIN, состояние Moonlight и логи Actions."
            )

        except Exception as error:
            print(
                f"[Pairing] Browser form submission failed: {error}",
                flush=True,
            )

            try:
                current_path = (
                    urllib.parse.urlparse(page.url).path.rstrip("/").lower()
                )

                if current_path != "/pin":
                    page.goto(
                        SUNSHINE_API + "/pin",
                        wait_until="domcontentloaded",
                        timeout=45000,
                    )
            except Exception:
                pass

            return False, (
                "Не удалось получить подтверждение от формы Sunshine. "
                "Проверь селекторы страницы /pin и логи Chromium."
            )

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
        print("[Browser] Chromium stopped.", flush=True)


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

        try:
            with self.opener.open(
                request,
                timeout=timeout,
            ) as response:
                content = response.read().decode(
                    "utf-8",
                    errors="replace",
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

            print(
                f"[Sunshine] HTTP {error.code}; "
                f"URL={error.geturl()}; "
                f"Location={error.headers.get('Location', '(none)')}; "
                f"response={content[:500]!r}",
                flush=True,
            )

            return (
                error.code,
                error.geturl(),
                content,
            )

        except Exception as error:
            print(
                f"[Sunshine] Request failed for {url}: {error}",
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
    # Authentication
    # --------------------------------------------------------

    def check_auth(self):
        status, url, content = self.request(
            "/api/apps",
            method="GET",
            auth=True,
        )

        if status != 200:
            print(
                f"[Sunshine] Auth check failed: HTTP {status}; URL={url}",
                flush=True,
            )
            return False

        result = self.parse_json(content)

        if not result and content.strip().lower().startswith(
            ("<!doctype html", "<html")
        ):
            print(
                "[Sunshine] API returned HTML instead of JSON.",
                flush=True,
            )
            return False

        if result.get("status") is False:
            print(
                "[Sunshine] API reported authentication failure.",
                flush=True,
            )
            return False

        print(
            "[Sunshine] Admin API responded successfully.",
            flush=True,
        )
        return True

    # --------------------------------------------------------
    # Initial setup
    # --------------------------------------------------------

    def ensure_setup(self):
        if not SUNSHINE_USER or not SUNSHINE_PASSWORD:
            print(
                "[Sunshine] SUNSHINE_USER or SUNSHINE_PASSWORD is missing.",
                flush=True,
            )
            return False

        try:
            page = SUNSHINE_BROWSER.start()

            if page is None or SUNSHINE_BROWSER.is_welcome():
                print(
                    "[Sunshine] Browser is still on Welcome.",
                    flush=True,
                )
                return False

        except Exception as error:
            print(
                f"[Sunshine] Browser initialization failed: {error}",
                flush=True,
            )
            return False

        if not self.check_auth():
            print(
                "[Sunshine] Admin API authentication check failed.",
                flush=True,
            )
            return False

        status, url, _ = self.request(
            "/pin",
            method="GET",
            auth=True,
        )

        final_path = urllib.parse.urlparse(url).path.rstrip("/").lower()

        if status != 200 or final_path == "/welcome":
            print(
                f"[Sunshine] PIN page check failed: HTTP {status}; URL={url}",
                flush=True,
            )
            return False

        print(
            "[Sunshine] Setup/authentication completed successfully.",
            flush=True,
        )
        return True

    # --------------------------------------------------------
    # Refresh PIN page
    # --------------------------------------------------------

    def refresh_pin_page(self):
        status, url, content = self.request(
            "/pin",
            method="GET",
            auth=True,
        )

        final_path = urllib.parse.urlparse(url).path.rstrip("/").lower()

        if status == 200 and final_path != "/welcome":
            print(
                f"[Sunshine] /pin refreshed: {url}",
                flush=True,
            )
        else:
            print(
                f"[Sunshine] /pin refresh failed: HTTP {status}; URL={url}",
                flush=True,
            )

        return status, url, content

    # --------------------------------------------------------
    # Pairing through the actual browser page
    # --------------------------------------------------------

    def pair(self, pin, name):
        status, url, _ = self.refresh_pin_page()
        final_path = urllib.parse.urlparse(url).path.rstrip("/").lower()

        if status != 200 or final_path == "/welcome":
            return False, (
                "Sunshine недоступен на PIN-странице. "
                "Проверь логи первоначальной настройки."
            )

        try:
            return SUNSHINE_BROWSER.pair(pin, name)
        except Exception as error:
            print(
                f"[Pairing] Browser pairing error: {error}",
                flush=True,
            )

            return False, (
                "Ошибка выполнения формы Sunshine. "
                "Подробности находятся в логах сервера."
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

        page = PAGE.replace("__PANEL_TOKEN__", WEB_TOKEN)
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
        SUNSHINE_BROWSER.close()
        raise SystemExit(
            "Sunshine initial setup/authentication failed. "
            "See the Sunshine and Browser logs above."
        )

    # IMPORTANT FIX:
    # Use TCPServer instead of ThreadingTCPServer.
    # The request handler now executes in the same thread as
    # sync_playwright(), avoiding "Cannot switch to a different thread".
    #
    # Requests are handled sequentially. While pairing is running,
    # additional HTTP requests wait until the current request finishes.
    class PairingServer(socketserver.TCPServer):
        allow_reuse_address = True

    try:
        with PairingServer((HOST, PORT), PairHandler) as server:
            print(
                f"[Panel] Listening on http://{HOST}:{PORT}/",
                flush=True,
            )

            print(
                "[Browser] Headless Chromium remains open on Sunshine /pin.",
                flush=True,
            )

            server.serve_forever()

    except KeyboardInterrupt:
        print("[Panel] Shutting down.", flush=True)

    finally:
        SUNSHINE_BROWSER.close()


if __name__ == "__main__":
    main()
