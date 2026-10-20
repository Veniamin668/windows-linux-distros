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
# LOGGING HELPERS
# ============================================================

def log(message):
    print(
        f"[{time.strftime('%H:%M:%S')}] {message}",
        flush=True,
    )


def safe_url(url):
    """Log URL path only; never print query parameters."""
    try:
        parsed = urllib.parse.urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    except Exception:
        return "<invalid-url>"


def safe_response_text(content, limit=1500):
    """
    Truncate a response and redact common sensitive fields.
    Never log request bodies, submitted PINs, or credentials.
    """
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
        self._events_attached = False

    # --------------------------------------------------------
    # BROWSER DIAGNOSTICS
    # --------------------------------------------------------

    def _attach_diagnostics(self):
        if self.page is None or self._events_attached:
            return

        self._events_attached = True

        self.page.on(
            "console",
            self._on_console,
        )

        self.page.on(
            "pageerror",
            self._on_page_error,
        )

        self.page.on(
            "requestfailed",
            self._on_request_failed,
        )

        self.page.on(
            "request",
            self._on_request,
        )

        self.page.on(
            "response",
            self._on_response,
        )

        self.page.on(
            "framenavigated",
            self._on_frame_navigated,
        )

        log("[BrowserDiag] Browser event listeners attached.")

    def _on_console(self, message):
        try:
            message_type = message.type
            message_text = message.text

            # Do not print arbitrary console output without a limit.
            if len(message_text) > 1000:
                message_text = message_text[:1000] + "... <truncated>"

            log(
                f"[BrowserConsole] type={message_type}; "
                f"text={message_text!r}"
            )
        except Exception as error:
            log(f"[BrowserConsole] Could not read console message: {error}")

    def _on_page_error(self, error):
        log(f"[BrowserPageError] {error}")

    def _on_request_failed(self, request):
        try:
            log(
                f"[BrowserNetwork] REQUEST FAILED "
                f"{request.method} {safe_url(request.url)}; "
                f"failure={request.failure}"
            )
        except Exception as error:
            log(f"[BrowserNetwork] Failed-request diagnostic error: {error}")

    def _on_request(self, request):
        try:
            parsed = urllib.parse.urlparse(request.url)
            path = parsed.path.lower()

            # Log API calls and document navigations, not every asset.
            interesting = (
                path.startswith("/api/")
                or request.is_navigation_request()
                or path in ("/pin", "/welcome")
            )

            if not interesting:
                return

            log(
                f"[BrowserNetwork] REQUEST "
                f"{request.method} {safe_url(request.url)}; "
                f"resource={request.resource_type}; "
                f"navigation={request.is_navigation_request()}"
            )

            # Deliberately do not print request.post_data:
            # it may contain the PIN or other sensitive values.

        except Exception as error:
            log(f"[BrowserNetwork] Request diagnostic error: {error}")

    def _on_response(self, response):
        try:
            parsed = urllib.parse.urlparse(response.url)
            path = parsed.path.lower()

            interesting = (
                path.startswith("/api/")
                or path in ("/pin", "/welcome")
            )

            if not interesting:
                return

            request = response.request

            log(
                f"[BrowserNetwork] RESPONSE "
                f"{request.method} {safe_url(response.url)}; "
                f"HTTP={response.status}; "
                f"ok={response.ok}; "
                f"resource={request.resource_type}"
            )

        except Exception as error:
            log(f"[BrowserNetwork] Response diagnostic error: {error}")

    def _on_frame_navigated(self, frame):
        try:
            if frame == self.page.main_frame:
                log(
                    f"[BrowserNavigation] Main frame navigated to "
                    f"{safe_url(frame.url)}"
                )
        except Exception as error:
            log(f"[BrowserNavigation] Diagnostic error: {error}")

    def _dump_page_state(self, label):
        if self.page is None:
            log(f"[DOM] {label}: page is None.")
            return

        log(f"[DOM] ===== PAGE SNAPSHOT: {label} =====")
        log(f"[DOM] URL: {safe_url(self.page.url)}")

        try:
            title = self.page.title()
            log(f"[DOM] Title: {title!r}")
        except Exception as error:
            log(f"[DOM] Could not read title: {error}")

        try:
            snapshot = self.page.evaluate(
                """() => ({
                    readyState: document.readyState,
                    bodyText: (document.body?.innerText || '').slice(0, 2000),
                    forms: Array.from(document.forms).map((form, index) => ({
                        index,
                        id: form.id || '',
                        name: form.name || '',
                        action: form.getAttribute('action') || '',
                        method: form.getAttribute('method') || 'GET',
                        visible: !!(
                            form.offsetWidth ||
                            form.offsetHeight ||
                            form.getClientRects().length
                        ),
                        inputs: Array.from(form.querySelectorAll('input')).map(
                            (input) => ({
                                type: input.type || '',
                                name: input.name || '',
                                id: input.id || '',
                                placeholder: input.placeholder || '',
                                ariaLabel: input.getAttribute('aria-label') || '',
                                autocomplete: input.autocomplete || '',
                                inputMode: input.inputMode || '',
                                visible: !!(
                                    input.offsetWidth ||
                                    input.offsetHeight ||
                                    input.getClientRects().length
                                ),
                                disabled: input.disabled
                            })
                        ),
                        buttons: Array.from(
                            form.querySelectorAll(
                                'button, input[type="submit"], input[type="button"]'
                            )
                        ).map((button) => ({
                            tag: button.tagName,
                            type: button.type || '',
                            text: (button.innerText || button.value || '').trim(),
                            name: button.name || '',
                            id: button.id || '',
                            disabled: !!button.disabled
                        }))
                    }))
                })"""
            )

            log(
                "[DOM] Snapshot: "
                + json.dumps(snapshot, ensure_ascii=False)
            )

        except Exception as error:
            log(f"[DOM] Snapshot failed: {error}")

        log(f"[DOM] ===== END SNAPSHOT: {label} =====")

    # --------------------------------------------------------
    # START
    # --------------------------------------------------------

    def start(self):
        if self.browser is not None and self.page is not None:
            if not self.browser.is_connected():
                log("[Browser] Existing browser disconnected; restarting.")
                self.close()
            else:
                return self.page

        log("[Browser] Starting Chromium with headless=True...")

        self.playwright = sync_playwright().start()

        try:
            self.browser = self.playwright.chromium.launch(
                headless=True,
            )

            log("[Browser] Chromium launched successfully.")

            self.context = self.browser.new_context(
                ignore_https_errors=True,
                http_credentials={
                    "username": SUNSHINE_USER,
                    "password": SUNSHINE_PASSWORD,
                },
            )

            log("[Browser] Browser context created.")

            self.page = self.context.new_page()
            self.page.set_default_timeout(15000)

            self._attach_diagnostics()

            log("[Browser] Opening Sunshine root page...")

            start_time = time.monotonic()

            self.page.goto(
                SUNSHINE_API + "/",
                wait_until="domcontentloaded",
                timeout=45000,
            )

            log(
                f"[Browser] Root navigation finished in "
                f"{time.monotonic() - start_time:.2f}s; "
                f"URL={safe_url(self.page.url)}"
            )

            # Welcome logic remains unchanged.
            if self.is_welcome():
                self.configure_welcome()

            log("[Browser] Opening Sunshine PIN page...")

            start_time = time.monotonic()

            self.page.goto(
                SUNSHINE_API + "/pin",
                wait_until="domcontentloaded",
                timeout=45000,
            )

            log(
                f"[Browser] PIN navigation finished in "
                f"{time.monotonic() - start_time:.2f}s; "
                f"URL={safe_url(self.page.url)}"
            )

            if self.is_welcome():
                raise RuntimeError(
                    "Sunshine redirected to /welcome after setup."
                )

            self._dump_page_state("initial /pin")

            log(
                "[Browser] PIN page is ready. Chromium remains running."
            )

            return self.page

        except Exception:
            log("[Browser] Startup failed; closing browser.")
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
        log(
            "[Browser] Welcome detected. Filling administrator form..."
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

        log(
            f"[Welcome] Visible inputs={visible_inputs.count()}; "
            f"visible password fields={password_count}"
        )

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
                log(f"[Welcome] Username selector: {selector}")
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
                    log(
                        f"[Welcome] Username fallback input index={index}"
                    )
                    break

        if username_field is None:
            raise RuntimeError(
                "Could not find the Welcome username field."
            )

        username_field.fill(SUNSHINE_USER)
        password_inputs.nth(0).fill(SUNSHINE_PASSWORD)
        password_inputs.nth(1).fill(SUNSHINE_PASSWORD)

        log(
            "[Welcome] Username and both password fields filled. "
            "Credential values are not logged."
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

        log("[Welcome] Clicking Login.")

        login_button.first.click()

        try:
            self.page.wait_for_load_state(
                "domcontentloaded",
                timeout=15000,
            )
        except Exception as error:
            log(
                f"[Welcome] Navigation wait ended without confirmation: "
                f"{error}"
            )

        self.page.wait_for_timeout(2000)

        log(
            f"[Welcome] After Login click: {safe_url(self.page.url)}"
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
            "inputmode",
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

    @staticmethod
    def _same_element(first, second):
        """
        Compare DOM element identity without passing a Locator as a JS argument.
        """
        try:
            first_index = first.evaluate(
                "(element) => Array.from("
                "document.querySelectorAll('input')"
                ").indexOf(element)"
            )

            second_index = second.evaluate(
                "(element) => Array.from("
                "document.querySelectorAll('input')"
                ").indexOf(element)"
            )

            return (
                first_index >= 0
                and second_index >= 0
                and first_index == second_index
            )

        except Exception:
            return False

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
                log(
                    f"[PairingDiag] PIN field found by selector "
                    f"{selector!r}; matches={candidate.count()}"
                )
                return candidate.first

        inputs = self.page.locator(
            "input:visible:not([type='hidden'])"
        )

        for index in range(inputs.count()):
            candidate = inputs.nth(index)
            description = self._input_description(candidate)

            log(
                f"[PairingDiag] Candidate PIN input index={index}; "
                f"attributes={description!r}"
            )

            if "password" in description:
                continue

            if "pin" in description or "numeric" in description:
                log(
                    f"[PairingDiag] PIN field selected by fallback "
                    f"index={index}"
                )
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

                if self._same_element(candidate, pin_field):
                    continue

                log(
                    f"[PairingDiag] Device-name field found by "
                    f"selector {selector!r}; candidate={index}"
                )

                return candidate

        inputs = self.page.locator(
            "input:visible:not([type='hidden'])"
        )

        for index in range(inputs.count()):
            candidate = inputs.nth(index)
            description = self._input_description(candidate)

            log(
                f"[PairingDiag] Candidate name input index={index}; "
                f"attributes={description!r}"
            )

            if self._same_element(candidate, pin_field):
                continue

            if "password" in description:
                continue

            if "name" in description or "device" in description:
                log(
                    f"[PairingDiag] Device-name field selected by "
                    f"attribute fallback index={index}"
                )
                return candidate

        for index in range(inputs.count()):
            candidate = inputs.nth(index)

            if self._same_element(candidate, pin_field):
                continue

            try:
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
                    log(
                        f"[PairingDiag] Device-name field selected by "
                        f"type fallback index={index}; type={input_type}"
                    )
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
                        log(
                            f"[PairingDiag] Submit button selected by "
                            f"accessible-name pattern={pattern!r}; "
                            f"candidate={index}"
                        )
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
                        log(
                            f"[PairingDiag] Submit button selected by "
                            f"fallback selector={selector!r}; "
                            f"candidate={index}"
                        )
                        return candidate
                except Exception:
                    continue

        return None

    def _describe_locator(self, label, locator):
        try:
            description = locator.evaluate(
                """element => ({
                    tag: element.tagName,
                    type: element.getAttribute('type') || '',
                    name: element.getAttribute('name') || '',
                    id: element.id || '',
                    placeholder: element.getAttribute('placeholder') || '',
                    ariaLabel: element.getAttribute('aria-label') || '',
                    autocomplete: element.getAttribute('autocomplete') || '',
                    inputMode: element.getAttribute('inputmode') || '',
                    disabled: !!element.disabled,
                    visible: !!(
                        element.offsetWidth ||
                        element.offsetHeight ||
                        element.getClientRects().length
                    ),
                    form: element.form ? {
                        id: element.form.id || '',
                        action: element.form.getAttribute('action') || '',
                        method: element.form.getAttribute('method') || 'GET'
                    } : null,
                    text: (element.innerText || element.value || '')
                        .trim().slice(0, 200)
                })"""
            )

            log(
                f"[PairingDiag] {label}: "
                + json.dumps(description, ensure_ascii=False)
            )

        except Exception as error:
            log(
                f"[PairingDiag] Could not describe {label}: {error}"
            )

    # --------------------------------------------------------
    # PAIRING
    # --------------------------------------------------------

    def pair(self, pin, name):
        page = self.start()

        log("[Pairing] ===== NEW PAIRING ATTEMPT =====")
        log("[Pairing] PIN received by server: four-digit value redacted.")
        log(f"[Pairing] Device name length={len(name)}.")

        current_path = (
            urllib.parse.urlparse(page.url).path.rstrip("/").lower()
        )

        log(
            f"[PairingDiag] Current page path={current_path!r}"
        )

        if current_path != "/pin":
            log(
                "[PairingDiag] Current page is not /pin; navigating "
                "to the PIN page before submitting."
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

        self._dump_page_state("before pairing")

        log("[PairingDiag] Searching for PIN input...")
        pin_field = self._find_pin_field()

        if pin_field is None:
            self._dump_page_state("PIN field not found")

            raise RuntimeError(
                "Could not find a visible PIN input on Sunshine /pin."
            )

        log("[PairingDiag] Searching for device-name input...")
        name_field = self._find_name_field(pin_field)

        if name_field is None:
            self._dump_page_state("device-name field not found")

            raise RuntimeError(
                "Could not find a visible device-name input on Sunshine /pin."
            )

        log("[PairingDiag] Searching for submit button...")
        submit_button = self._find_submit_button()

        if submit_button is None:
            self._dump_page_state("submit button not found")

            raise RuntimeError(
                "Could not find an enabled pairing submit button on /pin."
            )

        self._describe_locator("PIN input", pin_field)
        self._describe_locator("Device-name input", name_field)
        self._describe_locator("Submit button", submit_button)

        try:
            pin_field.fill(pin)
            log("[PairingDiag] PIN filled; value not logged.")

            name_field.fill(name)
            log("[PairingDiag] Device name filled.")

        except Exception as error:
            log(
                f"[PairingDiag] Failed to fill fields: "
                f"{type(error).__name__}: {error}"
            )
            self._dump_page_state("field filling failed")
            raise

        # Verify field lengths without revealing either value.
        try:
            pin_length = pin_field.evaluate(
                "(element) => String(element.value || '').length"
            )
            name_length = name_field.evaluate(
                "(element) => String(element.value || '').length"
            )

            log(
                f"[PairingDiag] Field verification: "
                f"PIN length={pin_length}; name length={name_length}"
            )

            if pin_length != 4:
                raise RuntimeError(
                    f"PIN input contains {pin_length} characters after fill."
                )

            if name_length != len(name):
                raise RuntimeError(
                    "Device-name field length differs from submitted name."
                )

        except Exception as error:
            log(
                f"[PairingDiag] Field verification failed: "
                f"{type(error).__name__}: {error}"
            )
            raise

        log(
            "[Pairing] Submitting the actual Sunshine form. "
            "No direct Python POST to /api/pin will be made."
        )

        started = time.monotonic()
        response_info = None

        try:
            # Wait for the actual POST generated by the Sunshine UI.
            # Do not navigate away or refresh /pin after submission:
            # a pairing handshake may still be in progress.
            with page.expect_response(
                lambda response: (
                    urllib.parse.urlparse(response.url)
                    .path.rstrip("/")
                    .lower() == "/api/pin"
                    and response.request.method.upper() == "POST"
                ),
                timeout=120000,
            ) as response_info_context:
                log("[PairingDiag] Clicking the selected submit button...")
                submit_button.click(timeout=15000)
                log(
                    "[PairingDiag] Click returned. Waiting for "
                    "Sunshine POST /api/pin response..."
                )

            response_info = response_info_context.value
            elapsed = time.monotonic() - started

            response_status = response_info.status
            response_url = safe_url(response_info.url)

            try:
                response_content = response_info.text()
            except Exception as error:
                response_content = ""
                log(
                    f"[PairingDiag] Could not read response body: "
                    f"{type(error).__name__}: {error}"
                )

            log(
                f"[Pairing] POST /api/pin response received after "
                f"{elapsed:.2f}s."
            )

            log(f"[Pairing] Response URL: {response_url}")
            log(f"[Pairing] HTTP status: {response_status}")
            log(
                "[Pairing] Response body: "
                + safe_response_text(response_content)
            )

            result = SunshineClient.parse_json(response_content)

            log(
                "[Pairing] Parsed JSON: "
                + json.dumps(result, ensure_ascii=False)
            )

            log(
                f"[PairingDiag] Page URL after POST: "
                f"{safe_url(page.url)}"
            )

            self._dump_page_state("immediately after /api/pin response")

            if response_status == 200 and result.get("status") is True:
                log(
                    "[Pairing] Sunshine returned status=true for the "
                    "PIN request. This confirms the HTTP/API response, "
                    "but does not by itself prove Moonlight completed "
                    "the entire pairing handshake."
                )

                return True, (
                    "Sunshine принял PIN-запрос. "
                    "Если Moonlight всё ещё показывает ошибку, "
                    "смотри логи Sunshine и Moonlight: HTTP-ответ "
                    "не гарантирует завершение handshake."
                )

            log(
                "[Pairing] Sunshine did not return the expected "
                "HTTP 200 + status=true combination."
            )

            return False, (
                f"Sunshine вернул HTTP {response_status}; "
                "подробности находятся в логах Actions."
            )

        except Exception as error:
            elapsed = time.monotonic() - started

            log(
                f"[Pairing] Submission/wait failed after "
                f"{elapsed:.2f}s."
            )

            log(
                f"[Pairing] Exception type={type(error).__name__}; "
                f"message={error}"
            )

            log(
                f"[PairingDiag] Current page URL: "
                f"{safe_url(page.url)}"
            )

            self._dump_page_state("pairing exception")

            # Intentionally do NOT navigate back to /pin here.
            # Refreshing the page can disturb a pending pairing flow.
            log(
                "[PairingDiag] Leaving the current page untouched after "
                "the failure to avoid interrupting a pending handshake."
            )

            return False, (
                "Не удалось получить ожидаемый ответ от Sunshine. "
                "Подробности смотри в логах Actions."
            )

    # --------------------------------------------------------
    # CLEANUP
    # --------------------------------------------------------

    def close(self):
        log("[Browser] Closing Chromium resources...")

        if self.context is not None:
            try:
                self.context.close()
            except Exception as error:
                log(f"[Browser] Context close warning: {error}")
            self.context = None

        if self.browser is not None:
            try:
                self.browser.close()
            except Exception as error:
                log(f"[Browser] Browser close warning: {error}")
            self.browser = None

        if self.playwright is not None:
            try:
                self.playwright.stop()
            except Exception as error:
                log(f"[Browser] Playwright stop warning: {error}")
            self.playwright = None

        self.page = None
        self._events_attached = False

        log("[Browser] Chromium stopped.")


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

        log(
            f"[SunshineHTTP] {method} {safe_url(url)}; "
            f"timeout={timeout}s; auth={'yes' if auth else 'no'}"
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

                log(
                    f"[SunshineHTTP] HTTP {response.status}; "
                    f"URL={safe_url(response.geturl())}; "
                    f"elapsed={time.monotonic() - started:.2f}s"
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
                f"[SunshineHTTP] HTTP ERROR {error.code}; "
                f"URL={safe_url(error.geturl())}; "
                f"Location={safe_url(error.headers.get('Location', ''))}; "
                f"elapsed={time.monotonic() - started:.2f}s; "
                f"response={safe_response_text(content, 500)}"
            )

            return (
                error.code,
                error.geturl(),
                content,
            )

        except Exception as error:
            log(
                f"[SunshineHTTP] Request failed for {safe_url(url)}; "
                f"elapsed={time.monotonic() - started:.2f}s; "
                f"error={type(error).__name__}: {error}"
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
                f"[Sunshine] Auth check failed: "
                f"HTTP {status}; URL={safe_url(url)}"
            )
            return False

        result = self.parse_json(content)

        if not result and content.strip().lower().startswith(
            ("<!doctype html", "<html")
        ):
            log("[Sunshine] API returned HTML instead of JSON.")
            return False

        if result.get("status") is False:
            log("[Sunshine] API reported authentication failure.")
            return False

        log("[Sunshine] Admin API responded successfully.")
        return True

    # --------------------------------------------------------
    # INITIAL SETUP
    # --------------------------------------------------------

    def ensure_setup(self):
        if not SUNSHINE_USER or not SUNSHINE_PASSWORD:
            log(
                "[Sunshine] SUNSHINE_USER or SUNSHINE_PASSWORD is missing."
            )
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

        log("[Sunshine] Setup/authentication completed successfully.")
        return True

    # --------------------------------------------------------
    # REFRESH PIN PAGE
    # --------------------------------------------------------

    def refresh_pin_page(self):
        status, url, content = self.request(
            "/pin",
            method="GET",
            auth=True,
        )

        final_path = (
            urllib.parse.urlparse(url).path.rstrip("/").lower()
        )

        if status == 200 and final_path != "/welcome":
            log(f"[Sunshine] /pin checked successfully: {safe_url(url)}")
        else:
            log(
                f"[Sunshine] /pin check failed: "
                f"HTTP {status}; URL={safe_url(url)}"
            )

        return status, url, content

    # --------------------------------------------------------
    # PAIRING THROUGH THE ACTUAL BROWSER PAGE
    # --------------------------------------------------------

    def pair(self, pin, name):
        log("[Pairing] Starting pre-flight checks.")

        status, url, _ = self.refresh_pin_page()

        final_path = (
            urllib.parse.urlparse(url).path.rstrip("/").lower()
        )

        if status != 200 or final_path == "/welcome":
            return False, (
                "Sunshine недоступен на PIN-странице. "
                "Проверь логи первоначальной настройки."
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

        log("[Panel] Incoming pairing request.")

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

        except Exception as error:
            log(
                f"[Panel] Invalid request body: "
                f"{type(error).__name__}: {error}"
            )

            self.send_json(400, {
                "ok": False,
                "message": "Некорректное тело запроса.",
            })
            return

        pin = str(payload.get("pin", "")).strip()
        name = str(payload.get("name", "")).strip()

        # Never print the PIN.
        log(
            f"[Panel] Payload validated structurally: "
            f"PIN length={len(pin)}; name length={len(name)}."
        )

        if not re.fullmatch(r"[0-9]{4}", pin):
            log("[Panel] Request rejected: PIN format is invalid.")

            self.send_json(400, {
                "ok": False,
                "message": "PIN должен содержать ровно 4 цифры.",
            })
            return

        if not name or len(name) > 100:
            log("[Panel] Request rejected: invalid device name.")

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
            log("[Panel] Request rejected: another pairing is active.")

            self.send_json(409, {
                "ok": False,
                "message": "Другой запрос pairing уже обрабатывается.",
            })
            return

        started = time.monotonic()

        try:
            log("[Panel] Pairing lock acquired; starting pairing flow.")

            ok, message = SUNSHINE.pair(pin, name)

            log(
                f"[Panel] Pairing flow returned ok={ok}; "
                f"elapsed={time.monotonic() - started:.2f}s; "
                f"message={message!r}"
            )

            self.send_json(200 if ok else 502, {
                "ok": ok,
                "message": message,
            })

        except Exception as error:
            log(
                f"[Panel] Unhandled pairing error: "
                f"{type(error).__name__}: {error}"
            )

            self.send_json(500, {
                "ok": False,
                "message": "Внутренняя ошибка pairing. Проверь логи Actions.",
            })

        finally:
            PAIR_LOCK.release()
            log("[Panel] Pairing lock released.")

    def log_message(self, fmt, *args):
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

    log("=" * 60)
    log("SUNSHINE MOONLIGHT PAIRING PANEL")
    log("=" * 60)

    log(f"[Config] Panel bind address: {HOST}:{PORT}")
    log(f"[Config] Sunshine admin URL: {SUNSHINE_API}/pin")
    log("[Config] Chromium headless=True")
    log("[Config] PIN values and credentials will not be logged.")

    setup_ok = False

    for attempt in range(1, 16):
        log(f"[Sunshine] Setup/auth check {attempt}/15")

        if SUNSHINE.ensure_setup():
            setup_ok = True
            break

        if attempt < 15:
            log(
                f"[Sunshine] Setup check failed; "
                f"retrying in {POLL_INTERVAL}s."
            )
            time.sleep(POLL_INTERVAL)

    if not setup_ok:
        SUNSHINE_BROWSER.close()

        raise SystemExit(
            "Sunshine initial setup/authentication failed. "
            "See the Sunshine and Browser logs above."
        )

    # IMPORTANT:
    # TCPServer keeps sync_playwright calls on the same thread
    # where the Playwright instance was created.
    class PairingServer(socketserver.TCPServer):
        allow_reuse_address = True

    try:
        with PairingServer((HOST, PORT), PairHandler) as server:
            log(f"[Panel] Listening on http://{HOST}:{PORT}/")
            log("[Browser] Headless Chromium is ready on Sunshine /pin.")

            server.serve_forever()

    except KeyboardInterrupt:
        log("[Panel] Shutting down.")

    finally:
        SUNSHINE_BROWSER.close()


if __name__ == "__main__":
    main()
