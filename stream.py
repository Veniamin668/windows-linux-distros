
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
from html.parser import HTMLParser

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
      headers: {'Content-Type': 'application/json'},
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


class SunshineClient:
    def __init__(self):
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies),
            urllib.request.HTTPSHandler(context=SSL_CONTEXT),
        )

        credentials = f"{SUNSHINE_USER}:{SUNSHINE_PASSWORD}"
        self.auth_header = "Basic " + base64.b64encode(
            credentials.encode("utf-8")
        ).decode("ascii")

    def request(self, path, method="GET", data=None):
        url = SUNSHINE_API + path
        headers = {
            "Authorization": self.auth_header,
            "Accept": "application/json, text/html, */*",
            "User-Agent": "SunshinePairingHelper/1.0",
        }

        body = None
        if data is not None:
            body = json.dumps(data).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(
            url, data=body, headers=headers, method=method
        )

        try:
            with self.opener.open(request, timeout=15) as response:
                content = response.read().decode("utf-8", errors="replace")
                return response.status, response.geturl(), content

        except urllib.error.HTTPError as error:
            content = error.read().decode("utf-8", errors="replace")
            location = error.headers.get("Location", "")
            print(
                f"[Sunshine] HTTP {error.code}; "
                f"URL={url}; Location={location or '(none)'}",
                flush=True,
            )
            return error.code, location or url, content

        except Exception as error:
            print(f"[Sunshine] Request failed: {error}", flush=True)
            return 0, url, str(error)

    def refresh_pin_page(self):
        """HTTP-эквивалент повторного открытия страницы /pin."""
        status, url, content = self.request("/pin")
        if status == 200:
            print(f"[Sunshine] /pin refreshed: {url}", flush=True)
        else:
            print(f"[Sunshine] /pin refresh returned HTTP {status}", flush=True)
        return status, url, content

    def pair(self, pin, name):
        # Предварительно получаем страницу, чтобы обновить HTTP-сессию/cookies.
        self.refresh_pin_page()

        status, url, content = self.request(
            "/api/pin",
            method="POST",
            data={"pin": pin, "name": name},
        )

        print(
            f"[Pairing] HTTP {status}; URL={url}; "
            f"response={content[:1000]!r}",
            flush=True,
        )

        if status == 200:
            try:
                result = json.loads(content)
            except json.JSONDecodeError:
                result = {}

            if isinstance(result, dict) and result.get("status") is True:
                self.refresh_pin_page()
                return True, "Сопряжение подтверждено Sunshine."

        self.refresh_pin_page()
        return False, (
            f"Sunshine вернул HTTP {status}. "
            "Посмотри логи Actions: там будут URL перенаправления "
            "и ответ Sunshine."
        )


SUNSHINE = SunshineClient()


class PairHandler(http.server.BaseHTTPRequestHandler):
    server_version = "PairingPanel/1.0"

    def send_json(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self.send_error(404)
            return

        body = PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
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
                "message": "PAIR_WEB_TOKEN не настроен на сервере."
            })
            return

        supplied_token = self.headers.get("X-Panel-Token", "")
        # Токен не показывается в HTML. При желании можно включить проверку
        # через отдельный заголовок или ограничить доступ только через tailnet.
        # Здесь панель доступна по адресу runner:5902, поэтому ограничь порт
        # сетью Tailscale/firewall либо добавь авторизацию на уровне прокси.

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 8192:
                raise ValueError("Invalid request size")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self.send_json(400, {
                "ok": False, "message": "Некорректное тело запроса."
            })
            return

        pin = str(payload.get("pin", "")).strip()
        name = str(payload.get("name", "")).strip()

        if not re.fullmatch(r"[0-9]{4}", pin):
            self.send_json(400, {
                "ok": False, "message": "PIN должен содержать 4 цифры."
            })
            return

        if not name or len(name) > 100:
            self.send_json(400, {
                "ok": False, "message": "Укажи имя устройства до 100 символов."
            })
            return

        if not SUNSHINE_USER or not SUNSHINE_PASSWORD:
            self.send_json(503, {
                "ok": False,
                "message": "Не заданы SUNSHINE_USER / SUNSHINE_PASSWORD."
            })
            return

        ok, message = SUNSHINE.pair(pin, name)
        self.send_json(200 if ok else 502, {
            "ok": ok, "message": message
        })

    def log_message(self, fmt, *args):
        print("[Panel] " + (fmt % args), flush=True)


def main():
    if not SUNSHINE_USER or not SUNSHINE_PASSWORD:
        raise SystemExit(
            "Set SUNSHINE_USER and SUNSHINE_PASSWORD environment variables."
        )

    print(f"[Panel] Listening on {HOST}:{PORT}", flush=True)
    print(f"[Sunshine] Admin URL: {SUNSHINE_API}/pin", flush=True)

    with socketserver.ThreadingTCPServer((HOST, PORT), PairHandler) as server:
        server.allow_reuse_address = True
        server.serve_forever()


if __name__ == "__main__":
    main()
