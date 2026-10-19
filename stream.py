
import base64
import json
import os
import re
import ssl
import urllib.error
import urllib.request
import http.server
import socketserver
import hmac
from urllib.parse import urlparse

# Web-интерфейс
HOST = os.environ.get("PAIR_HOST", "0.0.0.0")
PORT = int(os.environ.get("PAIR_PORT", "5902"))

# Sunshine API
SUNSHINE_API = os.environ.get(
    "SUNSHINE_API",
    "https://127.0.0.1:47990"
).rstrip("/")

SUNSHINE_USER = os.environ.get("SUNSHINE_USER", "")
SUNSHINE_PASSWORD = os.environ.get("SUNSHINE_PASSWORD", "")

# Пароль доступа к веб-форме
WEB_TOKEN = os.environ.get("PAIR_WEB_TOKEN", "")

# Sunshine использует самоподписанный сертификат
SSL_CONTEXT = ssl._create_unverified_context()


PAGE = """<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sunshine Pairing</title>
<style>
* { box-sizing: border-box; }
body {
    margin: 0;
    background: #0c1018;
    color: #e8edf7;
    font: 16px system-ui, sans-serif;
    min-height: 100vh;
    display: grid;
    place-items: center;
    padding: 20px;
}
main {
    width: 100%;
    max-width: 480px;
    padding: 28px;
    background: #151c29;
    border: 1px solid #2a3549;
    border-radius: 18px;
}
h1 { margin-top: 0; font-size: 27px; }
p { color: #9baac0; line-height: 1.5; }
label { display: block; margin-top: 17px; }
input {
    display: block;
    width: 100%;
    margin-top: 7px;
    padding: 12px;
    border-radius: 9px;
    border: 1px solid #35435a;
    background: #0c121d;
    color: white;
    font: inherit;
}
button {
    margin-top: 23px;
    width: 100%;
    padding: 13px;
    border: 0;
    border-radius: 9px;
    background: #657dff;
    color: white;
    font: inherit;
    font-weight: 700;
    cursor: pointer;
}
button:disabled { opacity: .5; }
#result {
    margin-top: 18px;
    white-space: pre-wrap;
    overflow-wrap: anywhere;
}
</style>
</head>
<body>
<main>
<h1>🌌 Sunshine Pairing</h1>
<p>Введи PIN, показанный в Moonlight, имя клиента и пароль веб-админки.</p>

<form id="pair">
<label>PIN Moonlight
<input name="pin" inputmode="numeric" pattern="[0-9]{4}"
       maxlength="4" minlength="4" required
       placeholder="1234">
</label>

<label>Имя клиента
<input name="name" maxlength="100"
       value="Moonlight Client" required>
</label>

<label>Пароль веб-админки
<input name="token" type="password" required
       autocomplete="current-password">
</label>

<button id="submit" type="submit">Подтвердить сопряжение</button>
</form>

<div id="result" role="status"></div>
</main>

<script>
const form = document.querySelector("#pair");
const result = document.querySelector("#result");
const button = document.querySelector("#submit");

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    result.textContent = "Отправляем запрос Sunshine...";
    button.disabled = true;

    try {
        const data = Object.fromEntries(new FormData(form).entries());
        const response = await fetch("/api/pair", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(data)
        });

        const body = await response.json();
        result.textContent = body.message ||
            (body.ok ? "Сопряжение успешно." : "Ошибка сопряжения.");

        result.style.color = body.ok ? "#65e6a1" : "#ff8888";
    } catch (error) {
        result.textContent = "Ошибка соединения с веб-сервером.";
        result.style.color = "#ff8888";
    } finally {
        button.disabled = false;
    }
});
</script>
</body>
</html>
"""


class ThreadingHTTPServer(
    socketserver.ThreadingMixIn,
    http.server.HTTPServer
):
    daemon_threads = True
    allow_reuse_address = True


class SunshinePairingHandler(http.server.BaseHTTPRequestHandler):
    server_version = "PairingPanel"
    sys_version = ""

    def log_message(self, fmt, *args):
        print("[WEB] " + (fmt % args), flush=True)

    def send_json(self, status, data):
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if urlparse(self.path).path != "/":
            self.send_error(404)
            return

        page = PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'unsafe-inline'; "
            "script-src 'unsafe-inline'; connect-src 'self'; "
            "base-uri 'none'; frame-ancestors 'none'"
        )
        self.end_headers()
        self.wfile.write(page)

    def do_POST(self):
        if urlparse(self.path).path != "/api/pair":
            self.send_json(404, {"ok": False, "message": "Not found"})
            return

        if not WEB_TOKEN:
            self.send_json(503, {
                "ok": False,
                "message": "Не задан PAIR_WEB_TOKEN."
            })
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0

        if length <= 0 or length > 8192:
            self.send_json(413, {
                "ok": False,
                "message": "Некорректный размер запроса."
            })
            return

        if "application/json" not in self.headers.get(
            "Content-Type", ""
        ).lower():
            self.send_json(415, {
                "ok": False,
                "message": "Ожидается JSON."
            })
            return

        try:
            data = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.send_json(400, {
                "ok": False,
                "message": "Некорректный JSON."
            })
            return

        if not isinstance(data, dict):
            self.send_json(400, {
                "ok": False,
                "message": "Ожидается объект JSON."
            })
            return

        token = data.get("token", "")
        if not isinstance(token, str) or not hmac.compare_digest(
            token, WEB_TOKEN
        ):
            self.send_json(403, {
                "ok": False,
                "message": "Неверный пароль веб-админки."
            })
            return

        pin = data.get("pin", "")
        name = data.get("name", "")

        if not isinstance(pin, str) or not re.fullmatch(r"\d{4}", pin):
            self.send_json(400, {
                "ok": False,
                "message": "PIN должен содержать ровно 4 цифры."
            })
            return

        if (
            not isinstance(name, str)
            or not name.strip()
            or len(name) > 100
        ):
            self.send_json(400, {
                "ok": False,
                "message": "Некорректное имя клиента."
            })
            return

        if not SUNSHINE_USER or not SUNSHINE_PASSWORD:
            self.send_json(503, {
                "ok": False,
                "message": "Не заданы SUNSHINE_USER и SUNSHINE_PASSWORD."
            })
            return

        # Pairing ID намеренно не передаётся.
        body = json.dumps({
            "pin": pin,
            "name": name.strip()
        }).encode("utf-8")

        credentials = base64.b64encode(
            f"{SUNSHINE_USER}:{SUNSHINE_PASSWORD}".encode("utf-8")
        ).decode("ascii")

        api_url = SUNSHINE_API + "/api/pin"

        request = urllib.request.Request(
            api_url,
            data=body,
            method="POST",
            headers={
                "Authorization": "Basic " + credentials,
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
        )

        print(f"[API] POST {api_url}", flush=True)
        print(f"[API] PIN supplied; client name: {name.strip()!r}",
              flush=True)

        try:
            with urllib.request.urlopen(
                request, context=SSL_CONTEXT, timeout=180
            ) as response:
                raw = response.read(1024 * 1024)
                status = response.status
                final_url = response.geturl()

            print(f"[API] HTTP {status}; final URL: {final_url}", flush=True)
            print(f"[API] Response body: {raw[:2000]!r}", flush=True)

            try:
                result = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.send_json(502, {
                    "ok": False,
                    "message": "Sunshine вернул некорректный JSON."
                })
                return

            if not isinstance(result, dict):
                result = {}

            if status == 200 and result.get("status") is True:
                print("[PAIR] Сопряжение подтверждено.", flush=True)
                self.send_json(200, {
                    "ok": True,
                    "message": "✅ Moonlight успешно сопряжён с Sunshine!"
                })
            else:
                print("[PAIR] Sunshine отклонил сопряжение.", flush=True)
                self.send_json(400, {
                    "ok": False,
                    "message": (
                        "Sunshine не подтвердил сопряжение. "
                        "Смотри вывод API в логах."
                    )
                })

        except urllib.error.HTTPError as exc:
            print(f"[API] HTTP error: {exc.code}", flush=True)
            print(f"[API] Request URL: {api_url}", flush=True)
            print(
                f"[API] Redirect Location: {exc.headers.get('Location', '')}",
                flush=True
            )
            try:
                error_body = exc.read(4096)
                print(f"[API] Error body: {error_body!r}", flush=True)
            except OSError:
                pass

            if exc.code == 307:
                redirect_url = exc.headers.get("Location", "")
                self.send_json(502, {
                    "ok": False,
                    "message": (
                        "Sunshine вернул HTTP 307. "
                        f"Адрес перенаправления: {redirect_url or 'не указан'}. "
                        "Подробности записаны в логи."
                    )
                })
                return

            message = {
                400: "Sunshine отклонил запрос. Проверь параметры API.",
                401: "Sunshine отклонил учётные данные.",
                403: "Sunshine запретил запрос.",
                404: "API-метод не найден. Проверь версию Sunshine.",
                409: "Запрос сопряжения конфликтует с текущим состоянием.",
            }.get(exc.code, f"Ошибка Sunshine API: HTTP {exc.code}")

            self.send_json(502, {"ok": False, "message": message})

        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"[API] Ошибка соединения: {type(exc).__name__}: {exc}",
                  flush=True)
            self.send_json(502, {
                "ok": False,
                "message": "Не удалось связаться с Sunshine API."
            })

        except Exception as exc:
            print(f"[API] Внутренняя ошибка: {type(exc).__name__}: {exc}",
                  flush=True)
            self.send_json(500, {
                "ok": False,
                "message": "Внутренняя ошибка веб-сервера."
            })


def main():
    if not WEB_TOKEN:
        print("[ERROR] Установи переменную PAIR_WEB_TOKEN.", flush=True)
        raise SystemExit(1)

    if not SUNSHINE_USER or not SUNSHINE_PASSWORD:
        print("[ERROR] Установи SUNSHINE_USER и SUNSHINE_PASSWORD.",
              flush=True)
        raise SystemExit(1)

    with ThreadingHTTPServer((HOST, PORT), SunshinePairingHandler) as server:
        print(f"[+] Sunshine Pairing UI: http://127.0.0.1:{PORT}/",
              flush=True)
        print(f"[+] Listen address: {HOST}:{PORT}", flush=True)
        print("[+] API endpoint: " + SUNSHINE_API + "/api/pin", flush=True)
        print("[!] Используй веб-панель только в доверенной сети.", flush=True)

        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[+] Сервер остановлен.", flush=True)


if __name__ == "__main__":
    main()
