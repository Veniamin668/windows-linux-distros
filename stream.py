import http.server
import socketserver
import subprocess
import json
import sys

PORT = 5902

class SunshinePairingHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Ожидаем запрос вида /XXXX, где XXXX - это 4 цифры ПИН-кода из Moonlight
        pin_code = self.path.strip('/')
        
        if pin_code.isdigit() and len(pin_code) == 4:
            print(f"[!] Перехвачен ПИН-код из браузера: {pin_code}. Отправляем в Sunshine...")
            
            # Формируем локальный POST-запрос к API Sunshine через встроенный curl.
            # Флаг -k нужен, так как Sunshine при старте генерирует самоподписанный SSL-сертификат.
            curl_cmd = [
                "curl", "-k", "-X", "POST", 
                "-H", "Content-Type: application/json",
                "-d", json.dumps({"pin": pin_code}),
                "https://localhost:47990/api/pin"
            ]
            
            try:
                subprocess.check_output(curl_cmd, stderr=subprocess.DEVNULL)
                
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                
                response_html = f"""
                <html>
                <body style="background:#111; color:#00ff00; font-family:sans-serif; text-align:center; padding-top:50px;">
                    <h1 style="font-size: 40px; margin-bottom: 10px;">УСПЕШНО СВЯЗАНО! 🚀</h1>
                    <p style="color:#aaa; font-size: 18px;">ПИН-код <b>{pin_code}</b> успешно отправлен и принят сервером Sunshine.</p>
                    <p style="color:#888;">Возвращайся в Moonlight на Windows — твой облачный Mac готов к стримингу!</p>
                </body>
                </html>
                """
                self.wfile.write(response_html.encode('utf-8'))
                return
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'text/plain; charset=utf-8')
                self.end_headers()
                self.wfile.write(f"Ошибка отправки запроса в Sunshine API: {str(e)}".encode('utf-8'))
                return
        
        # Если зашли просто на главную страницу порта 5902 без ПИН-кода
        self.send_response(200)
        self.send_header('Content-type', 'text/html; charset=utf-8')
        self.end_headers()
        html = """
        <html>
        <body style="background:#111; color:#fff; font-family:sans-serif; text-align:center; padding-top:100px;">
            <h1 style="font-size: 36px; margin-bottom: 20px;">Система Авто-Ввода ПИН Sunshine 🌌</h1>
            <p style="color:#aaa; font-size: 18px;">Чтобы привязать Moonlight, введи полученный 4-значный ПИН прямо в адресную строку браузера.</p>
            <p style="font-size:24px; color:#007bff; margin-top: 30px;">Пример: <b>http://runner-macosos:5902/1234</b></p>
        </body>
        </html>
        """
        self.wfile.write(html.encode('utf-8'))

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("", PORT), SunshinePairingHandler) as httpd:
    print(f"[+] Сервер авто-ввода ПИН успешно запущен на порту {PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
