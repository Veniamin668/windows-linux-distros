import http.server
import socketserver
import os
import time
import sys
import urllib.parse

PORT = 5901
tmp_file = '/tmp/live.jpg'

# Автоопределение пути к cliclick на macOS
if os.path.exists("/opt/homebrew/bin/cliclick"):
    CLICLICK = "/opt/homebrew/bin/cliclick"
else:
    CLICLICK = "/usr/local/bin/cliclick"

class KVMHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Обработка кликов из браузера
        if self.path.startswith('/click?'):
            parsed = urllib.parse.urlparse(self.path)
            params = urllib.parse.parse_qs(parsed.query)
            if 'x' in params and 'y' in params:
                x = params['x'][0]
                y = params['y'][0]
                # Выполняем клик в графической сессии пользователя 501
                os.system(f'sudo launchctl asuser 501 {CLICLICK} c:{x},{y}')
            
            self.send_response(200)
            self.end_headers()
            return

        # Главная страница с плеером и JS-обработчиком кликов
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            html = """
            <html>
            <head>
                <title>Mac Cloud PC - Web KVM</title>
                <style>
                    body { background:#111; margin:0; display:flex; justify-content:center; align-items:center; height:100vh; overflow:hidden; font-family:sans-serif; }
                    .container { position: relative; max-width:100%; max-height:100vh; }
                    img { display: block; max-width:100%; max-height:100vh; object-fit:contain; cursor: crosshair; }
                </style>
            </head>
            <body>
                <div class="container">
                    <img id="screen" src="/stream.mjpeg" draggable="false"/>
                </div>
                <script>
                    const img = document.getElementById('screen');
                    
                    img.addEventListener('click', function(e) {
                        // Получаем реальные размеры картинки, как она отображается в браузере
                        const rect = img.getBoundingClientRect();
                        
                        # Вычисляем относительные координаты клика (от 0 до 1)
                        const relX = (e.clientX - rect.left) / rect.width;
                        const relY = (e.clientY - rect.top) / rect.height;
                        
                        # Переводим в жесткое разрешение нашего виртуального экрана BetterDisplay (1920x1080)
                        const macX = Math.round(relX * 1920);
                        const macY = Math.round(relY * 1080);
                        
                        # Отправляем фоновый запрос на клик без перезагрузки страницы
                        fetch(`/click?x=${macX}&y=${macY}`);
                    });
                </script>
            </body>
            </html>
            """
            self.wfile.write(html.encode('utf-8'))
            
        elif self.path.startswith('/stream.mjpeg'):
            self.send_response(200)
            self.send_header('Content-type', 'multipart/x-mixed-replace; boundary=--jpgboundary')
            self.end_headers()
            while True:
                try:
                    os.system(f'screencapture -x -t jpg {tmp_file} >/dev/null 2>&1')
                    with open(tmp_file, 'rb') as f:
                        img_data = f.read()
                    self.wfile.write(b'--jpgboundary\(\r\\)n')
                    self.send_header('Content-type', 'image/jpeg')
                    self.send_header('Content-length', str(len(img_data)))
                    self.end_headers()
                    self.wfile.write(img_data)
                    self.wfile.write(b\('\r\\)n')
                    time.sleep(0.1)
                except Exception:
                    break
        else:
            self.send_error(404)

socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("", PORT), KVMHandler) as httpd:
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
