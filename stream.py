import http.server
import socketserver
import os
import time
import sys

PORT = 5901
tmp_file = '/tmp/live.jpg'

class MJPEGHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = """
            <html>
            <head>
                <title>Mac Cloud PC Live Stream</title>
                <style>
                    body { background:#111; margin:0; display:flex; justify-content:center; align-items:center; height:100vh; overflow:hidden; }
                    img { max-width:100%; max-height:100vh; object-fit:contain; }
                </style>
            </head>
            <body>
                <img src="/stream.mjpeg"/>
            </body>
            </html>
            """
            self.wfile.write(html.encode())
        elif self.path.startswith('/stream.mjpeg'):
            self.send_response(200)
            self.send_header('Content-type', 'multipart/x-mixed-replace; boundary=--jpgboundary')
            self.end_headers()
            while True:
                try:
                    # Захват кадра средствами встроенной утилиты macOS в RAM-диск /tmp
                    os.system(f'screencapture -x -t jpg {tmp_file} >/dev/null 2>&1')
                    with open(tmp_file, 'rb') as f:
                        img_data = f.read()
                    self.wfile.write(b'--jpgboundary\r\n')
                    self.send_header('Content-type', 'image/jpeg')
                    self.send_header('Content-length', str(len(img_data)))
                    self.end_headers()
                    self.wfile.write(img_data)
                    self.wfile.write(b'\r\n')
                    time.sleep(0.1) # ~10 FPS
                except Exception:
                    break
        else:
            self.send_error(404)

socketserver.TCERver = socketserver.TCPServer
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("", PORT), MJPEGHandler) as httpd:
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
