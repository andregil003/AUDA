"""Servidor de la interfaz local; solo loopback, sin dependencias externas."""
import json
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from src import workspace

WEB = Path(__file__).resolve().parent / 'web'


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address=('127.0.0.1', 0), directory=workspace.STORE):
        self.token = secrets.token_urlsafe(32)
        self.directory = directory
        super().__init__(address, Handler)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def reply(self, status, payload, content_type='application/json; charset=utf-8'):
        data = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(data)

    def valid_host(self):
        return self.headers.get('Host') == f'127.0.0.1:{self.server.server_port}'

    def do_GET(self):
        if not self.valid_host():
            return self.reply(403, {'error': 'Host no permitido.'})
        path = urlsplit(self.path).path
        assets = {'/': ('index.html', 'text/html; charset=utf-8'),
                  '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                  '/style.css': ('style.css', 'text/css; charset=utf-8')}
        try:
            if path in assets:
                name, kind = assets[path]
                data = (WEB / name).read_bytes()
                if name == 'index.html':
                    data = data.replace(b'__TOKEN__', self.server.token.encode())
                return self.reply(200, data, kind)
            if path == '/api/bootstrap':
                return self.reply(200, {'catalogo': workspace.catalog(), 'inventario': workspace.inventory(),
                                        'historial': workspace.history(self.server.directory)})
            if path.startswith('/api/report/'):
                return self.reply(200, workspace.load(path.rsplit('/', 1)[-1], self.server.directory))
            return self.reply(404, {'error': 'No encontrado.'})
        except (FileNotFoundError, ValueError):
            self.reply(404, {'error': 'Reporte no disponible.'})
        except OSError:
            self.reply(500, {'error': 'No se pudieron leer los datos locales.'})

    def do_POST(self):
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            return self.reply(400, {'error': 'Longitud inválida.'})
        if not 0 < length <= 16384:
            return self.reply(413, {'error': 'Solicitud demasiado grande o vacía.'})
        raw = self.rfile.read(length)
        origin = self.headers.get('Origin')
        expected = f'http://127.0.0.1:{self.server.server_port}'
        if (not self.valid_host() or origin not in (None, expected)
                or self.headers.get('X-AUDA-Token') != self.server.token):
            return self.reply(403, {'error': 'Solicitud no autorizada.'})
        if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
            return self.reply(415, {'error': 'Se requiere JSON.'})
        try:
            body = json.loads(raw)
            if not isinstance(body, dict):
                raise ValueError('Solicitud inválida.')
            if self.path == '/api/analyze':
                report = workspace.analyze(body.get('urls'))
                workspace.save(report, self.server.directory)
            elif self.path == '/api/action':
                report = workspace.update_action(body.get('report_id'), body.get('finding_id'),
                                                 body.get('action_id'), body.get('done'), self.server.directory)
            else:
                return self.reply(404, {'error': 'No encontrado.'})
            self.reply(200, report)
        except (ValueError, TypeError, KeyError) as exc:
            self.reply(400, {'error': str(exc)})
        except FileNotFoundError:
            self.reply(404, {'error': 'Reporte no encontrado.'})
        except OSError:
            self.reply(500, {'error': 'No se pudo guardar en disco. Revisa permisos y espacio.'})
