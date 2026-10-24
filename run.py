"""python run.py abre AUDA en el navegador; los datos permanecen en esta PC."""
import argparse
import webbrowser
from gui.server import LocalServer


def main():
    parser = argparse.ArgumentParser(description='AUDA · Workspace local')
    parser.add_argument('--port', type=int, default=0, help='0 elige un puerto local libre')
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    with LocalServer(('127.0.0.1', args.port)) as server:
        url = f'http://127.0.0.1:{server.server_port}'
        print(f'AUDA disponible en {url}', flush=True)
        print('Datos guardados en historial/workspace. Ctrl+C para detener.', flush=True)
        if not args.no_browser:
            webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
