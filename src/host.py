"""Inventario del host de Python mediante consultas de lectura."""
import hashlib
import json
import platform
import subprocess
from datetime import datetime, timezone


def command(args, timeout=20):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                          encoding='utf-8', errors='replace', creationflags=0x08000000 if platform.system() == 'Windows' else 0)


def windows_inventory():
    import winreg
    programs, notes, current = {}, [], {}
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows NT\CurrentVersion') as key:
        for name in ('ProductName', 'DisplayVersion', 'CurrentBuildNumber', 'UBR', 'EditionID'):
            try:
                current[name] = winreg.QueryValueEx(key, name)[0]
            except OSError:
                pass
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                with winreg.OpenKey(hive, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 0, winreg.KEY_READ | view) as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            with winreg.OpenKey(key, winreg.EnumKey(key, i)) as item:
                                def val(n):
                                    try: return str(winreg.QueryValueEx(item, n)[0])
                                    except OSError: return ''
                                name, version, vendor = val('DisplayName'), val('DisplayVersion'), val('Publisher')
                                if name:
                                    programs[(name, version)] = {'nombre': name, 'version': version or None, 'editor': vendor, 'origen': 'Registro de desinstalación de Windows'}
                        except OSError:
                            continue
            except OSError:
                notes.append('Una sección del registro de programas no estuvo accesible.')
    patches = []
    try:
        result = command(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                          '[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; @(Get-HotFix -ErrorAction Stop | Select-Object -ExpandProperty HotFixID) | ConvertTo-Json -Compress'])
        if result.returncode:
            raise ValueError('Get-HotFix no disponible')
        payload = json.loads(result.stdout.lstrip('\ufeff') or '[]')
        patches = payload if isinstance(payload, list) else [payload]
    except (OSError, subprocess.TimeoutExpired, ValueError):
        notes.append('No se pudieron consultar las actualizaciones con Get-HotFix.')
    build = str(current.get('CurrentBuildNumber', platform.version().split('.')[-1]))
    family = 'Windows 11' if build.isdigit() and int(build) >= 22000 else 'Windows 10' if build.isdigit() and int(build) >= 10240 else 'Windows'
    edition = current.get('EditionID', '')
    return {'nombre': f'{family} {edition}'.strip(), 'familia': family,
            'version': str(current.get('DisplayVersion', platform.release())),
            'build': f'{build}.{current.get("UBR", 0)}', 'arquitectura': platform.machine()}, sorted(programs.values(), key=lambda p:p['nombre'].lower()), patches, notes


def collect():
    system, notes = platform.system(), []
    os_info = {'nombre': f'{system} {platform.release()}', 'familia': system,
               'version': platform.release(), 'build': platform.version(), 'arquitectura': platform.machine()}
    programs, patches = [], []
    if system == 'Windows':
        try:
            os_info, programs, patches, notes = windows_inventory()
        except OSError:
            notes.append('No se pudo leer la versión detallada del registro de Windows.')
    elif system == 'Darwin':
        os_info.update(nombre='macOS', familia='macOS', version=platform.mac_ver()[0])
        notes.append('La recolección de programas y parches está implementada para Windows; en macOS solo se detecta el sistema.')
    else:
        notes.append('La recolección de programas y parches está implementada para Windows; en este host solo se detecta el sistema.')
    name = platform.node() or 'Equipo actual'
    return {'id': hashlib.sha256(name.encode()).hexdigest()[:16], 'nombre': name,
            'sistema_operativo': os_info, 'programas': programs, 'actualizaciones': patches,
            'capturado': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'notas': list(dict.fromkeys(notes)),
            'alcance': 'Registro de programas y Get-HotFix; no incluye todo el software portable, Store ni todas las clases de actualizaciones.'}
