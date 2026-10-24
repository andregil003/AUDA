"""Evaluación determinista de un aviso verificado sobre un inventario simulado."""
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
HISTORY = ROOT / "historial" / "analisis"
STATUSES = ("Exposición potencial", "Sin coincidencia", "Por verificar")
# Hotfix mínimo por versión de mantenimiento; aviso CVE-2024-3400.
FIXES = {(10, 2): [3, 2, 5, 13, 16, 6, 3, 8, 3, 1],
         (11, 0): [3, 4, 4, 10, 1], (11, 1): [3, 1, 3]}

def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

def source():
    return read_json(ROOT / "data" / "fuente_verificada.json")

def evaluate(device):
    if device.get("producto") != "PAN-OS":
        return STATUSES[1], "El producto no coincide con el alcance de este aviso.", "—"
    version = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?", device.get("version") or "")
    if not version:
        return STATUSES[2], "Falta una versión interpretable; confirmar en el dispositivo.", "Confirmar versión"
    major, minor, patch, hotfix = (int(v or 0) for v in version.groups())
    branch = (major, minor)
    if branch not in FIXES:
        if branch in {(9, 0), (9, 1), (10, 0), (10, 1)} or branch > (11, 1):
            return STATUSES[1], "Rama fuera del alcance de este CVE.", "—"
        return STATUSES[2], "Rama no cubierta por la regla local.", "Consultar fabricante"
    fixes = FIXES[branch]
    if patch >= len(fixes) or hotfix >= fixes[patch]:
        return STATUSES[1], "Versión corregida para este CVE según el aviso.", "—"
    target = f"{major}.{minor}.{patch}-h{fixes[patch]}"
    if device.get("globalprotect") is False:
        return STATUSES[1], "GlobalProtect deshabilitado: no cumple la configuración requerida.", target
    if device.get("globalprotect") is not True:
        return STATUSES[2], "Confirmar si existe portal o gateway GlobalProtect.", target
    return STATUSES[0], f"PAN-OS {device['version']} anterior a {target}; GlobalProtect habilitado.", target

def analyze(url, inventory=None):
    url = url.strip()
    parsed = urlsplit(url)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Ingresa una URL http o https válida, sin credenciales.")
    reference = source()
    known = (parsed.hostname.lower() == "security.paloaltonetworks.com"
             and parsed.path.rstrip("/").upper() == "/CVE-2024-3400")
    inventory = inventory if inventory is not None else read_json(ROOT / "data" / "ambiente_demo.json")
    rows = []
    for device in inventory["dispositivos"]:
        status, evidence, fix = evaluate(device) if known else (
            STATUSES[2], "Esta URL necesita extracción y una regla de evaluación verificadas.", "Pendiente")
        rows.append({**device, "estado": status, "evidencia": evidence, "correccion": fix})
    counts = Counter(r["estado"] for r in rows)
    return {
        "id": datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid4().hex[:8],
        "fecha": datetime.now().astimezone().isoformat(timespec="seconds"),
        "url": url, "fuente": reference if known else None,
        "empresa": inventory.get("empresa", "Ambiente demo"), "simulado": True,
        "dispositivos": rows, "conteos": {s: counts[s] for s in STATUSES},
        "expuestos_internet": sum(r["estado"] == STATUSES[0] and r.get("internet") is True for r in rows),
    }

def save(report, directory=HISTORY):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (report["id"] + ".json")
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)
    return path

def history(directory=HISTORY):
    reports = []
    for path in sorted(Path(directory).glob("*.json"), reverse=True):
        try:
            report = read_json(path)
            if all(k in report for k in ("id", "fecha", "fuente", "url", "conteos", "dispositivos")):
                reports.append(report)
        except (ValueError, OSError):
            continue
    return reports
