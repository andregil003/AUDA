"""Reportes trazables por noticia y dispositivo. Sin inspección de redes reales."""
import json
import re
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from pathlib import Path
from threading import RLock
from urllib.parse import urlsplit
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
STORE = ROOT / 'historial' / 'workspace'
LOCK = RLock()
STATUSES = ('expuesto', 'sin_coincidencia', 'pendiente')


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def catalog():
    return read(ROOT / 'data' / 'noticias_2026.json')


def inventory():
    return read(ROOT / 'data' / 'empresa_2026.json')


def canonical(url):
    if not isinstance(url, str) or len(url) > 2048:
        raise ValueError('La URL no es válida.')
    parsed = urlsplit(url.strip())
    if (parsed.scheme not in ('https', 'http') or not parsed.hostname
            or parsed.username or parsed.password or any(c.isspace() for c in url.strip())):
        raise ValueError('Pega enlaces http o https, uno por línea y sin credenciales.')
    try:
        port = parsed.port
    except ValueError:
        raise ValueError('Puerto inválido en la URL.') from None
    if port not in (None, 80, 443):
        raise ValueError('Usa el enlace público original de la noticia.')
    return (parsed.hostname.lower(), parsed.path.rstrip('/'))


def version_tuple(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d+\.\d+(?:\.\d+)?', value):
        return None
    parts = tuple(map(int, value.split('.')))
    return parts + (0,) * (3 - len(parts))


def evaluate(device, article):
    observed = device.get('version')
    parsed = version_tuple(observed)
    rules = article.get('versiones', {}).get(device['producto'], {})
    target = None
    if parsed:
        for branch, fixed in rules.items():
            prefix = tuple(map(int, branch.split('.')))
            if parsed[:len(prefix)] == prefix:
                target = fixed
                break
    condition = article.get('condicion')
    config = device.get(condition) if condition else None
    if not target:
        state = 'pendiente'
        reason = 'Versión ausente o rama no cubierta por la regla verificada. No se presume seguridad.'
    elif parsed >= version_tuple(target):
        state = 'sin_coincidencia'
        reason = f'{device["producto"]} {observed} incluye la corrección mínima {target} para este CVE.'
    elif condition and config is False:
        state = 'sin_coincidencia'
        reason = 'Versión anterior a la corrección, pero FortiCloud SSO está deshabilitado; no cumple la condición del ataque.'
    elif condition and config is not True:
        state = 'pendiente'
        reason = 'La versión es anterior a la corrección. Falta confirmar si FortiCloud SSO está habilitado.'
    else:
        state = 'expuesto'
        reason = f'{device["producto"]} {observed} es anterior a {target}.'
        if condition:
            reason += ' FortiCloud SSO está habilitado.'
    evidence = [deepcopy(e) for e in device.get('evidencias', []) if e.get('cve') == article['cve']]
    # Indicadores conservan su estado aun cuando el software ya fue actualizado.
    incident = 'indicios_simulados' if evidence else 'no_evaluado'
    priority = ('P0' if evidence else 'P1' if state == 'expuesto' else 'P2' if state == 'pendiente' else 'P3')
    args = dict(device, objetivo=target or 'una versión corregida confirmada por el fabricante')
    actions = []
    if state == 'expuesto' or evidence:
        keys = ['contencion', 'investigar', 'corregir', 'validar']
        labels = ['Reducir exposición', 'Buscar evidencia', 'Corregir el gap', 'Verificar el cierre']
        for key, label in zip(keys, labels):
            actions.append({'id': key, 'titulo': label, 'texto': article[key].format(**args),
                            'responsable': 'SOC / Respuesta a incidentes' if key == 'investigar' else device['responsable'],
                            'hecho': False})
    elif state == 'pendiente':
        actions = [{'id': 'inventariar', 'titulo': 'Completar evidencia de configuración',
                    'texto': f'En {device["nombre"]}, obtener versión completa y configuración del producto. Contrastar con {article["cve"]} y actualizar el inventario antes de emitir un dictamen.',
                    'responsable': device['responsable'], 'hecho': False}]
    else:
        actions = [{'id': 'mantener', 'titulo': 'Mantener y comprobar el control',
                    'texto': f'Conservar evidencia de versión y configuración de {device["nombre"]}. Esta conclusión solo aplica a {article["cve"]}; no certifica la seguridad general del equipo.',
                    'responsable': device['responsable'], 'hecho': False}]
    return {
        'id': article['id'] + ':' + device['id'], 'articulo_id': article['id'],
        'cve': article['cve'], 'dispositivo': deepcopy(device), 'estado': state,
        'compromiso': incident, 'evidencias': evidence, 'prioridad': priority,
        'gap': reason, 'impacto': article['impacto'], 'objetivo': target,
        'acciones': actions, 'fuente': article['url'],
        'metodo': 'Regla local de versión y configuración sobre inventario simulado',
    }


def analyze(urls, environment=None):
    if not isinstance(urls, list) or not 1 <= len(urls) <= 3:
        raise ValueError('Agrega entre una y tres noticias, una URL por línea.')
    environment = environment if environment is not None else inventory()
    articles, findings, seen = [], [], set()
    known = catalog()
    for url in urls:
        normalized = canonical(url)
        article = next((a for a in known if normalized in [canonical(u) for u in [a['url'], *a['aliases']]]), None)
        key = article['id'] if article else normalized
        if key in seen:
            continue
        seen.add(key)
        if not article:
            articles.append({'id': 'pendiente-' + str(len(articles)), 'url': url.strip(),
                             'titulo': 'Fuente pendiente de extracción', 'estado': 'pendiente',
                             'resumen': 'No existe una ficha verificada para esta URL. No se generaron hallazgos ni recomendaciones sobre su contenido.'})
            continue
        article = deepcopy(article)
        article.update(estado='evaluada', entrada=url.strip())
        related = [d for d in environment['dispositivos'] if d['producto'] in article['productos']]
        findings.extend(evaluate(d, article) for d in related)
        article['equipos_relacionados'] = len(related)
        articles.append(article)
    counts = Counter(f['estado'] for f in findings)
    exposed = {f['dispositivo']['id'] for f in findings if f['estado'] == 'expuesto'}
    checked = {f['dispositivo']['id'] for f in findings}
    return {
        'schema': 2, 'id': uuid4().hex,
        'fecha': datetime.now(timezone(timedelta(hours=-6))).isoformat(timespec='seconds'),
        'empresa': environment['nombre'], 'simulado': True,
        'articulos': articles, 'hallazgos': sorted(findings, key=lambda f: (f['prioridad'], f['dispositivo']['nombre'])),
        'inventario': deepcopy(environment['dispositivos']),
        'resumen': {'equipos': len(environment['dispositivos']), 'evaluados': len(checked),
                    'expuestos': len(exposed), 'indicios': len({f['dispositivo']['id'] for f in findings if f['evidencias']}),
                    'fuentes_pendientes': sum(a['estado'] == 'pendiente' for a in articles),
                    'evaluaciones': {s: counts[s] for s in STATUSES}},
    }


def report_path(report_id, directory=STORE):
    if not isinstance(report_id, str) or not re.fullmatch('[0-9a-f]{32}', report_id):
        raise ValueError('Identificador de reporte inválido.')
    return Path(directory) / (report_id + '.json')


def save(report, directory=STORE):
    path = report_path(report['id'], directory)
    with LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix('.' + uuid4().hex + '.tmp')
        temp.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        temp.replace(path)
    return path


def load(report_id, directory=STORE):
    with LOCK:
        return read(report_path(report_id, directory))


def history(directory=STORE):
    result = []
    for path in Path(directory).glob('*.json'):
        try:
            r = read(path)
            if r.get('schema') == 2:
                result.append({k: r[k] for k in ('id', 'fecha', 'empresa', 'resumen', 'articulos')}
                              | {k:r[k] for k in ('host_id','origen') if k in r})
        except (ValueError, OSError, KeyError, AttributeError):
            continue
    return sorted(result, key=lambda r: r['fecha'], reverse=True)


def update_action(report_id, finding_id, action_id, done, directory=STORE):
    if type(done) is not bool:
        raise ValueError('Estado de tarea inválido.')
    with LOCK:
        report = load(report_id, directory)
        finding = next((f for f in report['hallazgos'] if f['id'] == finding_id), None)
        action = next((a for a in finding['acciones'] if a['id'] == action_id), None) if finding else None
        if not action:
            raise ValueError('Tarea no encontrada.')
        action['hecho'] = done
        save(report, directory)
        return report
