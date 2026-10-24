"""Fuentes oficiales; no transmite inventario: KEV completo y NVD por CVE."""
import json
import gzip
import re
import time
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from src import workspace

KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
KEV_MIRROR = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json'
NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='
CACHE = workspace.ROOT / 'historial' / 'intelligence'


def fetch_json(url):
    req = Request(url, headers={'User-Agent': 'AUDA/1.0 vulnerability-monitor', 'Accept': 'application/json','Accept-Encoding':'gzip'})
    with urlopen(req, timeout=18) as response:
        reader=gzip.GzipFile(fileobj=response) if response.headers.get('Content-Encoding')=='gzip' else response
        data = reader.read(64_000_001)
    if len(data) > 64_000_000:
        raise ValueError('La respuesta excede el límite de lectura.')
    return json.loads(data)


class Sources:
    def __init__(self, directory=CACHE):
        self.directory = Path(directory)
        self.last_nvd = 0

    def cached(self, cve_id):
        if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cve_id):return None
        path=self.directory/(cve_id+'.json')
        if path.exists() and time.time()-path.stat().st_mtime<86400:
            try:return workspace.read(path)
            except (OSError,ValueError):pass
        return None

    def catalog(self):
        errors = []
        for url in (KEV_URL, KEV_MIRROR):
            try:
                data = fetch_json(url)
                if not isinstance(data.get('vulnerabilities'), list):
                    raise ValueError('Formato de KEV no válido.')
                return data, url
            except (OSError, ValueError) as exc:
                errors.append(type(exc).__name__)
        raise OSError('No se pudo consultar CISA ni su repositorio oficial (' + ', '.join(errors) + ').')

    def publications(self,host,identities):
        from src.publications import Publishers
        return Publishers(self.directory/'publishers').collect(host,identities)

    def cve(self, cve_id):
        if not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve_id):
            raise ValueError('CVE inválido.')
        path = self.directory / (cve_id + '.json')
        cached=self.cached(cve_id)
        if cached:return cached
        # NVD pública: como máximo una consulta cada 6,2 segundos por proceso.
        time.sleep(max(0, 6.2 - (time.monotonic() - self.last_nvd)))
        self.last_nvd = time.monotonic()
        data = fetch_json(NVD_URL + cve_id)
        if not data.get('vulnerabilities'):
            raise ValueError('NVD no tiene detalles para este CVE.')
        record = data['vulnerabilities'][0]['cve']
        self.directory.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record), encoding='utf-8')
        return record


# Identidades explícitas: evitan confundir Microsoft Edge con Edge de otro fabricante.
PRODUCTS = [
    ('chrome', 'Google Chrome', 'google', 'chrome', r'^google chrome$'),
    ('edge', 'Microsoft Edge', 'microsoft', 'edge', r'^microsoft edge$'),
    ('firefox', 'Mozilla Firefox', 'mozilla', 'firefox', r'^mozilla firefox(?:\s|$)'),
    ('7zip', '7-Zip', '7-zip', '7-zip', r'^7-zip\s'),
    ('winrar', 'WinRAR', 'rarlab', 'winrar', r'^winrar(?:\s|$)'),
    ('reader', 'Adobe Acrobat Reader', 'adobe', 'acrobat_reader', r'^adobe (?:acrobat reader|reader)(?:\s|$)'),
    ('acrobat', 'Adobe Acrobat', 'adobe', 'acrobat', r'^adobe acrobat(?:\s|$)'),
    ('vscode', 'Visual Studio Code', 'microsoft', 'visual_studio_code', r'^(?:microsoft )?visual studio code(?:\s|$)'),
    ('office', 'Microsoft Office', 'microsoft', 'office', r'^(?:microsoft )?(?:365|office)(?:\s|$)'),
    ('python', 'Python', 'python', 'python', r'^python\s\d.*(?:\(64-bit\)|\(32-bit\))$'),
    ('node', 'Node.js', 'nodejs', 'node.js', r'^node\.js$'),
    ('php', 'PHP', 'php', 'php', r'^php(?:\s|$)'),
]


def identities(host):
    result, seen = [], set()
    os_info = host['sistema_operativo']
    family = os_info['familia']
    if family.startswith('Windows'):
        result.append({'key':'windows', 'nombre':os_info['nombre'], 'version':os_info['build'],
                       'vendor':'microsoft', 'product':'windows', 'kind':'os', 'origen':'Sistema operativo de Python'})
    elif family == 'macOS':
        result.append({'key':'macos', 'nombre':'macOS', 'version':os_info['version'],
                       'vendor':'apple', 'product':'macos', 'kind':'os', 'origen':'Sistema operativo de Python'})
    for installed in host['programas']:
        for key, name, vendor, product, pattern in PRODUCTS:
            if re.search(pattern, installed['nombre'], re.I):
                pair = (key, installed['version'])
                if pair not in seen:
                    seen.add(pair)
                    result.append({'key':key, 'nombre':name, 'version':installed['version'], 'vendor':vendor,
                                   'product':product, 'kind':'app', 'origen':installed['origen']})
                break
    return result


def matches(entry, identity):
    product = entry.get('product', '').lower()
    vendor = entry.get('vendorProject', '').lower()
    if identity['key'] == 'windows':
        return 'microsoft' in vendor and re.search(r'\bwindows\b', product) is not None
    if identity['key'] == 'macos':
        return 'apple' in vendor and re.search(r'\bmac\s?os\b', product) is not None
    aliases = {'chrome':['chrome', 'chromium'], 'edge':['edge'], 'office':['office', 'word', 'excel', 'outlook'],
               'reader':['reader'], 'acrobat':['acrobat'], '7zip':['7-zip', '7zip'], 'vscode':['visual studio code'],
               'winrar':['winrar'], 'firefox':['firefox'], 'python':['python'], 'node':['node.js'], 'php':['php']}
    accepted_vendor = identity['vendor'].replace('-', '')
    actual_vendor = re.sub('[^a-z0-9]', '', vendor)
    if identity['key'] == '7zip':
        vendor_ok = '7zip' in actual_vendor or 'igor' in actual_vendor
    elif identity['key'] == 'winrar':
        vendor_ok = 'rarlab' in actual_vendor or 'winrar' in actual_vendor
    else:
        vendor_ok = accepted_vendor in actual_vendor
    return vendor_ok and any(re.search(r'(?<!\w)' + re.escape(term) + r'(?!\w)', product) for term in aliases[identity['key']])


def numbers(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d+(?:\.\d+)*', value): return None
    parts = tuple(map(int, value.split('.')))
    return parts + (0,) * max(0, 6-len(parts))


def version_check(identity, cve):
    """Solo confirma rangos numéricos simples. AND, negación y contexto quedan pendientes."""
    if identity['kind'] == 'os':
        if identity['key']=='windows':
            products=[]
            def products_in(node):
                for match in node.get('cpeMatch',[]):
                    parts=match.get('criteria','').split(':')
                    if len(parts)>5 and parts[3]=='microsoft' and match.get('vulnerable'):
                        products.append(parts[4])
                for child in node.get('nodes',[])+node.get('children',[]):products_in(child)
            for config in cve.get('configurations',[]):products_in(config)
            family='windows_11' if 'Windows 11' in identity['nombre'] else 'windows_10' if 'Windows 10' in identity['nombre'] else None
            os_products=[p for p in products if p.startswith('windows')]
            if family and os_products and all(p!=family and not p.startswith(family+'_') and p not in ('windows','windows_os') for p in os_products):
                return 'sin_coincidencia',None,'Los productos Windows identificados por NVD pertenecen a otras familias; no se atribuye este CVE a la familia detectada.'
        return 'pendiente', None, 'Falta contrastar edición, build y KB aplicable con el aviso del fabricante; Get-HotFix no demuestra cobertura completa.'
    current = numbers(identity['version'])
    if not current: return 'pendiente', None, 'La versión instalada no permite una comparación numérica fiable.'
    decisions = []
    def visit(node, complex_context=False):
        complex_context = complex_context or node.get('negate',False) or node.get('operator') == 'AND'
        for match in node.get('cpeMatch',[]):
            parts = match.get('criteria','').split(':')
            if len(parts)<13 or parts[3:5] != [identity['vendor'],identity['product']] or not match.get('vulnerable'): continue
            if complex_context or any(p not in ('*','-') for p in parts[6:]):
                decisions.append(('pendiente',None));continue
            target = None
            if parts[5] != '*':
                exact = numbers(parts[5]);inside = current == exact if exact else None
            else:
                inside = True
                bounds = [k for k in ('versionStartIncluding','versionStartExcluding','versionEndIncluding','versionEndExcluding') if k in match]
                if not bounds: inside = None
                for key in bounds:
                    bound = numbers(match[key])
                    if bound is None: inside = None;break
                    good = {'versionStartIncluding':current>=bound,'versionStartExcluding':current>bound,
                            'versionEndIncluding':current<=bound,'versionEndExcluding':current<bound}[key]
                    inside = inside and good
                target = match.get('versionEndExcluding')
            decisions.append(('expuesto' if inside is True else 'sin_coincidencia' if inside is False else 'pendiente',target))
        for child in node.get('nodes',[]) + node.get('children',[]): visit(child,complex_context)
    for config in cve.get('configurations',[]): visit(config)
    for state,target in decisions:
        if state == 'expuesto': return state,target,'La versión instalada coincide con un rango vulnerable numérico de NVD para el mismo producto.'
    if decisions and all(s=='sin_coincidencia' for s,t in decisions):
        return 'sin_coincidencia',None,'La versión instalada queda fuera de los rangos simples evaluados en NVD para este producto.'
    return 'pendiente',None,'No hay un rango simple y completo para confirmar aplicabilidad; revisar configuración, rama y aviso del fabricante.'


def extract_ids(text):
    if not isinstance(text,str) or len(text)>10000: raise ValueError('Entrada inválida.')
    found = list(dict.fromkeys(re.findall(r'\bCVE-\d{4}-\d{4,}\b',text.upper())))
    return found[:3]
