"""Publicaciones oficiales de parches, separadas del catálogo de explotación KEV."""
import hashlib
import json
import re
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from src import intelligence as intel

MSRC='https://api.msrc.microsoft.com/cvrf/v3.0'
CHROME='https://chromereleases.googleblog.com/feeds/posts/default?alt=json&max-results=40'


class Text(HTMLParser):
    def __init__(self):super().__init__();self.parts=[]
    def handle_data(self,data):self.parts.append(data)


def plain(html):
    parser=Text();parser.feed(html);return ' '.join(parser.parts)


def value(item):
    return item.get('Value','') if isinstance(item,dict) else str(item or '')


def windows_product(name,os_info):
    """Exige familia, release y arquitectura; excluye .NET, Server y otros componentes."""
    family='Windows 11' if os_info['familia']=='Windows 11' else 'Windows 10' if os_info['familia']=='Windows 10' else None
    if not family:return False
    release=os_info.get('version','')
    arch={'AMD64':'x64','x86_64':'x64','ARM64':'ARM64','aarch64':'ARM64','x86':'32-bit'}.get(os_info.get('arquitectura'))
    if not arch or not re.fullmatch(r'\d{2}H[12]',release):return False
    return bool(re.fullmatch(re.escape(family)+r' Version '+re.escape(release)+r' for '+re.escape(arch)+r'-based Systems',name,re.I))


def parse_msrc(document,host,identity,release):
    products={str(p['ProductID']):p['Value'] for p in document.get('ProductTree',{}).get('FullProductName',[])
              if windows_product(p.get('Value',''),host['sistema_operativo'])}
    entries=[]
    for vuln in document.get('Vulnerability',[]):
        cve=vuln.get('CVE','')
        if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cve):continue
        affected={str(pid) for s in vuln.get('ProductStatuses',[]) if s.get('Type')==3 for pid in s.get('ProductID',[])}
        for remedy in vuln.get('Remediations',[]):
            if remedy.get('Type')!=2:continue
            selected=set(map(str,remedy.get('ProductID',[])))&affected&products.keys()
            for pid in selected:
                kb_match=re.fullmatch(r'(?:KB)?(\d{6,8})',value(remedy.get('Description')).strip(),re.I)
                kb='KB'+kb_match[1] if kb_match else None
                fixed=remedy.get('FixedBuild') or None
                # No inventar un parche cuando el fabricante no da KB/build utilizable.
                if not kb and not fixed:continue
                notes=' '.join(value(n.get('Title'))+' '+value(n) for n in vuln.get('Notes',[]) if n.get('Type') in (1,2))
                refs=[r.get('URL') for r in vuln.get('Remediations',[]) if r.get('Type') in (0,1) and str(r.get('URL','')).startswith('https://')]
                entries.append({'cveID':cve,'product':identity['nombre'],'vendorProject':'Microsoft',
                    'identity_key':identity['key'],'vulnerabilityName':value(vuln.get('Title')),
                    'shortDescription':plain(notes)[:2500] or value(vuln.get('Title')),
                    'dateAdded':release.get('InitialReleaseDate','')[:10],
                    'modified':release.get('CurrentReleaseDate',''), 'editor':'Microsoft MSRC',
                    'url':'https://msrc.microsoft.com/update-guide/vulnerability/'+cve,
                    'requiredAction':f'Consultar el parche {kb or fixed} para {products[pid]}.',
                    'patch':{'tipo':'windows','producto_exacto':products[pid],'product_id':pid,'kb':kb,
                        'fixed_build':fixed,'url':remedy.get('URL') if str(remedy.get('URL','')).startswith('https://') else 'https://msrc.microsoft.com/update-guide/vulnerability/'+cve,
                        'reinicio':value(remedy.get('RestartRequired')) or 'Consultar el aviso',
                        'sustitucion':remedy.get('Supercedence',''),'mitigaciones':refs}})
    return entries


def chrome_version(text):
    """Solo una publicación que declare versión para Windows en su primer párrafo."""
    intro=re.split(r'Security Fixes|Security fixes|Security',text,maxsplit=1)[0][:1800]
    found=re.search(r'(\d+\.\d+\.\d+\.\d+)(?:/\.?(\d+))?\s*(?:for\s+(?:Windows(?:\s+and\s+Mac)?|Mac\s+and\s+Windows)\b|\(?Windows/Mac\)?|\(Windows\))',intro,re.I)
    if not found:return None
    versions=[found[1]]
    if found[2]:versions.append(found[1].rsplit('.',1)[0]+'.'+found[2])
    # Usar la menor de las builds declaradas como corregidas; no marcar la otra como vulnerable.
    return min(versions,key=intel.numbers)


def parse_chrome(feed,identity):
    entries=[]
    for item in feed.get('feed',{}).get('entry',[]):
        title=item.get('title',{}).get('$t','')
        if not re.search(r'stable.*(?:desktop|windows)',title,re.I) or re.search(r'extended|early',title,re.I):continue
        text=plain(item.get('content',{}).get('$t',''))
        target=chrome_version(text)
        if not target:continue
        link=next((l['href'] for l in item.get('link',[]) if l.get('rel')=='alternate' and l.get('href','').startswith('https://chromereleases.googleblog.com/')),None)
        if not link:continue
        for cve in list(dict.fromkeys(re.findall(r'\bCVE-\d{4}-\d{4,}\b',text.upper()))):
            entries.append({'cveID':cve,'product':'Google Chrome','vendorProject':'Google','identity_key':identity['key'],
                'vulnerabilityName':title+' · '+cve,'shortDescription':f'Publicación oficial del canal Stable para Windows. Google declara la versión {target} y menciona {cve}.',
                'dateAdded':item.get('published',{}).get('$t','')[:10],'modified':item.get('updated',{}).get('$t',''),
                'url':link,'editor':'Google Chrome Releases','requiredAction':f'Actualizar Google Chrome Stable a {target} o una versión corregida posterior.',
                'patch':{'tipo':'version','fixed_version':target,'canal':'Stable Windows','url':link}})
    return entries


class Publishers:
    def __init__(self,directory,fetch=intel.fetch_json):self.directory=Path(directory);self.fetch=fetch

    def cached_get(self,url):
        self.directory.mkdir(parents=True,exist_ok=True)
        path=self.directory/(hashlib.sha256(url.encode()).hexdigest()+'.json')
        if path.exists() and time.time()-path.stat().st_mtime<300:
            try:return json.loads(path.read_text(encoding='utf-8'))
            except (ValueError,OSError):pass
        data=self.fetch(url)
        tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(data),encoding='utf-8');tmp.replace(path)
        return data

    def collect(self,host,identities):
        entries=[];states=[]
        windows=next((i for i in identities if i['key']=='windows'),None)
        if windows:
            try:
                listing=self.cached_get(MSRC+'/updates')
                releases=[r for r in listing.get('value',[]) if re.fullmatch(r'\d{4}-[A-Za-z]{3}',r.get('ID',''))
                          and r.get('InitialReleaseDate','')[:10]<=datetime.now(timezone.utc).date().isoformat()]
                releases.sort(key=lambda r:r.get('InitialReleaseDate',''),reverse=True)
                if not releases:raise ValueError('MSRC no devolvió publicaciones fechadas.')
                errors=[];completed=0
                for release in releases[:2]:
                    try:
                        document=self.cached_get(MSRC+'/cvrf/'+release['ID'])
                        entries.extend(parse_msrc(document,host,windows,release));completed+=1
                    except (ValueError,OSError) as exc:errors.append(release['ID']+': '+type(exc).__name__)
                states.append({'nombre':'Microsoft MSRC','url':MSRC+'/updates','estado':'ok' if not errors else 'parcial' if completed else 'error',
                               'publicacion':releases[0]['CurrentReleaseDate'],'detalle':'Últimos dos boletines mensuales; producto/release/arquitectura exactos. '+', '.join(errors)})
            except (OSError,ValueError) as exc:states.append({'nombre':'Microsoft MSRC','url':MSRC+'/updates','estado':'error','detalle':str(exc)})
        chrome=next((i for i in identities if i['key']=='chrome'),None)
        if chrome and host['sistema_operativo']['familia'].startswith('Windows'):
            try:
                data=self.cached_get(CHROME);new=parse_chrome(data,chrome);entries.extend(new)
                states.append({'nombre':'Google Chrome Releases','url':'https://chromereleases.googleblog.com/','estado':'ok',
                               'publicacion':max((e['modified'] for e in new),default=None),
                               'detalle':f'{len(new)} menciones CVE extraídas de los 40 posts más recientes; solo Stable para Windows con versión explícita.'})
            except (OSError,ValueError) as exc:states.append({'nombre':'Google Chrome Releases','url':'https://chromereleases.googleblog.com/','estado':'error','detalle':str(exc)})
        return entries,states


def applicable(host,identity,patch):
    if patch['tipo']=='version':
        current,target=intel.numbers(identity['version']),intel.numbers(patch.get('fixed_version'))
        if not current or not target:return 'pendiente',None,'No se puede comparar de forma fiable la versión del canal instalado.'
        if current[:1]!=target[:1] and current<target:
            return 'pendiente',patch['fixed_version'],'El aviso corresponde a otro major/canal; confirmar si este CVE aplica a la rama instalada.'
        if current>=target:return 'sin_coincidencia',patch['fixed_version'],'La versión instalada alcanza o supera la versión corregida publicada para Stable Windows.'
        return 'pendiente',patch['fixed_version'],f'Chrome {identity["version"]} es anterior a la versión de seguridad publicada {patch["fixed_version"]}. Hay una actualización recomendada; falta delimitar el rango afectado de este CVE para confirmar vulnerabilidad.'
    info=host['sistema_operativo']
    if not windows_product(patch['producto_exacto'],info):return 'pendiente',None,'El producto, release o arquitectura del parche no coincide exactamente con el equipo.'
    kb=patch.get('kb')
    if kb and kb.upper() in {p.upper() for p in host['actualizaciones']}:
        return 'sin_coincidencia',kb,f'{kb} aparece en las actualizaciones instaladas y corresponde al producto exacto de MSRC.'
    observed=info.get('build','');fixed=patch.get('fixed_build')
    pieces=observed.split('.')
    if len(pieces)==2:observed='10.0.'+observed
    cur,target=intel.numbers(observed),intel.numbers(fixed)
    if cur and target and cur[:3]==target[:3]:
        if cur>=target:return 'sin_coincidencia',kb or fixed,f'Build {observed} alcanza o supera {fixed} en la misma rama de mantenimiento; la corrección puede estar incluida por acumulación aunque no aparezca la KB original.'
        return 'expuesto',kb or fixed,f'El producto exacto coincide. Build {observed} es anterior a {fixed} y {kb or "la actualización"} no aparece en las KB visibles.'
    return 'pendiente',kb or fixed,'La ausencia de una KB no demuestra vulnerabilidad: falta una build corregida comparable o confirmar sustitución de parches.'
