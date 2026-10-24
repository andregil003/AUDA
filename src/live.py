"""Servicio compartido por UI, API y agentes. Revisión programada con presencia de UI."""
import hashlib
import json
import threading
import time
from copy import deepcopy
from datetime import datetime, timezone,timedelta
from pathlib import Path
from uuid import uuid4
from src import host as host_reader, intelligence as intel, workspace as w
from src.publications import applicable
from src.osi import classify
from src.article_reader import resolve


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def evidence_only(finding):
    if finding.get('revision_actual',{}).get('estado',finding.get('estado'))=='sin_coincidencia':
        finding['acciones']=[]
        finding['plan_soc']=finding['plan_agente']={'estado':'no_requiere_correccion','fuente':finding.get('fuente')}
    return finding


def action_plan(host, identity, entry, state, target):
    product, version, machine = identity['nombre'], identity['version'] or 'desconocida', host['nombre']
    cve = entry['cveID']
    if state=='sin_coincidencia':
        return [],{'estado':'no_requiere_correccion','fuente':entry.get('url') or 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext='+cve}
    steps = [
        ('preparar','Validar antes de corregir', f'En {machine}, comprobar {product} {version} contra {cve}. Registrar edición, arquitectura y configuración afectada. Si el estado está pendiente, no ejecutar una corrección hasta confirmar aplicabilidad.'),
        ('corregir','Aplicar la recomendación del fabricante', f'Para {product} en {machine}: {entry.get("requiredAction") or "Consultar el aviso oficial y su actualización de seguridad."} ' + (f'Objetivo documentado: {target}. Confirmar prerrequisitos y ruta soportada en el aviso enlazado.' if target else 'Obtener la versión corregida o KB exacta desde el aviso; AUDA no ha determinado un objetivo instalable.')),
        ('validar','Verificar el resultado', f'Releer la versión de {product} y las actualizaciones del equipo {machine}. Ejecutar una nueva evaluación de {cve}, comprobar funcionamiento y guardar evidencia. Marcar esta tarea no cierra el gap automáticamente.'),
    ]
    if state=='pendiente':
        steps=[('preparar','Reunir la evidencia faltante',f'En {machine}, confirmar la versión, edición y configuración de {product} para {cve}. Contrastar las condiciones y la corrección descritas en la fuente; no dar por aplicable el parche solo por coincidir el nombre.'),
               ('dictamen','Determinar si existe un gap',f'Documentar si {cve} aplica realmente a {product} {version}. Solo si se confirma un gap, preparar el cambio específico para el SOC; si no aplica, cerrar la verificación con su evidencia.')]
    prereqs = ['Confirmar que el producto, versión y configuración realmente están afectados.',
               'Revisar la ruta de actualización soportada y disponer de instalador oficial o KB validada.',
               'Contar con copia recuperable y ventana de mantenimiento si el cambio afecta disponibilidad.']
    checks = []
    if host['sistema_operativo']['familia'].startswith('Windows'):
        checks = [{'titulo':'Consultar Windows (lectura)', 'shell':'PowerShell',
                   'comando':"Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' | Select-Object ProductName,DisplayVersion,CurrentBuildNumber,UBR"},
                  {'titulo':'Consultar actualizaciones visibles (lectura)', 'shell':'PowerShell','comando':'Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID,InstalledOn'}]
    if entry.get('patch'):
        patch=entry['patch']
        prereqs.append('Fuente del parche: '+patch['url'])
        if patch['tipo']=='windows':
            prereqs.append(f'Producto exacto: {patch["producto_exacto"]}. Build corregida: {patch.get("fixed_build") or "por confirmar"}. Reinicio: {patch.get("reinicio","Consultar aviso")}.')
            if patch.get('kb'):
                checks.append({'titulo':'Comprobar la KB específica (lectura)','shell':'PowerShell',
                               'comando':f'Get-HotFix -Id {patch["kb"]} -ErrorAction SilentlyContinue'})
    return [{'id':key,'titulo':title,'texto':text,'responsable':'SOC / administrador del equipo','hecho':False} for key,title,text in steps], {
        'objetivo':f'Resolver {cve} para {product} {version} en {machine}',
        'estado':'requiere_validacion' if state=='pendiente' else 'requiere_revision_del_operador',
        'requisitos':prereqs, 'comandos_lectura':checks,
        'ejecucion': 'Instrucciones para el SOC. El agente consulta evidencia y entrega este plan; no ejecuta correcciones.',
        'riesgos':['La actualización puede exigir reinicio o interrumpir aplicaciones.', 'La versión o KB debe corresponder a la edición y arquitectura detectadas.'],
        'reversion':['Consultar si el fabricante admite desinstalar el parche o regresar de versión.', 'Si no hay reversión soportada, disponer de un respaldo recuperable y validar el procedimiento antes del cambio.'],
        'verificacion':['Recapturar inventario y repetir evaluación.', 'Conservar versión/build/KB posterior y pruebas funcionales.'],
        'fuente': entry.get('url') or 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext='+cve}


def make_finding(host, identity, entry, detail=None):
    state,target,reason = applicable(host,identity,entry['patch']) if entry.get('patch') else intel.version_check(identity, detail) if detail else ('pendiente',None,'Coincide el producto instalado con CISA KEV; faltan detalles de versión y configuración del aviso.')
    actions, plan = action_plan(host,identity,entry,state,target)
    did = host['id'] + ':' + identity['key'] + ':' + str(identity['version'])
    device = {'id':did,'nombre':host['nombre'],'producto':identity['nombre'],'version':identity['version'],
              'ip':'Equipo de Python','rol':'Dispositivo actual','responsable':'Operador local','internet':None,
              'sistema_operativo':host['sistema_operativo']['nombre'], 'build':host['sistema_operativo']['build']}
    references=[r['url'] for r in (detail or {}).get('references',[]) if isinstance(r.get('url'),str) and r['url'].startswith('https://')][:8]
    plan['referencias']=references
    osi=classify(entry.get('vulnerabilityName'),entry.get('shortDescription'),identity)
    return {'id':entry['cveID']+':'+did,'articulo_id':entry['cveID'], 'cve':entry['cveID'],
            'dispositivo':device,'estado':state,'compromiso':'no_evaluado','evidencias':[],
            'prioridad':'P1' if state=='expuesto' else 'P2' if state=='pendiente' else 'P3',
            'gap':reason,'impacto':entry.get('shortDescription','Consultar aviso oficial.'), 'objetivo':target,
            'acciones':actions, 'plan_soc':plan, 'plan_agente':plan, 'fuente':plan['fuente'],
            'osi':osi,'parche':entry.get('patch'),
            'evidencia_version':{'producto':identity['nombre'],'version':identity['version'],'origen':identity['origen']},
            'metodo':'Producto/release/arquitectura y KB/build del fabricante' if entry.get('patch') else 'Coincidencia explícita de producto CISA KEV; rangos simples NVD cuando están disponibles.'}


def report_for(host, findings, entries, source, origin):
    counts = {s:sum(f['estado']==s for f in findings) for s in w.STATUSES}
    articles = [{'id':e['cveID'],'cve':e['cveID'],'titulo':e.get('vulnerabilityName',e['cveID']),
                 'editor':e.get('editor','CISA KEV / NVD'),'fecha':e.get('dateAdded',''),'consultado':now()[:10],
                 'url':e.get('url') or 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext='+e['cveID'],
                 'contexto':e.get('shortDescription',''),'estado':'evaluada'} for e in entries]
    return {'schema':2,'id':uuid4().hex,'fecha':now(),'empresa':host['nombre'],'simulado':False,
            'origen':origin,'host_id':host['id'],'entorno':deepcopy(host),'fuente_descarga':source,
            'articulos':articles,'hallazgos':sorted(findings,key=lambda f:(f['prioridad'],f['cve'])),
            'inventario':[f['dispositivo'] for f in findings],
            'resumen':{'equipos':1,'evaluados':int(bool(findings)), 'expuestos':int(any(f['estado']=='expuesto' for f in findings)),
                       'indicios':0,'fuentes_pendientes':0,'evaluaciones':counts}}


class Service:
    def __init__(self, directory=w.STORE, collector=host_reader.collect, sources=None, interval=300, clock=time.monotonic):
        self.directory=Path(directory)
        self.collector,self.sources,self.interval,self.clock=collector,sources or intel.Sources(),interval,clock
        self.lock=threading.RLock();self.clients={};self.last_run=-float('inf');self.busy=False
        self.host=None;self.host_time=0;self.stop_event=threading.Event();self.worker=None
        self.status={'estado':'esperando_interfaz','ultima_revision':None,'ultimo_exito':None,'proxima_revision':None,
                     'fuente':'CISA KEV + NVD','error':None,'reporte_id':None,'nuevas':0,'intervalo_segundos':interval}
        self.state_path=self.directory/'_monitor.json'
        try: self.seen=set(w.read(self.state_path).get('seen',[]))
        except (OSError,ValueError): self.seen=set()

    def environment(self, refresh=False):
        with self.lock:
            if refresh or self.host is None or self.clock()-self.host_time>60:
                self.host=self.collector();self.host_time=self.clock()
            return deepcopy(self.host)

    def evaluations(self):
        try:
            data=w.read(self.directory/'_evaluations.json')
            if data.get('host_id')==self.environment()['id']:
                data['hallazgos']=[evidence_only(f) for f in data['hallazgos']]
                return data
        except (ValueError,OSError):pass
        return {'host_id':self.environment()['id'],'fecha':None,'hallazgos':[],'fuentes':[]}

    def report(self,report_id):
        report=w.load(report_id,self.directory)
        current=self.evaluations()
        if report.get('host_id')==current['host_id']:
            lookup={(f['cve'],f['dispositivo']['producto']):f for f in current['hallazgos']}
            for old in report['hallazgos']:
                match=lookup.get((old['cve'],old['dispositivo']['producto']))
                if match:old['revision_actual']={'fecha':current['fecha'],'estado':match['estado'],'gap':match['gap'],
                                               'version':match['dispositivo']['version']}
        report['hallazgos']=[evidence_only(f) for f in report['hallazgos']]
        return report

    def presence(self, client, active=True):
        if not isinstance(client,str) or not 1<=len(client)<=80: raise ValueError('Cliente inválido.')
        with self.lock:
            if active: self.clients[client]=self.clock()
            else: self.clients.pop(client,None)
        return self.snapshot()

    def present(self):
        self.clients={k:v for k,v in self.clients.items() if self.clock()-v<90}
        return bool(self.clients)

    def snapshot(self):
        with self.lock:
            active=self.present()
            status=deepcopy(self.status)
            status.update(interfaz_activa=active,ejecutando=self.busy)
            status['proxima_revision']=(datetime.now(timezone.utc)+timedelta(seconds=max(0,self.interval-(self.clock()-self.last_run)))).isoformat(timespec='seconds') if active and self.last_run!=-float('inf') else None
            if not active and not self.busy: status['estado']='pausado'
            return status

    def start(self):
        def loop():
            while not self.stop_event.wait(1):
                with self.lock: due=self.present() and not self.busy and self.clock()-self.last_run>=self.interval
                if due: self.trigger()
        self.worker=threading.Thread(target=loop,daemon=True);self.worker.start()

    def close(self):
        self.stop_event.set()
        if self.worker:self.worker.join(timeout=2)

    def trigger(self, manual=None):
        with self.lock:
            if self.busy:return self.snapshot()
            if self.clock()-self.last_run<30:
                return self.snapshot()  # Evita exceder fuentes públicas con clics o agentes repetidos.
            self.busy=True;self.last_run=self.clock();self.status.update(estado='revisando',error=None,entrada_manual=None)
        thread=threading.Thread(target=self._review,args=(manual,),daemon=True);thread.start()
        return self.snapshot()

    def _review(self, manual=None):
        try:
            host=self.environment(refresh=True);identities=intel.identities(host)
            resolved=[]
            if manual:
                for text in manual:
                    alias=next((a for a in w.catalog() if text.strip().rstrip('/') in [u.rstrip('/') for u in [a['url'],*a['aliases']]]),None)
                    resolved.append({'entrada':text,'cves':[alias['cve']],'estado':'ficha_local','detalle':'Referencia local ya catalogada; no se releyó la página.'} if alias else resolve(text))
            source_states=[];entries=[];source=''
            try:
                data,source=self.sources.catalog();entries=data['vulnerabilities']
                source_states.append({'nombre':'CISA KEV','url':source,'estado':'ok','publicacion':data.get('dateReleased'),'detalle':'Catálogo de explotación conocida; no es un feed de parches.'})
            except (OSError,ValueError) as exc:
                source_states.append({'nombre':'CISA KEV','url':intel.KEV_URL,'estado':'error','detalle':str(exc)})
            publisher_entries=[]
            if hasattr(self.sources,'publications'):
                publisher_entries,publisher_states=self.sources.publications(host,identities)
                source_states.extend(publisher_states)
            if not any(s['estado'] in ('ok','parcial') for s in source_states):
                raise OSError('No se pudieron consultar las fuentes oficiales. '+ '; '.join(s['detalle'] for s in source_states))
            entries+=publisher_entries
            source=' · '.join(s['nombre'] for s in source_states if s['estado'] in ('ok','parcial'))
            ids=None
            if manual:
                ids=list(dict.fromkeys(cve for result in resolved for cve in result['cves']))[:20]
                with self.lock:self.status['entrada_manual']={'fuentes':resolved,'cves':ids,'estado':'consultando_aplicabilidad'}
                # Para CVEs fuera de KEV se consulta NVD, sin afirmar explotación real.
                for cve_id in ids:
                    if not any(e['cveID']==cve_id for e in entries):
                        detail=self.sources.cve(cve_id)
                        description=next((d['value'] for d in detail.get('descriptions',[]) if d['lang']=='en'),'')
                        # Extraer identidad solo de CPE; no adivinar por palabras de una noticia.
                        for identity in identities:
                            if cpe_contains(detail,identity):
                                entries.append({'cveID':cve_id,'product':identity['nombre'],'vendorProject':identity['vendor'],
                                                'vulnerabilityName':cve_id,'shortDescription':description,'dateAdded':detail.get('published','')[:10],
                                                'requiredAction':'Revisar las referencias del registro NVD y aplicar la solución oficial del fabricante.','identity_key':identity['key'],
                                                'url':'https://nvd.nist.gov/vuln/detail/'+cve_id,'editor':'NVD'})
            merged={}
            for entry in sorted(entries,key=lambda e:(bool(e.get('patch')),e.get('dateAdded',''),e.get('modified',''))):
                if ids is not None and entry['cveID'] not in ids:continue
                for identity in identities:
                    # Si la fuente ya declara la identidad exacta, no volver a usar alias amplios.
                    related=entry['identity_key']==identity['key'] if entry.get('identity_key') else intel.matches(entry,identity)
                    if related:merged[(entry['cveID'],identity['key'],identity['version'])]=(entry,identity)
            vendor_pairs=[p for p in merged.values() if p[0].get('patch')]
            kev_pairs=[p for p in merged.values() if not p[0].get('patch')]
            kev_pairs.sort(key=lambda p:p[0].get('dateAdded',''),reverse=True)
            pairs=vendor_pairs+kev_pairs[:20]
            findings=[];details={};errors=[];requests=0;assessments=[]
            for entry,identity in pairs:
                if not entry.get('patch') and entry['cveID'] not in details:
                    cached=self.sources.cached(entry['cveID']) if hasattr(self.sources,'cached') else None
                    if cached:
                        details[entry['cveID']]=cached
                    elif requests<4 or ids:
                        requests+=1
                        try:details[entry['cveID']]=self.sources.cve(entry['cveID'])
                        except (OSError,ValueError):details[entry['cveID']]=None;errors.append(entry['cveID'])
                    else:details[entry['cveID']]=None
                finding=make_finding(host,identity,entry,details.get(entry['cveID']))
                assessments.append(finding)
                signature=hashlib.sha256(json.dumps({'id':finding['id'],'estado':finding['estado'],'gap':finding['gap'],
                       'action':entry.get('requiredAction'),'patch':entry.get('patch'),'host':host['id'],'build':host['sistema_operativo']['build'],
                       'patches':sorted(host['actualizaciones'])},sort_keys=True).encode()).hexdigest()
                if finding['estado']!='sin_coincidencia' and (manual or signature not in self.seen):
                    findings.append((finding,signature,entry))
            report_id=None
            if findings:
                selected=list({e['cveID']:e for f,s,e in findings}.values())
                report=report_for(host,[f for f,s,e in findings],selected,source,'manual' if manual else 'automatica')
                report['fuentes']=source_states
                if manual:report['entrada_manual']={'fuentes':resolved,'cves':ids}
                w.save(report,self.directory);report_id=report['id']
                self.seen.update(s for f,s,e in findings)
                self.state_path.parent.mkdir(parents=True,exist_ok=True)
                temp=self.state_path.with_suffix('.tmp');temp.write_text(json.dumps({'seen':sorted(self.seen)}),encoding='utf-8');temp.replace(self.state_path)
            manual_result={'fuentes':resolved,'cves':ids,'estado':'evaluada',
                           'mensaje':f'{len(ids)} CVE(s) identificados; {len(assessments)} coincidencia(s) con productos detectados.' if assessments else f'Fuente procesada: {len(ids)} CVE(s) identificados. No se detectaron productos coincidentes dentro del inventario disponible; esto no descarta software portable o integrado en otras aplicaciones.'} if manual else None
            current={'host_id':host['id'],'fecha':now(),'hallazgos':assessments,'fuentes':source_states,'entrada_manual':manual_result}
            self.directory.mkdir(parents=True,exist_ok=True)
            current_path=self.directory/'_evaluations.json'
            temp=current_path.with_suffix('.tmp');temp.write_text(json.dumps(current,ensure_ascii=False),encoding='utf-8');temp.replace(current_path)
            with self.lock:
                self.status.update(estado='parcial' if any(s['estado']!='ok' for s in source_states) else 'al_dia',ultima_revision=now(),ultimo_exito=now(),fuente=source,
                                   nuevas=len(findings),reporte_id=report_id or self.status.get('reporte_id'),
                                   mensaje='Reporte nuevo guardado.' if findings else 'Sin coincidencias nuevas para guardar.',
                                   cobertura=f'{len(vendor_pairs)} correcciones de fabricante + {len(kev_pairs[:20])} coincidencias KEV revisadas. Hasta 4 detalles NVD nuevos por ciclo. No cubre todos los fabricantes ni todas las vulnerabilidades.',
                                   resultado_actual={s:sum(f['estado']==s for f in assessments) for s in w.STATUSES},
                                   fuentes=source_states,detalles_no_disponibles=errors,error=None)
                self.status['entrada_manual']=manual_result
        except Exception as exc:
            with self.lock:self.status.update(estado='error',ultima_revision=now(),error=str(exc),nuevas=0,
                                             fuentes=locals().get('source_states',[]))
        finally:
            with self.lock:self.busy=False


def cpe_contains(detail,identity):
    if identity['key']=='windows':return any('microsoft:windows_' in json.dumps(c) for c in detail.get('configurations',[]))
    return any(':'+identity['vendor']+':'+identity['product']+':' in json.dumps(c) for c in detail.get('configurations',[]))
