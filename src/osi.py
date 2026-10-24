"""Clasificación OSI explicable; una inferencia analítica, no telemetría de red."""
import re

NAMES={1:'Física',2:'Enlace de datos',3:'Red',4:'Transporte',5:'Sesión',6:'Presentación',7:'Aplicación'}
RULES=[
    (1,r'physical (?:signal|layer)|radio signal|optical signal|electrical signal','Señales o medio físico', 'media'),
    (2,r'\barp\b|802\.11|ethernet frame|wi-fi frame','Tramas o resolución local de enlace', 'alta'),
    (3,r'\bipv[46]\b|\bicmp\b|ip packet|ip fragment','Procesamiento de paquetes IP', 'alta'),
    (4,r'\btcp\b|\budp\b|\bsctp\b','Protocolo de transporte mencionado explícitamente', 'alta'),
    (5,r'netbios session service','Servicio explícito de sesión NetBIOS', 'media'),
    (6,r'\btls\b|\bssl\b','Protección de la representación de datos; ubicación OSI conceptual', 'media'),
    (7,r'\bhttp\b|\bsmb\b|\brpc\b|\brdp\b|\bdns\b|\bimap\b|\bsmtp\b|javascript|\bv8\b|\bpdf\b|\bhtml\b|web browser|browser engine|outlook|office|acrobat|chromium|google chrome|firefox','Protocolo o procesamiento de aplicación', 'alta'),
]


def classify(title,description,identity):
    text=' '.join([title or '',description or ''])
    matches=[]
    for layer,pattern,reason,confidence in RULES:
        found=re.search(pattern,text,re.I)
        if found:matches.append({'capa':layer,'nombre':NAMES[layer],'confianza':confidence,
                                 'justificacion':reason,'evidencia':found.group(0),
                                 'en_titulo':bool(re.search(pattern,title or '',re.I))})
    matches.sort(key=lambda m:not m['en_titulo'])
    # No inferir capa de red a partir del nombre Windows o de una escalada local.
    local=bool(re.search(r'local privilege|elevation of privilege|kernel|local attacker|\blocally\b|\blocal user\b',text,re.I))
    if re.search(r'TCP/IP',text,re.I) and not re.search(r'\bipv[46]\b|tcp packet|udp datagram',text,re.I):
        affected={'capa':None,'nombre':'No determinada','confianza':'insuficiente',
                  'justificacion':'El aviso menciona la suite TCP/IP, que abarca red y transporte. Falta identificar el protocolo o componente concreto para elegir entre capas 3 y 4.', 'evidencia':'TCP/IP'}
    elif local and not any(m['capa'] in (2,3,4,5) for m in matches):
        affected={'capa':None,'nombre':'No determinada','confianza':'no_aplica',
                  'justificacion':'El aviso describe un componente o privilegio local. Una falla local no se ubica de forma fiable en una capa OSI sin evidencia de protocolo.', 'evidencia':None}
    elif matches:
        affected=matches[0]
    else:
        affected={'capa':None,'nombre':'No determinada','confianza':'insuficiente',
                  'justificacion':'El aviso disponible no identifica un protocolo o función suficiente para asignar una capa OSI.', 'evidencia':None}
    controls=[{'capa':7 if identity['kind']=='app' else None,
               'nombre':NAMES[7] if identity['kind']=='app' else 'Mantenimiento del host',
               'medida':f'Aplicar la corrección oficial de {identity["nombre"]} y verificar versión/build. El parche del host no se atribuye automáticamente a una capa de red.'}]
    if affected['capa'] in (3,4,5,7) and not local:
        controls.insert(0,{'capa':3,'nombre':NAMES[3], 'medida':'Si el servicio está expuesto, el SOC debe validar segmentación y permitir únicamente orígenes IP autorizados. Confirmar alcance antes de cambiar reglas.'})
    if affected['capa']==4:
        controls.insert(1,{'capa':4,'nombre':NAMES[4], 'medida':'Identificar el servicio y puerto afectados y evaluar una restricción TCP/UDP específica. AUDA no ha medido puertos ni exposición.'})
    return {'afectada':affected,'otras_capas_mencionadas':[m for m in matches if m['capa']!=affected['capa']],
            'controles':controls,'metodo':'Inferencia por términos explícitos del aviso; no clasificación oficial del fabricante ni resultado de escaneo.',
            'advertencia':'Capa del problema y capa del control pueden ser distintas. No todas las vulnerabilidades pertenecen a una capa OSI.'}
