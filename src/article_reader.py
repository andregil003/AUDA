"""Lectura acotada de avisos oficiales. No ejecuta contenido ni sigue enlaces internos."""
import gzip
import hashlib
import re
from datetime import datetime,timezone
from html.parser import HTMLParser
from urllib.error import HTTPError,URLError
from urllib.parse import urlsplit
from urllib.request import Request,HTTPRedirectHandler,build_opener

HOSTS={'www.cisa.gov','cisa.gov','www.php.net','php.net','msrc.microsoft.com','www.microsoft.com',
       'support.microsoft.com','learn.microsoft.com','security.paloaltonetworks.com','www.csa.gov.sg',
       'www.cyber.gc.ca','www.fortinet.com','fortiguard.fortinet.com','www.fortiguard.com',
       'support.apple.com','chromereleases.googleblog.com','nvd.nist.gov','www.cve.org'}
# Referencia al boletín del MISMO editor, no un mapa de resultados/CVEs inventados.
MIRRORS={
 'https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching':
 'https://content.govdelivery.com/accounts/USDHSCISA/bulletins/42ff5ac'
}


def validate(url):
    p=urlsplit(url)
    try:port=p.port
    except ValueError:raise ValueError('Puerto inválido en la fuente.') from None
    allowed=p.hostname in HOSTS or (p.hostname=='content.govdelivery.com' and p.path.startswith('/accounts/USDHSCISA/bulletins/'))
    if p.scheme!='https' or port not in (None,443) or p.username or p.password or not allowed:
        raise ValueError('Lectura disponible para fuentes oficiales compatibles mediante HTTPS. Para otro medio, pega el texto de la noticia o sus CVEs.')
    return url


class Redirects(HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        validate(newurl)
        return super().redirect_request(req,fp,code,msg,headers,newurl)


class ArticleText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True);self.skip=0;self.depth=0;self.main_depth=0;self.article_depth=0
        self.text=[];self.main=[];self.article=[];self.title=[];self.in_title=False
    def handle_starttag(self,tag,attrs):
        if tag in ('script','style','nav','footer','aside'):self.skip+=1
        if tag=='title':self.in_title=True
        if tag=='main':self.main_depth+=1
        if tag=='article':self.article_depth+=1
    def handle_endtag(self,tag):
        if tag in ('script','style','nav','footer','aside'):self.skip=max(0,self.skip-1)
        if tag=='title':self.in_title=False
        if tag=='main':self.main_depth=max(0,self.main_depth-1)
        if tag=='article':self.article_depth=max(0,self.article_depth-1)
    def handle_data(self,data):
        if self.in_title:self.title.append(data)
        if self.skip:return
        self.text.append(data)
        if self.main_depth:self.main.append(data)
        if self.article_depth:self.article.append(data)


def download(url):
    validate(url)
    request=Request(url,headers={'User-Agent':'AUDA/1.0 advisory-reader','Accept':'text/html,application/xhtml+xml,text/plain','Accept-Encoding':'gzip'})
    with build_opener(Redirects()).open(request,timeout=18) as response:
        kind=response.headers.get('Content-Type','').lower()
        if not any(k in kind for k in ('text/html','application/xhtml+xml','text/plain')):
            raise ValueError('La fuente no devolvió una página de texto compatible.')
        reader=gzip.GzipFile(fileobj=response) if response.headers.get('Content-Encoding')=='gzip' else response
        data=reader.read(2_000_001)
        if len(data)>2_000_000:raise ValueError('La noticia excede el tamaño máximo de lectura.')
        charset=response.headers.get_content_charset() or 'utf-8'
        return data.decode(charset,errors='replace'),response.geturl()


def resolve(text,fetch=download):
    text=text.strip()
    if len(text)>10000:raise ValueError('Entrada demasiado larga.')
    direct=list(dict.fromkeys(re.findall(r'\bCVE-\d{4}-\d{4,}\b',text.upper())))
    if direct:
        return {'entrada':text,'cves':direct[:20],'estado':'identificador_recibido','url_leida':None,
                'detalle':'Identificadores recibidos; la página no se ha leído. Se verifican contra las fuentes de vulnerabilidades.'}
    validate(text)
    errors=[]
    for url in (text,MIRRORS.get(text.rstrip('/'))):
        if not url:continue
        try:
            html,actual=fetch(url)
            parsed=ArticleText();parsed.feed(html)
            body=' '.join(parsed.article or parsed.main or parsed.text)
            ids=list(dict.fromkeys(re.findall(r'\bCVE-\d{4}-\d{4,}\b',body.upper())))
            if not ids:raise ValueError('La página pudo leerse, pero no contiene identificadores CVE en el cuerpo del aviso.')
            return {'entrada':text,'cves':ids[:20],'estado':'fuente_leida','url_leida':actual,
                    'titulo':' '.join(parsed.title).strip()[:300], 'sha256':hashlib.sha256(html.encode()).hexdigest(),
                    'consultado':datetime.now(timezone.utc).isoformat(timespec='seconds'),
                    'detalle':'Leído desde el boletín oficial del mismo editor porque no se pudo leer la URL original.' if url!=text else 'CVEs extraídos del contenido de la página.'}
        except HTTPError as exc:errors.append('HTTP '+str(exc.code))
        except (URLError,OSError,ValueError) as exc:errors.append(str(exc))
    raise ValueError('No se pudo verificar la fuente: '+'; '.join(errors)+'. Puedes pegar el texto del aviso o sus CVEs para continuar; eso no equivale a haber leído la URL.')
