import json
import tempfile
import unittest
from copy import deepcopy
from unittest.mock import patch
from src import intelligence as i, workspace as w
from src.live import Service
from agent import rpc


HOST={'id':'testpc','nombre':'Test-PC','sistema_operativo':{'nombre':'Windows 11','familia':'Windows 11','version':'25H2','build':'26200.1','arquitectura':'AMD64'},
      'programas':[{'nombre':'WinRAR 7.12 (64-bit)','version':'7.12.0','editor':'win.rar GmbH','origen':'Registro'}],
      'actualizaciones':['KB1234567'],'capturado':'2026-10-24T12:00:00Z','notas':[],'alcance':'lectura'}
ENTRY={'cveID':'CVE-2025-8088','product':'WinRAR','vendorProject':'RARLAB','vulnerabilityName':'WinRAR traversal',
       'dateAdded':'2025-08-11','shortDescription':'Test record','requiredAction':'Apply vendor update.'}
CVE={'id':ENTRY['cveID'],'configurations':[{'nodes':[{'operator':'OR','cpeMatch':[{'vulnerable':True,
    'criteria':'cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*','versionEndExcluding':'7.13'}]}]}]}


class FakeSources:
    def catalog(self):return {'vulnerabilities':[deepcopy(ENTRY)]},i.KEV_URL
    def cve(self,key):return deepcopy(CVE)


class LiveTests(unittest.TestCase):
    def test_product_identity_and_version_boundary(self):
        product=i.identities(HOST)[1]
        self.assertTrue(i.matches(ENTRY,product))
        self.assertFalse(i.matches(dict(ENTRY,vendorProject='Other vendor'),product))
        self.assertEqual(i.version_check(product,CVE)[0],'expuesto')
        for version,expected in [('7.13','sin_coincidencia'),('7.13.1','sin_coincidencia'),('7.12-beta','pendiente')]:
            self.assertEqual(i.version_check(dict(product,version=version),CVE)[0],expected)
        complex_cve=deepcopy(CVE);complex_cve['configurations'][0]['operator']='AND'
        self.assertEqual(i.version_check(product,complex_cve)[0],'pendiente')

    def test_windows_cannot_be_declared_vulnerable_from_family_only(self):
        identity=i.identities(HOST)[0]
        self.assertEqual(i.version_check(identity,CVE)[0],'pendiente')

    def test_close_lease_and_five_minutes(self):
        clock=[0.0]
        with tempfile.TemporaryDirectory() as directory:
            service=Service(directory,collector=lambda:deepcopy(HOST),sources=FakeSources(),clock=lambda:clock[0])
            self.assertFalse(service.snapshot()['interfaz_activa'])
            service.presence('tab',True)
            self.assertTrue(service.present())
            service.presence('tab',False)
            self.assertFalse(service.present())
            service.presence('tab',True);clock[0]=91
            self.assertFalse(service.present())
            self.assertEqual(service.interval,300)

    def test_report_dedup_and_plan_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            service=Service(directory,collector=lambda:deepcopy(HOST),sources=FakeSources())
            service._review()
            reports=w.history(directory)
            self.assertEqual(len(reports),1)
            report=w.load(reports[0]['id'],directory)
            self.assertFalse(report['simulado'])
            self.assertEqual(report['hallazgos'][0]['estado'],'expuesto')
            self.assertIn('reversion',report['hallazgos'][0]['plan_agente'])
            service._review()
            self.assertEqual(len(w.history(directory)),1)
            # Reiniciar no vuelve a generar el mismo hallazgo.
            restarted=Service(directory,collector=lambda:deepcopy(HOST),sources=FakeSources())
            restarted._review()
            self.assertEqual(len(w.history(directory)),1)

    def test_network_error_not_a_clean_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            sources=FakeSources();sources.catalog=lambda:(_ for _ in ()).throw(OSError('offline'))
            service=Service(directory,collector=lambda:deepcopy(HOST),sources=sources)
            service._review()
            self.assertEqual(service.status['estado'],'error')
            self.assertIsNone(service.status['ultimo_exito'])
            self.assertEqual(w.history(directory),[])

    def test_patched_product_does_not_create_a_report(self):
        with tempfile.TemporaryDirectory() as directory:
            host=deepcopy(HOST);host['programas'][0]['version']='7.13'
            service=Service(directory,collector=lambda:host,sources=FakeSources())
            service._review()
            self.assertEqual(w.history(directory),[])

    def test_mcp_handshake_and_tools(self):
        init=rpc({'jsonrpc':'2.0','id':1,'method':'initialize','params':{}})
        self.assertEqual(init['result']['serverInfo']['name'],'auda')
        tools=rpc({'jsonrpc':'2.0','id':2,'method':'tools/list'})['result']['tools']
        self.assertEqual(len(tools),7)
        self.assertFalse(any('execute' in t['name'] for t in tools))
        with patch('agent.api',return_value={'nombre':'Test-PC'}) as api:
            response=rpc({'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'auda_environment'}})
            self.assertIn('Test-PC',response['result']['content'][0]['text'])
            api.assert_called_once_with('/api/environment')
        self.assertIsNone(rpc({'jsonrpc':'2.0','method':'notifications/initialized'}))
