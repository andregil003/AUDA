import json
import tempfile
import threading
import unittest
from copy import deepcopy
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import Mock
from gui.server import LocalServer
from src import workspace as w


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.articles = w.catalog()
        self.urls = [a['url'] for a in self.articles]

    def test_three_sources_have_distinct_device_plans(self):
        report = w.analyze(self.urls)
        self.assertEqual(len(report['articulos']), 3)
        self.assertEqual(report['resumen']['expuestos'], 4)
        self.assertEqual(report['resumen']['indicios'], 1)
        self.assertEqual(report['resumen']['evaluaciones'], {'expuesto': 4, 'sin_coincidencia': 4, 'pendiente': 1})
        fw = next(f for f in report['hallazgos'] if f['dispositivo']['id'] == 'fw-01')
        mac = next(f for f in report['hallazgos'] if f['dispositivo']['id'] == 'mac-01')
        self.assertEqual(fw['prioridad'], 'P0')
        self.assertIn('FortiCloud', fw['acciones'][0]['texto'])
        self.assertIn('26.7.1', mac['acciones'][2]['texto'])
        for finding in report['hallazgos']:
            self.assertTrue(all(finding['dispositivo']['nombre'] in a['texto'] for a in finding['acciones']))

    def test_version_boundaries_and_missing_config(self):
        cases = [('fortisiem', 'FortiSIEM', '7.5.0', 'expuesto'),
                 ('fortisiem', 'FortiSIEM', '7.5.1', 'sin_coincidencia'),
                 ('fortisiem', 'FortiSIEM', '7.4.2', 'pendiente'),
                 ('apple', 'macOS Tahoe', '26.7.0', 'expuesto'),
                 ('apple', 'macOS Tahoe', '26.7.1', 'sin_coincidencia'),
                 ('apple', 'iOS', '27.0', 'pendiente'),
                 ('apple', 'iOS', '26.7.1-beta', 'pendiente'),
                 ('forticloud', 'FortiOS', '7.6.6', 'sin_coincidencia')]
        for aid, product, version, expected in cases:
            a = next(a for a in self.articles if a['id'] == aid)
            d = dict(w.inventory()['dispositivos'][0], producto=product, version=version, forticloud_sso=True)
            with self.subTest(aid=aid, version=version):
                self.assertEqual(w.evaluate(d, a)['estado'], expected)
        a = self.articles[2]
        d = dict(w.inventory()['dispositivos'][6], forticloud_sso=None)
        self.assertEqual(w.evaluate(d,a)['estado'], 'pendiente')
        d['forticloud_sso'] = False
        self.assertEqual(w.evaluate(d,a)['estado'], 'sin_coincidencia')

    def test_indicators_survive_a_patch(self):
        d = dict(w.inventory()['dispositivos'][6], version='7.6.6')
        result = w.evaluate(d, self.articles[2])
        self.assertEqual(result['estado'], 'sin_coincidencia')
        self.assertEqual(result['compromiso'], 'indicios_simulados')
        self.assertEqual(result['prioridad'], 'P0')
        self.assertEqual(len(result['acciones']), 4)

    def test_alias_duplicate_and_unknown_url(self):
        result = w.analyze([self.urls[0], self.articles[0]['aliases'][0]])
        self.assertEqual(len(result['articulos']), 1)
        result = w.analyze(['https://example.org/?cve=CVE-2026-106173'])
        self.assertEqual(result['resumen']['fuentes_pendientes'], 1)
        self.assertEqual(result['hallazgos'], [])
        self.assertEqual(result['resumen']['evaluados'], 0)

    def test_invalid_urls(self):
        for urls in ([], self.urls*2, 'text', ['javascript:alert(1)'], ['https://user:pass@example.org'], ['http://localhost:bad']):
            with self.subTest(urls=urls), self.assertRaises(ValueError):
                w.analyze(urls)

    def test_persist_task_does_not_change_gap(self):
        with tempfile.TemporaryDirectory() as directory:
            r = w.analyze(self.urls)
            w.save(r, directory)
            f = r['hallazgos'][0]
            changed = w.update_action(r['id'], f['id'], f['acciones'][0]['id'], True, directory)
            self.assertTrue(changed['hallazgos'][0]['acciones'][0]['hecho'])
            self.assertEqual(changed['resumen'], r['resumen'])
            self.assertEqual(w.load(r['id'], directory), changed)
            Path(directory, 'broken.json').write_text('{')
            self.assertEqual(len(w.history(directory)), 1)
            with self.assertRaises(ValueError):
                w.load('../escape', directory)


class ServerTests(unittest.TestCase):
    def test_http_flow_security_and_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            saved=w.analyze([a['url'] for a in w.catalog()])
            w.save(saved,directory)
            service=Mock()
            service.environment.return_value={'id':'test'}
            service.snapshot.return_value={'estado':'pausado'}
            service.trigger.return_value={'reporte_id':saved['id'],'ejecutando':True}
            service.report.side_effect=lambda rid:w.load(rid,directory)
            with LocalServer(directory=directory,service=service) as server:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                conn = HTTPConnection('127.0.0.1', server.server_port, timeout=5)
                try:
                    conn.request('GET', '/')
                    response = conn.getresponse()
                    html = response.read().decode()
                    self.assertEqual(response.status, 200)
                    self.assertIn(server.token, html)
                    self.assertIn("frame-ancestors 'none'", response.getheader('Content-Security-Policy'))
                    for asset in ('/app.js', '/style.css', '/api/bootstrap'):
                        conn.request('GET', asset, headers={'X-AUDA-Token':server.token})
                        response = conn.getresponse()
                        response.read()
                        self.assertEqual(response.status, 200)
                    payload = json.dumps({'urls':[a['url'] for a in w.catalog()]})
                    headers = {'Content-Type':'application/json','X-AUDA-Token':server.token}
                    conn.request('POST', '/api/analyze', payload, headers)
                    response = conn.getresponse()
                    report = json.loads(response.read())
                    self.assertEqual(response.status, 200)
                    self.assertEqual(report['reporte_id'], saved['id'])
                    for overrides in ({'X-AUDA-Token':'wrong'}, {'Origin':'https://evil.example'}, {'Host':'evil.example'}):
                        conn.request('POST','/api/analyze',payload,dict(headers, **overrides))
                        response=conn.getresponse();response.read()
                        self.assertEqual(response.status,403)
                    conn.request('GET', '/api/report/'+saved['id'],headers=headers)
                    response=conn.getresponse()
                    self.assertEqual(json.loads(response.read())['id'],saved['id'])
                    conn.request('GET', '/../../data/empresa_2026.json')
                    response=conn.getresponse();response.read()
                    self.assertEqual(response.status,404)
                finally:
                    conn.close()
                    server.shutdown()
                    thread.join(timeout=5)
            # Un servidor nuevo lee el reporte del mismo directorio.
            self.assertEqual(w.history(directory)[0]['id'], saved['id'])
