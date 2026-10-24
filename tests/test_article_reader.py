import tempfile
import unittest
from copy import deepcopy
from urllib.error import HTTPError
from unittest.mock import patch
from src.article_reader import resolve, validate, MIRRORS
from src.live import Service, make_finding, evidence_only
from tests.test_live import HOST, ENTRY, CVE, FakeSources
from src import intelligence as intel, workspace


class ArticleTests(unittest.TestCase):
    def test_reads_cves_from_article_not_navigation_or_scripts(self):
        html='<title>Aviso</title><nav>CVE-2026-1111</nav><main><article>CVE-2026-2222 <script>CVE-2026-3333</script></article></main>'
        result=resolve('https://www.cisa.gov/news-events/alerts/example',fetch=lambda url:(html,url))
        self.assertEqual(result['cves'],['CVE-2026-2222'])
        self.assertEqual(result['estado'],'fuente_leida')
        self.assertTrue(result['sha256'])

    def test_fallback_is_read_from_same_editor(self):
        original,mirror=next(iter(MIRRORS.items()))
        calls=[]
        def fetch(url):
            calls.append(url)
            if url==original:raise HTTPError(url,403,'Forbidden',{},None)
            return '<main>CVE-2026-109618 CVE-2026-109619</main>',url
        result=resolve(original,fetch=fetch)
        self.assertEqual(calls,[original,mirror])
        self.assertEqual(result['url_leida'],mirror)
        self.assertEqual(len(result['cves']),2)

    def test_identifier_does_not_claim_to_have_read_url(self):
        result=resolve('https://example.com/CVE-2026-1234',fetch=lambda url:self.fail('Should not fetch'))
        self.assertEqual(result['estado'],'identificador_recibido')
        self.assertIsNone(result['url_leida'])

    def test_unreadable_and_read_without_cves_are_errors(self):
        url='https://www.cisa.gov/news-events/alerts/example'
        with self.assertRaisesRegex(ValueError,'no contiene identificadores CVE'):
            resolve(url,fetch=lambda url:('<main>Sin identificadores</main>',url))
        def fail(url):raise OSError('offline')
        with self.assertRaisesRegex(ValueError,'No se pudo verificar la fuente'):
            resolve(url,fetch=fail)

    def test_untrusted_targets_are_rejected(self):
        for url in ['http://www.cisa.gov/a','https://127.0.0.1/a','file:///tmp/a',
                    'https://www.cisa.gov.evil.test/a','https://user@www.cisa.gov/a',
                    'https://content.govdelivery.com/accounts/OTHER/bulletins/1']:
            with self.assertRaises(ValueError):validate(url)

    def test_safe_finding_has_no_correction_tasks_even_from_old_cache(self):
        identity=dict(intel.identities(HOST)[1],version='7.13')
        finding=make_finding(HOST,identity,ENTRY,CVE)
        self.assertEqual(finding['estado'],'sin_coincidencia')
        self.assertEqual(finding['acciones'],[])
        self.assertNotIn('reversion',finding['plan_soc'])
        finding['acciones']=[{'titulo':'Old correction'}]
        finding['plan_soc']={'requisitos':['Old plan']}
        self.assertEqual(evidence_only(finding)['acciones'],[])

    def test_manual_article_without_installed_product_is_not_a_report(self):
        with tempfile.TemporaryDirectory() as directory:
            sources=FakeSources()
            sources.cve=lambda key:{'id':key,'configurations':[]}
            service=Service(directory,collector=lambda:deepcopy(HOST),sources=sources)
            article={'cves':['CVE-2026-109618'],'estado':'fuente_leida','url_leida':'https://www.php.net/'}
            with patch('src.live.resolve',return_value=article):
                service._review(['https://www.php.net/advisory'])
            self.assertEqual(service.status['estado'],'al_dia')
            self.assertIn('No se detectaron productos coincidentes',service.status['entrada_manual']['mensaje'])
            self.assertEqual(workspace.history(directory),[])
            self.assertEqual(service.evaluations()['hallazgos'],[])
