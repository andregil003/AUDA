import tempfile
import unittest
from copy import deepcopy
from src.publications import parse_msrc,windows_product,applicable,parse_chrome,chrome_version
from src.osi import classify
from src.live import Service,make_finding
from src import workspace as w
from test_live import HOST,ENTRY,FakeSources

OS=dict(HOST['sistema_operativo'])
PRODUCT='Windows 11 Version 25H2 for x64-based Systems'
RELEASE={'InitialReleaseDate':'2026-10-13T07:00:00Z','CurrentReleaseDate':'2026-10-24T00:00:00Z'}
DOCUMENT={'ProductTree':{'FullProductName':[{'ProductID':'os1','Value':PRODUCT},{'ProductID':'os2','Value':'Windows 11 Version 25H2 for ARM64-based Systems'},{'ProductID':'net1','Value':'Microsoft .NET on '+PRODUCT}]},
 'Vulnerability':[{'CVE':'CVE-2026-99999','Title':{'Value':'Windows IPv6 remote code execution'},
 'ProductStatuses':[{'Type':3,'ProductID':['os1','os2','net1']}],
 'Remediations':[{'Type':2,'ProductID':['os1','os2','net1'],'Description':{'Value':'5071234'},'FixedBuild':'10.0.26200.100','URL':'https://support.microsoft.com/help/5071234','RestartRequired':{'Value':'Yes'}}]}]}
IDENTITY={'key':'windows','kind':'os','nombre':'Windows 11','version':'26200.1','vendor':'microsoft','product':'windows','origen':'Registry'}


class PatchTests(unittest.TestCase):
    def test_exact_release_architecture_and_component(self):
        self.assertTrue(windows_product(PRODUCT,OS))
        for name in ('Windows 11 Version 24H2 for x64-based Systems','Windows 11 Version 25H2 for ARM64-based Systems','Microsoft .NET on '+PRODUCT,'Windows Server 2025'):
            self.assertFalse(windows_product(name,OS))
        rows=parse_msrc(DOCUMENT,HOST,IDENTITY,RELEASE)
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['patch']['kb'],'KB5071234')

    def test_kb_missing_is_not_proof_without_build(self):
        patch=parse_msrc(DOCUMENT,HOST,IDENTITY,RELEASE)[0]['patch']
        self.assertEqual(applicable(HOST,IDENTITY,patch)[0],'expuesto')
        no_build=dict(patch,fixed_build=None)
        self.assertEqual(applicable(HOST,IDENTITY,no_build)[0],'pendiente')
        host=deepcopy(HOST);host['actualizaciones'].append('KB5071234')
        self.assertEqual(applicable(host,IDENTITY,patch)[0],'sin_coincidencia')

    def test_superseding_build_and_wrong_branch(self):
        patch=parse_msrc(DOCUMENT,HOST,IDENTITY,RELEASE)[0]['patch']
        host=deepcopy(HOST);host['sistema_operativo']['build']='26200.101'
        self.assertEqual(applicable(host,IDENTITY,patch)[0],'sin_coincidencia')
        host['sistema_operativo']['build']='26100.99999'
        self.assertEqual(applicable(host,IDENTITY,patch)[0],'pendiente')

    def test_chrome_channel_and_platform(self):
        self.assertEqual(chrome_version('updated to 155.0.8000.85/86 for Windows and Mac. Security fixes'), '155.0.8000.85')
        self.assertEqual(chrome_version('156.0.8078.47 (Linux) 156.0.8078.47/.48 Windows/Mac contains fixes. Security Fixes'), '156.0.8078.47')
        self.assertIsNone(chrome_version('155.0.8000.85 for Linux'))
        item={'title':{'$t':'Stable Channel Update for Desktop'},'content':{'$t':'<p>Updated to 155.0.8000.85/86 for Windows.</p><p>CVE-2026-12345</p>'},'link':[{'rel':'alternate','href':'https://chromereleases.googleblog.com/2026/10/stable.html'}],'published':{'$t':'2026-10-20'},'updated':{'$t':'2026-10-21'}}
        rows=parse_chrome({'feed':{'entry':[item]}},{'key':'chrome'})
        self.assertEqual(len(rows),1)
        item['title']['$t']='Beta Channel Update for Desktop'
        self.assertEqual(parse_chrome({'feed':{'entry':[item]}},{'key':'chrome'}),[])
        self.assertEqual(applicable(HOST,{'version':'155.0.8000.84'}, {'tipo':'version','fixed_version':'155.0.8000.85'})[0],'pendiente')

    def test_vendor_patch_overrides_broad_kev_match(self):
        entry=parse_msrc(DOCUMENT,HOST,IDENTITY,RELEASE)[0]
        class Sources(FakeSources):
            def catalog(self):return {'vulnerabilities':[dict(ENTRY,cveID=entry['cveID'],vendorProject='Microsoft',product='Windows')]},'cisa'
            def publications(self,h,i):return [entry],[{'nombre':'MSRC','estado':'ok','detalle':'test'}]
        with tempfile.TemporaryDirectory() as directory:
            service=Service(directory,collector=lambda:deepcopy(HOST),sources=Sources())
            service._review()
            evaluations=service.evaluations()
            self.assertEqual(len(evaluations['hallazgos']),1)
            finding=evaluations['hallazgos'][0]
            self.assertEqual(finding['estado'],'expuesto')
            self.assertEqual(finding['parche']['kb'],'KB5071234')
            self.assertEqual(finding['osi']['afectada']['capa'],3)
            self.assertIn('SOC',finding['plan_soc']['ejecucion'])
            self.assertEqual(len(w.history(directory)),1)

    def test_sources_continue_if_kev_fails(self):
        entry=parse_msrc(DOCUMENT,HOST,IDENTITY,RELEASE)[0]
        class Sources(FakeSources):
            def catalog(self):raise OSError('offline')
            def publications(self,h,i):return [entry],[{'nombre':'MSRC','estado':'ok','detalle':'test'}]
        with tempfile.TemporaryDirectory() as directory:
            service=Service(directory,collector=lambda:deepcopy(HOST),sources=Sources())
            service._review()
            self.assertEqual(service.status['estado'],'parcial')
            self.assertEqual(len(w.history(directory)),1)


class OSITests(unittest.TestCase):
    def test_layers_and_justification(self):
        for title,layer in [('ARP poisoning',2),('IPv6 parser',3),('TCP packet handling',4),('HTTP parser',7),('TLS certificate validation',6)]:
            with self.subTest(title=title):
                result=classify(title,'',IDENTITY)
                self.assertEqual(result['afectada']['capa'],layer)
                self.assertTrue(result['afectada']['evidencia'])

    def test_local_and_unknown_do_not_get_invented_layer(self):
        for title in ('Windows Kernel Elevation of Privilege','Unspecified vulnerability','Microsoft Word discloses data locally'):
            self.assertIsNone(classify(title,'',IDENTITY)['afectada']['capa'])

    def test_title_has_priority_and_controls_are_separate(self):
        result=classify('HTTP parser remote code execution','The service receives TCP connections.',dict(IDENTITY,kind='app',nombre='Web server'))
        self.assertEqual(result['afectada']['capa'],7)
        self.assertIn(3,[c['capa'] for c in result['controles']])
