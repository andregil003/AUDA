import tempfile
import unittest
from pathlib import Path
from src.hunting import analyze, evaluate, history, save, source, STATUSES


class HuntingTests(unittest.TestCase):
    def test_default_inventory(self):
        report = analyze(source()['url'])
        self.assertEqual(list(report['conteos'].values()), [2, 3, 1])
        self.assertEqual(report['expuestos_internet'], 1)

    def test_hotfix_boundaries_and_configuration(self):
        device = {'producto': 'PAN-OS', 'globalprotect': True}
        for version, expected in [('11.1.2-h2', 0), ('11.1.2-h3', 1),
                                  ('10.2.4-h15', 0), ('10.2.4-h16', 1),
                                  ('11.0.3-h9', 0), ('11.0.3-h10', 1),
                                  ('10.2.10', 1), ('10.1.0', 1), (None, 2)]:
            with self.subTest(version=version):
                self.assertEqual(evaluate(dict(device, version=version))[0], STATUSES[expected])
        self.assertEqual(evaluate(dict(device, version='11.1.2', globalprotect=False))[0], STATUSES[1])
        self.assertEqual(evaluate(dict(device, version='11.1.2', globalprotect=None))[0], STATUSES[2])

    def test_unknown_url_does_not_invent_results(self):
        report = analyze('https://example.org/CVE-2024-3400')
        self.assertIsNone(report['fuente'])
        self.assertEqual(report['conteos'][STATUSES[2]], 6)

    def test_invalid_input(self):
        for value in ('', 'una noticia', 'file:///C:/test', 'https://user:pass@example.org'):
            with self.assertRaises(ValueError):
                analyze(value)

    def test_persistence_and_corrupt_file(self):
        with tempfile.TemporaryDirectory() as directory:
            a, b = analyze(source()['url']), analyze(source()['url'])
            save(a, directory)
            save(b, directory)
            Path(directory, 'corrupt.json').write_text('{')
            restored = history(directory)
            self.assertEqual(len(restored), 2)
            self.assertEqual({r['id'] for r in restored}, {a['id'], b['id']})
            self.assertEqual(restored[0]['conteos'], a['conteos'])


if __name__ == '__main__':
    unittest.main()
