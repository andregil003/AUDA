import tempfile
import tkinter as tk
import unittest
from pathlib import Path
from unittest.mock import patch
from gui.app import AppThreatHunting
from src.hunting import history, save, STATUSES


class PanelTests(unittest.TestCase):
    def test_report_filter_validation_and_restore(self):
        root = tk.Tk()
        root.withdraw()
        try:
            with tempfile.TemporaryDirectory() as directory:
                with patch('gui.app.save', side_effect=lambda r: save(r, directory)), \
                     patch('gui.app.history', side_effect=lambda: history(directory)):
                    app = AppThreatHunting(root)
                    app._analyze()
                    root.update()
                    self.assertEqual(len(app.table.get_children()), 6)
                    self.assertEqual(len(list(Path(directory).glob('*.json'))), 1)
                    app.filter.set(STATUSES[0])
                    app._fill_devices()
                    self.assertEqual(len(app.table.get_children()), 2)
                    self.assertIn('11.1.2-h3', app.detail.cget('text'))
                    original_id = app.report['id']
                    app.url.set('invalid')
                    app._analyze()
                    self.assertEqual(app.report['id'], original_id)
                    app.history_box.current(0)
                    app._load_history()
                    root.update()
                    self.assertEqual(app.report['id'], original_id)
                    self.assertEqual(len(app.table.get_children()), 6)
                    app.url.set('https://example.org/news')
                    app._analyze()
                    root.update()
                    self.assertIsNone(app.report['fuente'])
                    self.assertEqual(app.report['conteos'][STATUSES[2]], 6)
        finally:
            root.destroy()
