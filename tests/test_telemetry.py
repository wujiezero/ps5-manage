"""Tests for Overview PS5 hardware, storage and current game telemetry."""
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
from power import PowerError  # noqa: E402
from telemetry import ConsoleTelemetry  # noqa: E402

PNG_1X1 = (
    b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01'
    b'\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc````\x00\x00\x00\x05'
    b'\x00\x01\xa5\xf6E@\x00\x00\x00\x00IEND\xaeB`\x82'
)


class FakeEngine:
    def __init__(self, responses=None, fail=False):
        self.responses = responses or {}
        self.fail = fail
        self.calls = []

    def request(self, method, path, body=None, timeout=5):
        self.calls.append((method, path))
        if self.fail:
            raise PowerError('engine offline')
        route = path.split('?', 1)[0]
        return self.responses.get(route, {})


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_aggregates_engine_telemetry_titles_and_caches_cover(self):
        engine = FakeEngine({
            '/api/ps5/hw/info': {
                'cpu': {'freq_mhz': 3200, 'logical_cores': 16, 'temp_c': 78.0,
                        'soc_temp_c': 77.0, 'power_w': 214.2, 'load_pct': 16, 'fan_pct': 23},
                'memory': {'used_mb': 10752, 'total_gb': 16.0, 'direct_memory_gb': 12.3,
                           'swap_mb': 3.6, 'wired_mb': 766},
                'game': {'title_id': 'PPSA26344', 'developer': 'Sucker Punch Productions',
                         'genre': '动作冒险 / 开放世界', 'fps': 40, 'description': '北海道动作冒险续作'},
            },
            '/api/ps5/volumes': {
                'volumes': [
                    {'path': '/data', 'used_bytes': 117 << 30, 'total_bytes': 628 << 30},
                    {'path': '/mnt/ext0', 'used_bytes': 915 << 30, 'total_bytes': 954 << 30},
                ]
            },
        })
        files = SimpleNamespace(
            host='192.0.2.10',
            read_bytes=lambda p, limit=0: PNG_1X1 if p.endswith('PPSA26344.png') else (_ for _ in ()).throw(FileNotFoundError()),
            volumes=lambda: {'volumes': []},
        )
        titles = SimpleNamespace(entry=lambda tid: {'zh': '羊蹄山之魂', 'en': 'Ghost of Yōtei', 'name': '羊蹄山之魂'} if tid == 'PPSA26344' else None)
        tel = ConsoleTelemetry(engine, files=files, titles=titles, data_dir=self.root, cache_ttl=0)
        res = tel.collect('192.0.2.10')
        self.assertTrue(res['engine_available'])
        self.assertTrue(res['has_hw'])
        self.assertEqual(res['cpu']['freq_ghz'], 3.2)
        self.assertEqual(res['cpu']['cores'], 16)
        self.assertEqual(res['cpu']['temp_c'], 78.0)
        self.assertEqual(res['cpu']['soc_temp_c'], 77.0)
        self.assertEqual(res['cpu']['power_w'], 214.2)
        self.assertEqual(res['cpu']['load_pct'], 16.0)
        self.assertEqual(res['cpu']['fan_pct'], 23.0)
        self.assertEqual(res['memory']['direct_bytes'], int(12.3 * (1 << 30)))
        self.assertEqual([v['label'] for v in res['volumes']], ['内置存储', '扩展 M.2 存储'])
        self.assertGreater(res['volumes'][1]['percent'], 90)
        self.assertEqual(res['game']['title_id'], 'PPSA26344')
        self.assertEqual(res['game']['name'], '羊蹄山之魂')
        self.assertEqual(res['game']['title_en'], 'Ghost of Yōtei')
        self.assertEqual(res['game']['fps'], 40)
        self.assertEqual(res['game']['cover_url'], '/api/ps5/telemetry/cover?title=PPSA26344')
        data, etag, ctype = tel.cover('PPSA26344')
        self.assertEqual((data, ctype), (PNG_1X1, 'image/png'))
        self.assertTrue(etag)

    def test_falls_back_to_file_proxy_and_ddp_when_engine_unavailable(self):
        engine = FakeEngine(fail=True)
        files = SimpleNamespace(
            host='192.0.2.10',
            volumes=lambda: {'volumes': [{'path': '/mnt/usb0', 'free_bytes': 50 << 30, 'total_bytes': 64 << 30}]},
        )
        tel = ConsoleTelemetry(engine, files=files, data_dir=self.root, cache_ttl=0)
        res = tel.collect('192.0.2.10', power_info={'state': 'on', 'name': 'LivingRoom',
                                                    'firmware': '9.60', 'running_app': 'ASTRO BOT',
                                                    'running_app_id': 'PPSA12345'})
        self.assertFalse(res['engine_available'])
        self.assertFalse(res['has_hw'])
        self.assertEqual(res['volumes'][0]['label'], '外置 USB 存储')
        self.assertTrue(res['game']['running'])
        self.assertEqual(res['game']['title_id'], 'PPSA12345')
        self.assertEqual(res['game']['name'], 'ASTRO BOT')
        with self.assertRaises(ValueError):
            tel.cover('../bad')


if __name__ == '__main__':
    unittest.main()
