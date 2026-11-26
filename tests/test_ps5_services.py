"""Tests for PS5 open ELF port scanning and GitHub service classification."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'server'))
from ps5_services import PortScanner  # noqa: E402


def _validate(ip):
    if ip != '192.0.2.50':
        raise ValueError('bad ip')
    return ip


class PortScannerTests(unittest.TestCase):
    def test_identifies_web_and_protocol_services_and_caches(self):
        tcp_calls = []
        now = [100.0]

        def tcp_probe(ip, port, timeout=0.45):
            tcp_calls.append(port)
            return port in (8084, 8888, 2120, 9021, 9090)

        def http_probe(ip, port, timeout=0.8):
            if port == 8084:
                return {'is_http': True, 'title': 'PS5 Payload Manager', 'server': '', 'content_type': 'text/html'}
            if port == 8888:
                return {'is_http': True, 'title': 'Web File Mgr', 'server': '', 'content_type': 'text/html'}
            if port == 9090:
                return {'is_http': True, 'title': 'etaHEN Web Tool', 'server': '', 'content_type': 'text/html'}
            return {'is_http': False, 'title': '', 'server': '', 'content_type': ''}

        scanner = PortScanner(_validate, cache_ttl=30.0, tcp_probe=tcp_probe, http_probe=http_probe,
                              clock=lambda: now[0])
        result = scanner.scan('192.0.2.50', running_processes=[{'name': 'zftpd.elf'}])
        self.assertTrue(result['online'])
        self.assertFalse(result['cached'])
        by_port = {item['port']: item for item in result['services']}
        self.assertEqual(by_port[8084]['web'], True)
        self.assertEqual(by_port[8084]['url'], 'http://192.0.2.50:8084/')
        self.assertEqual(by_port[8084]['repo'], 'itsPLK/ps5-payload-manager')
        self.assertEqual(by_port[8888]['title'], 'Web File Mgr')
        self.assertEqual(by_port[9090]['web'], True)
        self.assertEqual(by_port[9090]['url'], 'http://192.0.2.50:9090/')
        self.assertEqual(by_port[2120]['web'], False)
        self.assertEqual(by_port[2120]['protocol'], 'ftp')
        self.assertEqual(by_port[2120]['process'], 'zftpd.elf')
        self.assertEqual(by_port[9021]['web'], False)
        self.assertEqual(by_port[9021]['url'], '192.0.2.50:9021')

        first_calls = len(tcp_calls)
        cached = scanner.scan('192.0.2.50')
        self.assertTrue(cached['cached'])
        self.assertEqual(len(tcp_calls), first_calls)

        forced = scanner.scan('192.0.2.50', force=True)
        self.assertFalse(forced['cached'])
        self.assertGreater(len(tcp_calls), first_calls)

    def test_empty_result_and_invalid_ip(self):
        scanner = PortScanner(_validate, tcp_probe=lambda *a: False)
        empty = scanner.scan('192.0.2.50')
        self.assertFalse(empty['online'])
        self.assertEqual(empty['services'], [])
        with self.assertRaises(ValueError):
            scanner.scan('198.51.100.1')


if __name__ == '__main__':
    unittest.main()
