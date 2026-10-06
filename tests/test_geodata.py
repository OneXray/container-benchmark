import ipaddress
import tempfile
import unittest
from pathlib import Path

from container_benchmark import geodata


def field(number, content):
    return bytes([number * 8 + 2, len(content)]) + content


def category(name, records):
    return field(1, field(1, name) + b"".join(field(2, record) for record in records))


class GeoDataTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        entries = [
            b"\x08\x02" + field(2, b"example.cn"),
            b"\x08\x03" + field(2, b"full.cn"),
        ]
        (self.root / "geosite.dat").write_bytes(
            category(b"cn", entries) + category(b"us", entries)
        )
        network = ipaddress.ip_network("1.0.0.0/24")
        cidr = field(1, network.network_address.packed) + b"\x10\x18"
        (self.root / "geoip.dat").write_bytes(category(b"cn", [cidr]))

    def test_only_cn_counts_and_real_witnesses(self):
        result = geodata.witnesses(self.root)
        self.assertEqual(result["counts"], {"geosite": 2, "geoip": 1})
        self.assertEqual(result["domain_positive"], "example.cn")
        self.assertTrue(geodata.contains_ip(self.root, result["ip_positive"][4]))
        self.assertFalse(geodata.contains_ip(self.root, "192.0.2.1"))
        self.assertEqual(
            geodata.selection_statistics(self.root)["geosite"]["entries"], 2
        )
        with self.assertRaises(ValueError):
            geodata.category_entries(self.root / "geosite.dat", "us")

    def test_duplicate_and_missing_category_fail_before_load(self):
        path = self.root / "geosite.dat"
        for value in (category(b"cn", []) * 2, category(b"us", [])):
            path.write_bytes(value)
            with self.assertRaises(ValueError):
                geodata.category_entries(path)
