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

    def test_stress_uses_real_geoip_first_and_an_exact_geosite_prefix(self):
        site_path = self.root / "geosite.dat"
        site_path.write_bytes(
            site_path.read_bytes()
            + category(b"category-ads-all", [field(2, b"ad.example")])
        )
        destination = self.root / "stress"
        selection = geodata.prepare_stress_assets(self.root, destination, 3)
        self.assertEqual(selection["retained_records"], {"geoip": 1, "geosite": 2})
        self.assertFalse(selection["synthetic_records"])
        self.assertEqual(selection["codes"]["geosite_codes"], ["cn"])
        stats = geodata.selection_statistics(destination, codes=selection["codes"])
        self.assertEqual(sum(value["entries"] for value in stats.values()), 3)
        self.assertEqual(
            geodata.witnesses(destination)["domain_positive"], "example.cn"
        )
        self.assertEqual(len(geodata.category_entries(site_path)), 2)

    def test_stress_fills_from_large_categories_without_changing_comparison(self):
        site_path = self.root / "geosite.dat"
        site_path.write_bytes(
            site_path.read_bytes()
            + category(
                b"category-ads-all",
                [
                    field(2, b"ad.example"),
                    field(2, b"ad2.example"),
                    field(2, b"ad3.example"),
                ],
            )
        )
        selection = geodata.prepare_stress_assets(self.root, self.root / "stress", 5)
        self.assertEqual(
            selection["codes"]["geosite_codes"], ["category-ads-all", "cn"]
        )
        self.assertEqual(selection["retained_records"], {"geoip": 1, "geosite": 4})
        self.assertEqual(
            len(geodata.category_entries(self.root / "stress/geosite.dat")), 1
        )
        with self.assertRaises(ValueError):
            geodata.prepare_stress_assets(self.root, self.root / "too-large", 100)

    def test_stress_skips_a_large_earlier_category_that_would_empty_cn(self):
        site_path = self.root / "geosite.dat"
        entries = [field(2, name) for name in (b"one.test", b"two.test", b"three.test")]
        site_path.write_bytes(
            site_path.read_bytes()
            + category(b"category-ads-all", entries)
            + category(b"zz", entries)
        )
        destination = self.root / "stress"
        selection = geodata.prepare_stress_assets(self.root, destination, 4)
        self.assertEqual(selection["codes"]["geosite_codes"], ["cn", "zz"])
        self.assertEqual(selection["retained_records"], {"geoip": 1, "geosite": 3})
        self.assertEqual(len(geodata.category_entries(destination / "geosite.dat")), 2)
