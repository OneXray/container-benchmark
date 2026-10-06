"""All pressure and comparison configurations are fixed to complete CN rules."""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from container_benchmark import core_vcore_adapter as vcore


class VCoreAdapterTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.assets = self.root / "assets"
        self.assets.mkdir()
        for kind in ("geosite", "geoip"):
            (self.assets / f"{kind}.dat").write_bytes(kind.encode())
        self.origins = [
            SimpleNamespace(ipv4="192.0.2.2"),
            SimpleNamespace(ipv4="192.0.2.3"),
        ]
        self.witnesses = {"domain_positive": "example.cn"}

    def configure(self, *, geodata_update=False):
        result = vcore.configure(
            self.root / "vcore",
            self.assets,
            self.witnesses,
            self.origins,
            self.origins[1],
            SimpleNamespace(fd=11),
            geodata_update=geodata_update,
        )
        return json.loads(result["config"].read_text())

    def test_update_uses_a_controlled_proxy_without_changing_business_routes(self):
        config = self.configure(geodata_update=True)
        self.assertEqual(config["geo-update-interval"], 24)
        self.assertIs(config["geo-auto-update"], True)
        self.assertEqual(
            config["geox-url"],
            {
                "geosite": "http://geodata.update.test:24006/vcore/geosite.dat",
                "geoip": "http://geodata.update.test:24006/vcore/geoip.dat",
            },
        )
        self.assertEqual(config["rules"][-1], "MATCH,geodata-update")
        self.assertEqual(config["proxy-groups"][-1]["proxies"], ["geodata-fixture"])
        self.assertEqual(config["proxies"][-1]["server"], "192.0.2.3")
        self.assertEqual(config["proxies"][-1]["port"], 24005)
        self.assertEqual(
            config["rules"][:3],
            ["GEOSITE,cn,DIRECT", "DOMAIN,example.cn,REJECT", "GEOIP,cn,REJECT"],
        )

    def test_comparison_remains_cn_only_without_extra_selectors(self):
        config = self.configure()
        self.assertNotIn("nameserver-policy", config["dns"])
        self.assertEqual(
            config["rules"],
            [
                "GEOSITE,cn,DIRECT",
                "DOMAIN,example.cn,REJECT",
                "GEOIP,cn,REJECT",
                "IP-CIDR,192.0.2.2/32,DIRECT,no-resolve",
                "IP-CIDR,192.0.2.3/32,DIRECT,no-resolve",
                "MATCH,blocked",
            ],
        )

    def test_extra_witness_categories_never_change_the_cn_workload(self):
        self.witnesses.update(
            geosite_codes=["cn", "google", "!cn", "google@ads"],
            geoip_codes=["cn", "us", "!cn"],
        )
        config = self.configure()
        self.assertNotIn("nameserver-policy", config["dns"])
        self.assertEqual(
            config["rules"],
            [
                "GEOSITE,cn,DIRECT",
                "DOMAIN,example.cn,REJECT",
                "GEOIP,cn,REJECT",
                "IP-CIDR,192.0.2.2/32,DIRECT,no-resolve",
                "IP-CIDR,192.0.2.3/32,DIRECT,no-resolve",
                "MATCH,blocked",
            ],
        )
