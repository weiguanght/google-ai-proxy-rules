"""Offline unit and integration tests. All temporary files stay in an explicit work directory."""

from __future__ import annotations

import contextlib
import importlib
import io
import ipaddress
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
core = importlib.import_module("rules_core")
updater = importlib.import_module("update_rules")


class RuleSemanticsTests(unittest.TestCase):
    def rule(self, kind, value):
        return core.normalize_rule(kind, value)

    def test_exact_does_not_match_subdomain(self):
        rule = self.rule("DOMAIN", "Accounts.Google.Com.")
        self.assertTrue(core.matches_domain("accounts.google.com.", rule))
        self.assertFalse(core.matches_domain("sub.accounts.google.com", rule))

    def test_suffix_includes_root_and_children_but_not_lookalikes(self):
        rule = self.rule("DOMAIN-SUFFIX", "google.com")
        for name in ("google.com", "accounts.google.com", "a.b.google.com"):
            self.assertTrue(core.matches_domain(name, rule))
        for name in ("notgoogle.com", "google.com.example.net"):
            self.assertFalse(core.matches_domain(name, rule))

    def test_keyword_has_no_domain_boundary(self):
        rule = self.rule("DOMAIN-KEYWORD", "google")
        self.assertTrue(core.matches_domain("google.example.net", rule))
        self.assertTrue(core.matches_domain("notgoogle.example.net", rule))

    def test_goog_is_distinct_from_google(self):
        keyword = self.rule("DOMAIN-KEYWORD", "google")
        suffix = self.rule("DOMAIN-SUFFIX", "goog")
        self.assertFalse(core.matches_domain("antigravity-unleash.goog", keyword))
        self.assertTrue(core.matches_domain("antigravity-unleash.goog", suffix))

    def test_suffix_and_keyword_containment(self):
        parent = self.rule("DOMAIN-SUFFIX", "google.com")
        child = self.rule("DOMAIN-SUFFIX", "accounts.google.com")
        keyword = self.rule("DOMAIN-KEYWORD", "google")
        self.assertTrue(core.subsumes(parent, child))
        self.assertTrue(core.subsumes(keyword, parent))
        self.assertFalse(core.subsumes(parent, keyword))

    def test_one_keyword_can_contain_another(self):
        broad = self.rule("DOMAIN-KEYWORD", "google")
        narrow = self.rule("DOMAIN-KEYWORD", "aigoogle")
        self.assertTrue(core.subsumes(broad, narrow))
        self.assertFalse(core.subsumes(narrow, broad))

    def test_minimization_preserves_matching(self):
        rules = [
            self.rule("DOMAIN", "accounts.google.com"),
            self.rule("DOMAIN-SUFFIX", "google.com"),
            self.rule("DOMAIN-KEYWORD", "google"),
            self.rule("DOMAIN-SUFFIX", "goog"),
        ]
        final = core.minimize_rules(rules + rules)
        self.assertEqual(len(final), 2)
        for target in rules:
            self.assertTrue(any(core.subsumes(rule, target) for rule in final))

    def test_cidr_collapse_is_an_exact_union(self):
        final = core.minimize_rules([
            self.rule("IP-CIDR", "8.8.8.0/25"),
            self.rule("IP-CIDR", "8.8.8.128/25"),
            self.rule("IP-CIDR", "8.8.8.0/25"),
        ])
        self.assertEqual(final, [self.rule("IP-CIDR", "8.8.8.0/24")])
        self.assertEqual(ipaddress.ip_network(final[0].value).num_addresses, 256)

    def test_ipv6_normalization(self):
        rule = self.rule("IP-CIDR6", "2620:120:e000::1234/40")
        self.assertEqual(rule.value, "2620:120:e000::/40")
        self.assertTrue(rule.render().endswith(",no-resolve"))

    def test_private_and_mixed_public_private_cidrs_are_excluded(self):
        for value in ("10.0.0.0/8", "127.0.0.0/8", "192.168.0.0/16",
                      "172.16.0.0/12", "8.0.0.0/5", "fc00::/7", "fe80::/10"):
            kind = "IP-CIDR6" if ":" in value else "IP-CIDR"
            self.assertFalse(core.is_public_network(self.rule(kind, value)), value)

    def test_public_source_cidr_is_allowed(self):
        self.assertTrue(core.is_public_network(self.rule("IP-CIDR", "74.125.0.0/16")))

    def test_rejects_unrecognized_syntax(self):
        with self.assertRaises(ValueError):
            core.parse_list_rows("DOMAIN-WILDCARD,*.google.com")
        with self.assertRaises(ValueError):
            core.normalize_rule("DOMAIN", "google.com/extra")

    def test_patch_extractors_fail_on_changed_anchors(self):
        with self.assertRaises(ValueError):
            core.extract_patch_rows("var changed = [];", "patch-js")
        with self.assertRaises(ValueError):
            core.extract_pac_rows("function FindProxyForURL() {}")

    def test_patch_extractor_rejects_unknown_array_rule_types(self):
        source = "const prependRules = ['DOMAIN-SUFFIX,google.com,Proxy', 'DOMAIN-WILDCARD,*.google.com,Proxy'];"
        with self.assertRaises(ValueError):
            core.extract_patch_rows(source, "patch-js")

    def test_project_relative_paths(self):
        with self.assertRaises(ValueError):
            core.safe_path(ROOT, "../outside")
        with self.assertRaises(ValueError):
            core.safe_path(ROOT, "/outside")


class SourceIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config, cls.targets = updater.load_config(ROOT)
        cls.manifest, cls.raw, cls.licenses = updater.load_snapshots(ROOT, cls.config)
        cls.candidates, cls.excluded = core.collect_candidates(
            cls.config, {key: value.decode("utf-8-sig") for key, value in cls.raw.items()},
        )
        cls.final = core.minimize_rules(candidate.rule for candidate in cls.candidates)
        cls.artifacts, cls.report = core.build_artifacts(
            cls.config, cls.manifest, cls.raw, cls.licenses, cls.targets,
        )

    def test_all_24_baseline_domains(self):
        self.assertEqual(self.report["baseline"]["covered"], 24)
        self.assertEqual(self.report["baseline"]["total"], 24)
        for target in self.targets["baseline"]:
            with self.subTest(domain=target["domain"]):
                self.assertTrue(any(core.matches_domain(target["domain"], rule) for rule in self.final))

    def test_all_extended_domains(self):
        self.assertEqual(self.report["extended"]["covered"], self.report["extended"]["total"])

    def test_entire_eligible_source_rule_ranges_are_contained(self):
        for candidate in self.candidates:
            with self.subTest(source=candidate.source, rule=candidate.rule.render()):
                self.assertTrue(any(core.subsumes(rule, candidate.rule) for rule in self.final))
        self.assertEqual(self.report["source_union"]["uncovered"], [])

    def test_all_10_sources_contribute_eligible_rules(self):
        counts = self.report["statistics"]["candidate_occurrences_by_source"]
        self.assertEqual(len(counts), 10)
        for source in self.config["sources"]:
            self.assertGreater(counts[source["id"]], 0)

    def test_gemini_generic_keywords_are_preserved(self):
        for value in ("colab", "developerprofiles", "generativelanguage"):
            self.assertIn(core.Rule("DOMAIN-KEYWORD", value), self.final)

    def test_google_extra_roots_and_cloudcode_are_preserved(self):
        for domain in ("ai.studio", "gemma.ai", "gcr.io", "probe.goog",
                       "cloudcode.example.net", "antigravity.example.net"):
            self.assertTrue(any(core.matches_domain(domain, rule) for rule in self.final), domain)

    def test_foreign_ai_platform_domains_are_not_added(self):
        for domain in ("api.openai.com", "api.anthropic.com", "claude.ai",
                       "github.com", "raw.githubusercontent.com", "sentry.io",
                       "datadoghq.com", "api.cursor.sh"):
            self.assertFalse(any(core.matches_domain(domain, rule) for rule in self.final), domain)

    def test_only_google_source_networks_are_used(self):
        expected = set(core.minimize_rules(
            candidate.rule for candidate in self.candidates
            if candidate.rule.kind in core.NETWORK_KINDS
        ))
        actual = {rule for rule in self.final if rule.kind in core.NETWORK_KINDS}
        self.assertEqual(actual, expected)
        expected_addresses = sum(ipaddress.ip_network(rule.value).num_addresses
                                 for rule in expected if rule.kind == "IP-CIDR")
        self.assertEqual(self.report["public_networks"]["ipv4"]["addresses"], str(expected_addresses))

    def test_foreign_networks_and_asns_do_not_leak_into_output(self):
        excluded_values = {"160.79.104.0/21", "2607:6bc0::/32", "2604:f20::/32",
                           "199.47.142.0/23", "24.199.123.28/32", "64.23.132.171/32",
                           "399358", "14061", "401518"}
        for rule in self.final:
            self.assertNotIn(rule.value, excluded_values)

    def test_process_user_agent_and_direct_rules_are_absent(self):
        for rule in self.final:
            self.assertIn(rule.kind, core.RULE_KINDS)
            self.assertNotIn(",DIRECT", rule.render())
        self.assertTrue(any(item["reason"] == "non_google_pac_dependency" for item in self.excluded))

    def test_all_generated_cidrs_are_public(self):
        self.assertTrue(all(core.is_public_network(rule) for rule in self.final))

    def test_generated_csv_and_yaml_payloads_are_identical(self):
        for name in ("Google-AI", "Google-AI-Domains", "Google-AI-IP"):
            csv = self.artifacts[f"rules/loon/{name}.list"].decode().splitlines()
            yaml = self.artifacts[f"rules/clash/{name}.yaml"].decode().splitlines()
            left = [line for line in csv if line and not line.startswith("#")]
            right = [json.loads(line[4:]) for line in yaml if line.startswith("  - ")]
            self.assertEqual(left, right)

    def test_full_payload_is_union_of_domain_and_ip_payloads(self):
        def lines(name):
            return [line for line in self.artifacts[f"rules/loon/{name}.list"].decode().splitlines()
                    if line and not line.startswith("#")]
        self.assertEqual(lines("Google-AI"), lines("Google-AI-Domains") + lines("Google-AI-IP"))

    def test_generated_files_match_rebuild_exactly(self):
        for relative, expected in self.artifacts.items():
            with self.subTest(file=relative):
                self.assertEqual(core.safe_path(ROOT, relative).read_bytes(), expected)

    def test_byte_reproducibility(self):
        rebuilt, _ = core.build_artifacts(self.config, self.manifest, self.raw, self.licenses, self.targets)
        self.assertEqual(self.artifacts, rebuilt)

    def test_publication_urls_match_configured_repository(self):
        publication = self.config.get("publication")
        if not publication:
            self.skipTest("No publication repository configured")
        for name in ("Google-AI", "Google-AI-Domains", "Google-AI-IP"):
            for format_name, extension in (("loon", "list"), ("clash", "yaml")):
                url = core.published_file_url(
                    publication, f"rules/{format_name}/{name}.{extension}",
                )
                self.assertIn(url, self.artifacts["README.md"].decode())

    def test_published_examples_contain_no_placeholder_url(self):
        publication = self.config.get("publication")
        if not publication:
            self.skipTest("No publication repository configured")
        for name in ("examples/loon.conf", "examples/clash.yaml"):
            content = self.artifacts[name].decode()
            self.assertNotIn("example.com", content)
            self.assertIn(publication["repository"], content)
        self.assertNotIn("尚未部署公开订阅地址", self.artifacts["README.md"].decode())

    def test_every_origin_line_resolves_to_the_snapshot_text(self):
        for candidate in self.candidates:
            with self.subTest(source=candidate.source, line=candidate.line):
                lines = self.raw[candidate.source].decode("utf-8-sig").splitlines(keepends=True)
                span = "".join(lines[candidate.line - 1:candidate.line + candidate.raw.count("\n")])
                self.assertIn(candidate.raw, span)

    def test_tampered_snapshot_bytes_are_rejected(self):
        tampered = dict(self.raw)
        tampered["bm7-google"] += b"\n# fixture tamper\n"
        with self.assertRaisesRegex(ValueError, "Source hash mismatch"):
            core.build_artifacts(self.config, self.manifest, tampered, self.licenses, self.targets)

    def test_online_failure_leaves_generated_files_unchanged(self):
        before = {relative: core.safe_path(ROOT, relative).read_bytes() for relative in self.artifacts}
        with patch.object(updater, "fetch_current", side_effect=OSError("fixture network failure")):
            with contextlib.redirect_stderr(io.StringIO()):
                result = updater.main([], root=ROOT)
        self.assertEqual(result, 1)
        self.assertEqual(before, {relative: core.safe_path(ROOT, relative).read_bytes()
                                  for relative in self.artifacts})


class TransactionTests(unittest.TestCase):
    def test_failed_file_replacement_rolls_back(self):
        work = Path(os.environ.get("RULES_TEST_WORK_DIR", str(ROOT / "work")))
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="transaction-test-", dir=work) as temporary:
            root = Path(temporary) / "project"
            root.mkdir()
            (root / "a.txt").write_bytes(b"original-a")
            (root / "b.txt").write_bytes(b"original-b")
            real_replace = os.replace
            count = 0

            def injected_replace(source, target):
                nonlocal count
                if "new" in Path(source).parts:
                    count += 1
                    if count == 2:
                        raise OSError("fixture replacement failure")
                return real_replace(source, target)

            with patch.object(updater.os, "replace", side_effect=injected_replace):
                with self.assertRaises(OSError):
                    updater.write_batch(
                        root, {"a.txt": b"new-a", "b.txt": b"new-b"}, work / "staging",
                    )
            self.assertEqual((root / "a.txt").read_bytes(), b"original-a")
            self.assertEqual((root / "b.txt").read_bytes(), b"original-b")


if __name__ == "__main__":
    unittest.main()
