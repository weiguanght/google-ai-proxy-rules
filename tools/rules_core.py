"""Deterministic Google / Gemini / Antigravity rule extraction and generation.

The source installers are parsed as text. They are never imported or executed.
Licensing: see LICENSE and NOTICE.md.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

DOMAIN_KINDS = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}
NETWORK_KINDS = {"IP-CIDR", "IP-CIDR6", "IP-ASN"}
RULE_KINDS = DOMAIN_KINDS | NETWORK_KINDS
NON_SCOPE_KINDS = {"PROCESS-NAME", "USER-AGENT", "GEOIP"}
ORDER = {kind: i for i, kind in enumerate(
    ("DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "IP-ASN")
)}
FOREIGN_PAC_ROOTS = {
    "github.com", "githubusercontent.com", "anthropic.com", "openai.com"
}
SPECIAL_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24",
    "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "::ffff:0:0/96", "100::/64",
    "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
))
TICK = chr(96)
FENCE = TICK * 3


@dataclass(frozen=True)
class Rule:
    kind: str
    value: str

    def render(self) -> str:
        suffix = ",no-resolve" if self.kind in NETWORK_KINDS else ""
        return f"{self.kind},{self.value}{suffix}"


@dataclass(frozen=True)
class Candidate:
    rule: Rule
    source: str
    line: int
    raw: str
    note: str = ""

    def record(self) -> dict[str, Any]:
        return {
            "rule": self.rule.render(), "source": self.source,
            "line": self.line, "raw": self.raw, "note": self.note,
        }


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_path(root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"Expected a project-relative path: {relative}")
    return root / path


def normalize_rule(kind: str, value: str) -> Rule:
    kind = kind.strip().upper()
    value = value.strip().lower()
    if kind in DOMAIN_KINDS:
        value = value.rstrip(".")
        if kind == "DOMAIN-SUFFIX":
            value = value.lstrip(".")
        if not value or not re.fullmatch(r"[a-z0-9_.-]+", value):
            raise ValueError(f"Unsupported domain token: {kind},{value}")
        if kind != "DOMAIN-KEYWORD" and any(not label for label in value.split(".")):
            raise ValueError(f"Empty domain label: {value}")
    elif kind in {"IP-CIDR", "IP-CIDR6"}:
        network = ipaddress.ip_network(value, strict=False)
        kind = "IP-CIDR" if network.version == 4 else "IP-CIDR6"
        value = str(network)
    elif kind == "IP-ASN":
        number = int(value.removeprefix("as"))
        if not 1 <= number <= 4294967295:
            raise ValueError(f"Invalid ASN: {value}")
        value = str(number)
    else:
        raise ValueError(f"Unsupported rule kind: {kind}")
    return Rule(kind, value)


def is_public_network(rule: Rule) -> bool:
    if rule.kind not in {"IP-CIDR", "IP-CIDR6"}:
        return True
    network = ipaddress.ip_network(rule.value)
    return network.is_global and not any(
        network.version == blocked.version and network.overlaps(blocked)
        for blocked in SPECIAL_NETWORKS
    )


def matches_domain(domain: str, rule: Rule) -> bool:
    domain = domain.strip().lower().rstrip(".")
    if rule.kind == "DOMAIN":
        return domain == rule.value
    if rule.kind == "DOMAIN-SUFFIX":
        return domain == rule.value or domain.endswith("." + rule.value)
    if rule.kind == "DOMAIN-KEYWORD":
        return rule.value in domain
    return False


def subsumes(cover: Rule, target: Rule) -> bool:
    """Prove inclusion of the target rule's complete static matching range."""
    if target.kind == "DOMAIN":
        return matches_domain(target.value, cover)
    if target.kind == "DOMAIN-SUFFIX":
        return (
            cover.kind == "DOMAIN-SUFFIX"
            and (target.value == cover.value or target.value.endswith("." + cover.value))
        ) or (cover.kind == "DOMAIN-KEYWORD" and cover.value in target.value)
    if target.kind == "DOMAIN-KEYWORD":
        return cover.kind == "DOMAIN-KEYWORD" and cover.value in target.value
    if target.kind in {"IP-CIDR", "IP-CIDR6"}:
        if cover.kind != target.kind:
            return False
        return ipaddress.ip_network(target.value).subnet_of(ipaddress.ip_network(cover.value))
    return cover.kind == target.kind == "IP-ASN" and cover.value == target.value


def rule_sort_key(rule: Rule) -> tuple:
    if rule.kind in {"IP-CIDR", "IP-CIDR6"}:
        network = ipaddress.ip_network(rule.value)
        return ORDER[rule.kind], int(network.network_address), network.prefixlen
    if rule.kind == "IP-ASN":
        return ORDER[rule.kind], int(rule.value), 0
    return ORDER[rule.kind], rule.value, 0


def minimize_rules(rules: Iterable[Rule]) -> list[Rule]:
    unique = set(rules)
    domains = sorted((r for r in unique if r.kind in DOMAIN_KINDS), key=rule_sort_key)
    result = [
        rule for rule in domains
        if not any(other != rule and subsumes(other, rule) for other in domains)
    ]
    for version, kind in ((4, "IP-CIDR"), (6, "IP-CIDR6")):
        networks = [
            ipaddress.ip_network(rule.value) for rule in unique
            if rule.kind in {"IP-CIDR", "IP-CIDR6"}
            and ipaddress.ip_network(rule.value).version == version
        ]
        result.extend(Rule(kind, str(n)) for n in ipaddress.collapse_addresses(networks))
    result.extend(rule for rule in unique if rule.kind == "IP-ASN")
    return sorted(result, key=rule_sort_key)


def parse_list_rows(text: str) -> list[tuple[int, str, str, str, str]]:
    rows = []
    section = ""
    for line, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith(("#", "//", ";")):
            if stripped.startswith("# "):
                section = stripped[2:].strip()
            continue
        parts = [part.strip() for part in stripped.split(",")]
        if len(parts) < 2 or not parts[1]:
            raise ValueError(f"Malformed rule line {line}: {stripped}")
        kind = parts[0].upper()
        if kind not in RULE_KINDS | NON_SCOPE_KINDS:
            raise ValueError(f"Unknown source rule kind at line {line}: {kind}")
        if len(parts) > 2 and parts[2].upper() in {"DIRECT", "REJECT", "REJECT-DROP"}:
            kind = "EXCLUDED-POLICY"
        rows.append((line, kind, parts[1], stripped, section))
    return rows


def extract_patch_rows(text: str, mode: str) -> list[tuple[int, str, str, str]]:
    patterns = {
        "patch-js": r"\bconst\s+prependRules\s*=\s*\[([\s\S]*?)\]\s*;",
        "patch-py": r"\bantigravity_rules\s*=\s*\[([\s\S]*?)\]",
    }
    block = re.search(patterns[mode], text)
    if not block:
        raise ValueError(f"{mode}: rule array anchor is missing; review the extractor")
    rows = []
    literal = re.compile(r"""['"]([^'"]+)['"]""")
    for match in literal.finditer(block.group(1)):
        raw = match.group(1)
        parts = [part.strip() for part in raw.split(",")]
        line = text.count("\n", 0, block.start(1) + match.start()) + 1
        if len(parts) < 2 or not parts[1]:
            raise ValueError(f"{mode}:{line}: unexpected literal in rule array: {raw}")
        kind = parts[0].upper()
        if kind not in RULE_KINDS | NON_SCOPE_KINDS:
            raise ValueError(f"{mode}:{line}: unsupported rule kind in array: {kind}")
        if len(parts) > 2 and parts[2].upper() in {"DIRECT", "REJECT", "REJECT-DROP"}:
            kind = "EXCLUDED-POLICY"
        rows.append((line, kind, parts[1], raw))
    if not rows:
        raise ValueError(f"{mode}: rule array contains no recognized rules")
    return rows


def extract_pac_rows(text: str) -> list[tuple[int, str, str, str]]:
    block = re.search(r"//\s*2\.\s*Google[\s\S]*?//\s*3\.", text)
    if not block:
        raise ValueError("PAC Google core domain anchor is missing; review the extractor")
    pattern = re.compile(r"""shExpMatch\s*\(\s*host\s*,\s*["']([^"']+)["']\s*\)""")
    rows = []
    for match in pattern.finditer(block.group()):
        value = match.group(1)
        line = text.count("\n", 0, block.start() + match.start()) + 1
        kind = "DOMAIN-SUFFIX" if value.startswith("*.") else "DOMAIN"
        rows.append((line, kind, value[2:] if value.startswith("*.") else value, match.group()))
    if not rows:
        raise ValueError("PAC Google core domain section has no host patterns")
    return rows


def collect_candidates(
    config: dict, texts: dict[str, str]
) -> tuple[list[Candidate], list[dict]]:
    candidates: list[Candidate] = []
    excluded: list[dict] = []
    specs = config["sources"]

    def reject(source: str, line: int, raw: str, reason: str) -> None:
        excluded.append({"source": source, "line": line, "raw": raw, "reason": reason})

    def accept(source: str, line: int, kind: str, value: str, raw: str, note: str = "") -> None:
        rule = normalize_rule(kind, value)
        if not is_public_network(rule):
            reject(source, line, raw, "non_public_network")
        else:
            candidates.append(Candidate(rule, source, line, raw, note))

    # Provider-specific Google files establish the Google family scope.
    for spec in specs:
        if spec["mode"] != "google-list":
            continue
        rows = parse_list_rows(texts[spec["id"]])
        if not any(kind in DOMAIN_KINDS for _, kind, *_ in rows):
            raise ValueError(f"{spec['id']}: no domain rules found")
        for line, kind, value, raw, _ in rows:
            if kind in RULE_KINDS:
                accept(spec["id"], line, kind, value, raw)
            else:
                reject(spec["id"], line, raw, "outside_domain_public_ip_scope")

    for spec in specs:
        mode, source = spec["mode"], spec["id"]
        if mode not in {"patch-js", "patch-py", "patch-pac"}:
            continue
        family = [candidate.rule for candidate in candidates if candidate.rule.kind in DOMAIN_KINDS]
        rows = extract_pac_rows(texts[source]) if mode == "patch-pac" else extract_patch_rows(texts[source], mode)
        for line, kind, value, raw in rows:
            if kind not in RULE_KINDS:
                reason = "direct_or_reject_policy" if kind == "EXCLUDED-POLICY" else "outside_domain_public_ip_scope"
                reject(source, line, raw, reason)
                continue
            rule = normalize_rule(kind, value)
            if mode == "patch-pac" and rule.value in FOREIGN_PAC_ROOTS:
                reject(source, line, raw, "non_google_pac_dependency")
                continue
            permitted = (
                rule.kind in NETWORK_KINDS
                or (rule.kind == "DOMAIN-KEYWORD" and rule.value in config["patch_keywords"])
                or rule.value in config["pac_google_roots"]
                or any(subsumes(scope, rule) for scope in family)
            )
            if not permitted:
                raise ValueError(
                    f"{source}:{line}: new patch rule outside the configured Google scope: "
                    f"{rule.render()}; review config/sources.json"
                )
            note = "PAC *.host normalized to host suffix (including its root)" if mode == "patch-pac" and kind == "DOMAIN-SUFFIX" else ""
            accept(source, line, rule.kind, rule.value, raw, note)

    family = [candidate.rule for candidate in candidates if candidate.rule.kind in DOMAIN_KINDS]
    google_networks = {candidate.rule for candidate in candidates if candidate.rule.kind in NETWORK_KINDS}
    for spec in specs:
        if spec["mode"] != "google-filter":
            continue
        rows = parse_list_rows(texts[spec["id"]])
        if not any(kind in DOMAIN_KINDS for _, kind, *_ in rows):
            raise ValueError(f"{spec['id']}: no domain rules found")
        for line, kind, value, raw, section in rows:
            if kind not in RULE_KINDS:
                reject(spec["id"], line, raw, "outside_domain_public_ip_scope")
                continue
            rule = normalize_rule(kind, value)
            google_section = section.lower().startswith("google ai /")
            permitted = (
                google_section
                or (rule.kind in DOMAIN_KINDS and any(subsumes(scope, rule) for scope in family))
                or (rule.kind in NETWORK_KINDS and rule in google_networks)
            )
            if permitted:
                accept(spec["id"], line, rule.kind, rule.value, raw, "Google-related subset of multi-provider list")
            else:
                reject(spec["id"], line, raw, "non_google_provider_or_network")
    return candidates, excluded


def check_targets(final: list[Rule], targets: dict) -> dict:
    result: dict[str, Any] = {}
    for group in ("baseline", "extended"):
        cases = []
        for target in targets[group]:
            matches = [rule.render() for rule in final if matches_domain(target["domain"], rule)]
            cases.append({**target, "covered": bool(matches), "matches": matches})
        result[group] = {
            "covered": sum(case["covered"] for case in cases), "total": len(cases), "cases": cases,
        }
        missing = [case["domain"] for case in cases if not case["covered"]]
        if missing:
            raise ValueError(f"{group} target coverage gaps: {', '.join(missing)}")
    return result


def network_statistics(final: list[Rule]) -> dict:
    result: dict[str, Any] = {}
    for version, kind in ((4, "IP-CIDR"), (6, "IP-CIDR6")):
        networks = [ipaddress.ip_network(rule.value) for rule in final if rule.kind == kind]
        result[f"ipv{version}"] = {
            "cidrs": [str(network) for network in networks],
            "addresses": str(sum(network.num_addresses for network in networks)),
        }
    result["asns"] = [rule.value for rule in final if rule.kind == "IP-ASN"]
    return result


def source_url(spec: dict, line: int | None = None) -> str:
    path = quote(spec["path"], safe="/")
    url = f"https://github.com/{spec['repo']}/blob/{spec['commit']}/{path}"
    return url + (f"#L{line}" if line else "")


def render_rule_file(final: list[Rule], checked_on: str, profile: str, yaml: bool = False) -> bytes:
    counts = Counter(rule.kind for rule in final)
    header = [
        "# NAME: Google / Gemini / Antigravity",
        f"# GENERATED: {checked_on} (Asia/Shanghai)",
        f"# PROFILE: {profile}",
        "# SOURCE MANIFEST: sources/manifest.json",
        "# POLICY: supplied by the client; no DIRECT / process / user-agent rules",
        *[f"# {kind}: {counts[kind]}" for kind in ORDER if counts[kind]],
        f"# TOTAL: {len(final)}",
    ]
    if yaml:
        header.append("payload:")
        header.extend("  - " + json.dumps(rule.render(), ensure_ascii=False) for rule in final)
    else:
        header.extend(rule.render() for rule in final)
    return ("\n".join(header) + "\n").encode("utf-8")


def published_file_url(publication: dict | None, path: str) -> str:
    if publication:
        ref = quote(publication.get("ref", "main"), safe="")
        return f"https://raw.githubusercontent.com/{publication['repository']}/{ref}/{path}"
    return "https://example.com/google-ai-proxy-rules/" + path


def render_readme(manifest: dict, report: dict, final: list[Rule], publication: dict | None = None) -> bytes:
    stats = report["statistics"]
    keywords = [rule.value for rule in final if rule.kind == "DOMAIN-KEYWORD"]
    subscription_lines = []
    if publication:
        repository = publication["repository"]
        subscription_lines = [
            "## 订阅地址", "",
            f"仓库：[{repository}](https://github.com/{repository})。", "",
            "| 内容 | Loon | Clash / Mihomo |", "|---|---|---|",
        ]
        for name, title in (
            ("Google-AI", "汇总"), ("Google-AI-Domains", "仅域名"),
            ("Google-AI-IP", "仅公网 IP"),
        ):
            loon_url = published_file_url(publication, f"rules/loon/{name}.list")
            clash_url = published_file_url(publication, f"rules/clash/{name}.yaml")
            subscription_lines.append(f"| {title} | [订阅]({loon_url}) | [订阅]({clash_url}) |")
        subscription_lines.append("")
        import_lines = [
            "使用 [Loon 示例](examples/loon.conf) 或 [Clash/Mihomo 示例](examples/clash.yaml) 中的真实订阅地址。",
            "将 Google-AI 换成客户端已有的策略组名。", "",
        ]
    else:
        import_lines = [
            "条件：规则文件已发布到客户端可访问的 HTTPS 地址。",
            "将 [Loon 示例](examples/loon.conf) 或 [Clash/Mihomo 示例](examples/clash.yaml) 中的 example.com 换成发布地址。",
            "将 Google-AI 换成客户端已有的策略组名。",
            "本项目尚未部署公开订阅地址。", "",
        ]
    rows = [
        "# Google / Gemini / Antigravity Proxy Rules", "",
        "本项目合并指定来源的 Google、Gemini、Antigravity 域名与公网 IP 规则。", "",
        f"- 生成日期：**{manifest['checked_on']}，Asia/Shanghai**。",
        f"- 合并后：**{stats['domain_rules']} 条域名规则、"
        f"{len(report['public_networks']['ipv4']['cidrs'])} 条 IPv4 CIDR、"
        f"{len(report['public_networks']['ipv6']['cidrs'])} 条 IPv6 CIDR、"
        f"{len(report['public_networks']['asns'])} 条 ASN 规则**。",
        f"- 24 个关键域名 **{report['baseline']['covered']}/{report['baseline']['total']}**；"
        f"扩展检查 **{report['extended']['covered']}/{report['extended']['total']}**。",
        f"- 纳入的 {report['source_union']['unique_rules']} 条不同源规则，其完整静态匹配范围均被最终规则覆盖。", "",
        "## 使用哪个文件", "",
        "| 用途 | Loon | Clash / Mihomo |", "|---|---|---|",
        "| 域名 + 公网 IP 汇总 | [Google-AI.list](rules/loon/Google-AI.list) | [Google-AI.yaml](rules/clash/Google-AI.yaml) |",
        "| 仅域名 | [Google-AI-Domains.list](rules/loon/Google-AI-Domains.list) | [Google-AI-Domains.yaml](rules/clash/Google-AI-Domains.yaml) |",
        "| 仅公网 IP | [Google-AI-IP.list](rules/loon/Google-AI-IP.list) | [Google-AI-IP.yaml](rules/clash/Google-AI-IP.yaml) |", "",
        "汇总文件和分表二选一，不重复引入。策略组由客户端配置指定，规则文件不写死代理节点。", "",
        *subscription_lines,
        "## 合并口径", "",
        "- blackmatrix7 Google、Gemini：纳入域名和公网 IP。",
        "- dayvight：纳入 google-auth、google-full；保留整个 .goog 后缀的覆盖。",
        "- antigravity-proxy：只读取安装器的规则数组和 PAC 的 Google 核心域名分支。",
        "- VPSDance：纳入 google-ai，并提取 global/all 中属于 Google 范围的规则。",
        "- 重复规则合并；被更广的后缀或关键词完全包含的规则移除。",
        "- 公网 CIDR 按地址集合等价合并；ASN 按编号保留。", "",
        "本项目不执行安装器，不修改 Antigravity 应用，不注入代理环境变量。",
        "PROCESS-NAME、USER-AGENT、PAC 默认代理分支和私网 DIRECT 排除项不纳入生成规则。",
        "VPSDance 中 OpenAI、Anthropic 等其他平台的网段和 ASN 不混入 Google IP 分表。", "",
        "## 广覆盖的实际范围", "",
        "以下关键词按域名字符串匹配，不限定为 Google 官方域名：",
        ", ".join(TICK + word + TICK for word in keywords) + "。",
        "Cloud Run / App Engine 等公共后缀也包含第三方租户。",
        "Google 账号、Gmail 等通用服务同样会匹配到所选策略组。", "",
        "当前公网 CIDR 取自 blackmatrix7 的 Google.list。",
        "IP / ASN 规则带 no-resolve，按已有目标 IP 匹配。",
        "关键链路检查用于回归；源规则包含检查用于验证合并后的覆盖范围。", "",
        "## 导入客户端", "",
        *import_lines,
        "Clash/Mihomo rule-provider 使用 behavior: classical 和 format: yaml。",
        "需要分别指定域名与 IP 策略时，引入两个分表；需要同一策略时，引入汇总文件。",
        "需要让这些域名使用专用策略时，规则应排在会抢先命中的通用规则和 FINAL/MATCH 之前。", "",
        "## 更新与核验", "",
        "条件：终端当前目录为本项目根目录。Python 3.10+，不需要第三方 Python 包。",
        "目的：从配置中的四个仓库取得当前指定分支，固定提交后重新生成规则。", "",
        FENCE + "bash", "python3 tools/update_rules.py", FENCE, "",
        "目的：只用附带快照离线重建。", "",
        FENCE + "bash", "python3 tools/update_rules.py --offline", FENCE, "",
        "目的：核验快照哈希、覆盖结果与所有生成文件，不改动文件。", "",
        FENCE + "bash",
        "python3 tools/update_rules.py --check",
        "python3 -m unittest discover -s tests -v", FENCE, "",
        "提取结构变化、下载失败或覆盖检查失败时，更新命令退出，保留旧生成文件。",
        "工具只访问 config/sources.json 中指定的仓库、规则路径和随附许可证路径。",
        "",
        "## 追溯", "",
        "- [来源与固定提交](SOURCES.md)",
        "- [覆盖报告](reports/coverage.md)",
        "- [覆盖数据](reports/coverage.json)",
        "- [最终规则的源规则映射](reports/provenance.json)",
        "- [被排除的规则及原因](reports/exclusions.json)",
        "- [来源清单和文件哈希](sources/manifest.json)",
        "- [上游许可与署名](NOTICE.md)", "",
    ]
    return ("\n".join(rows)).encode("utf-8")


def build_artifacts(
    config: dict, manifest: dict, source_bytes: dict[str, bytes],
    license_bytes: dict[str, bytes], targets: dict,
) -> tuple[dict[str, bytes], dict]:
    texts = {key: value.decode("utf-8-sig") for key, value in source_bytes.items()}
    candidates, excluded = collect_candidates(config, texts)
    unique = sorted({candidate.rule for candidate in candidates}, key=rule_sort_key)
    final = minimize_rules(unique)
    domains = [rule for rule in final if rule.kind in DOMAIN_KINDS]
    networks = [rule for rule in final if rule.kind in NETWORK_KINDS]
    records = {item["id"]: item for item in manifest["sources"]}
    origins: dict[Rule, list[dict]] = defaultdict(list)
    for candidate in candidates:
        origin = candidate.record()
        origin["url"] = source_url(records[candidate.source], candidate.line)
        origins[candidate.rule].append(origin)

    mappings: dict[Rule, list[dict]] = defaultdict(list)
    uncovered = []
    for rule in unique:
        covers = [output for output in final if subsumes(output, rule)]
        if not covers:
            uncovered.append(rule.render())
        else:
            mappings[covers[0]].append({"input_rule": rule.render(), "origins": origins[rule]})
    if uncovered:
        raise ValueError("Source union gaps: " + ", ".join(uncovered))
    if any(
        a != b and subsumes(a, b)
        for a in domains for b in domains
    ):
        raise ValueError("Domain minimization left redundant rules")
    checks = check_targets(final, targets)
    report = {
        "schema_version": 1, "checked_on": manifest["checked_on"], "timezone": "Asia/Shanghai",
        "comparison": "static domain/rule matching; no live network connectivity test",
        **checks,
        "source_union": {
            "candidate_occurrences": len(candidates), "unique_rules": len(unique),
            "fully_covered": len(unique) - len(uncovered), "uncovered": uncovered,
        },
        "statistics": {
            "domain_rules": len(domains), "network_rules": len(networks),
            "total_rules": len(final), "rule_kinds": dict(Counter(rule.kind for rule in final)),
            "candidate_occurrences_by_source": dict(Counter(c.source for c in candidates)),
            "excluded_occurrences_by_source": dict(Counter(item["source"] for item in excluded)),
        },
        "public_networks": network_statistics(final),
    }
    artifacts: dict[str, bytes] = {}
    for source in manifest["sources"]:
        data = source_bytes[source["id"]]
        if sha256(data) != source["sha256"]:
            raise ValueError(f"Source hash mismatch: {source['id']}")
        artifacts[source["local_path"]] = data
    for record in manifest["licenses"]:
        data = license_bytes[record["repo"]]
        if sha256(data) != record["sha256"]:
            raise ValueError(f"License hash mismatch: {record['repo']}")
        artifacts[record["local_path"]] = data

    for name, profile, rules in (
        ("Google-AI", "full", final), ("Google-AI-Domains", "domains", domains),
        ("Google-AI-IP", "public-ip", networks),
    ):
        artifacts[f"rules/loon/{name}.list"] = render_rule_file(rules, manifest["checked_on"], profile)
        artifacts[f"rules/clash/{name}.yaml"] = render_rule_file(rules, manifest["checked_on"], profile, yaml=True)
    artifacts["reports/coverage.json"] = json_bytes(report)
    artifacts["reports/provenance.json"] = json_bytes({
        "schema_version": 1,
        "rules": [
            {"output_rule": rule.render(), "covered_input_rules": mappings[rule]} for rule in final
        ],
    })
    artifacts["reports/exclusions.json"] = json_bytes({
        "schema_version": 1, "total": len(excluded),
        "reasons": dict(Counter(item["reason"] for item in excluded)), "rules": excluded,
    })

    coverage_md = [
        "# 覆盖报告", "",
        f"生成日期：{manifest['checked_on']}，Asia/Shanghai。",
        f"域名规则：{len(domains)}；公网 IP/ASN 规则：{len(networks)}。",
        f"源规则完整包含：{len(unique) - len(uncovered)}/{len(unique)}。",
        "校验范围：域名规则匹配、源规则包含关系与公网 CIDR 集合。", "",
    ]
    for group, title in (("baseline", "24 个 Antigravity 关键域名"), ("extended", "扩展匹配检查")):
        coverage_md += [
            "## " + title, "",
            f"结果：**{checks[group]['covered']}/{checks[group]['total']}**。", "",
            "| 域名 | 用途 | 结果 | 命中规则 |", "|---|---|---|---|",
        ]
        coverage_md += [
            f"| {case['domain']} | {case['purpose']} | {'通过' if case['covered'] else '缺口'} | "
            + "; ".join(TICK + value + TICK for value in case["matches"]) + " |"
            for case in checks[group]["cases"]
        ]
        coverage_md.append("")
    coverage_md += [
        "## 公网 IP", "",
        *["- " + TICK + cidr + TICK for version in ("ipv4", "ipv6") for cidr in report["public_networks"][version]["cidrs"]],
        f"- IPv4 CIDR 地址数量：{report['public_networks']['ipv4']['addresses']}。",
        "- ASN：" + (", ".join(report["public_networks"]["asns"]) or "当前无 Google 专属 ASN 规则") + "。", "",
        f"基准域名来源：[dayvight 校验脚本]({targets['baseline_source']})。", "",
    ]
    artifacts["reports/coverage.md"] = ("\n".join(coverage_md)).encode("utf-8")
    publication = config.get("publication")
    artifacts["README.md"] = render_readme(manifest, report, final, publication)

    source_md = [
        "# 来源记录", "",
        "每次更新先固定四个仓库的提交，再读取下面的明确文件。",
        "完整 SHA-256、字节数和快照路径见 sources/manifest.json。", "",
        "| 来源 | 文件 | 提交 | SHA-256 前 12 位 | 纳入规则出现次数 |",
        "|---|---|---|---|---|",
    ]
    source_md += [
        f"| {record['id']} | [{record['path']}]({source_url(record)}) | "
        f"{TICK}{record['commit'][:12]}{TICK} | {TICK}{record['sha256'][:12]}{TICK} | "
        f"{report['statistics']['candidate_occurrences_by_source'].get(record['id'], 0)} |"
        for record in manifest["sources"]
    ]
    source_md += ["", "PAC 只提取 Google 核心域名分支；不把默认代理分支转换为全流量规则。", ""]
    artifacts["SOURCES.md"] = ("\n".join(source_md)).encode("utf-8")

    notice = [
        "# 上游许可与署名", "",
        "本项目保留各上游的规则来源与许可文本。",
        "Google/Gemini 合并规则包含 blackmatrix7 的 GPL-2.0 来源内容；对应许可文本保存在根目录 LICENSE。",
        "生成工具采用与合并规则一致的 GPL-2.0 许可。MIT 来源的许可与署名单独保留。", "",
        "| 上游 | 声明许可 | 许可文本 |", "|---|---|---|",
    ]
    for record in manifest["licenses"]:
        notice.append(
            f"| [{record['repo']}](https://github.com/{record['repo']}) | {record['spdx']} | "
            f"[{Path(record['local_path']).name}]({record['local_path']}) |"
        )
    notice.append("")
    artifacts["NOTICE.md"] = ("\n".join(notice)).encode("utf-8")
    artifacts["LICENSE"] = license_bytes["blackmatrix7/ios_rule_script"]
    example_note = (
        "# 此 URL 已指向项目仓库；将 Google-AI 换成你已有的策略组名。\n"
        if publication else "# 条件：规则文件已发布；替换 URL 和已有策略组名。\n"
    )
    artifacts["examples/loon.conf"] = (
        example_note
        + "[Remote Rule]\n"
        + published_file_url(publication, "rules/loon/Google-AI.list") + ", "
        "policy=Google-AI, tag=Google-AI, enabled=true\n"
    ).encode("utf-8")
    artifacts["examples/clash.yaml"] = (
        example_note
        +
        "rule-providers:\n"
        "  Google-AI:\n"
        "    type: http\n"
        "    behavior: classical\n"
        "    format: yaml\n"
        f"    url: {published_file_url(publication, 'rules/clash/Google-AI.yaml')}\n"
        "    path: ./rule-providers/Google-AI.yaml\n"
        "    interval: 86400\n"
        "rules:\n"
        "  - RULE-SET,Google-AI,Google-AI\n"
        "# 将 RULE-SET 放在会抢先命中的通用规则和 MATCH 之前。\n"
    ).encode("utf-8")

    complete_manifest = dict(manifest)
    complete_manifest["generated_sha256"] = {
        path: sha256(data) for path, data in sorted(artifacts.items())
    }
    artifacts["sources/manifest.json"] = json_bytes(complete_manifest)
    return artifacts, report
