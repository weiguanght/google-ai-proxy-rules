#!/usr/bin/env python3
"""Fetch only configured source files; validate before replacing generated files."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import datetime as dt
import json
import os
import re
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from urllib.parse import quote
from zoneinfo import ZoneInfo

from rules_core import build_artifacts, json_bytes, safe_path, sha256

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "sources/manifest.json"
USER_AGENT = "Google-AI-Proxy-Rules/1.0"


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_config(root: Path) -> tuple[dict, dict]:
    config = load_json(root / "config/sources.json")
    targets = load_json(root / "config/targets.json")
    if config.get("schema_version") != 1 or targets.get("schema_version") != 1:
        raise ValueError("Unsupported configuration schema")
    ids = [source["id"] for source in config["sources"]]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate source identifiers")
    for source in config["sources"]:
        if source["mode"] not in {"google-list", "google-filter", "patch-js", "patch-py", "patch-pac"}:
            raise ValueError(f"Unknown source mode: {source['mode']}")
        safe_path(root, source["local_path"])
        if len(source["repo"].split("/")) != 2 or ".." in source["path"].split("/"):
            raise ValueError("Invalid repository/path in source configuration")
    for record in config["licenses"]:
        safe_path(root, record["local_path"])
    publication_path = root / "config/publish.json"
    if publication_path.is_file():
        publication = load_json(publication_path)
        if publication.get("schema_version") != 1:
            raise ValueError("Unsupported publication configuration schema")
        if not re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", publication.get("repository", "")):
            raise ValueError("Invalid publication repository name")
        if not re.fullmatch(r"[A-Za-z0-9_./-]+", publication.get("ref", "")):
            raise ValueError("Invalid publication ref")
        config = {**config, "publication": publication}
    return config, targets


def load_snapshots(root: Path, config: dict) -> tuple[dict, dict[str, bytes], dict[str, bytes]]:
    manifest = load_json(root / MANIFEST)
    records = {source["id"]: source for source in manifest["sources"]}
    data = {}
    for spec in config["sources"]:
        record = records[spec["id"]]
        if any(record[key] != spec[key] for key in ("repo", "ref", "path", "mode", "local_path")):
            raise ValueError(f"Configuration/snapshot mismatch: {spec['id']}; run an online update")
        raw = safe_path(root, record["local_path"]).read_bytes()
        if sha256(raw) != record["sha256"]:
            raise ValueError(f"Snapshot hash mismatch: {spec['id']}")
        data[spec["id"]] = raw
    licenses = {}
    for record in manifest["licenses"]:
        raw = safe_path(root, record["local_path"]).read_bytes()
        if sha256(raw) != record["sha256"]:
            raise ValueError(f"License hash mismatch: {record['repo']}")
        licenses[record["repo"]] = raw
    return manifest, data, licenses


def request_bytes(url: str) -> bytes:
    for attempt in range(3):
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"},
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read()
        except Exception as error:
            if attempt == 2:
                raise RuntimeError(f"GET {url}: {error}") from error
            time.sleep(attempt + 1)
    raise RuntimeError("Unreachable retry state")


def request_json(url: str) -> dict:
    return json.loads(request_bytes(url))


def fetch_current(root: Path, config: dict, old: dict, checked_on: str) -> tuple[dict, dict, dict]:
    refs = {}
    for source in config["sources"]:
        previous = refs.setdefault(source["repo"], source["ref"])
        if previous != source["ref"]:
            raise ValueError("All sources in one repository must use the same configured ref")

    def resolve(item: tuple[str, str]) -> tuple[str, dict]:
        repo, ref = item
        info = request_json(f"https://api.github.com/repos/{repo}/commits/{quote(ref, safe='')}")
        metadata = dict(old.get("repositories", {}).get(repo, {}))
        metadata.update({
            "ref": ref, "commit": info["sha"],
            "commit_date_utc": info["commit"]["committer"]["date"],
        })
        return repo, metadata

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        repositories = dict(pool.map(resolve, refs.items()))

    def fetch_source(spec: dict) -> tuple[dict, bytes]:
        commit = repositories[spec["repo"]]["commit"]
        path = quote(spec["path"], safe="/")
        url = f"https://raw.githubusercontent.com/{spec['repo']}/{commit}/{path}"
        raw = request_bytes(url)
        record = {**spec, "commit": commit, "url": url, "sha256": sha256(raw),
                  "bytes": len(raw), "lines": len(raw.decode("utf-8-sig").splitlines())}
        return record, raw

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        fetched = list(pool.map(fetch_source, config["sources"]))
    records = [record for record, _ in fetched]
    source_bytes = {record["id"]: raw for record, raw in fetched}
    old_licenses = {record["repo"]: record for record in old.get("licenses", [])}

    def fetch_license(spec: dict) -> tuple[dict, bytes]:
        repo = spec["repo"]
        commit = repositories[repo]["commit"]
        cached = old_licenses.get(repo)
        if cached and cached["commit"] == commit and cached["path"] == spec["path"]:
            cache_path = safe_path(root, cached["local_path"])
            if cache_path.is_file():
                raw = cache_path.read_bytes()
                if sha256(raw) == cached["sha256"]:
                    return {**cached, "local_path": spec["local_path"]}, raw
        info = request_json(f"https://api.github.com/repos/{repo}/license?ref={commit}")
        if info["path"] != spec["path"]:
            raise ValueError(f"License path changed for {repo}; review config/sources.json")
        raw = base64.b64decode(info["content"])
        spdx = info["license"]["spdx_id"]
        record = {
            **spec, "commit": commit, "spdx": spdx,
            "sha256": sha256(raw), "bytes": len(raw),
        }
        return record, raw

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        fetched_licenses = list(pool.map(fetch_license, config["licenses"]))
    license_records = [record for record, _ in fetched_licenses]
    license_bytes = {record["repo"]: raw for record, raw in fetched_licenses}
    for record in license_records:
        repositories[record["repo"]]["license_spdx"] = record["spdx"]
    manifest = {
        "schema_version": 1, "checked_on": checked_on, "timezone": config["timezone"],
        "repositories": repositories, "sources": records, "licenses": license_records,
    }
    return manifest, source_bytes, license_bytes


def write_batch(root: Path, artifacts: dict[str, bytes], work_dir: Path | None = None) -> None:
    """Stage every file first; roll back completed replacements on write failure."""
    work_dir = work_dir or root / "work"
    work_dir.mkdir(parents=True, exist_ok=True)
    ordered = sorted(artifacts, key=lambda path: (path == MANIFEST, path))
    with tempfile.TemporaryDirectory(prefix="update-", dir=work_dir) as temporary:
        stage = Path(temporary)
        existing = {}
        for relative in ordered:
            target = safe_path(root, relative)
            new = safe_path(stage / "new", relative)
            new.parent.mkdir(parents=True, exist_ok=True)
            new.write_bytes(artifacts[relative])
            existing[relative] = target.exists()
            if target.exists():
                backup = safe_path(stage / "old", relative)
                backup.parent.mkdir(parents=True, exist_ok=True)
                backup.write_bytes(target.read_bytes())
        replaced = []
        try:
            for relative in ordered:
                target = safe_path(root, relative)
                target.parent.mkdir(parents=True, exist_ok=True)
                os.replace(safe_path(stage / "new", relative), target)
                replaced.append(relative)
        except Exception:
            for relative in reversed(replaced):
                target = safe_path(root, relative)
                if existing[relative]:
                    os.replace(safe_path(stage / "old", relative), target)
                else:
                    target.unlink(missing_ok=True)
            raise


def main(argv: list[str] | None = None, root: Path | None = None) -> int:
    root = root or ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--offline", action="store_true", help="Regenerate from attached snapshots")
    modes.add_argument("--check", action="store_true", help="Verify offline; do not write any files")
    parser.add_argument("--date", help="Override the Asia/Shanghai build date (YYYY-MM-DD)")
    parser.add_argument("--work-dir", type=Path, help="Explicit staging directory; default: project/work")
    args = parser.parse_args(argv)
    try:
        config, targets = load_config(root)
        if args.date:
            dt.date.fromisoformat(args.date)
        if args.offline or args.check:
            manifest, raw, licenses = load_snapshots(root, config)
            if args.date:
                manifest = {**manifest, "checked_on": args.date}
        else:
            old = load_json(root / MANIFEST) if (root / MANIFEST).exists() else {}
            checked_on = args.date or dt.datetime.now(dt.timezone.utc).astimezone(
                ZoneInfo(config["timezone"])
            ).date().isoformat()
            manifest, raw, licenses = fetch_current(root, config, old, checked_on)
        artifacts, report = build_artifacts(config, manifest, raw, licenses, targets)
        if args.check:
            stale = [
                relative for relative, expected in artifacts.items()
                if not safe_path(root, relative).is_file()
                or safe_path(root, relative).read_bytes() != expected
            ]
            if stale:
                raise ValueError("Generated files are missing or stale: " + ", ".join(stale[:12]))
        else:
            write_batch(root, artifacts, args.work_dir)
        print(json.dumps({
            "mode": "check" if args.check else ("offline" if args.offline else "online"),
            "project": str(root), "checked_on": report["checked_on"],
            "domain_rules": report["statistics"]["domain_rules"],
            "network_rules": report["statistics"]["network_rules"],
            "baseline": f"{report['baseline']['covered']}/{report['baseline']['total']}",
            "extended": f"{report['extended']['covered']}/{report['extended']['total']}",
            "source_union": f"{report['source_union']['fully_covered']}/{report['source_union']['unique_rules']}",
            "generated_files": len(artifacts),
        }, ensure_ascii=False, indent=2))
        return 0
    except Exception as error:
        print(f"Update failed; no validated new rule set published: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
