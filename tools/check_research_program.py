"""Check report completeness, regeneration and optionally the pinned Git blobs."""

import argparse
import json
import re
import subprocess
from datetime import date
from html.parser import HTMLParser
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from build_research_program import OUTPUT, ROOT, SNAPSHOT, render, source_url

CAMERAS = ("k3iii", "k3ii", "q7")
GATES = {"firmware": 5, "color": 5, "af": 4, "ui": 4}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def copy_fields(mapping, names):
    for name in names:
        value = mapping[name]
        require(isinstance(value, str) and value.strip(), f"{name} must be nonempty text")


def pairs(rows, count, label):
    require(isinstance(rows, list) and len(rows) == count, f"{label}: expected {count} items")
    for row in rows:
        require(isinstance(row, list) and len(row) == 2, f"{label}: expected title and criteria")
        copy_fields(dict(enumerate(row)), (0, 1))
    require(len({name for name, _ in rows}) == count, f"{label}: repeated title")


def check_snapshot(data):
    require(data["schema_version"] == 1, "unsupported snapshot schema")
    require(date.fromisoformat(data["as_of"]).isoformat() == data["as_of"], "use ISO snapshot date")
    require(data["time_zone"] == "Asia/Seoul", "unexpected snapshot time zone")
    copy_fields(data, ("title", "summary", "boundary", "refresh_note"))
    require(tuple(c["id"] for c in data["cameras"]) == CAMERAS, "expected three ordered camera records")
    require(tuple(t["id"] for t in data["tracks"]) == tuple(GATES), "expected four ordered tracks")
    sources = data["sources"]
    used = set()
    for key, source in sources.items():
        copy_fields(source, ("label",))
        if "url" in source:
            require(set(source) == {"url", "label"}, f"{key}: mixed source types")
            url = urlsplit(source["url"])
            require(url.scheme == "https" and url.hostname and not url.username, f"{key}: expected a public HTTPS citation")
        else:
            require(set(source) == {"camera", "path", "label"}, f"{key}: incomplete Git source")
            path = PurePosixPath(source["path"])
            require(source["camera"] in CAMERAS, f"{key}: unknown source camera")
            require(not path.is_absolute() and all(re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9_.-]*", p) for p in path.parts)
                    and path.as_posix() == source["path"] and path.suffix in {".html", ".json", ".md"},
                    f"{key}: expected a public repository document")
    for camera in data["cameras"]:
        copy_fields(camera, ("name", "firmware_version", "digest_field"))
        for field, length in (("commit", 40), ("firmware_sha256", 64)):
            require(re.fullmatch(rf"[a-f0-9]{{{length}}}", camera[field]), f"{camera['id']}: invalid {field}")
        for field, suffix in (("digest_source", ".json"), ("report_source", ".html")):
            key = camera[field]
            source = sources[key]
            require(source.get("camera") == camera["id"] and source["path"].endswith(suffix),
                    f"{camera['id']}: invalid {field}")
            used.add(key)
    for track in data["tracks"]:
        label = track["id"]
        copy_fields(track, ("title", "dependency"))
        require(set(track["cards"]) == set(CAMERAS), f"{label}: missing or unexpected camera card")
        pairs(track["gates"], GATES[label], f"{label} gates")
        require(("routes" in track) == (label == "firmware"), f"{label}: misplaced or missing build routes")
        if label == "firmware":
            pairs(track["routes"], 3, "build routes")
        for camera, card in track["cards"].items():
            copy_fields(card, ("state", "finding", "next"))
            refs = card["sources"]
            require(isinstance(refs, list) and refs and len(set(refs)) == len(refs),
                    f"{label}/{camera}: expected distinct citations")
            require(set(refs) <= sources.keys(), f"{label}/{camera}: unknown citation")
            used.update(refs)
    require(used == sources.keys(), f"unused source records: {sources.keys() - used}")
    pairs(data["inputs"], 4, "hardware and user inputs")
    pairs(data["loop"], 5, "research loop")


class ReportLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.links = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            require(attrs["id"] not in self.ids, f"duplicate ID: {attrs['id']}")
            self.ids.add(attrs["id"])
        if tag == "a":
            self.links.add(attrs["href"])
        require(tag not in {"link", "script", "iframe", "object", "embed"} and "src" not in attrs,
                f"unexpected dependency or script: {tag}")


def check_report(data):
    html = OUTPUT.read_text(encoding="utf-8")
    require(html == render(data), "HTML is stale: run python tools/build_research_program.py")
    parser = ReportLinks()
    parser.feed(html)
    require(set(GATES) <= parser.ids, "missing track anchors")
    for href in parser.links:
        target = urlsplit(href)
        if target.scheme:
            require(target.scheme == "https" and target.hostname and not target.username, f"unsafe link: {href}")
        elif target.path:
            path = (OUTPUT.parent / target.path).resolve()
            require(path.is_relative_to(ROOT) and path.is_file(), f"broken report link: {href}")
        else:
            require(target.fragment in parser.ids, f"missing anchor: {href}")
    for key in data["sources"]:
        for pinned in (False, True):
            require(source_url(data, key, pinned=pinned) in parser.links, f"unlinked source: {key}")
    return len(parser.links)


def check_git_sources(data):
    directories = {"k3iii": ROOT, "k3ii": ROOT.parent / "Pentax K-3mk2", "q7": ROOT.parent / "Pentax Q7"}
    for camera in data["cameras"]:
        camera_id = camera["id"]
        sources = {key: source for key, source in data["sources"].items() if source.get("camera") == camera_id}
        for key, source in sources.items():
            ref = f'{camera["commit"]}:{source["path"]}'
            result = subprocess.run(
                ["git", "cat-file", "blob", ref], cwd=directories[camera_id], capture_output=True
            )
            require(result.returncode == 0, f"{camera_id}: cannot read pinned source {ref}")
            if key == camera["digest_source"]:
                digest = json.loads(result.stdout)[camera["digest_field"]]
                require(digest == camera["firmware_sha256"], f"{camera_id}: pinned firmware digest mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-sources", action="store_true", help="also check Git blobs in the three local clones")
    args = parser.parse_args()
    try:
        data = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        check_snapshot(data)
        link_count = check_report(data)
        if args.verify_sources:
            check_git_sources(data)
    except (KeyError, ValueError, OSError, TypeError) as error:
        parser.exit(1, f"Research program check failed: {error}\n")
    print(f"OK: 3 cameras × 4 tracks, 18 gates, {link_count} links, deterministic offline HTML")
    if args.verify_sources:
        print("OK: all pinned repository documents and 3 original firmware SHA-256 records")


if __name__ == "__main__":
    main()
