"""Check every published HTML report: structure, links, anchors and shared navigation.

    python tools/check_site.py

Checks, for each HTML file tracked by Git (or new and not ignored):
  - lang="ko", exactly one <h1> and one <main>, unique ids, <img> alt text
  - local links resolve to files inside the repository; #fragments exist in the target page
  - external links use https; no scripts, iframes or embedded objects
  - the page is listed in site-map.json, uses assets/site.css and its navigation is up to date

Standard library only.
"""
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

from site_chrome import ROOT, Site

FORBIDDEN = {"script", "iframe", "object", "embed"}


class Document(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.ids, self.links, self.tags, self.problems = [], [], [], []
        self.lang = None
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append(tag)
        if tag == "html":
            self.lang = attrs.get("lang")
        if "id" in attrs:
            self.ids.append(attrs["id"])
        for key in ("href", "src"):
            if attrs.get(key):
                self.links.append(attrs[key])
        if tag == "img" and not attrs.get("alt"):
            self.problems.append("image without alternative text")
        if tag in FORBIDDEN:
            self.problems.append(f"<{tag}> is not allowed")


def published(pattern):
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", pattern], cwd=ROOT, text=True
    ).splitlines()
    return [name for name in names if (ROOT / name).is_file()]


def main():
    site = Site()
    pages = published("*.html")
    documents = {name: Document((ROOT / name).read_text(encoding="utf-8")) for name in pages}
    problems, links = [], 0
    for name, doc in documents.items():
        text = (ROOT / name).read_text(encoding="utf-8")
        problems += [f"{name}: {problem}" for problem in doc.problems]
        if doc.lang != "ko" or doc.tags.count("h1") != 1 or doc.tags.count("main") != 1:
            problems.append(f'{name}: expected lang="ko", one <h1> and one <main>')
        duplicates = {i for i in doc.ids if doc.ids.count(i) > 1}
        if duplicates:
            problems.append(f"{name}: duplicate ids {sorted(duplicates)}")
        if "STUB-PLACEHOLDER" in text or "{{" in text:
            problems.append(f"{name}: unfinished placeholder text")
        if name not in site.index:
            problems.append(f"{name}: not listed in site-map.json")
        else:
            try:
                stale = site.render(name, text) != text
            except ValueError as error:
                problems.append(str(error))
            else:
                if stale:
                    problems.append(f"{name}: navigation is stale; run python tools/site_chrome.py")
            if "assets/site.css" not in text:
                problems.append(f"{name}: must link the shared stylesheet")
        for link in doc.links:
            url = urlsplit(link)
            if url.scheme or url.netloc:
                if url.scheme != "https":
                    problems.append(f"{name}: external link is not https: {link}")
                continue
            target = (ROOT / name).parent / unquote(url.path) if url.path else ROOT / name
            target = target.resolve()
            if not target.is_relative_to(ROOT) or not target.is_file():
                problems.append(f"{name}: broken link {link}")
                continue
            links += 1
            relative = target.relative_to(ROOT).as_posix()
            if ".private" in target.parts or "_workspace" in target.parts:
                problems.append(f"{name}: link into a private folder: {link}")
            if url.fragment and relative in documents and unquote(url.fragment) not in documents[relative].ids:
                problems.append(f"{name}: missing anchor {link}")
    for name in site.index:
        if name not in documents:
            problems.append(f"{name}: listed in site-map.json but missing")
    if problems:
        sys.exit("\n".join(problems))
    print(f"OK: {len(documents)} pages, {links} local links, anchors and navigation consistent")


if __name__ == "__main__":
    main()
