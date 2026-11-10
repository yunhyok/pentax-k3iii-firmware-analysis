"""Keep the shared navigation of the HTML reports in sync with site-map.json.

Every report carries three marker-delimited regions that this tool owns:

    <!-- chrome:top -->     skip link, top bar, breadcrumb                         (required)
    <!-- chrome:toc -->     table of contents built from the page's own <h2>       (optional)
    <!-- chrome:map -->     every section with its pages, for the landing page     (optional)
    <!-- chrome:bottom -->  pages of the same section, previous/next, footer       (required)

Everything outside the markers is hand-written content and is never touched.

    python tools/site_chrome.py           rewrite the regions in place
    python tools/site_chrome.py --check   exit 1 if any page is stale or unlisted

Standard library only.
"""
import argparse
import json
import posixpath
import re
import subprocess
import sys
from html import escape as esc
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE_MAP = ROOT / "site-map.json"
PAGES_HOST = "https://yunhyok.github.io"
CAMERAS = (("k3iii", "K-3 III"), ("k3ii", "K-3 II"), ("q7", "Q7"))
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}


def load_map():
    return json.loads(SITE_MAP.read_text(encoding="utf-8"))


def pages_url(camera, path=""):
    return f"{PAGES_HOST}/pentax-{camera}-firmware-analysis/{path}"


def relative(target, page):
    """Link from the published location of ``page`` to ``target`` (both repository-relative)."""
    path, _, fragment = target.partition("#")
    link = posixpath.relpath(path, posixpath.dirname(page) or ".")
    return link + ("#" + fragment if fragment else "")


class Headings(HTMLParser):
    """Collect (anchor, text) for every <h2> in <main> that has an anchor of its own or its section's."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack, self.items, self.in_main, self.current, self.used = [], [], False, None, set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "main":
            self.in_main = True
        if tag not in VOID:
            self.stack.append((tag, attrs.get("id")))
        if tag == "h2" and self.in_main and attrs.get("data-toc") != "no":
            anchor = attrs.get("id")
            if not anchor:
                anchor = next((i for t, i in reversed(self.stack[:-1]) if t == "section"), None)
            if anchor and anchor not in self.used:
                self.used.add(anchor)
                self.current = [anchor, ""]

    def handle_endtag(self, tag):
        if tag == "h2" and self.current:
            self.items.append((self.current[0], re.sub(r"\s+", " ", self.current[1]).strip()))
            self.current = None
        if tag == "main":
            self.in_main = False
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        if self.current:
            self.current[1] += data


class Site:
    def __init__(self, data=None):
        self.data = data or load_map()
        self.camera = self.data["camera"]
        self.sections = self.data["sections"]
        self.order = [(section, page) for section in self.sections for page in section["pages"]]
        self.index = {page["file"]: n for n, (_, page) in enumerate(self.order)}
        if len(self.index) != len(self.order):
            raise ValueError("site-map.json lists a page twice")
        self.sources = self.data.get("sources", {})

    def source_path(self, page):
        return ROOT / self.sources.get(page, page)

    def top(self, page):
        section, entry = self.order[self.index[page]]
        home = self.data["home"]
        cams = []
        for camera, label in CAMERAS:
            if camera == self.camera:
                cams.append(f'<a href="{esc(relative(home, page))}" aria-current="true">{label}</a>')
            else:
                cams.append(f'<a href="{pages_url(camera)}">{label}</a>')
        nav = []
        for item in self.sections:
            current = ' aria-current="true"' if item is section else ""
            nav.append(f'<a href="{esc(relative(item["hub"], page))}"{current}>{esc(item["nav"])}</a>')
        crumbs = [f'<li><a href="{esc(relative(home, page))}">{esc(self.data["name"])}</a></li>']
        if page != home:
            if section["hub"] != page:
                crumbs.append(f'<li><a href="{esc(relative(section["hub"], page))}">{esc(section["title"])}</a></li>')
            crumbs.append(f'<li aria-current="page">{esc(entry["label"])}</li>')
        return (
            '<a class="skip" href="#main">본문 바로가기</a>\n'
            '<div class="topbar"><div class="topbar-in">'
            f'<a class="brand" href="{esc(relative(home, page))}">PENTAX <b>펌웨어 연구</b></a>'
            f'<div class="cams" aria-label="기종 선택">{"".join(cams)}</div>'
            f'<nav class="topnav" aria-label="주제">{"".join(nav)}</nav></div></div>\n'
            f'<nav class="crumbs" aria-label="현재 위치"><ol>{"".join(crumbs)}</ol></nav>'
        )

    def toc(self, html):
        parser = Headings()
        parser.feed(html)
        if len(parser.items) < 2:
            return ""
        items = "".join(f'<li><a href="#{esc(anchor)}">{esc(text)}</a></li>' for anchor, text in parser.items)
        return f'<nav class="toc" aria-label="이 문서의 목차"><h2 data-toc="no">이 문서에서</h2><ol>{items}</ol></nav>'

    def bottom(self, page):
        number = self.index[page]
        section, _ = self.order[number]
        related = ""
        if len(section["pages"]) > 1:
            links = []
            for item in section["pages"]:
                current = ' aria-current="page"' if item["file"] == page else ""
                note = f'<span>{esc(item["note"])}</span>' if item.get("note") else ""
                links.append(f'<li><a href="{esc(relative(item["file"], page))}"{current}>{esc(item["label"])}{note}</a></li>')
            related = (f'<nav class="related" aria-label="같은 주제의 문서"><h2 data-toc="no">{esc(section["title"])} — 이 주제의 문서</h2>'
                       f'<ol>{"".join(links)}</ol></nav>\n')
        pager = []
        if number:
            target = self.order[number - 1][1]
            pager.append(f'<a class="prev" href="{esc(relative(target["file"], page))}"><small>← 이전</small>{esc(target["label"])}</a>')
        if number + 1 < len(self.order):
            target = self.order[number + 1][1]
            pager.append(f'<a class="next" href="{esc(relative(target["file"], page))}"><small>다음 →</small>{esc(target["label"])}</a>')
        home = self.data["home"]
        program = (relative("analysis/research-program.html", page) if self.camera == "k3iii"
                   else pages_url("k3iii", "analysis/research-program.html"))
        repository = f"https://github.com/yunhyok/pentax-{self.camera}-firmware-analysis"
        foot = [
            f'<a href="{esc(relative(home + "#map", page))}">문서 지도</a>',
            f'<a href="{esc(relative(home + "#levels", page))}">검증 수준 읽는 법</a>',
            f'<a href="{esc(relative(self.data["glossary"], page))}">용어집</a>',
            f'<a href="{esc(program)}">세 기종 연구 본부</a>',
            f'<a href="{repository}">GitHub 저장소</a>',
        ]
        return (
            f'{related}<nav class="pager" aria-label="이전·다음 문서">{"".join(pager)}</nav>\n'
            f'<footer class="sitefoot"><div class="sitefoot-in"><nav aria-label="사이트">{"".join(foot)}</nav>'
            f'<p>{esc(self.data["name"])} {esc(self.data["firmware"])} 분석 문서. {esc(self.data["footer"])}</p></div></footer>'
        )

    def site_map(self, page):
        parts = []
        for section in self.sections:
            links = []
            for item in section["pages"]:
                if item["file"] == page:
                    continue
                note = f'<span>{esc(item["note"])}</span>' if item.get("note") else ""
                links.append(f'<li><a href="{esc(relative(item["file"], page))}">{esc(item["label"])}</a>{note}</li>')
            parts.append(f'<section><h3 id="map-{esc(section["id"])}">{esc(section["title"])}</h3><ol>{"".join(links)}</ol></section>')
        return f'<div class="sitemap">{"".join(parts)}</div>'

    def render(self, page, html):
        """Return ``html`` with every marker region refreshed."""
        html = replace_region(html, "top", self.top(page), page)
        html = replace_region(html, "bottom", self.bottom(page), page)
        html = replace_region(html, "map", self.site_map(page), page, required=False)
        return replace_region(html, "toc", self.toc(html), page, required=False)


def replace_region(html, region, block, page, required=True):
    pattern = re.compile(rf"<!-- chrome:{region} -->.*?<!-- /chrome:{region} -->", re.S)
    found = len(pattern.findall(html))
    if found == 0 and not required:
        return html
    if found != 1:
        raise ValueError(f"{page}: expected exactly one chrome:{region} region")
    return pattern.sub(lambda _: f"<!-- chrome:{region} -->\n{block}\n<!-- /chrome:{region} -->", html)


def published_html():
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "*.html"], cwd=ROOT, text=True
    ).splitlines()
    return {name for name in names if (ROOT / name).is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="report stale or unlisted pages without writing")
    args = parser.parse_args()
    site = Site()
    problems, changed = [], 0
    listed = set(site.index) | set(site.sources.values()) | set(site.data.get("unlisted", []))
    for name in sorted(published_html() - listed):
        problems.append(f"{name}: not listed in site-map.json")
    for page in site.index:
        path = site.source_path(page)
        try:
            before = path.read_text(encoding="utf-8")
            after = site.render(page, before)
        except (OSError, ValueError) as error:
            problems.append(str(error))
            continue
        if after != before:
            changed += 1
            if args.check:
                problems.append(f"{path.relative_to(ROOT).as_posix()}: navigation is stale; run python tools/site_chrome.py")
            else:
                path.write_text(after, encoding="utf-8", newline="\n")
    if problems:
        sys.exit("\n".join(problems))
    print(f"site chrome: {len(site.index)} pages, {changed} {'stale' if args.check else 'updated'}")


if __name__ == "__main__":
    main()
