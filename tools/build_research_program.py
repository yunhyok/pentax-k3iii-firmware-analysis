"""Render the three-camera status snapshot (analysis/research-program.json) as an HTML report.

The page uses the shared stylesheet and navigation of the site (assets/site.css, tools/site_chrome.py).
"""

import json
import re
from html import escape as esc
from pathlib import Path

from site_chrome import Site

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "analysis/research-program.json"
OUTPUT = SNAPSHOT.with_suffix(".html")
PAGE = OUTPUT.relative_to(ROOT).as_posix()


def repository(camera):
    return f"https://github.com/yunhyok/pentax-{camera}-firmware-analysis"


def source_url(data, key, *, pinned=False):
    source = data["sources"][key]
    if "url" in source:
        return source["url"]
    camera, path = source["camera"], source["path"]
    if not pinned and path.endswith(".html"):
        if camera == "k3iii":
            return f"../{path}"
        return f"https://yunhyok.github.io/pentax-{camera}-firmware-analysis/{path}"
    commit = next(c["commit"] for c in data["cameras"] if c["id"] == camera)
    return f"{repository(camera)}/blob/{commit}/{path}"


def anchor(href, label):
    return f'<a href="{esc(href)}">{esc(label)}</a>'


def source_link(data, key, *, pinned=False):
    return anchor(source_url(data, key, pinned=pinned), data["sources"][key]["label"])


def pairs(items, tag="ol", css="flow"):
    contents = "".join(f"<li><strong>{esc(name)}</strong><span>{esc(detail)}</span></li>" for name, detail in items)
    return f'<{tag} class="{css}">{contents}</{tag}>'


def steps(items):
    contents = "".join(f"<li><strong>{esc(name)}</strong> {esc(detail)}</li>" for name, detail in items)
    return f'<ol class="steps">{contents}</ol>'


def panels(items):
    contents = "".join(f'<li class="card"><h3>{esc(name)}</h3><p>{esc(detail)}</p></li>' for name, detail in items)
    return f'<ul class="cards">{contents}</ul>'


def overview(data):
    """One table: four goals down, three cameras across, each cell the current state."""
    head = "".join(f'<th scope="col">{esc(camera["name"])} <small>v{esc(camera["firmware_version"])}</small></th>'
                   for camera in data["cameras"])
    rows = []
    for number, track in enumerate(data["tracks"], 1):
        cells = "".join(f'<td>{esc(track["cards"][camera["id"]]["state"])}</td>' for camera in data["cameras"])
        rows.append(f'<tr><th scope="row"><a href="#{esc(track["id"])}">{number}. {esc(track["title"])}</a></th>{cells}</tr>')
    return (f'<div class="table-wrap"><table><caption>목표별·기종별 현재 상태</caption>'
            f'<thead><tr><th scope="col">목표</th>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table></div>')


def findings(text):
    """A long finding is easier to scan as a list: one sentence per item."""
    sentences = [part for part in re.split(r"(?<=[다요]\.)\s+", text.strip()) if part]
    if len(sentences) <= 3:
        return esc(text)
    return "<ul>" + "".join(f"<li>{esc(sentence)}</li>" for sentence in sentences) + "</ul>"


def track_section(data, track, number):
    cards = []
    for camera in data["cameras"]:
        card = track["cards"][camera["id"]]
        links = " · ".join(source_link(data, key) for key in card["sources"])
        cards.append(f'''<li class="card goal"><span class="tag">{esc(camera["name"])}</span>
<p class="state">{esc(card["state"])}</p>
<dl><dt>알아낸 것</dt><dd>{findings(card["finding"])}</dd>
<dt>다음에 확인할 것</dt><dd>{esc(card["next"])}</dd></dl>
<details><summary>근거 문서 {len(card["sources"])}개</summary><p>{links}</p></details></li>''')
    routes = ""
    if "routes" in track:
        routes = f'<h3>펌웨어를 다시 만드는 세 가지 길</h3>{panels(track["routes"])}'
    return f'''<section id="{esc(track["id"])}">
<h2>목표 {number}. {esc(track["title"])}</h2>
<p class="takeaway">{esc(track["dependency"])}</p>
<ul class="cards one">{"".join(cards)}</ul>
{routes}
<h3>검증 순서와 통과 기준</h3>
{pairs(track["gates"])}
</section>'''


def ledger(data):
    entries = []
    for camera in data["cameras"]:
        repo = repository(camera["id"])
        entries.append(f'''<li class="card"><h3>{esc(camera["name"])} <small>v{esc(camera["firmware_version"])}</small></h3>
<p>{anchor(repo, "저장소")} · {source_link(data, camera["report_source"])} · {anchor(f"{repo}/releases", "릴리스")}</p>
<dl class="kv"><dt>기준 커밋</dt><dd><code class="wrap">{anchor(f'{repo}/commit/{camera["commit"]}', camera["commit"])}</code></dd>
<dt>원본 펌웨어 SHA-256</dt><dd><code class="wrap">{esc(camera["firmware_sha256"])}</code></dd></dl>
<p class="small">{source_link(data, camera["digest_source"], pinned=True)}</p></li>''')
    archive = "".join(
        f"<li>{source_link(data, key, pinned=True)}"
        + (f' <small>{esc(source["path"])}</small>' if "path" in source else "")
        + "</li>"
        for key, source in data["sources"].items()
    )
    return f'''<section id="ledger"><h2>근거 원장</h2>
<p>아래 해시는 배포 ZIP이나 해제한 데이터가 아니라 원본 펌웨어 BIN의 SHA-256입니다. 세 기준 커밋이 이 판본이 인용하는 범위를 고정합니다. 기준 커밋 이후에 문서의 모양과 구성은 바뀌었지만, 이 표가 가리키는 근거는 그 커밋의 파일입니다.</p>
<ul class="cards">{"".join(entries)}</ul>
<details><summary>인용한 파일의 고정본과 공식 사양 ({len(data["sources"])}개)</summary><ul class="refs">{archive}</ul></details></section>'''


def render(data):
    title = esc(data["title"])
    tracks = "\n".join(track_section(data, track, n) for n, track in enumerate(data["tracks"], 1))
    page = f'''<!doctype html>
<!-- Generated by tools/build_research_program.py from analysis/research-program.json. -->
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — PENTAX 펌웨어 연구</title>
<meta name="description" content="{esc(data["summary"])}">
<link rel="stylesheet" href="../assets/site.css">
</head>
<body data-camera="k3iii">
<!-- chrome:top -->
<!-- /chrome:top -->
<header class="page-head">
<p class="eyebrow">K-3 Mark III · K-3 II · Q7 — <time datetime="{esc(data["as_of"])}">{esc(data["as_of"])}</time> 기준</p>
<h1>{title}</h1>
<p class="lead">{esc(data["summary"])}</p>
</header>
<div class="layout">
<!-- chrome:toc -->
<!-- /chrome:toc -->
<main class="doc" id="main">
<section class="summary"><h2 data-toc="no">이 판본의 검증 범위</h2><p>{esc(data["boundary"])}</p></section>
<section id="overview"><h2>한눈에 보기</h2>
<p>세 기종을 같은 네 가지 목표로 조사합니다. 표의 각 칸은 그 기종에서 지금 다루고 있는 지점입니다. 목표 이름을 누르면 자세한 내용으로 갑니다.</p>
{overview(data)}
<p class="small muted">기종별 문서: <a href="../index.html">K-3 Mark III</a> · <a href="https://yunhyok.github.io/pentax-k3ii-firmware-analysis/">K-3 II</a> · <a href="https://yunhyok.github.io/pentax-q7-firmware-analysis/">Q7</a>. 표시의 뜻은 <a href="../index.html#levels">검증 수준 읽는 법</a>에 있습니다.</p>
</section>
{tracks}
<section id="inputs"><h2>실기 단계에 필요한 입력</h2>
<p>각 시험 전에 기종과 조건을 확정해야 비교 결과를 재현할 수 있습니다.</p>{panels(data["inputs"])}</section>
<section id="loop"><h2>다음 조사로 이어가는 방법</h2>
<p>{esc(data["refresh_note"])}</p>{steps(data["loop"])}</section>
{ledger(data)}
<section id="refs"><h2>이 문서의 원본</h2>
<ul class="refs"><li><a href="research-program.json">research-program.json</a> — 이 문서를 만드는 현황 데이터. 기준일 {esc(data["as_of"])} ({esc(data["time_zone"])})</li>
<li><a href="../tools/build_research_program.py">tools/build_research_program.py</a> · <a href="../tools/check_research_program.py">tools/check_research_program.py</a> — 생성기와 검사기</li></ul></section>
</main>
</div>
<!-- chrome:bottom -->
<!-- /chrome:bottom -->
</body>
</html>
'''
    return Site().render(PAGE, page)


if __name__ == "__main__":
    OUTPUT.write_text(render(json.loads(SNAPSHOT.read_text(encoding="utf-8"))), encoding="utf-8", newline="\n")
