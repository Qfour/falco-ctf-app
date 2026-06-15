#!/usr/bin/env python3
"""Generate MkDocs mission pages + pandoc PDF sources from the canonical
challenges/ tree (single source of truth).

  python3 gen-pages.py <repo-root> <mode>     # mode: participant | admin

Outputs (relative to docs-site/, both gitignored):
  docs/missions/<NN>.md   — site pages (MkDocs). participant: brief + time-gated
                            hints (HTML+JS). admin: brief + 攻略と解説 + plain hints.
  pdfsrc/<NN>.md          — pandoc sources (static; hints always shown plainly).

Per challenge the brief comes from fixtures/welcome.txt; the "# 表示名について"
section is stripped (it lives on the はじめに page) and trailing HINT blocks are
split out so they can be revealed over time on the site.
"""
import os, re, shutil, sys

root = sys.argv[1] if len(sys.argv) > 1 else ".."
mode = sys.argv[2] if len(sys.argv) > 2 else "participant"
if mode not in ("participant", "admin"):
    sys.exit("mode must be participant|admin")

MISS, PDFSRC = "docs/missions", "pdfsrc"
for d in (MISS, PDFSRC):
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)

BAR = re.compile(r"^[─\-]{3,}\s*$")


def parse_welcome(text):
    lines = text.splitlines()
    # strip the cross-cutting "# 表示名について" section (moved to はじめに)
    kept, skip = [], False
    for ln in lines:
        if ln.startswith("# 表示名について"):
            skip = True
            continue
        if skip and re.match(r"^# ", ln):
            skip = False
        if not skip:
            kept.append(ln)
    lines = kept
    # split brief vs trailing HINT region
    hstart = None
    for i, ln in enumerate(lines):
        if ln.startswith("HINT "):
            hstart = i - 1 if i > 0 and BAR.match(lines[i - 1]) else i
            break
    brief = lines if hstart is None else lines[:hstart]
    hlines = [] if hstart is None else lines[hstart:]
    while brief and not brief[-1].strip():
        brief.pop()
    # parse individual hints (skip the ─ separators)
    hints, cur = [], None
    for ln in hlines:
        if BAR.match(ln):
            continue
        if ln.startswith("HINT "):
            cur = {"title": ln.strip(), "body": []}
            hints.append(cur)
        elif cur is not None:
            cur["body"].append(ln)
    for h in hints:
        while h["body"] and not h["body"][-1].strip():
            h["body"].pop()
    return "\n".join(brief), hints


def split_after_background(brief):
    """Split the brief right after its '# 背景' section so the Falco rule can be
    inserted there. Returns (before_incl_background, after) or (brief, "") when
    there is no 背景 section."""
    lines = brief.split("\n")
    start = next((i for i, l in enumerate(lines) if l.startswith("# 背景")), None)
    if start is None:
        return brief, ""
    end = next((j for j in range(start + 1, len(lines)) if lines[j].startswith("# ")), len(lines))
    before = "\n".join(lines[:end]).rstrip("\n")
    after = "\n".join(lines[end:]).strip("\n")
    return before, after


def page(nn, title, welcome_path, readme_path, rule_path, target):
    out = [f"# {title}\n"]
    if mode == "admin":
        out.append('!!! warning "運営専用 — 想定解・解説を含む"\n')
    if target == "site":
        out.append(f"[PDF をダウンロード](/pdf/{nn}.pdf){{ .md-button .md-button--primary }}\n")
    imgdir = os.path.join("docs/assets/missions", nn)
    if os.path.isdir(imgdir):
        for img in sorted(os.listdir(imgdir)):
            if not img.endswith(".md"):
                out.append(f"![{nn}](../assets/missions/{nn}/{img})\n")

    brief, hints = ("", [])
    if welcome_path and os.path.isfile(welcome_path):
        brief, hints = parse_welcome(open(welcome_path, encoding="utf-8").read())
    rule = ""
    if rule_path and os.path.isfile(rule_path):
        rule = open(rule_path, encoding="utf-8").read().strip("\n")

    if brief:
        out.append("## ミッションブリーフ\n")
        before, after = split_after_background(brief)
        out.append("```text\n" + before + "\n```\n")
        if rule:
            out.append("## 検知ルール (Falco Rule)\n")
            out.append("```yaml\n" + rule + "\n```\n")
        if after:
            out.append("```text\n" + after + "\n```\n")
    elif rule:
        out.append("## 検知ルール (Falco Rule)\n")
        out.append("```yaml\n" + rule + "\n```\n")

    if hints:
        out.append("## ヒント\n")
        if target == "site":
            # Operator-controlled reveal (assets/hints.js): participants see a
            # hint only after an admin releases it; admin pages get a release
            # button. State lives in the scoreboard (GET/POST /api/hints).
            admin_cls = " ctf-hint--admin" if mode == "admin" else ""
            for idx, h in enumerate(hints, 1):
                out.append(f'<div class="ctf-hint{admin_cls}" data-mission="{nn}" data-hint="{idx}" markdown="1">')
                out.append(f"**{h['title']}**\n")
                out.append("```text\n" + "\n".join(h["body"]) + "\n```")
                out.append("</div>\n")
        else:
            for h in hints:  # pdf: static, always visible
                out.append(f"### {h['title']}\n")
                out.append("```text\n" + "\n".join(h["body"]) + "\n```\n")

    if mode == "admin" and readme_path and os.path.isfile(readme_path):
        body = open(readme_path, encoding="utf-8").read().splitlines()[1:]  # drop H1
        out.append("## 攻略と解説\n")
        out.append("\n".join(body))
    return "\n".join(out)


# index of the missions section
banner = (
    '!!! warning "運営専用ビュー"\n    各ページに **想定解・解説** を含みます。参加者には配布しないこと。\n\n'
    if mode == "admin" else ""
)
with open(os.path.join(MISS, "index.md"), "w", encoding="utf-8") as f:
    f.write("# ミッション一覧\n\n" + banner +
            "Operation NimbusBreach の全ミッション。各ページにミッションブリーフ"
            + ("と攻略・解説" if mode == "admin" else "")
            + "、ページ上部から PDF をダウンロードできます。\n")

challenges = sorted(
    d for d in os.listdir(os.path.join(root, "challenges"))
    if re.match(r"^\d\d-", d) and os.path.isdir(os.path.join(root, "challenges", d))
)
for nn in challenges:
    cdir = os.path.join(root, "challenges", nn)
    readme = os.path.join(cdir, "README.md")
    title = nn
    if os.path.isfile(readme):
        first = open(readme, encoding="utf-8").readline().lstrip("# ").strip()
        if first:
            title = first
    welcome = os.path.join(cdir, "fixtures", "welcome.txt")
    rule = os.path.join(cdir, "rule.yaml")
    open(os.path.join(MISS, f"{nn}.md"), "w", encoding="utf-8").write(
        page(nn, title, welcome, readme, rule, "site"))
    open(os.path.join(PDFSRC, f"{nn}.md"), "w", encoding="utf-8").write(
        page(nn, title, welcome, readme, rule, "pdf"))
    print(f"[{mode}] {nn}")
