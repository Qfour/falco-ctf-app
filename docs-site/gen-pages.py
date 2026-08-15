#!/usr/bin/env python3
"""Generate MkDocs mission pages from the canonical challenges/ tree.

  python3 gen-pages.py <repo-root> <mode>     # mode: participant | admin

Output (relative to docs-site/, gitignored):
  docs/missions/<NN>.md   — participant: brief only.
                            admin: brief + 攻略と解説 (README.md).

Per challenge the brief comes from fixtures/welcome.txt; the "# 表示名について"
section is stripped (it lives on the はじめに page).

Hints are NOT rendered here. The single source of truth for hints is the
progressive reveal in journey.yaml (`/journey` UI, penalty-gated). welcome.txt
no longer carries a HINT block (P22-1) — this avoids a fairness gap where
docs-site hints could be unlocked without the journey penalty.
"""
import os, re, shutil, sys

root = sys.argv[1] if len(sys.argv) > 1 else ".."
mode = sys.argv[2] if len(sys.argv) > 2 else "participant"
if mode not in ("participant", "admin"):
    sys.exit("mode must be participant|admin")

MISS = "docs/missions"
shutil.rmtree(MISS, ignore_errors=True)
os.makedirs(MISS)


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
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(lines)


def strip_sections(text, headers):
    """Drop '# <header>' sections (the header line through the next '# ')."""
    out, skip = [], False
    for ln in text.split("\n"):
        if any(ln.startswith("# " + h) for h in headers):
            skip = True
            continue
        if skip and ln.startswith("# "):
            skip = False
        if not skip:
            out.append(ln)
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out)


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


def page(nn, title, welcome_path, readme_path, rule_path, explain_path=None):
    out = [f"# {title}\n"]
    if mode == "admin":
        out.append('!!! warning "運営専用 — 想定解・解説を含む"\n')
    # 導線: 解くときに使う基本コマンドは全課題共通のチートシートへ (missions/ 配下から
    # 見た相対リンク)。参加者・運営どちらの build にも出す。
    out.append(
        '!!! tip "コマンドに迷ったら"\n'
        "    基本コマンド(偵察・ファイル探索・ネットワーク・flag 提出)は"
        " [チートシート / TIPS](../cheatsheet.md) にまとめてあります。\n"
    )
    imgdir = os.path.join("docs/assets/missions", nn)
    if os.path.isdir(imgdir):
        for img in sorted(os.listdir(imgdir)):
            if not img.endswith(".md"):
                out.append(f"![{nn}](../assets/missions/{nn}/{img})\n")

    brief = ""
    if welcome_path and os.path.isfile(welcome_path):
        brief = parse_welcome(open(welcome_path, encoding="utf-8").read())
    # 試すこと / クリア条件 / 環境にあるもの are direct answers — operator (admin) only.
    if brief and mode != "admin":
        brief = strip_sections(brief, ["試すこと", "クリア条件", "環境にあるもの"])
    rule = ""
    if rule_path and os.path.isfile(rule_path):
        rule = open(rule_path, encoding="utf-8").read().strip("\n")
    # rule-explain.md — participant-safe prose that explains how to read the
    # Falco rule (condition/output/fields), why an evade slips past it, and how a
    # managed Sysdig ruleset would still cover the scenario. Rendered right after
    # the rule block in both modes (no solution commands — concept level only).
    explain = ""
    if explain_path and os.path.isfile(explain_path):
        explain = open(explain_path, encoding="utf-8").read().strip("\n")

    def rule_block():
        out.append("## 検知ルール (Falco Rule)\n")
        out.append("```yaml\n" + rule + "\n```\n")
        if explain:
            out.append(explain + "\n")

    if brief:
        out.append("## ミッションブリーフ\n")
        before, after = split_after_background(brief)
        out.append("```text\n" + before + "\n```\n")
        if rule:
            rule_block()
        if after:
            out.append("```text\n" + after + "\n```\n")
    elif rule:
        rule_block()

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
            "CTF Company の全ミッション。各ページにミッションブリーフ"
            + ("と攻略・解説" if mode == "admin" else "")
            + "を掲載しています。\n")

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
    explain = os.path.join(cdir, "rule-explain.md")
    open(os.path.join(MISS, f"{nn}.md"), "w", encoding="utf-8").write(
        page(nn, title, welcome, readme, rule, explain))
    print(f"[{mode}] {nn}")
