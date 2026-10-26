#!/usr/bin/env python3
"""The reference scanner for hidden characters in files (ADR-0045, app#511 F2).

app is the source of the rule: Go's internal/sourcehygiene (invisible.go, chars.go). A
repo that cannot import it (platform, workspace) and a host with no go run THIS file from
a sibling clone of app. It reads three data files of the checkout it lives in, by a path
from its own position and never from the command line:

  internal/sourcehygiene/testdata/hidden-ranges.tsv   the table (range, rule, name)
  internal/sourcehygiene/testdata/hidden-cases.tsv    input and the findings expected
  internal/sourcehygiene/testdata/binary-ext.tsv      the extensions that are not scanned

and re-implements the context rules of sourcehygiene.Hidden (invisible.go `scan`) and the
walk of `make test` (bidi_test.go checkTree). The shared cases keep this file and the Go
code one definition: --selftest runs every row of them, and app's flag-guard job runs
--selftest and a scan of the app tree on every PR.

Usage:
  sourcehygiene-scan.py --selftest
  sourcehygiene-scan.py DIR [--allowlist FILE] [--also-untracked REL]...

DIR: the files `git ls-files` lists when DIR/.git exists (a file is fine: a worktree), else
every file under DIR. Symlinks and submodules are not followed. A file whose extension is
in binary-ext.tsv is not scanned. --also-untracked REL adds the regular files under REL
(a clean relative path to a file or a directory; it must exist), for an untracked file the
session reads all the same (a .claude/ the VCS ignores).

The walk: a path that is not printable ASCII (U+0021-007E) is a problem; a NUL byte is one
problem per file (U+0000 is not reported as a finding); --allowlist FILE is a closed set,
`<path><TAB><U+XXXX[,U+XXXX...]><TAB><reason>` per file, the format of
invisible-allowlist.txt except that a bidi control may be listed too: only the listed code
points are allowed in that file, and an entry that matches nothing (a file that does not
hold the character, is absent, binary or listed twice) is a FAIL. Without --allowlist the
set is empty; a named file that does not exist is a FAIL.

Output: one problem per line, `path:line:col U+XXXX NAME: raw invisible character ...`,
never the content of a file; then `OK|FAIL sourcehygiene-scan: N files, B binary, K
problems (data unicode X)`. Exit 0 = nothing found, 1 = a problem, or data that cannot be
read, or a scan of zero files (never a skip), 2 = a wrong command line.
If `unicodedata.unidata_version` differs from the header of hidden-ranges.tsv (the
Unicode of Go's unicode.Version) a WARN goes to stderr and the exit status does not
change: only whether a symbol assigned in between is a base for U+FE0E / U+FE0F / U+200D
differs (ADR-0045 D9).

Standard library only; python3 3.9 or later; ASCII only.
"""

import bisect
import os
import re
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "internal" / "sourcehygiene" / "testdata"
RANGES_FILE = DATA / "hidden-ranges.tsv"
CASES_FILE = DATA / "hidden-cases.tsv"
BINARY_EXT_FILE = DATA / "binary-ext.tsv"

# The closed vocabulary of the rule column (ADR-0045 D2): Go's ruleKind identifiers, and
# `bidi` for a row of bidiControls.
RULES = ("always", "vsAfterSymbol", "zwjInEmoji", "bomAtStart", "loneCR", "bidi")
MIN_CASES = 45  # a floor under hidden-cases.tsv (V1-c)
INVALID = -2  # an invalid UTF-8 byte: no table row, no symbol (Go's RuneError of width 1)

USAGE = """usage: sourcehygiene-scan.py --selftest
       sourcehygiene-scan.py DIR [--allowlist FILE] [--also-untracked REL]...
(see the head of this file)
"""


class Fail(Exception):
    """A FAIL: reported on stderr, exit 1."""


# ---- reading the data files ------------------------------------------------


def read_ascii(path):
    try:
        data = Path(path).read_bytes()
    except OSError as e:
        raise Fail("%s: cannot read the data file this scanner stands on: %s" % (path, e))
    return check_ascii(data, str(path))


def check_ascii(data, label):
    if any(b >= 0x80 or b == 0x0D or (b < 0x20 and b not in (0x09, 0x0A)) for b in data):
        raise Fail("%s: holds a byte that is not printable ASCII, TAB or LF (a CR counts): every character is a placeholder" % label)
    if not data.endswith(b"\n"):
        raise Fail("%s: no final newline" % label)
    return data.decode("ascii")[:-1].split("\n")


def is_data_row(line):
    """Not a blank line and not a comment. A comment is "#" or "# " and a text, so a line
    like "#n" is a row (and a row whose name starts with # is refused)."""
    return line != "" and line != "#" and not line.startswith("# ")


def fmt_cp(cp):
    return "U+%04X" % cp


def parse_cp(tok, where):
    m = re.match(r"^U\+([0-9A-F]{4,6})$", tok)
    if not m or fmt_cp(int(m.group(1), 16)) != tok or int(m.group(1), 16) > 0x10FFFF:
        raise Fail("%s: %r is not a code point written U+%%04X (upper-case hex, at least 4 digits, within Unicode)" % (where, tok))
    return int(m.group(1), 16)


def parse_cp_ranges(text, where):
    out = []
    for part in text.split(","):
        lo, _, hi = part.partition("-")
        out.append((parse_cp(lo, where), parse_cp(hi, where)))
    return out


class Table:
    def __init__(self, unicode_version, skin, vs, rows):
        self.unicode_version = unicode_version
        self.skin = skin  # [(lo, hi)]
        self.vs = vs  # [(lo, hi)]
        self.rows = rows  # [(lo, hi, rule, name)], ascending, no overlap
        self.los = [r[0] for r in rows]

    def lookup(self, cp):
        i = bisect.bisect_right(self.los, cp) - 1
        if i >= 0 and cp <= self.rows[i][1]:
            return self.rows[i]
        return None

    def with_rows(self, rows):
        return Table(self.unicode_version, self.skin, self.vs, rows)


def parse_ranges(lines, label="hidden-ranges.tsv"):
    if len(lines) < 4:
        raise Fail("%s: shorter than its three header lines and a row" % label)
    m = re.match(r"^# unicode: ([0-9]+\.[0-9]+\.[0-9]+)$", lines[0])
    if not m:
        raise Fail("%s:1: line 1 must be '# unicode: <version>', got %r" % (label, lines[0]))
    ranges = []
    for n, key in ((1, "skin-tone"), (2, "variation-selector")):
        mm = re.match(r"^# %s: (U\+[0-9A-F]{4,6}-U\+[0-9A-F]{4,6}(,U\+[0-9A-F]{4,6}-U\+[0-9A-F]{4,6})*)$" % key, lines[n])
        if not mm:
            raise Fail("%s:%d: line %d must be '# %s: U+LLLL-U+HHHH[,...]', got %r" % (label, n + 1, n + 1, key, lines[n]))
        ranges.append(parse_cp_ranges(mm.group(1), "%s:%d" % (label, n + 1)))
    rows = []
    for n, line in enumerate(lines[3:], 4):
        if not is_data_row(line):
            continue
        cols = line.split("\t")
        where = "%s:%d" % (label, n)
        if len(cols) != 4 or not cols[3]:
            raise Fail("%s: want U+LLLL<TAB>U+HHHH<TAB>rule<TAB>name, got %r" % (where, line))
        lo, hi = parse_cp(cols[0], where), parse_cp(cols[1], where)
        if cols[2] not in RULES:
            raise Fail("%s: rule %r is outside the closed vocabulary %s" % (where, cols[2], ", ".join(RULES)))
        if lo > hi or (rows and lo <= rows[-1][1]):
            raise Fail("%s: rows must be ascending and not overlap (%s-%s)" % (where, fmt_cp(lo), fmt_cp(hi)))
        if cols[2] == "bidi" and lo != hi:
            raise Fail("%s: a bidi row is one code point" % where)
        rows.append((lo, hi, cols[2], cols[3]))
    for rule in RULES:
        if not any(r[2] == rule for r in rows):
            raise Fail("%s: no row has rule %r: the table was not read in full" % (label, rule))
    return Table(m.group(1), ranges[0], ranges[1], rows)


PLACEHOLDER = re.compile(r"\{(U\+[0-9A-F]{4,6}|x[89A-F][0-9A-F])\}")
EXPECTED = re.compile(r"^[0-9]+:[0-9]+ U\+[0-9A-F]{4,6}(,[0-9]+:[0-9]+ U\+[0-9A-F]{4,6})*$")


def decode_input(s):
    """The bytes an input stands for: a printable ASCII byte as it is, {U+XXXX} the UTF-8 of
    that code point, {xHH} (80-FF) one raw byte. Anything else is a reader error."""
    out = bytearray()
    pos = 0
    for m in PLACEHOLDER.finditer(s):
        out += literal(s[pos:m.start()])
        tok = m.group(1)
        if tok[0] == "x":
            out.append(int(tok[1:], 16))
        else:
            v = int(tok[2:], 16)
            if v > 0x10FFFF or 0xD800 <= v <= 0xDFFF:
                raise Fail("{%s} is not a code point a string can hold" % tok)
            if 0x21 <= v <= 0x7E and v not in (0x7B, 0x7D):
                raise Fail("{%s} writes a printable ASCII character as a placeholder: write it as it is" % tok)
            out += chr(v).encode("utf-8")
        pos = m.end()
    out += literal(s[pos:])
    if not out:
        raise Fail("the input decodes to nothing")
    return bytes(out)


def literal(s):
    if "{" in s or "}" in s:
        raise Fail("a brace is left after the placeholders ('{' is {U+007B}): %r" % s)
    return s.encode("ascii")


def parse_cases(lines, label="hidden-cases.tsv"):
    rows = []
    names = set()
    for n, line in enumerate(lines, 1):
        if not is_data_row(line):
            continue
        cols = line.split("\t")
        where = "%s:%d" % (label, n)
        if len(cols) != 3:
            raise Fail("%s: want <name><TAB><input><TAB><expected>, got %d columns" % (where, len(cols)))
        name, raw, exp = cols
        if name == "" or name.startswith("#") or name in names:
            raise Fail("%s: the name %r is empty, starts with # or is used twice" % (where, name))
        names.add(name)
        try:
            data = decode_input(raw)
        except Fail as e:
            raise Fail("%s: %s (a reader error, not a verdict)" % (where, e))
        if exp != "none" and not EXPECTED.match(exp):
            raise Fail("%s: expected must be 'none' or '<line>:<col> U+XXXX' joined by commas, got %r" % (where, exp))
        rows.append((n, name, raw, data, exp))
    return rows


def parse_binary_ext(lines, label="binary-ext.tsv"):
    exts = []
    for n, line in enumerate(lines, 1):
        if not is_data_row(line):
            continue
        cols = line.split("\t")
        if len(cols) != 2 or not re.match(r"^\.[a-z0-9]+$", cols[0]) or not cols[1]:
            raise Fail("%s:%d: want <.ext><TAB><reason> (lower case), got %r" % (label, n, line))
        if exts and cols[0] <= exts[-1]:
            raise Fail("%s:%d: extensions must be ascending and not repeat (%r after %r)" % (label, n, cols[0], exts[-1]))
        exts.append(cols[0])
    if not exts:
        raise Fail("%s: no extension" % label)
    return tuple(exts)


class Data:
    def __init__(self):
        self.table = parse_ranges(read_ascii(RANGES_FILE))
        self.cases = parse_cases(read_ascii(CASES_FILE))
        self.binary_ext = parse_binary_ext(read_ascii(BINARY_EXT_FILE))
        if len(self.cases) < MIN_CASES:
            raise Fail("hidden-cases.tsv holds %d rows, fewer than the floor %d" % (len(self.cases), MIN_CASES))


def warn_unicode_version(table):
    if unicodedata.unidata_version != table.unicode_version:
        sys.stderr.write(
            "WARN unicode: data %s / python %s: a symbol assigned in between may count as a base for "
            "U+FE0E / U+FE0F / U+200D here and not in Go (ADR-0045 D9)\n"
            % (table.unicode_version, unicodedata.unidata_version)
        )


# ---- the scan: the context rules of invisible.go `scan` --------------------


def in_ranges(cp, ranges):
    return any(lo <= cp <= hi for lo, hi in ranges)


def is_non_ascii_symbol(cp):
    return cp >= 0x80 and unicodedata.category(chr(cp)) == "So"


def decode(data):
    """The code points of data, one per rune; an invalid byte is INVALID (and one rune)."""
    out = []
    for ch in data.decode("utf-8", errors="surrogateescape"):
        o = ord(ch)
        out.append(INVALID if 0xDC80 <= o <= 0xDCFF else o)
    return out


def scan(data, table):
    """[(line, col, cp, name, why)] for every hidden rune of data, in order."""
    cps = decode(data)
    out = []
    line, col = 1, 1
    prev = -1  # the previous rune; -1 at the start of the file
    prev_allowed_vs = False  # the previous rune is a U+FE0F that is allowed (so U+200D may follow)
    for i, r in enumerate(cps):
        allowed_vs = False
        row = table.lookup(r) if r >= 0 else None
        if row is not None:
            rule, name = row[2], row[3]
            why, bad = "", False
            if rule == "always" or rule == "bidi":
                bad = True
            elif rule == "vsAfterSymbol":
                if is_non_ascii_symbol(prev):
                    allowed_vs = r == 0xFE0F
                elif prev >= 0 and in_ranges(prev, table.vs):
                    bad, why = True, "second variation selector on one base"
                else:
                    bad, why = True, "%s not directly after a non-ASCII symbol (So)" % fmt_cp(r)
            elif rule == "zwjInEmoji":
                # The next rune must be a real non-ASCII symbol: the end of the file and an
                # invalid byte are not one.
                nxt = cps[i + 1] if i + 1 < len(cps) else INVALID
                next_is_symbol = nxt >= 0 and is_non_ascii_symbol(nxt)
                before = (is_non_ascii_symbol(prev) or (prev >= 0 and in_ranges(prev, table.skin))
                          or (prev == 0xFE0F and prev_allowed_vs))
                if not before or not next_is_symbol:
                    bad, why = True, "U+200D not between two pictographic symbols"
            elif rule == "bomAtStart":
                if i != 0:
                    bad, why = True, "U+FEFF not at the start of the file"
            elif rule == "loneCR":
                if i + 1 >= len(cps) or cps[i + 1] != 0x0A:
                    bad, why = True, "CR not followed by LF"
            if bad:
                out.append((line, col, r, name, why))
        prev, prev_allowed_vs = r, allowed_vs
        if r == 0x0A:
            line += 1
            col = 1
        else:
            col += 1
    return out


def fmt_findings(found):
    return ",".join("%d:%d %s" % (f[0], f[1], fmt_cp(f[2])) for f in found) or "none"


def disagreements(cases, table):
    """[(line no, name, got, expected)] for the rows whose findings differ from the file's."""
    bad = []
    for n, name, _, data, exp in cases:
        got = fmt_findings(scan(data, table))
        if got != exp:
            bad.append((n, name, got, exp))
    return bad


# ---- the self-test ---------------------------------------------------------


def coverage_problems(cases, table):
    """V1-c: the cases exercise every context rule both ways, a bidi control and a raw byte."""
    out = []
    flagged, green = set(), set()
    for _, _, _, data, _ in cases:
        hit = {f[2] for f in scan(data, table)}
        flagged |= hit
        for r in (0xFE0F, 0x200D, 0xFEFF, 0x0D):
            if chr(r).encode("utf-8") in data and r not in hit:
                green.add(r)
    for r in (0xFE0F, 0x200D, 0xFEFF, 0x0D):
        if r not in green:
            out.append("no case holds %s where it is allowed" % fmt_cp(r))
        if r not in flagged:
            out.append("no case holds %s where it is a finding" % fmt_cp(r))
    if not any(row[2] == "bidi" and row[0] in flagged for row in table.rows):
        out.append("no case has a bidi control as a finding")
    if not any("{x" in raw for _, _, raw, _, _ in cases):
        out.append("no case has a raw byte ({xHH})")
    for lo, hi, _, name in table.rows:
        for cp in (lo, hi):
            if cp not in flagged:
                out.append("no case has a finding at %s (an edge of %r)" % (fmt_cp(cp), name))
    return out


def mutants(table):
    """The three data mutants of ADR-0045 V2: what a reader that lost a rule would see."""
    rows = table.rows
    return [
        ("M1 the U+200D row dropped", table.with_rows([r for r in rows if r[2] != "zwjInEmoji"])),
        ("M2 U+FE0E-FE0F read as always", table.with_rows([(lo, hi, "always" if rule == "vsAfterSymbol" else rule, n)
                                                           for lo, hi, rule, n in rows])),
        ("M3 the bidi rows dropped", table.with_rows([r for r in rows if r[2] != "bidi"])),
    ]


def reader_negatives(table_lines):
    """[(what, callable)] each of which must raise Fail: a reader that accepts one of these
    reads less than the contract."""
    def ranges_with(i, text):
        lines = list(table_lines)
        lines[i] = text
        return lambda: parse_ranges(lines)

    ok_row = "U+0041\tU+0042\talways\tA"
    head = table_lines[:3]
    neg = [
        ("ranges: an unknown rule", lambda: parse_ranges(head + ["U+0041\tU+0042\tvs-after-symbol\tx"])),
        ("ranges: a missing header line", lambda: parse_ranges(table_lines[1:])),
        ("ranges: a wrong skin-tone line", ranges_with(1, "# skin-tone: U+1F3FB")),
        ("ranges: an overlap", lambda: parse_ranges(head + [ok_row, "U+0042\tU+0043\talways\tB"])),
        ("ranges: rows out of order", lambda: parse_ranges(head + ["U+0042\tU+0043\talways\tB", ok_row])),
        ("ranges: a lower-case code point", lambda: parse_ranges(head + ["U+00aa\tU+00aa\talways\tx"])),
        ("ranges: a rule never used", lambda: parse_ranges(head + [ok_row])),
        ("ranges: a bidi row of two code points", lambda: parse_ranges(head + ["U+202A\tU+202B\tbidi\tx"])),
        ("ranges: three columns", lambda: parse_ranges(head + ["U+0041\talways\tx"])),
        ("binary-ext: a capital", lambda: parse_binary_ext([".PDF\tx"])),
        ("binary-ext: not ascending", lambda: parse_binary_ext([".tgz\tx", ".pdf\ty"])),
        ("binary-ext: no reason", lambda: parse_binary_ext([".pdf\t"])),
        ("non-ASCII file", lambda: check_ascii(("caf" + chr(0xE9) + "\n").encode("utf-8"), "x")),
        ("a CR in a file", lambda: check_ascii(b"a\r\n", "x")),
        ("no final newline", lambda: check_ascii(b"a", "x")),
    ]
    for what, line in (
        ("{U+12} (too few digits)", "n\t{U+12}\tnone"),
        ("{u+200B} (lower-case u)", "n\t{u+200B}\tnone"),
        ("{LF} (a placeholder of an earlier draft)", "n\ta{LF}\tnone"),
        ("a lone }", "n\ta}\tnone"),
        ("a lone {", "n\ta{\tnone"),
        ("{x41} (a raw byte below 80)", "n\t{x41}\tnone"),
        ("{xff} (lower-case hex)", "n\t{xff}\tnone"),
        ("{U+D800} (a surrogate)", "n\t{U+D800}\tnone"),
        ("{U+110000} (beyond Unicode)", "n\t{U+110000}\tnone"),
        ("{U+0041} (a printable ASCII character as a placeholder)", "n\t{U+0041}\tnone"),
        ("an input that decodes to nothing", "n\t\tnone"),
        ("two columns", "n\tabc"),
        ("four columns", "n\tabc\tnone\tx"),
        ("an empty name", "\tabc\tnone"),
        ("a name that starts with #", "#n\tabc\tnone"),
        ("an expected that is neither none nor a list", "n\tabc\tmaybe"),
        ("an expected with a lower-case code point", "n\tabc\t1:1 U+00ad"),
    ):
        neg.append(("cases: " + what, lambda line=line: parse_cases([line])))
    neg.append(("cases: a name used twice", lambda: parse_cases(["n\tabc\tnone", "n\tabd\tnone"])))
    return neg


def walk_negatives(me):
    """Run this file on planted trees: [(what, args builder, want exit, text that must be in the output)]."""
    zwsp, rlo, tag = chr(0x200B), chr(0x202E), chr(0xE0041)
    with tempfile.TemporaryDirectory() as tmp:
        results = []

        def plant(name, files, git=False):
            d = os.path.join(tmp, name)
            os.makedirs(d)
            for rel, body in files.items():
                p = os.path.join(d, rel)
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, "wb") as f:
                    f.write(body if isinstance(body, bytes) else body.encode("utf-8"))
            if git:
                subprocess.run(["git", "-C", d, "init", "-q"], check=True)
                subprocess.run(["git", "-C", d, "add", "-A", "--", "."], check=True)
            return d

        def run(what, args, want, must):
            res = subprocess.run([sys.executable, me] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            text = (res.stdout + res.stderr).decode("utf-8", "replace")
            ok = res.returncode == want and must in text
            results.append((what, ok, "exit %d, want %d; %r in output: %s" % (res.returncode, want, must, must in text)))

        empty = plant("empty", {})
        run("an empty directory", [empty], 1, "no file listed")
        run("a directory that does not exist", [os.path.join(tmp, "nope")], 1, "no file listed")
        d = plant("zwsp", {"a.md": "ab" + zwsp + "\n"})
        run("a raw U+200B", [d], 1, "a.md:1:3 U+200B ZERO WIDTH SPACE: raw invisible character")
        d = plant("tag", {"a.md": "x\n\ngo" + tag + "\n"})
        run("a raw Tag character (line and column)", [d], 1, "a.md:3:3 U+E0041")
        d = plant("bidi", {"a.md": "a" + rlo + "b\n"})
        run("a raw bidi control", [d], 1, "a.md:1:2 U+202E")
        d = plant("sofe0f", {"a.md": "x " + chr(0x26A0) + chr(0xFE0F) + " careful\n"})
        run("So + U+FE0F is clean", [d], 0, "OK sourcehygiene-scan")
        d = plant("bom", {"a.md": b"\xef\xbb\xbfkey: 1\r\nb: 2\r\n"})
        run("a leading BOM and CRLF are clean", [d], 0, "OK sourcehygiene-scan")
        d = plant("nul", {"n.txt": b"a\x00b\n"})
        run("a NUL byte is one problem and no U+0000 finding", [d], 1, "n.txt: holds a NUL byte")
        d = plant("nonascii", {"caf" + chr(0xE9) + ".md": "x\n"})
        run("a path that is not printable ASCII", [d], 1, "path name is not printable ASCII")
        d = plant("pdf", {"a.pdf": "x" + zwsp + "y", "b.md": "clean\n"})
        run("a file with an extension of binary-ext.tsv is not scanned", [d], 0, "1 binary")
        d = plant("onlybin", {"a.pdf": "x"})
        run("a tree of only binary files scans no text: FAIL", [d], 1, "no text file was scanned")
        d = plant("allow", {"a.md": "x" + zwsp + "y\n"})
        al = os.path.join(tmp, "allow.txt")
        with open(al, "w") as f:
            f.write("# c\na.md\tU+200B\tthe raw U+200B is the input of a case\n")
        run("the code point listed for the file is allowed", [d, "--allowlist", al], 0, "OK sourcehygiene-scan")
        for what, line, must in (
            ("a dead entry (the file holds none of it)", "a.md\tU+2029\tx\n", "dead allowlist entry 'a.md'"),
            ("a dead code point", "a.md\tU+200B,U+2029\tx\n", "dead allowlist code point U+2029"),
            ("a file that is not in the tree", "gone.md\tU+200B\tx\n", "the file is not a tracked regular file"),
            ("a file listed twice", "a.md\tU+200B\tx\na.md\tU+200C\tx\n", "listed twice"),
            ("NUL in the list", "a.md\tU+0000\tx\n", "U+0000 is the NUL rule"),
            ("a code point outside the table", "a.md\tU+0041\tx\n", "is not in the table"),
            ("no reason", "a.md\tU+200B\t\n", "has no reason"),
            ("a glob", "a/*.md\tU+200B\tx\n", "not an exact, clean, slash-separated file path"),
        ):
            with open(al, "w") as f:
                f.write(line)
            run("the allowlist: " + what, [d, "--allowlist", al], 1, must)
        run("an allowlist that does not exist", [d, "--allowlist", os.path.join(tmp, "no-such-list")], 1, "the allowlist is unreadable")
        d = plant("bidiallow", {"a.md": "a" + rlo + "b\n"})
        with open(al, "w") as f:
            f.write("a.md\tU+202E\tan attack fixture\n")
        run("a bidi control can be listed too", [d, "--allowlist", al], 0, "OK sourcehygiene-scan")
        g = plant("git", {"a.md": "clean\n", ".claude/x.md": "x" + rlo + "y\n"}, git=False)
        subprocess.run(["git", "-C", g, "init", "-q"], check=True)
        subprocess.run(["git", "-C", g, "add", "a.md"], check=True)
        run("git: the untracked file is not scanned", [g], 0, "OK sourcehygiene-scan")
        run("git: --also-untracked reaches it", [g, "--also-untracked", ".claude"], 1, ".claude/x.md:1:2 U+202E")
        run("git: --also-untracked of a path that does not exist", [g, "--also-untracked", "nope"], 1, "does not exist")
        run("git: --also-untracked wants a clean relative path", [g, "--also-untracked", "../x"], 1, "clean relative path")
        run("--selftest with a directory is a usage error", ["--selftest", g], 2, "usage:")
        run("no argument is a usage error", [], 2, "usage:")
        run("an unknown option is a usage error", [g, "--nope"], 2, "usage:")
        return results


def selftest():
    data = Data()
    warn_unicode_version(data.table)
    problems = []
    bad = disagreements(data.cases, data.table)
    for n, name, got, exp in bad:
        problems.append("hidden-cases.tsv:%d: %s: scan gives %s, the file says %s" % (n, name, got, exp))
    problems += ["hidden-cases.tsv: " + p for p in coverage_problems(data.cases, data.table)]
    caught = 0
    for label, mutated in mutants(data.table):
        if disagreements(data.cases, mutated):
            caught += 1
        else:
            problems.append("mutant %s: not one case disagrees: the cases cannot see that rule" % label)
    negatives = reader_negatives(read_ascii(RANGES_FILE))
    for what, fn in negatives:
        try:
            fn()
        except Fail:
            continue
        problems.append("reader negative '%s': the reader accepted it" % what)
    walks = walk_negatives(os.path.realpath(__file__))
    for what, ok, why in walks:
        if not ok:
            problems.append("walk '%s': %s" % (what, why))
    for p in problems:
        sys.stderr.write("FAIL: %s\n" % p)
    if problems:
        raise Fail("selftest: %d problems" % len(problems))
    print("OK sourcehygiene-scan --selftest: %d table rows, %d cases agree, %d/3 mutants caught, %d reader negatives, "
          "%d walk checks (data unicode %s)" % (len(data.table.rows), len(data.cases), caught, len(negatives), len(walks),
                                                data.table.unicode_version))


# ---- the allowlist ---------------------------------------------------------


def parse_allowlist(path, table):
    try:
        text = Path(path).read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise Fail("%s: the allowlist is unreadable (it must exist, even with no entry): %s" % (path, e))
    allow = {}
    for n, raw in enumerate(text.split("\n"), 1):
        line = raw.rstrip("\r")
        if line.strip() == "" or line.startswith("#"):
            continue
        where = "%s:%d" % (path, n)
        cols = line.split("\t", 2)
        if len(cols) != 3:
            raise Fail("%s: want <path><TAB><U+XXXX[,...]><TAB><reason>, got %r" % (where, line))
        p, lst, reason = cols
        if reason.strip() == "":
            raise Fail("%s: %r has no reason" % (where, p))
        if (p == "" or p != p.strip() or any(c in p for c in "*?[]{}\\") or os.path.normpath(p) != p
                or p.startswith("/") or p.startswith("../") or p == "."):
            raise Fail("%s: %r is not an exact, clean, slash-separated file path (no glob, no directory)" % (where, p))
        cps = []
        for tok in lst.split(","):
            cp = parse_cp(tok, where)
            if cp == 0:
                raise Fail("%s: U+0000 is the NUL rule, not an exception" % where)
            if table.lookup(cp) is None:
                raise Fail("%s: %s is not in the table, so there is nothing to allow" % (where, tok))
            if cps and cp <= cps[-1]:
                raise Fail("%s: code points must be strictly ascending (%s after %s)" % (where, tok, fmt_cp(cps[-1])))
            cps.append(cp)
        if p in allow:
            raise Fail("%s: %r is listed twice" % (where, p))
        allow[p] = cps
    return allow


# ---- the walk --------------------------------------------------------------


def show(path):
    """A path for a message: printable ASCII as it is, anything else escaped (a path may hide too)."""
    return path if re.match(r"^[!-~]+$", path) else ascii(path)


def list_files(root):
    if os.path.lexists(os.path.join(root, ".git")):
        try:
            res = subprocess.run(["git", "-C", root, "-c", "core.quotepath=off", "ls-files", "-z"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        except OSError as e:
            raise Fail("git ls-files: cannot run git: %s" % e)
        if res.returncode != 0:
            raise Fail("git ls-files in %s failed: %s" % (root, res.stderr.decode("utf-8", "replace").strip()))
        return sorted(p.decode("utf-8", "surrogateescape") for p in res.stdout.split(b"\0") if p)
    out = []
    for d, dirs, files in os.walk(root):
        dirs.sort()
        out += [os.path.relpath(os.path.join(d, f), root).replace(os.sep, "/") for f in sorted(files)]
    return sorted(out)


def untracked_files(root, rels):
    out = []
    for rel in rels:
        if (rel == "" or os.path.isabs(rel) or os.path.normpath(rel) != rel or rel == "." or rel.startswith("../")
                or "\\" in rel):
            raise Fail("--also-untracked %r: want a clean relative path" % rel)
        p = os.path.join(root, rel)
        if not os.path.lexists(p):
            raise Fail("--also-untracked %s: the path does not exist" % rel)
        if os.path.isdir(p) and not os.path.islink(p):
            for d, dirs, files in os.walk(p):
                dirs[:] = sorted(x for x in dirs if x != ".git")
                out += [os.path.relpath(os.path.join(d, f), root).replace(os.sep, "/") for f in sorted(files)]
        else:
            out.append(rel)
    return out


def scan_tree(root, allowlist, also, data):
    table = data.table
    allow = parse_allowlist(allowlist, table) if allowlist else {}
    files = sorted(set(list_files(root)) | set(untracked_files(root, also)))
    if not files:
        raise Fail("no file listed under %s: a scan of nothing proves nothing" % root)
    problems = []
    scanned, binary, skipped = set(), set(), 0
    seen = {}
    for rel in files:
        if not re.match(r"^[!-~]+$", rel):
            problems.append("%s: path name is not printable ASCII (U+0021-007E, no space)" % ascii(rel))
        p = os.path.join(root, rel)
        if not os.path.lexists(p) or os.path.islink(p) or not os.path.isfile(p):
            skipped += 1  # absent, a symlink or a submodule: not followed
            continue
        if os.path.splitext(rel)[1].lower() in data.binary_ext:
            binary.add(rel)
            continue
        content = Path(p).read_bytes()
        scanned.add(rel)
        if b"\x00" in content:
            problems.append("%s: holds a NUL byte but its extension is not in binary-ext.tsv, so it cannot be told from a text "
                            "file that hides something (remove the NUL, or add the extension with a reason)" % show(rel))
        allowed = allow.get(rel, [])
        for line, col, cp, name, why in scan(content, table):
            if cp == 0:
                continue  # a NUL byte is reported once, above
            if cp in allowed:
                seen.setdefault(rel, set()).add(cp)
                continue
            msg = "%s:%d:%d %s %s: raw invisible character (write it as an escape; an exception needs a reviewed line in the allowlist)" % (
                show(rel), line, col, fmt_cp(cp), name)
            problems.append(msg + ("; " + why if why else ""))
    for p in sorted(allow):
        if not seen.get(p):
            if p in binary:
                why = "the file has an extension of binary-ext.tsv and is not scanned"
            elif p not in scanned:
                why = "the file is not a tracked regular file"
            else:
                why = "the file holds none of the listed raw characters"
            problems.append("%s: dead allowlist entry %r: %s; delete the line" % (allowlist, p, why))
            continue
        for cp in allow[p]:
            if cp not in seen[p]:
                problems.append("%s: dead allowlist code point %s for %r: the file does not hold it raw; remove it from the line"
                                % (allowlist, fmt_cp(cp), p))
    if not scanned:
        raise Fail("no text file was scanned under %s (%d binary, %d not regular): a scan of nothing proves nothing"
                   % (root, len(binary), skipped))
    return problems, len(scanned), len(binary)


# ---- main ------------------------------------------------------------------


def main(argv):
    args = argv[1:]
    if args == ["--selftest"]:
        selftest()
        return 0
    allowlist, also, positional = None, [], []
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--allowlist", "--also-untracked"):
            if i + 1 >= len(args):
                sys.stderr.write("%s needs a value\n%s" % (a, USAGE))
                return 2
            if a == "--allowlist":
                allowlist = args[i + 1]
            else:
                also.append(args[i + 1])
            i += 2
        elif a.startswith("-"):
            sys.stderr.write("unknown option or a misplaced one: %s\n%s" % (a, USAGE))
            return 2
        else:
            positional.append(a)
            i += 1
    if len(positional) != 1:
        sys.stderr.write(USAGE)
        return 2
    data = Data()
    warn_unicode_version(data.table)
    problems, n_scanned, n_binary = scan_tree(positional[0], allowlist, also, data)
    for p in problems:
        print(p)
    summary = "sourcehygiene-scan: %d files, %d binary, %d problems (data unicode %s)" % (
        n_scanned, n_binary, len(problems), data.table.unicode_version)
    if problems:
        sys.stderr.write("FAIL %s\n" % summary)
        return 1
    print("OK " + summary)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Fail as e:
        sys.stderr.write("FAIL: %s\n" % e)
        sys.exit(1)
    except Exception as e:  # an internal error is not a pass: any non-zero status is a FAIL for a consumer
        sys.stderr.write("FAIL: sourcehygiene-scan: internal error: %s: %s\n" % (type(e).__name__, e))
        sys.exit(1)
