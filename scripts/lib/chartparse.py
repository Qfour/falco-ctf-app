"""Shared reader for rendered chart manifests (`helm template` output).

Used by the chart checks under scripts/ (scripts/check-seccomp.py today); a
check imports this module instead of carrying its own parser, so a rendered
Pod is read the same way by every check. Extracted from check-seccomp.py, then
extended with the helpers below the Pod traversal (`scan_containers` /
`containers` / `container_names` / `security_context` / `flow_list` /
`as_list`) and with block scalar support in the parser (a rendered Pod whose
init container runs a `sh -c` script carries one).

WHAT THIS IS, AND WHAT IT IS NOT
---------------------------------
This is NOT a YAML parser. It is a minimal, intentionally strict reader for
the shapes `helm template` emits, with no third-party dependency (PyYAML is
not guaranteed on the CI runner's stock python3, and repo convention forbids
adding installs for a lint check). It supports:

  - block mappings and block sequences (spaces only; a tab in an
    indentation-sensitive line raises),
  - quoted ('...' / "...") and plain scalars, returned as `str` (no type
    resolution: `true`, `0`, `null` all stay strings),
  - `#` comments,
  - `---` document separators,
  - block scalars: `|` (literal), `>` (folded), each with an optional chomping
    indicator (`-` strip, `+` keep, none = clip) and indentation indicator
    (1-9), as a mapping value or a sequence item. The body is taken verbatim
    (a `#`, `:` or `-` in it is text) and returned as one `str`. Folding is
    minimal: adjacent lines join with a space, blank lines become newlines,
    more-indented lines keep their line breaks. A body line indented less than
    the first one, and any other header form (`|+-`, `|0`, `>foo`), raise,
  - flow collections ("[...]" / "{...}") kept as OPAQUE scalar strings by
    the parser; `flow_list()` / `as_list()` / `security_context()` turn the
    forms listed there into values and raise on anything else.

It does NOT support, and never interprets: anchors / aliases / tags (an
inline `&a x` stays part of the scalar text; an anchor followed by a nested
block raises), multi-line flow
collections (raise), and nested flow collections inside
`flow_list` (raise). Anything it cannot confidently read raises
`YamlSubsetError` (or its subclass `PodShapeError` for a Pod whose shape is
not what a checker needs). A caller must treat either as a FAIL, never as
"nothing found": a silently skipped container is a silently unchecked
container. A flow mapping other than `{}` is NOT expanded: it reaches the
caller as an opaque string, so `security_context()` raises on it, but a
caller that reads `container.get("securityContext")` directly sees a `str`
and must treat a non-mapping there as a FAIL itself (or go through
`security_context()`).

KNOWN LIMIT: a quoted scalar is unquoted before anything looks at it, so a
quoted "[one]" is indistinguishable from the flow form [one] once parsed.
`helm template` never emits that for the fields the checks read (Kubernetes
would reject a string where a list is required), so this is accepted rather
than tracked with extra state.

Scope (2026-11-01): this Python reader is the source of truth for the chart
Hard Invariant checks in this repo; the conftest approach of app#67 is limited
to the platform-side Key Guards.

The self-test is scripts/test-chartparse.py (run by `make lint`).
"""
import re
from collections import namedtuple

# Kinds whose Pod template lives at .spec.template.spec.
POD_TEMPLATE_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}

CONTAINER_GROUPS = ("initContainers", "containers", "ephemeralContainers")


class YamlSubsetError(Exception):
    """Raised when input isn't in the restricted YAML subset this parser
    supports. Callers must treat this as a FAIL, never a skip/pass."""


class PodShapeError(YamlSubsetError):
    """Raised when a Pod spec parses but its shape is not what a checker can
    rely on (a container group that is not a list, a container that is not a
    mapping, a securityContext that is not a mapping). Subclass of
    YamlSubsetError so one `except` covers both; always a FAIL."""


# ---------------------------------------------------------------------------
# Minimal block-style YAML subset parser
# ---------------------------------------------------------------------------

def _strip_comment(line: str) -> str:
    """Remove a trailing '# ...' comment that isn't inside a quoted scalar."""
    in_single = in_double = False
    for idx, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            if idx == 0 or line[idx - 1].isspace():
                return line[:idx].rstrip()
    return line.rstrip()


class _BlockBody(str):
    """The body of a block scalar, as one entry of the preprocessed line list
    that directly follows its header line. `str(self)` is a placeholder so
    that nothing mistakes it for content; the value is `.text`."""

    def __new__(cls, text: str):
        obj = super().__new__(cls, "<block scalar body>")
        obj.text = text
        return obj


# `|` / `>` with an optional chomping (+ / -) and indentation (1-9) indicator
# in either order, each at most once. Anything else that starts with `|` or
# `>` where a value is expected is not a valid YAML scalar start, so it raises.
_BLOCK_HEADER = re.compile(r"([|>])(?:([1-9])([+-])?|([+-])([1-9])?)?")


def _block_header(content: str):
    """If the (comment-stripped, stripped) line `content` ends in a block
    scalar header, return (style, chomp, indent_indicator, n) where n is the
    column offset of the parent node (the key, or the `-` of a scalar
    sequence item) inside `content`; else None. Raises YamlSubsetError for a
    value that starts with `|` / `>` but is not a supported header."""
    off = 0
    unit = None
    rest = content
    while rest.startswith("- "):
        unit = off
        rest = rest[2:]
        off += 2
        stripped = rest.lstrip(" ")
        off += len(rest) - len(stripped)
        rest = stripped
    colon = _find_key_colon(rest)
    if colon is not None:
        value = rest[colon + 1:].strip()
        n = off
    else:
        value = rest.strip()
        n = unit
    if not value or value[0] not in "|>":
        return None
    m = _BLOCK_HEADER.fullmatch(value)
    if m is None:
        raise YamlSubsetError(f"unsupported block scalar header {value!r} in {content!r}")
    if n is None:
        raise YamlSubsetError(f"block scalar with no parent key or sequence item: {content!r}")
    style = m.group(1)
    digit = m.group(2) or m.group(5)
    chomp = m.group(3) or m.group(4) or ""
    return style, chomp, int(digit) if digit else None, n


def _fold(lines):
    """Fold the body lines of a `>` scalar into (text, trailing blank count):
    adjacent non-blank lines join with one space, k blank lines between two
    lines become k newlines, and a line that starts with whitespace is kept on
    its own line (YAML's "more-indented" rule)."""
    out = ""
    prev = None
    blanks = 0
    for line in lines:
        if line == "":
            blanks += 1
            continue
        if prev is None:
            out += "\n" * blanks + line
        else:
            if line[0] in " \t" or prev[0] in " \t":
                out += "\n" * (blanks + 1)
            elif blanks:
                out += "\n" * blanks
            else:
                out += " "
            out += line
        prev = line
        blanks = 0
    return out, blanks


def _block_scalar_text(style: str, chomp: str, lines):
    """The value of a block scalar from its de-indented body `lines` (blank
    lines are ""). `|` keeps line breaks, `>` folds (see _fold); chomping:
    "" = clip (one final newline), "-" = strip, "+" = keep trailing blanks."""
    while lines and lines[-1] == "" and chomp != "+":
        lines = lines[:-1]
    if style == "|":
        trailing = 0
        body = lines
        if chomp == "+":
            while body and body[-1] == "":
                body = body[:-1]
                trailing += 1
        text = "\n".join(body)
    else:
        text, trailing = _fold(lines)
    if not text:
        return "\n" * trailing if chomp == "+" else ""
    if chomp == "-":
        return text
    if chomp == "+":
        return text + "\n" + "\n" * trailing
    return text + "\n"


def _preprocess(doc_text: str):
    """Return [(indent, content), ...] for non-blank, comment-stripped lines.
    A block scalar header line is followed by one extra entry, a `_BlockBody`
    at the body's indent, which carries the scalar's text: the body is taken
    verbatim here (comments, blank lines, `:` and `-` in it are content)."""
    lines = []
    raws = doc_text.splitlines()
    k = 0
    while k < len(raws):
        raw = raws[k]
        k += 1
        code_part = raw.split("#", 1)[0]
        if "\t" in code_part:
            raise YamlSubsetError(f"tab character in indentation-sensitive line: {raw!r}")
        stripped = _strip_comment(raw)
        if stripped.strip() == "":
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        content = stripped.strip()
        lines.append((indent, content))
        header = _block_header(content)
        if header is None:
            continue
        style, chomp, digit, n_off = header
        n = indent + n_off
        body = []  # (leading spaces, raw line) of non-blank lines, None for blank
        block_indent = n + digit if digit else None
        while k < len(raws):
            line = raws[k]
            if line.strip() == "":
                body.append(None if len(line) <= (block_indent or 0) else line)
                k += 1
                continue
            lead = len(line) - len(line.lstrip(" "))
            if lead <= n:
                break
            if block_indent is None:
                block_indent = lead
            if lead < block_indent:
                raise YamlSubsetError(f"block scalar line indented less than its first line: {line!r}")
            body.append(line)
            k += 1
        bi = block_indent if block_indent is not None else n + 1
        texts = ["" if ln is None else ln[bi:] for ln in body]
        lines.append((bi, _BlockBody(_block_scalar_text(style, chomp, texts))))
    return lines


def _parse_scalar(rest: str):
    rest = rest.strip()
    if len(rest) >= 2 and rest[0] == rest[-1] and rest[0] in ("'", '"'):
        return rest[1:-1]
    return rest


def _find_key_colon(content: str):
    """Return the index of the ':' that separates a mapping key from its
    value, or None if `content` is a plain scalar (no such colon). Only a
    ':' followed by whitespace or end-of-line counts (matches YAML's rule
    for distinguishing `key: value` from scalars that merely contain a
    colon, e.g. bare `http://...` URLs)."""
    in_single = in_double = False
    for idx, ch in enumerate(content):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == ":" and not in_single and not in_double:
            if idx + 1 == len(content) or content[idx + 1] == " ":
                return idx
    return None


def _take_block_body(lines, i):
    """lines[i] is the _BlockBody that follows a header; return (text, i + 1)."""
    if i >= len(lines) or not isinstance(lines[i][1], _BlockBody):
        raise YamlSubsetError("block scalar header without its body")
    return lines[i][1].text, i + 1


def _parse_block(lines, i, indent0):
    """Parse the block starting at lines[i] (all at indent indent0) until
    indentation decreases. Returns (value, next_index)."""
    if i >= len(lines) or lines[i][0] != indent0:
        got = lines[i] if i < len(lines) else "EOF"
        raise YamlSubsetError(f"expected block at indent {indent0}, got {got!r}")
    content = lines[i][1]
    if isinstance(content, _BlockBody):
        raise YamlSubsetError(f"block scalar body with no header at indent {indent0}")
    if content == "-" or content.startswith("- "):
        return _parse_sequence(lines, i, indent0)
    if _find_key_colon(content) is not None:
        return _parse_mapping(lines, i, indent0)
    if _BLOCK_HEADER.fullmatch(content):  # `- |`: the item is a block scalar (its header was validated in _preprocess)
        return _take_block_body(lines, i + 1)
    # Plain scalar occupying its own line (e.g. a bare-string sequence item
    # like `- Ingress`). Must be the only line in this block.
    if i + 1 < len(lines) and lines[i + 1][0] >= indent0:
        raise YamlSubsetError(f"unexpected content after scalar {content!r} at indent {indent0}")
    return _parse_scalar(content), i + 1


def _parse_sequence(lines, i, indent0):
    seq = []
    while i < len(lines) and lines[i][0] == indent0 and (
        lines[i][1] == "-" or lines[i][1].startswith("- ")
    ):
        content = lines[i][1]
        if content == "-":
            i += 1
            if i < len(lines) and lines[i][0] > indent0:
                val, i = _parse_block(lines, i, lines[i][0])
            else:
                val = None
            seq.append(val)
            continue

        rest = content[2:]
        item_indent = indent0 + 2
        item_lines = [(item_indent, rest)]
        j = i + 1
        while j < len(lines) and lines[j][0] > indent0:
            item_lines.append(lines[j])
            j += 1
        val, consumed = _parse_block(item_lines, 0, item_indent)
        if consumed != len(item_lines):
            raise YamlSubsetError(f"trailing unparsed content in sequence item near indent {indent0}")
        seq.append(val)
        i = j
    return seq, i


def _parse_mapping(lines, i, indent0):
    mapping = {}
    while i < len(lines) and lines[i][0] == indent0:
        content = lines[i][1]
        if content == "-" or content.startswith("- "):
            raise YamlSubsetError(f"unexpected sequence item inside mapping at indent {indent0}: {content!r}")
        colon_idx = _find_key_colon(content)
        if colon_idx is None:
            raise YamlSubsetError(f"expected 'key:' or 'key: value', got {content!r}")
        key = _parse_scalar(content[:colon_idx])
        rest = content[colon_idx + 1:].strip()
        i += 1
        if rest == "":
            if i < len(lines) and lines[i][0] > indent0:
                val, i = _parse_block(lines, i, lines[i][0])
            else:
                val = None
        elif _block_header(content) is not None:
            val, i = _take_block_body(lines, i)
        else:
            val = _parse_scalar(rest)
        mapping[key] = val
    return mapping, i


def load_all_documents(text: str):
    """Split on top-level '---' document separators; parse each document."""
    raw_docs = re.split(r"(?m)^---[ \t]*$", text)
    docs = []
    for raw in raw_docs:
        lines = _preprocess(raw)
        if not lines:
            continue
        if lines[0][0] != 0:
            raise YamlSubsetError(f"document does not start at indent 0: {lines[0]!r}")
        val, next_i = _parse_block(lines, 0, 0)
        if next_i != len(lines):
            raise YamlSubsetError(
                f"trailing unparsed content after top-level document (line index {next_i}/{len(lines)})"
            )
        docs.append(val)
    return docs

# ---------------------------------------------------------------------------
# Kubernetes-specific traversal + the actual invariant check
# ---------------------------------------------------------------------------

def extract_pod_specs(doc):
    """Return [(label, pod_spec), ...] for Pod-spec-bearing objects in `doc`.
    Objects that don't carry a Pod spec (Service, ConfigMap, Namespace, ...)
    are out of scope and yield nothing — that is not a failure."""
    if not isinstance(doc, dict):
        return []
    kind = doc.get("kind")
    name = (doc.get("metadata") or {}).get("name", "<unknown>")

    if kind == "Pod":
        return [(f"Pod/{name}", doc.get("spec"))]

    if kind in POD_TEMPLATE_KINDS:
        spec = doc.get("spec")
        template = spec.get("template") if isinstance(spec, dict) else None
        pod_spec = template.get("spec") if isinstance(template, dict) else None
        return [(f"{kind}/{name}", pod_spec)]

    if kind == "CronJob":
        spec = doc.get("spec")
        job_template = spec.get("jobTemplate") if isinstance(spec, dict) else None
        job_spec = job_template.get("spec") if isinstance(job_template, dict) else None
        pod_template = job_spec.get("template") if isinstance(job_spec, dict) else None
        pod_spec = pod_template.get("spec") if isinstance(pod_template, dict) else None
        return [(f"CronJob/{name}", pod_spec)]

    return []



# ---------------------------------------------------------------------------
# Containers, securityContext, flow lists
# ---------------------------------------------------------------------------

# One element of a Pod spec's container groups, in document order. `spec` is
# the container mapping itself; `name` is "<unnamed>" when the container has
# no name (a checker should treat that as a defect, not skip it).
Container = namedtuple("Container", ["group", "name", "spec"])

# A shape defect found while walking the groups (`msg` is the message text a
# caller may prefix with its own location, e.g. "initContainers is not a list").
ShapeProblem = namedtuple("ShapeProblem", ["msg"])


def scan_containers(pod_spec):
    """Walk initContainers, containers, ephemeralContainers (in that order)
    and return an ordered list of `Container` and `ShapeProblem` items.

    A group that is absent (`None`) contributes nothing. A group that is not
    a list, or an entry that is not a mapping, becomes a `ShapeProblem` and
    the walk continues, so a caller that reports every defect (check-seccomp
    does) sees all of them. `pod_spec` must be a mapping (caller checks)."""
    out = []
    for group in CONTAINER_GROUPS:
        entries = pod_spec.get(group)
        if entries is None:
            continue
        if not isinstance(entries, list):
            out.append(ShapeProblem(f"{group} is not a list"))
            continue
        for c in entries:
            if not isinstance(c, dict):
                out.append(ShapeProblem(f"{group} entry is not a mapping"))
                continue
            out.append(Container(group, c.get("name", "<unnamed>"), c))
    return out


def containers(pod_spec):
    """Strict form of `scan_containers`: the list of `Container`, or
    `PodShapeError` if any group/entry has the wrong shape or any container
    has no name. Use this when a defect must stop the check."""
    if not isinstance(pod_spec, dict):
        raise PodShapeError("pod spec is not a mapping")
    found = []
    for item in scan_containers(pod_spec):
        if isinstance(item, ShapeProblem):
            raise PodShapeError(item.msg)
        if not isinstance(item.spec.get("name"), str) or item.spec["name"] == "":
            raise PodShapeError(f"{item.group} entry has no usable name: {item.spec.get('name')!r}")
        found.append(item)
    return found


def container_names(pod_spec):
    """{group: set of container names} for every group in CONTAINER_GROUPS
    (a missing group maps to an empty set). Raises like `containers`. A
    checker compares this against the names it EXPECTS to find: an empty or
    short result is a failure of the reader, not a clean pass."""
    names = {g: set() for g in CONTAINER_GROUPS}
    for c in containers(pod_spec):
        names[c.group].add(c.name)
    return names


def security_context(obj):
    """The `securityContext` of a container (or of a Pod spec) as a dict.

    Absent / null -> {}. The empty flow mapping `{}` -> {}. A block mapping
    is returned as parsed. Anything else (a scalar, a list, a non-empty flow
    mapping, which this reader does not expand) raises PodShapeError."""
    value = obj.get("securityContext")
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if value == "{}":
        return {}
    raise PodShapeError(f"securityContext is not a block mapping: {value!r}")


def _split_flow_items(body: str):
    """Split the inside of a flow sequence on top-level commas, honoring
    '...' and \"...\" quoting. Raises on an unterminated quote."""
    items = []
    cur = []
    in_single = in_double = False
    for ch in body:
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        if ch == "," and not in_single and not in_double:
            items.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if in_single or in_double:
        raise YamlSubsetError(f"unterminated quote in flow sequence: {body!r}")
    items.append("".join(cur))
    return items


def flow_list(value):
    """Read a one-line flow sequence of scalars, e.g. `["one"]`, `[one, two]`,
    `['a', "b"]`, `[]`, and return a list of str. The parser hands these over
    as opaque strings.

    Raises YamlSubsetError for: a non-string, a string that is not wrapped in
    exactly one `[` ... `]`, a nested `[` / `{`, an empty element (`[a,,b]`,
    `[,]`; a single trailing comma `[a,]` is allowed as in YAML), or an
    unterminated quote, a backslash or a repeated quote char inside a quoted element."""
    if not isinstance(value, str):
        raise YamlSubsetError(f"flow sequence expected, got {type(value).__name__}: {value!r}")
    text = value.strip()
    if not (len(text) >= 2 and text[0] == "[" and text[-1] == "]"):
        raise YamlSubsetError(f"not a flow sequence: {value!r}")
    body = text[1:-1].strip()
    if body == "":
        return []
    parts = _split_flow_items(body)
    if parts and parts[-1].strip() == "" and len(parts) > 1:
        parts = parts[:-1]  # one trailing comma
    items = []
    for part in parts:
        raw = part.strip()
        if raw == "":
            raise YamlSubsetError(f"empty element in flow sequence: {value!r}")
        if raw[0] in "'\"":
            if len(raw) < 2 or raw[-1] != raw[0]:
                raise YamlSubsetError(f"malformed quoted element in flow sequence: {value!r}")
            quote = raw[0]
            raw = raw[1:-1]
            # No escape handling here: a backslash, or the quote char again
            # inside (an escaped or adjacent quote: "a\"b", "a""b", 'a''b'),
            # is refused rather than guessed at.
            if quote in raw or "\\" in raw:
                raise YamlSubsetError(f"escaped or adjacent quote in flow sequence element is not supported: {value!r}")
        elif any(ch in raw for ch in "[]{}"):
            raise YamlSubsetError(f"nested flow collection is not supported: {value!r}")
        items.append(raw)
    return items


def as_list(value):
    """A list of scalar strings from either YAML style of the same sequence:
    a block sequence (already a list from the parser) or a one-line flow
    sequence. `None` (key with no value) -> []. Raises YamlSubsetError when a
    block item is not a scalar or the value is neither style (e.g. a bare
    `one`)."""
    if value is None:
        return []
    if isinstance(value, list):
        for item in value:
            if not isinstance(item, str):
                raise YamlSubsetError(f"sequence item is not a scalar: {item!r}")
        return list(value)
    return flow_list(value)
