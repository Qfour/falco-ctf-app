#!/usr/bin/env python3
"""Fail-closed Hard Invariant guard: every effective container (containers /
initContainers / ephemeralContainers) in every Pod spec produced by
`helm template` for every chart under charts/ must run with
securityContext.seccompProfile.type == "RuntimeDefault", and must not set
securityContext.privileged: true (privileged disables seccomp regardless of
the profile).

WHY THIS EXISTS
----------------
`make lint` / CI's `chart-lint` job only run `helm lint` + `helm template
>/dev/null` — neither inspects the *rendered content*. Without this script,
deleting the Pod-level `seccompProfile` from charts/ctf-user/templates/pod.yaml
(the only inheritance path for the `challenge` container, which sets no
container-level `securityContext` at all) would go undetected: CI would stay
green. See ".claude/rules/falco-ctf-app-conventions.md" ("SecurityContext").

WHY FIELD-LEVEL, NOT BLOCK-LEVEL
---------------------------------
Kubernetes overrides Pod securityContext with container securityContext on a
per-FIELD basis, not as a whole block. A container only overrides seccomp if
it sets `securityContext.seccompProfile` itself — every other field is
independent. So the "effective" seccomp profile for container C is:

    C.securityContext.seccompProfile.type    if C sets seccompProfile
    else Pod.spec.securityContext.seccompProfile.type

This script evaluates exactly that, for every container/initContainer/
ephemeralContainer in every rendered Pod/Deployment/StatefulSet/DaemonSet/
ReplicaSet/Job/CronJob.

WHY NO YAML / THIRD-PARTY DEPENDENCY
--------------------------------------
PyYAML is not guaranteed to be importable from the stock `python3` on the CI
runner, and repo convention forbids adding new installs (pip packages, `yq`,
etc.) for a lint check. This module implements a minimal, intentionally
*strict* block-style YAML-subset parser sufficient for `helm template`
output (block mappings/sequences, quoted scalars, flow collections treated
as opaque scalars, `#` comments). Anything it cannot confidently parse raises
YamlSubsetError, which is always treated as a FAIL — never a silent skip.
"""
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHARTS_DIR = REPO_ROOT / "charts"

# Kinds whose Pod template lives at .spec.template.spec.
POD_TEMPLATE_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}

CONTAINER_GROUPS = ("initContainers", "containers", "ephemeralContainers")


class YamlSubsetError(Exception):
    """Raised when input isn't in the restricted YAML subset this parser
    supports. Callers must treat this as a FAIL, never a skip/pass."""


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


def _preprocess(doc_text: str):
    """Return [(indent, content), ...] for non-blank, comment-stripped lines."""
    lines = []
    for raw in doc_text.splitlines():
        code_part = raw.split("#", 1)[0]
        if "\t" in code_part:
            raise YamlSubsetError(f"tab character in indentation-sensitive line: {raw!r}")
        stripped = _strip_comment(raw)
        if stripped.strip() == "":
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        lines.append((indent, stripped.strip()))
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


def _parse_block(lines, i, indent0):
    """Parse the block starting at lines[i] (all at indent indent0) until
    indentation decreases. Returns (value, next_index)."""
    if i >= len(lines) or lines[i][0] != indent0:
        got = lines[i] if i < len(lines) else "EOF"
        raise YamlSubsetError(f"expected block at indent {indent0}, got {got!r}")
    content = lines[i][1]
    if content == "-" or content.startswith("- "):
        return _parse_sequence(lines, i, indent0)
    if _find_key_colon(content) is not None:
        return _parse_mapping(lines, i, indent0)
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


def effective_seccomp_type(container: dict, pod_security_context):
    """Return (type_or_None, source_label) for the seccompProfile.type that
    actually applies to `container`, honoring k8s per-FIELD inheritance."""
    csc = container.get("securityContext")
    if isinstance(csc, dict) and "seccompProfile" in csc:
        sp = csc.get("seccompProfile")
        if not isinstance(sp, dict):
            return None, "container (malformed seccompProfile)"
        return sp.get("type"), "container"

    if isinstance(pod_security_context, dict):
        sp = pod_security_context.get("seccompProfile")
        if isinstance(sp, dict):
            return sp.get("type"), "pod (inherited)"

    return None, "none set at either level"


def check_pod_spec(chart, label, pod_spec, errors):
    if not isinstance(pod_spec, dict):
        errors.append(f"{chart}: {label}: pod spec missing or unparsable")
        return

    pod_sc = pod_spec.get("securityContext")
    if pod_sc is not None and not isinstance(pod_sc, dict):
        errors.append(f"{chart}: {label}: spec.securityContext is not a mapping")
        pod_sc = None

    if not isinstance(pod_spec.get("containers"), list) or not pod_spec.get("containers"):
        errors.append(f"{chart}: {label}: spec.containers missing/empty (unparsable pod spec)")
        return

    for group in CONTAINER_GROUPS:
        containers = pod_spec.get(group)
        if containers is None:
            continue
        if not isinstance(containers, list):
            errors.append(f"{chart}: {label}: {group} is not a list")
            continue
        for c in containers:
            if not isinstance(c, dict):
                errors.append(f"{chart}: {label}: {group} entry is not a mapping")
                continue
            cname = c.get("name", "<unnamed>")
            csc = c.get("securityContext")

            if isinstance(csc, dict) and str(csc.get("privileged")).strip().lower() == "true":
                errors.append(
                    f"{chart}: {label}: {group}[{cname}] sets privileged: true "
                    "(disables seccomp regardless of profile)"
                )
                continue

            sc_type, source = effective_seccomp_type(c, pod_sc)
            if sc_type != "RuntimeDefault":
                errors.append(
                    f"{chart}: {label}: {group}[{cname}] effective seccompProfile.type="
                    f"{sc_type!r} (source: {source}) — want 'RuntimeDefault'"
                )
            else:
                print(f"    ok: {group}[{cname}] seccompProfile.type=RuntimeDefault (source: {source})")


def main() -> int:
    if not CHARTS_DIR.is_dir():
        print(f"FAIL: charts dir not found: {CHARTS_DIR}", file=sys.stderr)
        return 1

    chart_dirs = sorted(p for p in CHARTS_DIR.iterdir() if p.is_dir())
    if not chart_dirs:
        print(f"FAIL: no chart directories found under {CHARTS_DIR}", file=sys.stderr)
        return 1

    errors = []
    for chart_dir in chart_dirs:
        chart = chart_dir.name
        print(f"== {chart} ==")
        proc = subprocess.run(
            ["helm", "template", str(chart_dir)],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            errors.append(
                f"{chart}: `helm template` failed (exit {proc.returncode}): {proc.stderr.strip()}"
            )
            continue

        try:
            docs = load_all_documents(proc.stdout)
        except YamlSubsetError as e:
            errors.append(f"{chart}: could not parse rendered manifest (fail-closed): {e}")
            continue

        for doc in docs:
            for label, pod_spec in extract_pod_specs(doc):
                print(f"  {label}")
                check_pod_spec(chart, label, pod_spec, errors)

    if errors:
        print("\nFAIL: seccomp invariant violated:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(
        "\nOK: every container/initContainer/ephemeralContainer in every "
        "rendered chart has effective seccompProfile.type=RuntimeDefault "
        "and none are privileged."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
