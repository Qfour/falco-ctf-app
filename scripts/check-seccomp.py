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
etc.) for a lint check. The rendered manifest is read by scripts/lib/
chartparse.py, a minimal, intentionally *strict* YAML-subset reader shared
with the other chart checks (its docstring lists what it does and does not
support). Anything it cannot confidently parse raises YamlSubsetError, which
is always treated as a FAIL — never a silent skip.

FAIL-CLOSED READS
-----------------
A container's / Pod's `securityContext` is read through
chartparse.security_context(): a value that is not a block mapping (and not
`{}`) is a FAIL, and so is a container whose `name` is missing or not a
non-empty string. Neither is judged as "unset".
"""
import re
import subprocess
import sys
from pathlib import Path

# scripts/lib is not a package: put it on sys.path so `chartparse` resolves
# the same way whether this runs as `python3 scripts/check-seccomp.py` (make,
# CI) or from another cwd. No .pyc: a scripts/lib/__pycache__ is not in
# .dockerignore, so it would land in the `make test` build context and trip
# the source-hygiene scan (NUL / control bytes) after a local `make lint`.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))

from chartparse import (  # noqa: E402
    Container,
    PodShapeError,
    YamlSubsetError,
    extract_pod_specs,
    load_all_documents,
    scan_containers,
    security_context,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
CHARTS_DIR = REPO_ROOT / "charts"


def effective_seccomp_type(container: dict, pod_security_context):
    """Return (type_or_None, source_label) for the seccompProfile.type that
    actually applies to `container`, honoring k8s per-FIELD inheritance."""
    # security_context() raises PodShapeError for a securityContext that is not
    # a mapping (fail-closed: the caller reports it, it is never read as "unset").
    csc = security_context(container)
    if "seccompProfile" in csc:
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

    try:
        pod_sc = security_context(pod_spec)
    except PodShapeError:
        errors.append(f"{chart}: {label}: spec.securityContext is not a mapping")
        pod_sc = {}

    if not isinstance(pod_spec.get("containers"), list) or not pod_spec.get("containers"):
        errors.append(f"{chart}: {label}: spec.containers missing/empty (unparsable pod spec)")
        return

    for item in scan_containers(pod_spec):
        if not isinstance(item, Container):
            errors.append(f"{chart}: {label}: {item.msg}")
            continue
        group, _, c = item
        cname = c.get("name")
        if not isinstance(cname, str) or cname == "":
            errors.append(f"{chart}: {label}: {group} entry has no usable name: {cname!r}")
            continue

        try:
            csc = security_context(c)
        except PodShapeError:
            errors.append(f"{chart}: {label}: {group}[{cname}] securityContext is not a mapping")
            continue

        if str(csc.get("privileged")).strip().lower() == "true":
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


def is_library_chart(chart_dir: Path) -> bool:
    """True iff chart_dir's Chart.yaml declares `type: library` (P21 item 5:
    charts/falco-ctf-common). Library charts are not installable — `helm
    template` on one always fails with "library charts are not installable",
    regardless of content — so they carry no renderable Pod spec of their
    own and are out of scope for this check the same way a Service or
    ConfigMap-only chart would be. This is not a weakening of the invariant:
    a library chart's named templates only ever take effect once `include`d
    by a real (type: application) chart, and every such caller is still
    checked here with the library's templates expanded inline."""
    chart_yaml = chart_dir / "Chart.yaml"
    if not chart_yaml.is_file():
        return False
    return bool(re.search(r"(?m)^type:\s*library\s*$", chart_yaml.read_text()))


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
        if is_library_chart(chart_dir):
            print(f"== {chart} == (type: library — not installable, skipping)")
            continue
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
