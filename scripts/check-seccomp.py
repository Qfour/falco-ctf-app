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

EXTRA RENDERS (scenario.missions)
----------------------------------
`charts/ctf-user` renders a `missions-scope` initContainer only when
`scenario.missions` is non-empty, so a render with default values never contains
it. After the default-values pass over every chart, ctf-user is therefore
rendered again (a) with a synthetic `scenario.missions=["01-a"]` and (b) once
per `challenges/values-scenario-*.yaml` (passed with `-f` only: challengeId and
username do not change the container set or any securityContext, so they are not
passed; the source of the list of renders is currently that glob), and
`check_pod_spec` is applied to those Pods too. Each extra render must contain `initContainers[missions-scope]`: a render
that lacks it (the template stopped emitting it, or a values file lost
`scenario.missions`) is a FAIL, not an empty pass, and so is a `helm template`
failure or an empty `values-scenario-*.yaml` glob. Other charts are rendered
with default values only. The lines of the default-values pass are unchanged;
the extra renders follow them.

FAIL-CLOSED READS
-----------------
A container's / Pod's `securityContext` is read through
chartparse.security_context(): a value that is not a block mapping (and not
`{}`) is a FAIL, and so is a container whose `name` is missing or not a
non-empty string. Neither is judged as "unset". An explicit `null` / `~`
securityContext is also not a mapping (omit the key instead). `privileged` is
judged as a YAML 1.1 boolean: a true (true/yes/on/y) or any value that is not a
clear false (false/no/off/n) is a FAIL.
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
CHALLENGES_DIR = REPO_ROOT / "challenges"

# The renders of charts/ctf-user that carry scenario.missions (see the docstring).
# `scenario.missions` renders a `missions-scope` initContainer; every extra render
# must contain it, so an extraction that lost it is an error and not a pass.
SYNTHETIC_MISSIONS = ["--set-json", 'scenario.missions=["01-a"]']
EXTRA_REQUIRED = (("initContainers", "missions-scope"),)


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


# YAML 1.1 booleans (what a Kubernetes API server accepts for a bool field,
# case-insensitively). Anything that is not one of these is not a clear false.
PRIVILEGED_TRUE = {"true", "yes", "on", "y"}
PRIVILEGED_FALSE = {"false", "no", "off", "n"}


def privileged_state(csc: dict) -> str:
    """"false" only when `privileged` is absent or a clear false; "true" for a
    clear true; "unclear" for anything else (fail-closed: a value this check
    cannot place is an error, not "not privileged")."""
    if "privileged" not in csc:
        return "false"
    value = csc["privileged"]
    word = value.strip().lower() if isinstance(value, str) else None
    if word in PRIVILEGED_TRUE:
        return "true"
    if word in PRIVILEGED_FALSE:
        return "false"
    return "unclear"


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
        group, cname, c = item

        try:
            csc = security_context(c)
        except PodShapeError:
            errors.append(f"{chart}: {label}: {group}[{cname}] securityContext is not a mapping")
            continue

        priv = privileged_state(csc)
        if priv != "false":
            if priv == "true":
                problem = "sets privileged: true (disables seccomp regardless of profile)"
            else:
                problem = (
                    f"has privileged={csc.get('privileged')!r}, which is not a clear false "
                    "(privileged disables seccomp regardless of profile)"
                )
            errors.append(
                f"{chart}: {label}: {group}[{cname}] {problem}"
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


def check_render(chart, chart_dir, errors, extra_args=(), desc=None, require=()):
    """`helm template chart_dir *extra_args`, then `check_pod_spec` on every Pod
    spec of the output. `desc` names an extra render in the error prefix (the
    default-values pass keeps the bare chart name). Every (group, name) in
    `require` must be among the containers found in the rendered Pod specs.
    Returns the set of (group, name) found (empty when the render failed)."""
    where = chart if desc is None else f"{chart} ({desc})"
    proc = subprocess.run(
        ["helm", "template", str(chart_dir), *extra_args],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        errors.append(
            f"{where}: `helm template` failed (exit {proc.returncode}): {proc.stderr.strip()}"
        )
        return set()

    try:
        docs = load_all_documents(proc.stdout)
    except YamlSubsetError as e:
        errors.append(f"{where}: could not parse rendered manifest (fail-closed): {e}")
        return set()

    found = set()
    for doc in docs:
        for label, pod_spec in extract_pod_specs(doc):
            print(f"  {label}")
            check_pod_spec(where, label, pod_spec, errors)
            if isinstance(pod_spec, dict):
                found.update((item.group, item.name) for item in scan_containers(pod_spec) if isinstance(item, Container))
    for group, name in require:
        if (group, name) not in found:
            errors.append(
                f"{where}: {group}[{name}] not found in the rendered Pod specs "
                "(the extra render would not cover it)"
            )
    return found


def extra_render_specs(challenges_dir=CHALLENGES_DIR):
    """([(description, helm args)], [problem]) for the extra ctf-user renders:
    the synthetic scenario.missions, then one per challenges/values-scenario-*.yaml.
    An empty glob is a problem (a check over zero files would pass silently)."""
    specs = [('scenario.missions=["01-a"]', list(SYNTHETIC_MISSIONS))]
    problems = []
    files = sorted(Path(challenges_dir).glob("values-scenario-*.yaml"))
    if not files:
        problems.append(f"no values-scenario-*.yaml found under {challenges_dir}")
    for f in files:
        specs.append((f"-f {f.name}", ["-f", str(f)]))
    return specs, problems


def check_extra_renders(errors, challenges_dir=CHALLENGES_DIR):
    """Render charts/ctf-user with scenario.missions set and judge those Pods
    (the `missions-scope` initContainer exists only in these renders)."""
    chart_dir = CHARTS_DIR / "ctf-user"
    specs, problems = extra_render_specs(challenges_dir)
    errors.extend(f"ctf-user: {p}" for p in problems)
    for desc, args in specs:
        print(f"== ctf-user ({desc}) ==")
        check_render("ctf-user", chart_dir, errors, args, desc, EXTRA_REQUIRED)


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
        check_render(chart, chart_dir, errors)

    check_extra_renders(errors)

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
