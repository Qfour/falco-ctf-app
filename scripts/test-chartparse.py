#!/usr/bin/env python3
"""Self-test of scripts/lib/chartparse.py (the shared reader for rendered
chart manifests; scripts/check-seccomp.py imports it).

Three layers, all of which must hold (exit status is the verdict):

  1. CASES: the reader's contract on inline manifests: block and flow style,
     the three container groups, empty / absent input, shape defects, and the
     unsupported syntax that must RAISE (fail-closed) instead of being
     skipped.
  2. REAL TREE: `helm template charts/ctf-user` (default values) is read
     through the reader and the container names found must include the
     expected ones. An empty / short result is a failure of the reader, not
     "no violations".
  3. MUTANTS: the module source is mutated one defect at a time (a group
     dropped, a fail-closed raise removed, a colon rule loosened ...) and the
     SAME CASES must go red for each. A mutant that stays green means the
     cases do not pin that behavior. Each mutation must apply exactly once,
     or the test fails (a stale mutation proves nothing).

The mutants load the mutated source with importlib on purpose: they are
test inputs, not the module under test. The check scripts themselves import
`chartparse` normally.
"""
import subprocess
import sys
import types

# The mutants are exec'd from source and the real module is read as text, so
# no .pyc is wanted (see check-seccomp.py: __pycache__ is not in .dockerignore).
sys.dont_write_bytecode = True
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
LIB_PATH = HERE / "lib" / "chartparse.py"


def load_module(source: str, name: str = "chartparse_under_test"):
    mod = types.ModuleType(name)
    mod.__file__ = str(LIB_PATH)
    exec(compile(source, str(LIB_PATH), "exec"), mod.__dict__)
    return mod


# ---------------------------------------------------------------------------
# Fixtures: shapes `helm template` emits for a Pod
# ---------------------------------------------------------------------------

POD_BLOCK = """\
---
# Source: ctf-user/templates/pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: workspace
spec:
  securityContext:
    runAsNonRoot: false
    seccompProfile:
      type: RuntimeDefault
  initContainers:
    - name: plant
      image: "img:tag"
      command: ["sh", "-c", "echo hi # not a comment"]
    - name: missions-scope
      image: "img:tag"
      securityContext:
        runAsUser: 0
      args:
        - ONE
  containers:
    - name: ttyd
      image: "img:tag"
      securityContext:
        runAsUser: 1000
        seccompProfile:
          type: RuntimeDefault
      args: ["ONE"]
    - name: challenge
      image: "img:tag"
  ephemeralContainers:
    - name: dbg
      image: "img:tag"
      args: [ONE, 'TWO']
"""

DEPLOY = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
        - name: web
          image: x
"""

CRON = """\
apiVersion: batch/v1
kind: CronJob
metadata:
  name: tick
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: tick
              image: x
"""

NOT_A_POD = """\
apiVersion: v1
kind: Service
metadata:
  name: svc
spec:
  ports:
    - port: 80
"""


def pod_spec_of(m, text, index=0):
    specs = []
    for doc in m.load_all_documents(text):
        specs.extend(m.extract_pod_specs(doc))
    assert len(specs) > index, f"expected a pod spec at index {index}, found {len(specs)}"
    return specs[index][1]


def raises(m, exc_name, fn):
    exc = getattr(m, exc_name)
    try:
        fn()
    except exc:
        return
    except Exception as e:  # wrong type is a failure, say which
        raise AssertionError(f"expected {exc_name}, got {type(e).__name__}: {e}")
    raise AssertionError(f"expected {exc_name}, nothing was raised")


# ---------------------------------------------------------------------------
# CASES: (name, fn(m)) ; each raises AssertionError (or anything) on failure
# ---------------------------------------------------------------------------

def case_three_groups_named(m):
    names = m.container_names(pod_spec_of(m, POD_BLOCK))
    assert names == {
        "initContainers": {"plant", "missions-scope"},
        "containers": {"ttyd", "challenge"},
        "ephemeralContainers": {"dbg"},
    }, names


def case_group_order_is_init_then_main_then_ephemeral(m):
    got = [(c.group, c.name) for c in m.containers(pod_spec_of(m, POD_BLOCK))]
    assert got == [
        ("initContainers", "plant"),
        ("initContainers", "missions-scope"),
        ("containers", "ttyd"),
        ("containers", "challenge"),
        ("ephemeralContainers", "dbg"),
    ], got


def case_expected_name_set_is_checkable(m):
    names = m.container_names(pod_spec_of(m, POD_BLOCK))
    found = set().union(*names.values())
    expected = {"plant", "missions-scope", "ttyd", "challenge"}
    assert expected <= found, f"missing {sorted(expected - found)}"
    assert not ({"plant", "ghost"} <= found), "a name that is not there must not be found"


def case_container_spec_is_the_mapping(m):
    cs = {c.name: c.spec for c in m.containers(pod_spec_of(m, POD_BLOCK))}
    assert cs["ttyd"]["image"] == "img:tag"
    assert cs["plant"]["command"] == '["sh", "-c", "echo hi # not a comment"]'


def case_security_context_block_dict(m):
    cs = {c.name: c.spec for c in m.containers(pod_spec_of(m, POD_BLOCK))}
    sc = m.security_context(cs["ttyd"])
    assert sc["runAsUser"] == "1000", sc
    assert sc["seccompProfile"] == {"type": "RuntimeDefault"}, sc


def case_security_context_absent_is_empty_dict(m):
    cs = {c.name: c.spec for c in m.containers(pod_spec_of(m, POD_BLOCK))}
    assert m.security_context(cs["challenge"]) == {}
    assert m.security_context({"securityContext": "{}"}) == {}
    assert m.security_context({"securityContext": None}) == {}


def case_security_context_pod_level(m):
    sc = m.security_context(pod_spec_of(m, POD_BLOCK))
    assert sc["seccompProfile"] == {"type": "RuntimeDefault"}, sc


def case_security_context_rejects_non_mapping(m):
    raises(m, "PodShapeError", lambda: m.security_context({"securityContext": "nope"}))
    raises(m, "PodShapeError", lambda: m.security_context({"securityContext": "{seccompProfile: {type: Unconfined}}"}))
    raises(m, "PodShapeError", lambda: m.security_context({"securityContext": ["a"]}))


def case_block_style_list(m):
    cs = {c.name: c.spec for c in m.containers(pod_spec_of(m, POD_BLOCK))}
    assert m.as_list(cs["missions-scope"]["args"]) == ["ONE"], cs["missions-scope"]


def case_flow_style_list(m):
    cs = {c.name: c.spec for c in m.containers(pod_spec_of(m, POD_BLOCK))}
    assert m.as_list(cs["ttyd"]["args"]) == ["ONE"]
    assert m.as_list(cs["dbg"]["args"]) == ["ONE", "TWO"]


def case_flow_and_block_agree(m):
    block = m.load_all_documents("args:\n  - ONE\n  - TWO\n")[0]["args"]
    flow = m.load_all_documents('args: ["ONE", TWO]\n')[0]["args"]
    assert m.as_list(block) == m.as_list(flow) == ["ONE", "TWO"]


def case_flow_list_forms(m):
    f = m.flow_list
    assert f("[]") == []
    assert f("[ ]") == []
    assert f('["ONE"]') == ["ONE"]
    assert f("['ONE']") == ["ONE"]
    assert f("[ONE]") == ["ONE"]
    assert f("[ ONE , TWO ]") == ["ONE", "TWO"]
    assert f('["a,b", c]') == ["a,b", "c"]
    assert f("[ONE,]") == ["ONE"]


def case_flow_list_rejects_unsupported(m):
    for bad in ("[[ONE]]", "[{a: b}]", "[a, [b]]", "[a,,b]", "[,]", "ONE", "[ONE", "ONE]", '["ONE]', "{a: b}", "", '[a"b]'):
        raises(m, "YamlSubsetError", lambda b=bad: m.flow_list(b))
    raises(m, "YamlSubsetError", lambda: m.flow_list(None))
    raises(m, "YamlSubsetError", lambda: m.flow_list(["ONE"]))


def case_as_list_forms(m):
    assert m.as_list(None) == []
    assert m.as_list([]) == []
    assert m.as_list(["a", "b"]) == ["a", "b"]
    raises(m, "YamlSubsetError", lambda: m.as_list("ONE"))
    raises(m, "YamlSubsetError", lambda: m.as_list([{"a": "b"}]))
    raises(m, "YamlSubsetError", lambda: m.as_list({"a": "b"}))


def case_empty_and_absent_groups(m):
    spec = pod_spec_of(m, DEPLOY)
    assert m.container_names(spec) == {
        "initContainers": set(),
        "containers": {"web"},
        "ephemeralContainers": set(),
    }
    assert m.containers({"containers": []}) == []
    assert m.containers({}) == []
    assert m.load_all_documents("") == []
    assert m.load_all_documents("# only a comment\n\n---\n---\n") == []


def case_pod_kinds(m):
    assert m.extract_pod_specs(m.load_all_documents(NOT_A_POD)[0]) == []
    assert pod_spec_of(m, CRON)["containers"][0]["name"] == "tick"
    label, _ = [(lbl, s) for d in m.load_all_documents(DEPLOY) for lbl, s in m.extract_pod_specs(d)][0]
    assert label == "Deployment/web", label
    assert m.extract_pod_specs("not a mapping") == []


def case_multi_document_stream(m):
    docs = m.load_all_documents(POD_BLOCK + "---\n" + DEPLOY + "---\n" + NOT_A_POD)
    labels = [lbl for d in docs for lbl, _ in m.extract_pod_specs(d)]
    assert labels == ["Pod/workspace", "Deployment/web"], labels


def case_comment_handling(m):
    doc = m.load_all_documents('a: "x # y"  # tail\nb: z # tail\n# whole line\n')[0]
    assert doc == {"a": "x # y", "b": "z"}, doc


def case_colon_rule(m):
    doc = m.load_all_documents("url: http://example.test:8080/x\nk: v\n")[0]
    assert doc == {"url": "http://example.test:8080/x", "k": "v"}, doc
    # a bare scalar item that merely contains a colon is not a one-key mapping
    assert m.load_all_documents("ports:\n  - http://x:80/y\n")[0] == {"ports": ["http://x:80/y"]}


def case_shape_problems_are_reported_in_order(m):
    spec = {"initContainers": "nope", "containers": [{"name": "a"}, "str"], "ephemeralContainers": [{"image": "x"}]}
    items = m.scan_containers(spec)
    kinds = [type(i).__name__ for i in items]
    assert kinds == ["ShapeProblem", "Container", "ShapeProblem", "Container"], kinds
    assert items[0].msg == "initContainers is not a list", items[0]
    assert items[2].msg == "containers entry is not a mapping", items[2]
    assert items[3].name == "<unnamed>", items[3]


def case_strict_containers_raise_on_shape(m):
    raises(m, "PodShapeError", lambda: m.containers({"initContainers": "nope", "containers": []}))
    raises(m, "PodShapeError", lambda: m.containers({"containers": ["str"]}))
    raises(m, "PodShapeError", lambda: m.containers({"containers": [{"image": "x"}]}))  # unnamed
    raises(m, "PodShapeError", lambda: m.containers(None))
    raises(m, "PodShapeError", lambda: m.container_names("nope"))


def case_unsupported_syntax_raises(m):
    for label, text in (
        ("tab indentation", "a:\n\tb: 1\n"),
        ("block scalar", "kind: ConfigMap\ndata:\n  x: |\n    hello\n"),
        ("anchor then nested block", "a: &x\n  b: 1\n"),
        ("multi-line flow", "a: [\n  b,\n  c\n]\n"),
        ("sequence at mapping indent", "a:\n- b\n"),
        ("document not at indent 0", "  a: 1\n"),
        ("trailing deeper content", "a: 1\n  b: 2\n"),
        ("scalar followed by content", "- x\n  y: 1\n"),
    ):
        raises(m, "YamlSubsetError", lambda t=text: m.load_all_documents(t))


def case_flow_collections_stay_opaque(m):
    doc = m.load_all_documents("a: {b: 1}\nc: [x, y]\n")[0]
    assert doc == {"a": "{b: 1}", "c": "[x, y]"}, doc


def case_error_hierarchy(m):
    assert issubclass(m.PodShapeError, m.YamlSubsetError)


CASES = [(n[len("case_"):], f) for n, f in sorted(globals().items()) if n.startswith("case_")]


def run_cases(m):
    """Return [(case name, message)] for every failing case."""
    failures = []
    for name, fn in CASES:
        try:
            fn(m)
        except Exception as e:  # any exception is a failed case
            failures.append((name, f"{type(e).__name__}: {e}"))
    return failures


# ---------------------------------------------------------------------------
# MUTANTS: (name, old, new): `old` must occur exactly once in the source
# ---------------------------------------------------------------------------

MUTANTS = [
    ("remove initContainers from CONTAINER_GROUPS",
     '("initContainers", "containers", "ephemeralContainers")',
     '("containers", "ephemeralContainers")'),
    ("remove ephemeralContainers from CONTAINER_GROUPS",
     '("initContainers", "containers", "ephemeralContainers")',
     '("initContainers", "containers")'),
    ("tab in indentation no longer raises",
     'if "\\t" in code_part:',
     'if False:'),
    ("a colon without a following space splits a key",
     'content[idx + 1] == " "',
     'True'),
    ("comments are no longer stripped",
     'return line[:idx].rstrip()',
     'return line.rstrip()'),
    ("flow_list accepts nested collections",
     'elif any(ch in raw for ch in "[]{}"):',
     'elif False:'),
    ("flow_list ignores an unterminated quote",
     'if in_single or in_double:\n        raise',
     'if False:\n        raise'),
    ("flow_list keeps empty elements instead of raising",
     'if raw == "":\n            raise',
     'if False:\n            raise'),
    ("as_list reads a bare scalar as a list",
     'return flow_list(value)',
     'return [value]'),
    ("security_context takes a non-empty flow mapping as unset",
     'raise PodShapeError(f"securityContext is not a block mapping',
     'return {}  # f"securityContext is not a block mapping'),
    ("scan_containers skips a non-list group silently",
     'out.append(ShapeProblem(f"{group} is not a list"))',
     'pass'),
    ("scan_containers skips a non-mapping entry silently",
     'out.append(ShapeProblem(f"{group} entry is not a mapping"))',
     'pass'),
    ("strict containers() lets an unnamed container through",
     'if item.name == "<unnamed>":',
     'if False:'),
    ("CronJob pods are no longer found",
     'if kind == "CronJob":',
     'if False:'),
    ("a trailing unparsed block no longer raises",
     'if next_i != len(lines):',
     'if False:'),
    ("--- no longer separates documents",
     'r"(?m)^---[ \\t]*$"',
     'r"(?m)^----[ \\t]*$"'),
]


# ---------------------------------------------------------------------------
# REAL TREE
# ---------------------------------------------------------------------------

# Only the default render: a render with scenario.missions emits a `|` block
# scalar (the missions-scope script), which this reader does not support and
# raises on (pinned by the "block scalar" case above). Do not add that render
# here until the reader supports it.
REAL_RENDERS = (
    ("default values", [],
     {"initContainers": {"plant"}, "containers": {"ttyd", "ttyd-proxy", "challenge"}}),
)


def real_tree(m):
    failures = []
    for label, extra, expected in REAL_RENDERS:
        proc = subprocess.run(
            ["helm", "template", str(REPO_ROOT / "charts" / "ctf-user")] + extra,
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            failures.append(f"{label}: helm template failed (exit {proc.returncode}): {proc.stderr.strip()}")
            continue
        pods = []
        for doc in m.load_all_documents(proc.stdout):
            pods.extend(m.extract_pod_specs(doc))
        pods = [(lbl, s) for lbl, s in pods if lbl == "Pod/workspace"]
        if len(pods) != 1:
            failures.append(f"{label}: expected exactly one Pod/workspace, found {len(pods)}")
            continue
        names = m.container_names(pods[0][1])
        for group, want in expected.items():
            if not want <= names[group]:
                failures.append(f"{label}: {group} missing {sorted(want - names[group])} (found {sorted(names[group])})")
        print(f"  {label}: " + "; ".join(f"{g}={sorted(n)}" for g, n in names.items() if n))
    return failures


def main() -> int:
    source = LIB_PATH.read_text()
    problems = []

    print("== cases (real module) ==")
    m = load_module(source, "chartparse_real")
    if len(CASES) < 20:
        problems.append(f"only {len(CASES)} cases are defined (<20): the case table was truncated")
    fails = run_cases(m)
    for name, _ in CASES:
        bad = [msg for n, msg in fails if n == name]
        print(f"  {'FAIL' if bad else 'ok  '} {name}" + (f"  -> {bad[0]}" if bad else ""))
    problems += [f"case {n}: {msg}" for n, msg in fails]

    print("== real tree (charts/ctf-user via helm template) ==")
    problems += real_tree(m)

    print("== mutants (each must turn at least one case red) ==")
    if len(MUTANTS) < 3:
        problems.append("fewer than 3 mutants are defined")
    for name, old, new in MUTANTS:
        count = source.count(old)
        if count != 1:
            problems.append(f"mutant '{name}': pattern occurs {count} times (want exactly 1), the mutation is stale")
            print(f"  STALE {name}")
            continue
        try:
            mm = load_module(source.replace(old, new, 1), "chartparse_mutant")
        except Exception as e:  # a mutant that does not even import is a broken mutant
            problems.append(f"mutant '{name}': mutated module failed to load: {type(e).__name__}: {e}")
            print(f"  BROKEN {name}")
            continue
        caught = run_cases(mm)
        if not caught:
            problems.append(f"mutant '{name}' survived: no case went red")
            print(f"  SURVIVED {name}")
        else:
            print(f"  killed   {name}  ({len(caught)} case(s): {', '.join(n for n, _ in caught[:3])}{' ...' if len(caught) > 3 else ''})")

    if problems:
        print("\nFAIL: scripts/lib/chartparse.py self-test:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(f"\nOK: {len(CASES)} cases, real tree, {len(MUTANTS)} mutants all killed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
