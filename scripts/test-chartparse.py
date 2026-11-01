#!/usr/bin/env python3
"""Self-test of scripts/lib/chartparse.py (the shared reader for rendered
chart manifests; scripts/check-seccomp.py imports it).

Three layers, all of which must hold (exit status is the verdict):

  1. CASES: the reader's contract on inline manifests: block and flow style,
     the three container groups, empty / absent input, shape defects, and the
     unsupported syntax that must RAISE (fail-closed) instead of being
     skipped.
  2. REAL TREE: `helm template charts/ctf-user` (default values) is read
     through the reader (also with scenario.missions, whose render carries a
     block scalar) and the container names found must include the expected
     ones. An empty / short result is a failure of the reader, not
     "no violations".
  3. MUTANTS: the module source is mutated one defect at a time (a group
     dropped, a fail-closed raise removed, a colon rule loosened ...) and the
     SAME CASES must go red for each. A mutant that stays green means the
     cases do not pin that behavior. Each mutation must apply exactly once,
     or the test fails (a stale mutation proves nothing).

A fourth layer pins the seccomp decision itself (`check_pod_spec` in
scripts/check-seccomp.py): synthetic Pods are read through the shared reader and
judged, then check-seccomp.py is mutated branch by branch and the same cases must go
red.

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
SECCOMP_PATH = HERE / "check-seccomp.py"


def load_module(source: str, name: str = "chartparse_under_test", path: Path = LIB_PATH):
    mod = types.ModuleType(name)
    mod.__file__ = str(path)
    exec(compile(source, str(path), "exec"), mod.__dict__)
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


def case_flow_list_refuses_escapes_and_adjacent_quotes(m):
    for bad in ('["a\\"b"]', '["a""b"]', "['a''b']", '["a\\nb"]', "['a\\b']"):
        raises(m, "YamlSubsetError", lambda b=bad: m.flow_list(b))
    assert m.flow_list("['a\"b']") == ['a"b']  # the other quote char is plain text


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
    raises(m, "PodShapeError", lambda: m.containers({"containers": [{"name": ""}]}))
    raises(m, "PodShapeError", lambda: m.containers({"containers": [{"name": None}]}))
    raises(m, "PodShapeError", lambda: m.containers({"containers": [{"name": ["a"]}]}))
    raises(m, "PodShapeError", lambda: m.containers(None))
    raises(m, "PodShapeError", lambda: m.container_names("nope"))


def case_unsupported_syntax_raises(m):
    for label, text in (
        ("tab indentation", "a:\n\tb: 1\n"),
        ("block scalar, unsupported chomping", "kind: ConfigMap\ndata:\n  x: |+-\n    hello\n"),
        ("block scalar, indentation indicator 0", "x: |0\n  hello\n"),
        ("block scalar, indentation indicator 10", "x: |10\n  hello\n"),
        ("block scalar, header with trailing junk", "x: >foo\n  hello\n"),
        ("block scalar, a line indented less than the first", "x: |\n    hello\n  bye\ny: 1\n"),
        ("block scalar, tab where indentation is", "x: |\n\thello\n"),
        ("block scalar, header with no parent", "|\n  hello\n"),
        ("anchor then nested block", "a: &x\n  b: 1\n"),
        ("multi-line flow", "a: [\n  b,\n  c\n]\n"),
        ("sequence at mapping indent", "a:\n- b\n"),
        ("document not at indent 0", "  a: 1\n"),
        ("trailing deeper content", "a: 1\n  b: 2\n"),
        ("scalar followed by content", "- x\n  y: 1\n"),
    ):
        raises(m, "YamlSubsetError", lambda t=text: m.load_all_documents(t))


def case_block_scalar_literal_clip(m):
    doc = m.load_all_documents("a:\n  b: |\n    l1\n    l2\n  c: d\n")[0]
    assert doc == {"a": {"b": "l1\nl2\n", "c": "d"}}, doc


def case_block_scalar_literal_strip_and_keep(m):
    assert m.load_all_documents("a: |-\n  x\n  y\n\n\nb: 1\n")[0] == {"a": "x\ny", "b": "1"}
    assert m.load_all_documents("a: |+\n  x\n\n\nb: 1\n")[0] == {"a": "x\n\n\n", "b": "1"}
    assert m.load_all_documents("a: |\n  x\n\n\nb: 1\n")[0] == {"a": "x\n", "b": "1"}  # clip drops trailing blanks


def case_block_scalar_folded(m):
    doc = m.load_all_documents("a: >\n  one\n  two\n\n  three\n    more\n  four\nb: 1\n")[0]
    assert doc == {"a": "one two\nthree\n  more\nfour\n", "b": "1"}, doc
    assert m.load_all_documents("a: >-\n  one\n  two\nb: 1\n")[0] == {"a": "one two", "b": "1"}
    assert m.load_all_documents("a: >+\n  one\n\nb: 1\n")[0] == {"a": "one\n\n", "b": "1"}


def case_block_scalar_indent_indicator(m):
    # the indicator is relative to the parent key's column: key at 0, |2 -> content at column 2
    doc = m.load_all_documents("a: |2\n    x\n   y\nb: 1\n")[0]
    assert doc == {"a": "  x\n y\n", "b": "1"}, doc
    # without it the first line sets the indent, so leading spaces would be lost
    assert m.load_all_documents("a: |\n    x\n    y\n")[0] == {"a": "x\ny\n"}
    assert m.load_all_documents("a: |1-\n  x\n")[0] == {"a": " x"}


def case_block_scalar_body_is_verbatim(m):
    body = "# not a comment\nk: v\n- item\nhttp://x:80/y\n  indented: more\n---\n"
    text = "a: |\n" + "".join("  " + ln + "\n" for ln in body.splitlines()) + "b: 2 # real comment\n"
    doc = m.load_all_documents(text)
    assert doc == [{"a": body, "b": "2"}], doc


def case_block_scalar_followed_by_keys_and_dedent(m):
    text = "top:\n  inner:\n    s: |\n      text\n    t: u\n  other: v\nlast: w\n"
    assert m.load_all_documents(text)[0] == {"top": {"inner": {"s": "text\n", "t": "u"}, "other": "v"}, "last": "w"}


def case_block_scalar_in_sequences(m):
    doc = m.load_all_documents("c:\n  - sh\n  - -c\n  - |\n    echo hi\n    ls\n  - tail\n")[0]
    assert doc == {"c": ["sh", "-c", "echo hi\nls\n", "tail"]}, doc
    doc = m.load_all_documents("c:\n  - name: x\n    s: |\n      body: 1\n    t: u\n  - name: y\n")[0]
    assert doc == {"c": [{"name": "x", "s": "body: 1\n", "t": "u"}, {"name": "y"}]}, doc
    assert m.load_all_documents("c:\n  - |\n    only\n")[0] == {"c": ["only\n"]}


def case_block_scalar_empty_and_header_comment(m):
    assert m.load_all_documents("a: |\nb: 1\n")[0] == {"a": "", "b": "1"}
    assert m.load_all_documents("a: |\n")[0] == {"a": ""}
    assert m.load_all_documents("a: |+\n\n\nb: 1\n")[0] == {"a": "\n\n", "b": "1"}
    assert m.load_all_documents("a: | # why\n  x\n")[0] == {"a": "x\n"}


def case_block_scalar_in_a_container_command(m):
    text = pod_text(
        "  containers:\n    - name: a\n      command:\n        - sh\n        - -c\n        - |\n"
        "          set -eu\n          mkdir -p /x # kept\n      image: i\n"
    )
    c = m.containers(pod_spec_of(m, text))
    assert [x.name for x in c] == ["a"], c
    assert c[0].spec["command"] == ["sh", "-c", "set -eu\nmkdir -p /x # kept\n"], c[0].spec
    assert c[0].spec["image"] == "i"


def case_flow_collections_stay_opaque(m):
    doc = m.load_all_documents("a: {b: 1}\nc: [x, y]\n")[0]
    assert doc == {"a": "{b: 1}", "c": "[x, y]"}, doc


def case_error_hierarchy(m):
    assert issubclass(m.PodShapeError, m.YamlSubsetError)


CASES = [(n[len("case_"):], f) for n, f in sorted(globals().items()) if n.startswith("case_")]


# ---------------------------------------------------------------------------
# SECCOMP CASES: the decision in scripts/check-seccomp.py (`check_pod_spec`).
# Synthetic Pods go through load_all_documents -> extract_pod_specs ->
# check_pod_spec. `s` is the check-seccomp module (real or mutated).
# ---------------------------------------------------------------------------

def pod_text(body: str) -> str:
    return "kind: Pod\nmetadata:\n  name: p\nspec:\n" + body


POD_SC_OK = "  securityContext:\n    seccompProfile:\n      type: RuntimeDefault\n"


def judge(s, text, index=0):
    """Return (errors, stdout) of check_pod_spec on the index-th pod in text."""
    import contextlib
    import io

    specs = []
    for d in s.load_all_documents(text):
        specs.extend(s.extract_pod_specs(d))
    assert len(specs) > index, f"no pod spec at index {index}"
    errors = []
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        s.check_pod_spec("chart", specs[index][0], specs[index][1], errors)
    return errors, buf.getvalue()


def want_one_error(errors, *needles):
    assert len(errors) == 1, errors
    for n in needles:
        assert n in errors[0], (n, errors[0])


def seccomp_case_all_runtime_default_is_clean(s):
    text = pod_text(POD_SC_OK + "  containers:\n    - name: a\n      image: x\n")
    errors, out = judge(s, text)
    assert errors == [], errors
    assert "ok: containers[a] seccompProfile.type=RuntimeDefault (source: pod (inherited))" in out, out


def seccomp_case_container_level_runtime_default_without_pod_level(s):
    text = pod_text(
        "  containers:\n    - name: a\n      securityContext:\n        seccompProfile:\n          type: RuntimeDefault\n"
    )
    errors, out = judge(s, text)
    assert errors == [], errors
    assert "(source: container)" in out, out


def seccomp_case_no_seccomp_at_either_level(s):
    errors, _ = judge(s, pod_text("  containers:\n    - name: a\n      image: x\n"))
    want_one_error(errors, "containers[a]", "None", "none set at either level")


def seccomp_case_container_unconfined_overrides_pod_level(s):
    text = pod_text(
        POD_SC_OK
        + "  containers:\n    - name: a\n      securityContext:\n        seccompProfile:\n          type: Unconfined\n"
    )
    errors, _ = judge(s, text)
    want_one_error(errors, "containers[a]", "Unconfined", "source: container")


def seccomp_case_pod_level_unconfined_is_inherited(s):
    text = pod_text(
        "  securityContext:\n    seccompProfile:\n      type: Unconfined\n  containers:\n    - name: a\n      image: x\n"
    )
    errors, _ = judge(s, text)
    want_one_error(errors, "containers[a]", "Unconfined", "pod (inherited)")


def seccomp_case_malformed_container_seccomp_profile(s):
    text = pod_text(
        POD_SC_OK + "  containers:\n    - name: a\n      securityContext:\n        seccompProfile: Unconfined\n"
    )
    errors, _ = judge(s, text)
    want_one_error(errors, "containers[a]", "malformed seccompProfile")


def seccomp_case_privileged_true_fails_even_with_runtime_default(s):
    text = pod_text(
        POD_SC_OK + "  containers:\n    - name: a\n      securityContext:\n        privileged: true\n"
    )
    errors, out = judge(s, text)
    want_one_error(errors, "containers[a]", "privileged: true")
    assert "ok:" not in out, out


def seccomp_case_privileged_is_matched_case_insensitively(s):
    for v in ('"True"', "TRUE"):
        text = pod_text(
            POD_SC_OK + "  containers:\n    - name: a\n      securityContext:\n        privileged: " + v + "\n"
        )
        errors, _ = judge(s, text)
        want_one_error(errors, "privileged: true")
    errors, _ = judge(
        s, pod_text(POD_SC_OK + "  containers:\n    - name: a\n      securityContext:\n        privileged: false\n")
    )
    assert errors == [], errors


def seccomp_case_containers_not_a_list(s):
    errors, _ = judge(s, pod_text(POD_SC_OK + "  containers: nope\n"))
    want_one_error(errors, "spec.containers missing/empty")


def seccomp_case_containers_missing_or_empty(s):
    errors, _ = judge(s, pod_text(POD_SC_OK + "  initContainers:\n    - name: i\n"))
    want_one_error(errors, "spec.containers missing/empty")
    errors, _ = judge(s, pod_text(POD_SC_OK + "  containers: []\n"))
    want_one_error(errors, "spec.containers missing/empty")


def seccomp_case_other_group_not_a_list(s):
    text = pod_text(POD_SC_OK + "  initContainers: nope\n  containers:\n    - name: a\n      image: x\n")
    errors, out = judge(s, text)
    want_one_error(errors, "initContainers is not a list")
    assert "ok: containers[a]" in out, out  # the walk continues past the defect


def seccomp_case_entry_not_a_mapping(s):
    text = pod_text(POD_SC_OK + "  containers:\n    - name: a\n      image: x\n    - nope\n")
    errors, _ = judge(s, text)
    want_one_error(errors, "containers entry is not a mapping")


def seccomp_case_init_container_violation(s):
    text = pod_text(
        POD_SC_OK
        + "  initContainers:\n    - name: i\n      securityContext:\n        seccompProfile:\n          type: Unconfined\n"
        + "  containers:\n    - name: a\n      image: x\n"
    )
    errors, out = judge(s, text)
    want_one_error(errors, "initContainers[i]", "Unconfined")
    assert "ok: containers[a]" in out, out


def seccomp_case_ephemeral_container_violation(s):
    text = pod_text(
        POD_SC_OK
        + "  containers:\n    - name: a\n      image: x\n"
        + "  ephemeralContainers:\n    - name: e\n      securityContext:\n        privileged: true\n"
    )
    errors, _ = judge(s, text)
    want_one_error(errors, "ephemeralContainers[e]", "privileged: true")


def seccomp_case_every_violation_is_reported_in_order(s):
    text = pod_text(
        "  initContainers:\n    - name: i\n      image: x\n"
        "  containers:\n    - name: a\n      image: x\n"
        "  ephemeralContainers:\n    - name: e\n      image: x\n"
    )
    errors, _ = judge(s, text)
    assert len(errors) == 3, errors
    assert "initContainers[i]" in errors[0] and "containers[a]" in errors[1] and "ephemeralContainers[e]" in errors[2], errors


def seccomp_case_pod_spec_missing_or_security_context_not_a_mapping(s):
    errors = []
    s.check_pod_spec("chart", "Pod/p", None, errors)
    want_one_error(errors, "pod spec missing or unparsable")
    errors, _ = judge(s, pod_text("  securityContext: nope\n  containers:\n    - name: a\n      image: x\n"))
    assert any("spec.securityContext is not a mapping" in e for e in errors), errors
    assert any("containers[a]" in e for e in errors), errors  # falls back to "no pod level", still judged


def seccomp_case_container_level_ok_does_not_hide_a_sibling(s):
    text = pod_text(
        POD_SC_OK
        + "  containers:\n    - name: a\n      securityContext:\n        seccompProfile:\n          type: RuntimeDefault\n"
        + "    - name: b\n      securityContext:\n        seccompProfile:\n          type: Localhost\n"
    )
    errors, _ = judge(s, text)
    want_one_error(errors, "containers[b]", "Localhost")


SECCOMP_CASES = [(n[len("seccomp_case_"):], f) for n, f in sorted(globals().items()) if n.startswith("seccomp_case_")]


def run_cases(m, cases=None):
    """Return [(case name, message)] for every failing case."""
    failures = []
    for name, fn in (CASES if cases is None else cases):
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
     'if not isinstance(item.spec.get("name"), str) or item.spec["name"] == "":',
     'if False:'),
    ("strict containers() accepts an empty name",
     'or item.spec["name"] == "":',
     ':'),
    ("flow_list accepts an escaped or adjacent quote",
     'if quote in raw or "\\\\" in raw:',
     'if False:'),
    ("block scalar: strip chomping is ignored",
     'if chomp == "-":\n        return text',
     'if False:\n        return text'),
    ("block scalar: keep chomping drops the trailing blanks",
     'return text + "\\n" + "\\n" * trailing',
     'return text + "\\n"'),
    ("block scalar: folded lines are joined with a newline",
     'out += " "',
     'out += "\\n"'),
    ("block scalar: the body swallows the following keys",
     'if lead <= n:\n                break',
     'if False:\n                break'),
    ("block scalar: the indentation indicator is ignored",
     'block_indent = n + digit if digit else None',
     'block_indent = None'),
    ("block scalar: an unsupported header is accepted",
     'if m is None:\n        raise',
     'if False:\n        raise'),
    ("block scalar: a less-indented body line no longer raises",
     'if lead < block_indent:',
     'if False:'),
    ("block scalar: a sequence item header is not recognised",
     'if _BLOCK_HEADER.fullmatch(content):',
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


# Mutants of scripts/check-seccomp.py (each `old` must occur exactly once).
SECCOMP_MUTANTS = [
    ("a non-RuntimeDefault type is accepted",
     'if sc_type != "RuntimeDefault":',
     'if False:'),
    ("privileged: true is no longer an error",
     'str(csc.get("privileged")).strip().lower() == "true"',
     'str(csc.get("privileged")).strip().lower() == "never"'),
    ("privileged is matched case-sensitively",
     'str(csc.get("privileged")).strip().lower() == "true"',
     'str(csc.get("privileged")).strip() == "true"'),
    ("a privileged container is also judged as non-privileged",
     '            )\n            continue\n\n        sc_type',
     '            )\n\n        sc_type'),
    ("an empty / non-list containers is not an error",
     'if not isinstance(pod_spec.get("containers"), list) or not pod_spec.get("containers"):',
     'if False:'),
    ("a shape problem from the walk is dropped",
     'errors.append(f"{chart}: {label}: {item.msg}")',
     'pass'),
    ("the container-level seccompProfile is ignored",
     'if isinstance(csc, dict) and "seccompProfile" in csc:',
     'if False:'),
    ("the Pod-level profile is trusted without reading its type",
     'return sp.get("type"), "pod (inherited)"',
     'return "RuntimeDefault", "pod (inherited)"'),
    ("a malformed container seccompProfile is read as fine",
     'return None, "container (malformed seccompProfile)"',
     'return "RuntimeDefault", "container (malformed seccompProfile)"'),
    ("a Pod spec that is not a mapping is not an error",
     'errors.append(f"{chart}: {label}: pod spec missing or unparsable")',
     'pass'),
    ("a malformed Pod securityContext is not reported",
     'errors.append(f"{chart}: {label}: spec.securityContext is not a mapping")',
     'pass'),
]


# ---------------------------------------------------------------------------
# REAL TREE
# ---------------------------------------------------------------------------

# The second render emits the missions-scope initContainer, whose `sh -c` script
# is a `|` block scalar: this is the render the block scalar support is for.
REAL_RENDERS = (
    ("default values", [],
     {"initContainers": {"plant"}, "containers": {"ttyd", "ttyd-proxy", "challenge"}}),
    ("with scenario.missions", ["--set-json", 'scenario.missions=["01-a"]'],
     {"initContainers": {"plant", "missions-scope"}, "containers": {"ttyd", "ttyd-proxy", "challenge"}}),
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


def run_mutants(source, mutants, cases, path):
    """Apply each mutation once, run `cases` on the result, and return the
    problems (stale pattern, mutant that does not load, mutant that survives)."""
    problems = []
    for name, old, new in mutants:
        count = source.count(old)
        if count != 1:
            problems.append(f"mutant '{name}': pattern occurs {count} times (want exactly 1), the mutation is stale")
            print(f"  STALE {name}")
            continue
        try:
            mm = load_module(source.replace(old, new, 1), "mutant_under_test", path)
        except Exception as e:  # a mutant that does not even import is a broken mutant
            problems.append(f"mutant '{name}': mutated module failed to load: {type(e).__name__}: {e}")
            print(f"  BROKEN {name}")
            continue
        caught = run_cases(mm, cases)
        if not caught:
            problems.append(f"mutant '{name}' survived: no case went red")
            print(f"  SURVIVED {name}")
        else:
            print(f"  killed   {name}  ({len(caught)} case(s): {', '.join(n for n, _ in caught[:3])}{' ...' if len(caught) > 3 else ''})")
    return problems


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

    print("== seccomp decision (scripts/check-seccomp.py, check_pod_spec) ==")
    sec_source = SECCOMP_PATH.read_text()
    s = load_module(sec_source, "check_seccomp_real", SECCOMP_PATH)
    if len(SECCOMP_CASES) < 12:
        problems.append(f"only {len(SECCOMP_CASES)} seccomp cases are defined (<12): the case table was truncated")
    sec_fails = run_cases(s, SECCOMP_CASES)
    for name, _ in SECCOMP_CASES:
        bad = [msg for n, msg in sec_fails if n == name]
        print(f"  {'FAIL' if bad else 'ok  '} {name}" + (f"  -> {bad[0]}" if bad else ""))
    problems += [f"seccomp case {n}: {msg}" for n, msg in sec_fails]

    print("== mutants of chartparse.py (each must turn at least one case red) ==")
    if len(MUTANTS) < 3:
        problems.append("fewer than 3 mutants are defined")
    problems += run_mutants(source, MUTANTS, CASES, LIB_PATH)

    print("== mutants of check-seccomp.py (each must turn at least one seccomp case red) ==")
    if len(SECCOMP_MUTANTS) < 3:
        problems.append("fewer than 3 seccomp mutants are defined")
    problems += run_mutants(sec_source, SECCOMP_MUTANTS, SECCOMP_CASES, SECCOMP_PATH)

    if problems:
        print("\nFAIL: scripts/lib/chartparse.py self-test:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1
    print(
        f"\nOK: {len(CASES)} cases, real tree, {len(MUTANTS)} chartparse mutants killed; "
        f"{len(SECCOMP_CASES)} seccomp cases, {len(SECCOMP_MUTANTS)} seccomp mutants killed."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
