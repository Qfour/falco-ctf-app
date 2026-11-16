"""ADR-0056 V2 / D13: the answers table's Secret reaches the scoreboard container only.

Reads a rendered manifest (`helm template charts/scoreboard` with
`answersSecret.enabled` and a SENTINEL secret name and key) with the shared reader
scripts/lib/chartparse.py, and checks the STRUCTURE, not the strings:

  * the sentinel secret name appears exactly once in the whole render, and that
    place is a `volumes[]` entry of a Deployment with `secret.secretName` equal to
    it (so no other document, no other field such as an env `secretKeyRef` or a
    projected source, names the Secret);
  * the volumeMounts that name that volume, over `containers`, `initContainers` and
    `ephemeralContainers` of that pod, are exactly one, in the container named
    `scoreboard` (group `containers`), with `readOnly: true`, at /etc/ctf-answers;
  * the sentinel key appears exactly once in the whole render, as the value of the
    one `ANSWERS_FILE` env of the `scoreboard` container, under that mountPath.

A grep that counts strings does not tie a mount to a container: a second container
or an initContainer that mounts the same volume at another path would pass it. The
reader raises on anything it cannot read, and that is a FAIL here (never "nothing
found").

Usage:
  python3 -I scripts/check-answers-secret.py check --sentinel-name N --sentinel-key K < render
  python3 -I scripts/check-answers-secret.py --selftest      # no helm needed

`--selftest` feeds the check a hand-written good render, which must pass, and a set
of deliberately wrong ones (a second container or an initContainer that mounts the
volume, no readOnly, two mounts, the sentinel in another document, ...), each of
which must be refused: the check is shown to be able to fail.

Exit status: 0 iff every check held.
"""
import argparse
import sys
from pathlib import Path

# scripts/lib is not a package; no .pyc (see check-seccomp.py for why).
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))

from chartparse import (  # noqa: E402
    ShapeProblem,
    YamlSubsetError,
    extract_pod_specs,
    load_all_documents,
    scan_containers,
)

CONTAINER = "scoreboard"
MOUNT_PATH = "/etc/ctf-answers"
ENV_NAME = "ANSWERS_FILE"


def _strings(node):
    """Every str in node, mapping keys included."""
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str):
                yield k
            yield from _strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v)
    elif isinstance(node, str):
        yield node


def _kind(doc):
    return doc.get("kind") if isinstance(doc, dict) and isinstance(doc.get("kind"), str) else "<no kind>"


def check_render(text, secret_name, key):
    """Return the list of problems of one render (empty = every check held)."""
    try:
        docs = load_all_documents(text)
    except YamlSubsetError as e:
        return [f"the render is not readable (fail-closed): {e}"]
    if not docs:
        return ["the render has no document"]
    problems = []

    # 1. each sentinel appears exactly once in the whole render.
    for label, needle in (("secret name", secret_name), ("key", key)):
        where = []
        for d in docs:
            where += [_kind(d)] * sum(1 for s in _strings(d) if needle in s)
        if len(where) != 1:
            problems.append(
                f"the sentinel {label} appears {len(where)} time(s) ({', '.join(where) or 'nowhere'}), want exactly 1"
            )

    # 2. the volume that holds the Secret: exactly one, in a Deployment.
    holders = []  # (pod label, volume name, pod spec)
    pods = []  # (pod label, pod spec)
    for d in docs:
        for label, spec in extract_pod_specs(d):
            if not isinstance(spec, dict):
                problems.append(f"{label}: the pod spec is not a mapping")
                continue
            pods.append((label, spec))
            vols = spec.get("volumes")
            if vols is None:
                continue
            if not isinstance(vols, list):
                problems.append(f"{label}: volumes is not a list")
                continue
            for v in vols:
                sec = v.get("secret") if isinstance(v, dict) else None
                if isinstance(sec, dict) and sec.get("secretName") == secret_name:
                    holders.append((label, v.get("name"), spec))
    if len(holders) != 1:
        problems.append(f"{len(holders)} volume(s) hold the sentinel Secret, want exactly 1")
        return problems
    label, vol, spec = holders[0]
    if not label.startswith("Deployment/"):
        problems.append(f"the Secret's volume is in {label}, want a Deployment")
    if not isinstance(vol, str) or vol == "":
        problems.append("the Secret's volume has no usable name")
        return problems

    # 3. who mounts that volume: every container group of that pod.
    refs = []  # (group, container name, mount)
    envs = []  # (group, container name, env entry)
    for item in scan_containers(spec):
        if isinstance(item, ShapeProblem):
            problems.append(f"{label}: {item.msg}")
            continue
        mounts = item.spec.get("volumeMounts")
        if mounts is not None and not isinstance(mounts, list):
            problems.append(f"{label}: {item.group}/{item.name}: volumeMounts is not a list")
            continue
        for m in mounts or []:
            if isinstance(m, dict) and m.get("name") == vol:
                refs.append((item.group, item.name, m))
        env = item.spec.get("env")
        if env is not None and not isinstance(env, list):
            problems.append(f"{label}: {item.group}/{item.name}: env is not a list")
            continue
        for e in env or []:
            if isinstance(e, dict) and e.get("name") == ENV_NAME:
                envs.append((item.group, item.name, e))
    where = ", ".join(f"{g}/{n}" for g, n, _ in refs) or "nowhere"
    if len(refs) != 1:
        problems.append(f"the volume {vol!r} is mounted {len(refs)} time(s) ({where}), want exactly 1")
    else:
        group, name, m = refs[0]
        if (group, name) != ("containers", CONTAINER):
            problems.append(f"the volume {vol!r} is mounted by {group}/{name}, want containers/{CONTAINER}")
        if m.get("readOnly") != "true":
            problems.append(f"the mount in {group}/{name} is not readOnly: true (readOnly is {m.get('readOnly')!r})")
        if m.get("mountPath") != MOUNT_PATH:
            problems.append(f"the mount in {group}/{name} is at {m.get('mountPath')!r}, want {MOUNT_PATH}")

    # 4. ANSWERS_FILE: one env, in the scoreboard container, under that mountPath.
    if len(envs) != 1:
        problems.append(f"{ENV_NAME} is set {len(envs)} time(s), want exactly 1")
    else:
        group, name, e = envs[0]
        if (group, name) != ("containers", CONTAINER):
            problems.append(f"{ENV_NAME} is set in {group}/{name}, want containers/{CONTAINER}")
        if e.get("value") != f"{MOUNT_PATH}/{key}":
            problems.append(f"{ENV_NAME} is not {MOUNT_PATH}/<the key>")
    return problems


# ---------------------------------------------------------------------------
# Self-test: a good render, and renders with one deliberate defect each.
# ---------------------------------------------------------------------------

_NAME = "selftest-answers-secret"
_KEY = "selftest-answers-key.tsv"

_GOOD = """---
# Source: scoreboard/templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: scoreboard
  namespace: scoreboard
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: scoreboard
          image: "example.invalid/scoreboard:1"
          env:
            - name: SCOREBOARD_DB
              value: "/var/lib/scoreboard/scoreboard.db"
            - name: ANSWERS_FILE
              value: /etc/ctf-answers/@KEY@
          volumeMounts:
            - name: data
              mountPath: /var/lib/scoreboard
            - name: answers
              mountPath: /etc/ctf-answers
              readOnly: true
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: scoreboard-data
        - name: answers
          secret:
            secretName: @NAME@
---
# Source: scoreboard/templates/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: scoreboard
spec:
  ports:
    - name: http
      port: 8000
"""

_MOUNT = "            - name: answers\n              mountPath: /etc/ctf-answers\n              readOnly: true\n"
_ENV = "            - name: ANSWERS_FILE\n              value: /etc/ctf-answers/@KEY@\n"
_SIDE = "        - name: {n}\n          volumeMounts:\n            - name: answers\n              mountPath: /elsewhere\n              readOnly: true\n"


def _swap(old, new):
    def f(t):
        assert old in t, f"selftest bug: {old!r} is not in the good render"
        return t.replace(old, new, 1)

    return f


def _append(extra):
    return lambda t: t + extra


_MUTANTS = [
    ("a second container mounts the same volume", _swap("      volumes:\n", _SIDE.format(n="sidecar") + "      volumes:\n")),
    ("an initContainer mounts the same volume", _swap("      containers:\n", "      initContainers:\n" + _SIDE.format(n="init") + "      containers:\n")),
    ("an ephemeralContainer mounts the same volume", _swap("      volumes:\n", "      ephemeralContainers:\n" + _SIDE.format(n="dbg") + "      volumes:\n")),
    ("the scoreboard container's mount has no readOnly", _swap(_MOUNT, "            - name: answers\n              mountPath: /etc/ctf-answers\n")),
    ("the scoreboard container's mount is readOnly: false", _swap("readOnly: true", "readOnly: false")),
    ("the scoreboard container mounts the volume twice", _swap(_MOUNT, _MOUNT + _MOUNT.replace("/etc/ctf-answers", "/twice"))),
    ("the volume is not mounted at all", _swap(_MOUNT, "")),
    ("the volume is mounted at another path", _swap("mountPath: /etc/ctf-answers", "mountPath: /etc/other")),
    ("the mounting container is not named scoreboard", _swap("- name: scoreboard\n          image", "- name: other\n          image")),
    ("the sentinel name is in another document", _append("---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: leak\ndata:\n  s: @NAME@\n")),
    ("the sentinel key is in another document", _append("---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: leak\ndata:\n  s: @KEY@\n")),
    ("two volumes hold the Secret", _swap("      volumes:\n", "      volumes:\n        - name: answers2\n          secret:\n            secretName: @NAME@\n")),
    ("the Secret is also an env secretKeyRef", _swap("          env:\n", "          env:\n            - name: LEAK\n              valueFrom:\n                secretKeyRef:\n                  name: @NAME@\n                  key: x\n")),
    ("ANSWERS_FILE is not set", _swap(_ENV, "")),
    ("ANSWERS_FILE points outside the mount", _swap("value: /etc/ctf-answers/@KEY@", "value: /etc/other/@KEY@")),
    ("a tab in an indentation-sensitive line (unreadable)", _swap("  replicas: 1", "\treplicas: 1")),
]


def selftest():
    rc = 0
    good = _GOOD.replace("@NAME@", _NAME).replace("@KEY@", _KEY)
    problems = check_render(good, _NAME, _KEY)
    if problems:
        print("FAIL: the good render was refused (the check is wrong or the reader cannot read a render):", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    print("ok: the good render is accepted")
    for name, mutate in _MUTANTS:
        text = mutate(_GOOD).replace("@NAME@", _NAME).replace("@KEY@", _KEY)
        if text == good:
            print(f"FAIL: mutant '{name}' did not change the render (selftest bug)", file=sys.stderr)
            rc = 1
            continue
        found = check_render(text, _NAME, _KEY)
        if not found:
            print(f"FAIL: mutant '{name}' was ACCEPTED: the check cannot see this defect", file=sys.stderr)
            rc = 1
        else:
            print(f"ok: refused '{name}': {found[0]}")
    # An empty or unrelated input must never read as a pass.
    for name, text in (("empty input", ""), ("a render without the sentinel", "---\nkind: Service\nmetadata:\n  name: x\n")):
        if not check_render(text, _NAME, _KEY):
            print(f"FAIL: '{name}' was accepted", file=sys.stderr)
            rc = 1
        else:
            print(f"ok: refused '{name}'")
    return rc


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--selftest", action="store_true", help="run the check against good and deliberately wrong renders (no helm)")
    sub = ap.add_subparsers(dest="cmd")
    c = sub.add_parser("check", help="check a rendered manifest read from stdin")
    c.add_argument("--sentinel-name", required=True)
    c.add_argument("--sentinel-key", required=True)
    args = ap.parse_args(argv[1:])
    if args.selftest:
        return selftest()
    if args.cmd != "check":
        ap.error("give `check ...` or --selftest")
    problems = check_render(sys.stdin.read(), args.sentinel_name, args.sentinel_key)
    for p in problems:
        print(f"  FAIL: {p}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
