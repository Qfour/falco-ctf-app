#!/usr/bin/env python3
"""Verdict of `make e2e` (ADR-0031 D1 (b), V6). Runs on the host, after the
image build, on the files Dockerfile.e2e's run stage exported.

Fail-closed: exit 0 only when ALL of these hold; anything else (a missing, empty
or unreadable file included) exits non-zero with the reasons on stderr.

  - test.json, exit, run_id, sha exist and are not empty;
  - run_id and sha equal the values this `make e2e` generated (so a verdict left
    over from an earlier run, or from a cached layer, is refused);
  - the recorded `go test` exit code is 0;
  - every line of test.json is a JSON object (no unreadable line);
  - no test, at any depth, was skipped or failed, and the package passed;
  - the set of top-level tests that passed equals the names in expected_tests.txt:
    none missing, none unlisted, the list not empty.

usage: e2e-verdict.py --dir DIR --expected FILE --run-id ID --sha SHA
"""
import argparse
import json
import os
import sys


def fail(problems):
    for p in problems:
        print("e2e-verdict: FAIL: " + p, file=sys.stderr)
    sys.exit(1)


def read(path, problems):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = f.read()
    except OSError as e:
        problems.append("cannot read %s: %s" % (path, e.strerror or e))
        return None
    except UnicodeDecodeError:
        problems.append("%s is not valid UTF-8" % path)
        return None
    if not data.strip():
        problems.append("%s is empty" % path)
        return None
    return data


def expected_names(path, problems):
    data = read(path, problems)
    if data is None:
        return None
    names = []
    for line in data.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line)
    if not names:
        problems.append("%s lists no tests" % path)
        return None
    dup = sorted({n for n in names if names.count(n) > 1})
    if dup:
        problems.append("%s lists a test twice: %s" % (path, ", ".join(dup)))
    return set(names)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--expected", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--sha", required=True)
    a = ap.parse_args()
    problems = []

    if not a.run_id or not a.sha:
        fail(["--run-id and --sha must be non-empty"])
    want = expected_names(a.expected, problems)
    raw = {n: read(os.path.join(a.dir, n), problems) for n in ("test.json", "exit", "run_id", "sha")}

    if raw["run_id"] is not None and raw["run_id"].strip() != a.run_id:
        problems.append("run_id %r is not this run's %r (stale verdict)" % (raw["run_id"].strip(), a.run_id))
    if raw["sha"] is not None and raw["sha"].strip() != a.sha:
        problems.append("sha %r is not this run's %r" % (raw["sha"].strip(), a.sha))
    if raw["exit"] is not None and raw["exit"].strip() != "0":
        problems.append("go test exited with %r, not 0" % raw["exit"].strip())

    passed, package_ok = set(), False
    if raw["test.json"] is not None:
        for n, line in enumerate(raw["test.json"].splitlines(), 1):
            if not line.strip():
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                problems.append("test.json line %d is not JSON" % n)
                continue
            if not isinstance(ev, dict):
                problems.append("test.json line %d is not an object" % n)
                continue
            action, test = ev.get("Action"), ev.get("Test")
            if action == "skip":
                problems.append("skipped: %s" % (test or "(package)"))
            elif action == "fail":
                problems.append("failed: %s" % (test or "(package)"))
            elif action == "pass":
                if test is None:
                    package_ok = True
                elif "/" not in test:
                    passed.add(test)
        if not package_ok:
            problems.append("test.json has no passing package result")

    if want is not None:
        if passed - want:
            problems.append("passed but not in the expected list: " + ", ".join(sorted(passed - want)))
        if want - passed:
            problems.append("expected but did not pass: " + ", ".join(sorted(want - passed)))

    if problems:
        fail(problems)
    print("e2e-verdict: PASS: %d tests, run %s, sha %s" % (len(passed), a.run_id, a.sha[:12]))


if __name__ == "__main__":
    main()
