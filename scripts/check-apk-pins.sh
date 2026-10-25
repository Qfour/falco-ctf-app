#!/usr/bin/env bash
# check-apk-pins.sh — every `apk add` exact pin in every Dockerfile must still be in the
# index of the very base image its RUN builds from, and `apk add` must only use exact
# pins (ADR-0036 D1 + D5; absorbs scripts/check-e2e-pins.sh, ADR-0031 D5).
#
# WHY: Alpine's index keeps ONE version of each package. The day upstream ships a
# security release, a pinned `name=version` that is not in the base image vanishes and
# the next `docker build` fails (`breaks: world[...]`, rc 3). That happened 5 times in 53
# days (ADR-0036 C1); the last one sat red for 4 days because nothing told a human. This
# looks every day, in every Dockerfile, and a red run opens an Issue (apk-pins.yaml).
#
# The set of Dockerfiles is DERIVED (`git ls-files '*Dockerfile*'`), never listed (D5):
# a new Dockerfile is covered the day it is added. For each Dockerfile the script reads
# `FROM <ref> [AS <stage>]`, resolves `FROM <earlier stage>` to that stage's base, and
# attributes each `RUN ... apk add` to the stage it is in. Then, per distinct base image,
# it runs `apk update && apk policy <names>` INSIDE that image (entrypoint overridden: the
# falco image has one) and compares. `apk policy` lists the index versions and also the
# version the base already has installed (`lib/apk/db/installed`), which is exactly the
# set `apk add name=version` can satisfy.
#
# Grammar (D1 + security condition F4, app#382): the only version syntax is exact
# `name=version`, and the packages come from the repositories and keys the base ships.
# Fails on
#   - a range (`>=` `>` `<` `<=` `~` `=~`), a repository tag (`name@edge`);
#   - another repository: `--repository` / `--repositories-file` (also `=` attached), `-X`
#     (also attached `-Xurl` and in a short cluster such as `-uX`);
#   - `--keys-dir` (also `=` attached): another key directory;
#   - `--allow-untrusted`;
#   - a write to apk's configuration: any name containing `/etc/apk` (so `/etc/apk`,
#     `/etc/apk/`, `.../repositories`, `.../keys`, `.../world`) in a RUN command that is not a
#     plain read (cat grep head tail wc ls stat test diff, after a leading if/then/do/!) or
#     that redirects into it, or in a `--mount` of a RUN; any COPY / ADD naming it;
#   - a version or package taken from a shell variable (not checkable), `name=` with no version.
# A bare `apk add name` is allowed. `--root` / `--cache-dir` are allowed for now (they move
# apk's root or its package cache, not its trust); that call waits for security (R1) to
# confirm (#505 review-5x 65).
#
# What it does NOT see (a net, not a proof; review sees these): `COPY rootfs/ /` (a source
# tree that carries /etc/apk/...), a write inside a heredoc RUN (also `apk add` there: the
# coverage cross-check turns that into exit 1), `cd /etc/apk && echo x > repositories` (the
# path is never one token), a path built from a variable, `sh -c "..."` (same coverage check),
# an ENV / ARG that apk reads.
#
# Reads: `\` continuations, quotes, several commands in one RUN (`apk del ... && apk add ...`),
# `--upgrade`, `RUN ["apk","add",...]`, apk in a non-first stage, `FROM <stage>` inheritance,
# an indented FROM. It does NOT read heredoc RUNs.
#
#   scripts/check-apk-pins.sh               every tracked *Dockerfile* (derived)
#   scripts/check-apk-pins.sh FILE...       just these (the planted fixtures under
#                                           scripts/testdata/e2e-pin-*.txt are not
#                                           Dockerfiles, so the derivation never sees them)
#   scripts/check-apk-pins.sh --parse [FILE...]   print the parse table (TSV) and exit 0;
#                                           offline, for fixtures and for later checks
#   scripts/check-apk-pins.sh --lint [FILE...]   offline, no docker: the real tree's gate.
#                                           Grammar (D1 + F4), at least one pin, and the
#                                           parser read every `apk add`; one file:line per
#                                           violation; exit 0 / 1. The flag-guard job runs it
#                                           as its own step. ADR-0036 V2 (the D2 class check)
#                                           is added to it (lint_rows), not to --selftest.
#   scripts/check-apk-pins.sh --selftest    offline: the checker's own test only. Planted
#                                           defects must fail (and --lint must go red on them),
#                                           parse tables must be exact; it does not look at
#                                           the real tree, so a red here means the checker broke
#
# Needs Docker and network (not --parse / --lint / --selftest). No Docker is a FAIL (exit 2) with
# the reason, never a skip: a check that did not run must not look like a pass.
# Exit: 0 every pin is in its base's index (or installed), the grammar holds
#       1 a pin is gone, a grammar violation, no pin found at all (fail-closed), the base
#         has no apk, or the parser's `apk add` count differs from the text's
#       2 Docker or network trouble (not a verdict about the pins; a verdict of 1 wins)
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

# --- parse ------------------------------------------------------------------------------
# Prints one TSV row per finding. No field is ever empty ("-" stands in), because tab is
# whitespace to `read` and would collapse empty fields.
#   file  line  stage  base  kind  name  version  upgrade
# kind: pin    name=version                      (version = the pin, upgrade = 0|1)
#       addcmd one `apk add` command was seen    (counted by the coverage cross-check)
#       range  >= > < <= ~   |  edge  name@tag   |  repo  --repository / -X / --repositories-file
#       var    a `$` in a package or version     |  bad   `name=` with no version
#       untrusted  --allow-untrusted             |  reposfile / keysfile  a write to
#       /etc/apk/repositories / /etc/apk/keys (RUN other than a plain read, or COPY / ADD)
# For a violation, `version` carries the offending token as written.
parse() {
  awk -F'\t' -v sq="'" '
    function emit(kind, name, version, upgrade) {
      printf "%s\t%d\t%s\t%s\t%s\t%s\t%s\t%d\n", FILENAME, ln0, stage, base, kind, \
        (name == "" ? "-" : name), (version == "" ? "-" : version), upgrade
    }
    function from_instr(s,    n, t, i, ref, alias) {
      sub(/^[ \t]+/, "", s)
      n = split(s, t, /[ \t]+/); ref = ""; alias = ""
      for (i = 2; i <= n; i++) {
        if (t[i] == "" || substr(t[i], 1, 2) == "--") continue
        if (ref == "") { ref = t[i]; continue }
        if (toupper(t[i]) == "AS" && i < n) alias = tolower(t[i + 1])
        break
      }
      nstage++
      if (index(ref, "$") > 0) base = "UNRESOLVED:" ref
      else if (tolower(ref) in alias_base) base = alias_base[tolower(ref)]
      else base = ref
      stage = (alias == "" ? "#" nstage : alias)
      if (alias != "") alias_base[alias] = base
    }
    # apk options that change where packages come from, which keys are trusted, or whether
    # signatures are checked: called on t[k]; returns how many following tokens it consumed.
    # Not flagged on purpose: --root / --cache-dir (see the header).
    function apk_opt(k,    p) {
      p = t[k]
      if (p == "--allow-untrusted") { emit("untrusted", "-", p, 0); return 0 }
      if (p == "--repository" || p == "--repositories-file" || p ~ /^-[A-Za-z]*X$/) { emit("repo", "-", p " " t[k + 1], 0); return 1 }
      if (p ~ /^--repository=/ || p ~ /^--repositories-file=/ || p ~ /^-[A-Za-z]*X./) { emit("repo", "-", p, 0); return 0 }
      if (p == "--keys-dir") { emit("keysfile", "-", p " " t[k + 1], 0); return 1 }
      if (p ~ /^--keys-dir=/) { emit("keysfile", "-", p, 0); return 0 }
      return 0
    }
    # A command (segment) that names a path under /etc/apk and is not a plain read is a write
    # to apk'"'"'s configuration: echo/printf/sed -i/tee/cp/mv/ln/wget/curl/..., or a redirect
    # into it, or a --mount of it.
    function seg_flush() {
      if (sp != "" && (!(sf in ro) || sw)) emit((sp ~ /\/etc\/apk\/keys/ ? "keysfile" : "reposfile"), "-", sp, 0)
      sf = ""; sw = 0; sp = ""; sprev = ""
    }
    function run_instr(s,    i, j, k, mode, upgrade, apk_seen, p, q, tok) {
      sub(/^[ \t]*[Rr][Uu][Nn][ \t]*/, "", s)
      if (substr(s, 1, 1) == "[") gsub(/[\[\],"]/, " ", s)      # exec form
      gsub(/&&/, " ; ", s); gsub(/\|\|/, " ; ", s); gsub(/;/, " ; ", s); gsub(/\|/, " ; ", s)
      n = split(s, t, /[ \t]+/); mode = 0; apk_seen = 0
      for (i = 1; i <= n; i++) {
        if (t[i] == "" ) continue
        if (t[i] == ";") { mode = 0; apk_seen = 0; continue }
        if (mode == 0) {
          if (t[i] == "apk") {
            apk_seen = 1
            # global options, then the sub-command
            j = i + 1
            while (j <= n && (t[j] == "" || substr(t[j], 1, 1) == "-")) {
              if (t[j] == "-p" || t[j] == "--root" || t[j] == "--arch" || \
                  t[j] == "--cache-dir" || t[j] == "--wait" || t[j] == "--cache-max-age") j++
              else j += apk_opt(j)
              j++
            }
            if (j <= n && t[j] == "add") { mode = 1; upgrade = 0; i = j; emit("addcmd", "-", "-", 0) }
          } else if (apk_seen) i += apk_opt(i)                     # options after another sub-command
          continue
        }
        # inside `apk add`
        p = t[i]
        if (substr(p, 1, 1) == "-") {
          if (p == "-u" || p == "--upgrade") upgrade = 1
          else if (p ~ /^-[A-Za-z]+$/ && index(p, "u") > 0) upgrade = 1
          if (p == "-t" || p == "--virtual") i++                    # the virtual name
          else i += apk_opt(i)
          continue
        }
        if (p ~ /^[0-9]*[<>]+$/) { i++; continue }                  # `> file` / `2> file`
        if (p ~ /^[0-9]*[<>]/) continue                             # `>/dev/null`
        gsub("[\"" sq "]", "", p)
        if (p == "" || index(p, "/") > 0) continue                  # empty / a local .apk path
        if (index(p, "$") > 0) { emit("var", "-", p, 0); continue }
        if (index(p, "@") > 0) { emit("edge", "-", p, 0); continue }
        if (p ~ /[<>~]/) { emit("range", "-", p, 0); continue }
        q = index(p, "=")
        if (q == 0) continue                                        # bare name: allowed
        if (q == 1 || q == length(p)) { emit("bad", "-", p, 0); continue }
        emit("pin", substr(p, 1, q - 1), substr(p, q + 1), upgrade)
      }
      # second pass over the same tokens: writes under /etc/apk
      sf = ""; sw = 0; sp = ""; sprev = ""
      for (k = 1; k <= n + 1; k++) {
        tok = (k <= n ? t[k] : ";")
        if (tok == "") continue
        if (tok == ";") { seg_flush(); continue }
        if (sf == "") {
          if (tok in kw || tok ~ /^--(mount|network|security)/) { if (tok ~ /^--mount/ && index(tok, "/etc/apk") > 0) { sf = tok; sw = 1; sp = tok } ; continue }
          sf = tok
        }
        if (index(tok, "/etc/apk") > 0) {
          sp = tok
          if (index(tok, ">") > 0 || sprev ~ /^[0-9&]*>+$/ || tok ~ /^--mount/) sw = 1
        }
        sprev = tok
      }
    }
    function instr_done(s,    w) {
      w = s; sub(/^[ \t]+/, "", w); sub(/[ \t].*$/, "", w); w = toupper(w)
      if (w == "FROM") from_instr(s)
      else if (w == "RUN") run_instr(s)
      else if (w == "COPY" || w == "ADD") {                        # also a way to write them
        if (index(s, "/etc/apk/keys") > 0) emit("keysfile", "-", w " ... /etc/apk/keys", 0)
        else if (index(s, "/etc/apk") > 0) emit("reposfile", "-", w " ... /etc/apk", 0)
      }
    }
    BEGIN {
      split("cat grep head tail wc ls stat test [ diff", ro_words, " "); for (w in ro_words) ro[ro_words[w]] = 1
      split("if then else elif while until do ! { (", kw_words, " "); for (w in kw_words) kw[kw_words[w]] = 1
    }
    FNR == 1 { buf = ""; ln0 = 0; nstage = 0; stage = "#0"; base = "NOFROM"; delete alias_base }
    {
      sub(/\r$/, "")
      if ($0 ~ /^[ \t]*#/ || $0 ~ /^[ \t]*$/) next                  # comment / blank (also inside a continuation)
      if (buf == "") ln0 = FNR
      if ($0 ~ /\\[ \t]*$/) { sub(/\\[ \t]*$/, ""); buf = buf $0 " "; next }
      instr_done(buf $0); buf = ""
    }
    END { }
  ' "$@"
}

# --- coverage cross-check ---------------------------------------------------------------
# An independent count: `apk ... add` occurrences in the non-comment text (grep, not the
# awk above). If the parser saw fewer `apk add` commands than the text contains, it has a
# blind spot, and a blind spot is a silent green. Prints "<text count> <parsed count>".
# The regex follows parse()'s rule: `apk`, then options (those that take an argument bring it
# along: `-p dir`, `--root dir`, `-X url` ...), then `add`.
apk_add_re='apk([[:space:]]+(-p|--root|--arch|--cache-dir|--wait|--cache-max-age|--keys-dir|--repository|--repositories-file|-[A-Za-z]*X)[[:space:]]+[^[:space:]]+|[[:space:]]+-[^[:space:]]+)*[[:space:]]+add([[:space:]]|$)'
coverage() { # rows-file, files...
  local rows="$1" text parsed f
  shift
  text=0
  for f in "$@"; do
    text=$((text + $({ grep -vE '^[[:space:]]*#' "$f" | grep -oE "$apk_add_re" || true; } | wc -l)))
  done
  parsed="$(awk -F'\t' '$5 == "addcmd"' "$rows" | wc -l | tr -d ' ')"
  echo "$text $parsed"
}

# --- index query ------------------------------------------------------------------------
# query_index BASE NAME... prints `apk policy` for NAME... as seen inside BASE.
# Returns 0 ok / 2 Docker or network trouble / 3 the base has no apk (a verdict, not a failure).
# The selftest redefines this function; nothing else calls docker.
query_index() {
  local base="$1" rc err
  shift
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker is not installed: the index cannot be queried (this is a FAIL, not a skip)" >&2
    return 2
  fi
  err="$(mktemp)" || return 2
  docker run --rm --user 0 --entrypoint sh "$base" -c '
    command -v apk >/dev/null 2>&1 || exit 90
    out="$(apk update 2>&1)" || { echo "$out" >&2; exit 91; }
    exec apk policy "$@"' sh "$@" 2>"$err" </dev/null
  rc=$?
  if [ "$rc" -ne 0 ]; then
    cat "$err" >&2
    rm -f "$err"
    [ "$rc" -eq 90 ] && return 3
    echo "docker run $base exited $rc (docker or network trouble, not a verdict about the pins)" >&2
    return 2
  fi
  rm -f "$err"
  return 0
}

# versions NAME  — reads `apk policy` text on stdin, prints the versions it lists for NAME.
versions() {
  awk -v n="$1" '
    $0 == n " policy:" { in_pkg = 1; next }
    /^[^ ]/ { in_pkg = 0 }
    in_pkg && /^  [^ ].*:$/ { sub(/^  /, ""); sub(/:$/, ""); print }'
}

# --- lint (offline, the real-tree gate) -------------------------------------------------
# lint_rows ROWS FILE... : the verdict that needs no index: grammar (ADR-0036 D1 + security
# condition F4), at least one pin, and the parser read every `apk add` the text contains.
# Prints one FAIL line per finding (file:line), returns 0 / 1, sets LINT_PINS_N. Used by
# `--lint` and, first, by check_files, so the two never disagree about the grammar.
# ADR-0036 V2 (the D2 class check: allow-list names, `--upgrade` syntax, allow-list rows
# without a pin) is added HERE, as a further check over the same rows, not to --selftest.
LINT_PINS_N=0
lint_rows() {
  local rows="$1" status=0 files_n cov text_n parsed_n
  local file line stage kind version
  shift
  files_n=$#
  # grammar (D1 + F4)
  while IFS=$'\t' read -r file line stage _ kind _ version _; do
    case "$kind" in
      range) echo "FAIL: $file:$line [$stage] '$version' — a version range; the only version syntax is exact name=version (ADR-0036 D1)"; status=1 ;;
      edge)  echo "FAIL: $file:$line [$stage] '$version' — a repository tag (@edge etc.) is not allowed (ADR-0036 D1)"; status=1 ;;
      repo)  echo "FAIL: $file:$line [$stage] '$version' — another repository is not allowed (ADR-0036 D1)"; status=1 ;;
      untrusted) echo "FAIL: $file:$line [$stage] '$version' — turns off signature verification (ADR-0036 security condition F4)"; status=1 ;;
      reposfile) echo "FAIL: $file:$line [$stage] '$version' — writes apk's configuration under /etc/apk; the repository list decides where every unpinned package comes from (ADR-0036 security condition F4)"; status=1 ;;
      keysfile)  echo "FAIL: $file:$line [$stage] '$version' — writes apk's trusted keys (ADR-0036 security condition F4)"; status=1 ;;
      var)   echo "FAIL: $file:$line [$stage] '$version' — a shell variable in apk add cannot be checked against the index"; status=1 ;;
      bad)   echo "FAIL: $file:$line [$stage] '$version' — name= with no version (or no name)"; status=1 ;;
    esac
  done <"$rows"

  # fail-closed: a check that looked at nothing is not a pass
  LINT_PINS_N="$(awk -F'\t' '$5 == "pin"' "$rows" | wc -l | tr -d ' ')"
  if [ "$LINT_PINS_N" -eq 0 ]; then
    echo "FAIL: no apk exact pin found in $files_n file(s) (a check that looked at nothing is not a pass)"
    status=1
  fi
  cov="$(coverage "$rows" "$@")"
  text_n="${cov% *}"; parsed_n="${cov#* }"
  if [ "$text_n" != "$parsed_n" ]; then
    echo "FAIL: the text has $text_n 'apk add' occurrence(s) but the parser read $parsed_n; a form it does not read can hide a pin — extend parse() in $0"
    status=1
  fi
  return "$status"
}

# lint_files FILE... : parse, then lint_rows. Offline: no docker, no network.
lint_files() {
  local tmp rc
  tmp="$(mktemp -d)" || return 2
  parse "$@" >"$tmp/rows" || { echo "FAIL: the parser failed" >&2; rm -rf "$tmp"; return 2; }
  lint_rows "$tmp/rows" "$@"; rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "ok: lint — $LINT_PINS_N pin(s) in $# file(s), grammar clean, every apk add read (offline; the index comparison is check-apk-pins / apk-pins.yaml)"
  fi
  rm -rf "$tmp"
  return "$rc"
}

# --- the check --------------------------------------------------------------------------
# check_files FILE... : prints findings, returns 0 / 1 / 2 (see the header).
check_files() {
  local rows tmp status infra files_n pins_n base names policy qrc
  local file line stage name version listed bases_n bases idx
  status=0; infra=0
  files_n=$#
  tmp="$(mktemp -d)" || return 2
  rows="$tmp/rows"
  parse "$@" >"$rows" || { echo "FAIL: the parser failed" >&2; rm -rf "$tmp"; return 2; }

  # grammar (D1 + F4), no pin at all, coverage: the same report `--lint` gives (lint_rows)
  lint_rows "$rows" "$@" || status=1
  pins_n="$LINT_PINS_N"

  # index (D5): one docker run per distinct base image
  bases_n=0
  bases="$(awk -F'\t' '$5 == "pin" { print $4 }' "$rows" | sort -u)"
  while IFS= read -r base; do
    [ -n "$base" ] || continue
    bases_n=$((bases_n + 1))
    case "$base" in
      UNRESOLVED:*|NOFROM|scratch)
        awk -F'\t' -v b="$base" '$5 == "pin" && $4 == b { printf "FAIL: %s:%s [%s] %s=%s — its base is %s, which has no apk index to check\n", $1, $2, $3, $6, $7, b }' "$rows"
        status=1; continue ;;
    esac
    names="$(awk -F'\t' -v b="$base" '$5 == "pin" && $4 == b { print $6 }' "$rows" | sort -u | tr '\n' ' ')"
    # shellcheck disable=SC2086  # $names is a space-separated list of package names
    policy="$(query_index "$base" $names)"; qrc=$?
    if [ "$qrc" -eq 3 ]; then
      echo "FAIL: base $base has no apk, but $names is apk-added on it"
      status=1; continue
    elif [ "$qrc" -ne 0 ]; then
      echo "ERROR: could not query the index of $base (exit $qrc)"
      infra=1; continue
    fi
    while IFS=$'\t' read -r file line stage _ _ name version _; do
      listed="$(printf '%s\n' "$policy" | versions "$name")"
      if printf '%s\n' "$listed" | grep -Fxq -- "$version"; then
        echo "ok:   $file:$line [$stage] $name=$version is in the index of ${base%@*}"
      else
        idx="$(printf '%s' "$listed" | tr '\n' ' ' | sed 's/ $//')"
        echo "FAIL: $file:$line [$stage] $name=$version is not in the index of $base (index has: ${idx:-nothing}) — bump the pin"
        status=1
      fi
    done < <(awk -F'\t' -v b="$base" '$5 == "pin" && $4 == b' "$rows")
  done <<<"$bases"

  rm -rf "$tmp"
  if [ "$status" -ne 0 ]; then return 1; fi
  if [ "$infra" -ne 0 ]; then return 2; fi
  echo "ok: $pins_n pin(s) in $files_n file(s), $bases_n base image(s): every pin is in its base's index; grammar holds"
  return 0
}

tracked() { git ls-files '*Dockerfile*'; }

# --- selftest ---------------------------------------------------------------------------
selftest() {
  local tmp n rc
  tmp="$(mktemp -d)" || return 2
  trap 'rm -rf "$tmp"' RETURN
  n=0
  # A stand-in index (no docker, no network). Each `apk policy` block is what Alpine prints.
  POLICY_TEXT="$(printf '%s\n' \
    'vim policy:' '  9.2.1202-r0:' '    https://dl-cdn.alpinelinux.org/alpine/v3.24/community' \
    'zlib policy:' '  1.3.2-r0:' '    lib/apk/db/installed' '  1.3.2-r1:' '    https://dl-cdn.alpinelinux.org/alpine/v3.24/main' \
    'chromium policy:' '  155.0.8059.84-r0:' '    https://dl-cdn.alpinelinux.org/alpine/v3.24/community' \
    'font-wqy-zenhei policy:' '  0.9.46-r0:' '    https://dl-cdn.alpinelinux.org/alpine/v3.24/community')"
  query_index() { printf '%s\n' "$POLICY_TEXT"; return 0; }

  # planted: the text goes through check_files with the stub index
  planted() { # name, wanted exit, Dockerfile text, [text the output must contain: red for the intended reason]
    local name="$1" want="$2" text="$3" must="${4:-}"
    n=$((n + 1))
    printf '%s\n' "$text" >"$tmp/Dockerfile.$n"
    check_files "$tmp/Dockerfile.$n" >"$tmp/out" 2>&1; rc=$?
    if [ "$rc" -ne "$want" ]; then
      echo "FAIL: selftest: '$name' exited $rc, wanted $want"; cat "$tmp/out"; return 1
    fi
    if [ -n "$must" ] && ! grep -qF -- "$must" "$tmp/out"; then
      echo "FAIL: selftest: '$name' exited $rc but not for the intended reason ('$must' missing)"; cat "$tmp/out"; return 1
    fi
    echo "  planted ($name): exit $rc — $( { grep -m1 '^FAIL' "$tmp/out" || grep -m1 -E '^(ok|ERROR)' "$tmp/out" || echo '(no output)'; } | sed "s|$tmp/||" | cut -c1-140)"
  }
  # table NAME EXPECTED DOCKERFILE-TEXT : the parse table (file column dropped) must equal EXPECTED exactly
  table() {
    local name="$1" expected="$2" text="$3" got
    n=$((n + 1))
    printf '%s\n' "$text" >"$tmp/Dockerfile.$n"
    got="$(parse "$tmp/Dockerfile.$n" | awk -F'\t' '$5 != "addcmd" { sub(/^[^\t]*\t/, ""); print }')"
    if [ "$got" != "$expected" ]; then
      echo "FAIL: selftest: parse table '$name' differs"; echo "--- want"; printf '%s\n' "$expected"; echo "--- got"; printf '%s\n' "$got"; return 1
    fi
    echo "  parsed ($name): $(printf '%s\n' "$got" | wc -l | tr -d ' ') row(s) as expected"
  }
  T=$'\t'
  A='FROM alpine:3.24@sha256:aaaa AS final'
  B='alpine:3.24@sha256:aaaa'

  # `--lint` (the real-tree gate) can go red, through the real entry point. The tree here is a
  # clean stand-in (two Dockerfiles, multi-stage, pins), so this test does not depend on the
  # real tree: a violation in the real tree fails the `--lint` step, never this one.
  # Each planted file is added to the stand-in tree alone and `--lint` must exit 1 for the
  # intended reason; the unplanted tree must exit 0.
  mkdir -p "$tmp/tree/images/a" "$tmp/tree/images/b"
  printf '%s\n' 'FROM alpine:3.24@sha256:aaaa AS base' 'RUN apk add --no-cache vim=9.2.1202-r0 jq' \
    'FROM base AS final' 'RUN apk add --no-cache --upgrade zlib=1.3.2-r1' >"$tmp/tree/images/a/Dockerfile"
  printf '%s\n' 'FROM python:3.12-slim@sha256:bbbb AS build' 'RUN pip install x' \
    'FROM alpine:3.24@sha256:aaaa' 'RUN apk del --no-cache curl && apk add chromium=155.0.8059.84-r0' >"$tmp/tree/images/b/Dockerfile"
  lintcase() { # name, wanted exit, must-contain ("" = none), extra files to add to the tree...
    local name="$1" want="$2" must="$3" f
    shift 3
    n=$((n + 1))
    "$0" --lint "$tmp/tree/images/a/Dockerfile" "$tmp/tree/images/b/Dockerfile" "$@" >"$tmp/out" 2>&1; rc=$?
    if [ "$rc" -ne "$want" ]; then
      echo "FAIL: selftest: --lint '$name' exited $rc, wanted $want"; cat "$tmp/out"; return 1
    fi
    if [ -n "$must" ] && ! grep -qF -- "$must" "$tmp/out"; then
      echo "FAIL: selftest: --lint '$name' exited $rc but not for the intended reason ('$must' missing)"; cat "$tmp/out"; return 1
    fi
    echo "  lint ($name): exit $rc — $( { grep -m1 '^FAIL' "$tmp/out" || grep -m1 '^ok' "$tmp/out" || echo '(no output)'; } | sed "s|$tmp/||" | cut -c1-140)"
  }
  lintcase "the stand-in tree is clean" 0 "ok: lint — 3 pin(s) in 2 file(s)" || return 1
  printf '%s\n' 'FROM alpine:3.24@sha256:aaaa' 'RUN apk add --no-cache vim=9.2.1202-r0 jq' 'RUN apk add --no-cache "curl>=8.0"' >"$tmp/lint-grammar"
  lintcase "a grammar violation (a range) in one added file" 1 "lint-grammar:3 [#1] 'curl>=8.0' — a version range" "$tmp/lint-grammar" || return 1
  printf '%s\n' 'FROM alpine:3.24@sha256:aaaa' 'RUN apk add --no-cache vim=9.2.1202-r0' 'RUN echo https://m.example >> /etc/apk/repositories' >"$tmp/lint-etcapk"
  lintcase "a write to /etc/apk/repositories (F4) in one added file" 1 "lint-etcapk:3 [#1]" "$tmp/lint-etcapk" || return 1
  # no pin at all: the tree is only bare names (the stand-in tree's own pins left out)
  printf '%s\n' 'FROM alpine:3.24@sha256:aaaa' 'RUN apk add --no-cache vim jq' >"$tmp/lint-nopin"
  n=$((n + 1))
  "$0" --lint "$tmp/lint-nopin" >"$tmp/out" 2>&1; rc=$?
  if [ "$rc" -ne 1 ] || ! grep -qF 'no apk exact pin found in 1 file(s)' "$tmp/out"; then
    echo "FAIL: selftest: --lint with no pin exited $rc"; cat "$tmp/out"; return 1
  fi
  echo "  lint (no pin at all): exit $rc — $(grep -m1 '^FAIL' "$tmp/out" | cut -c1-140)"
  printf '%s\n' 'FROM alpine:3.24@sha256:aaaa' 'RUN apk add --no-cache vim=9.2.1202-r0' 'RUN <<EOF' 'apk add jq' 'EOF' >"$tmp/lint-cover"
  lintcase "a parser coverage mismatch (apk add in a heredoc) in one added file" 1 "the text has 5 'apk add' occurrence(s) but the parser read 4" "$tmp/lint-cover" || return 1
  # a missing file is not a pass
  n=$((n + 1))
  "$0" --lint "$tmp/does-not-exist" >"$tmp/out" 2>&1; rc=$?
  [ "$rc" -eq 1 ] && grep -q 'not found' "$tmp/out" || { echo "FAIL: selftest: --lint on a missing file exited $rc"; cat "$tmp/out"; return 1; }
  echo "  lint (a missing file): exit $rc — not a pass"

  # parse tables (ADR-0036 V1): each form, exact
  table "plain, one line" "2${T}final${T}$B${T}pin${T}vim${T}9.2.1202-r0${T}0" \
    "$A
RUN apk add --no-cache vim=9.2.1202-r0" || return 1
  table "a pin on a \\ continuation line, quoted pin, bare names skipped" \
    "2${T}final${T}$B${T}pin${T}vim${T}9.2.1202-r0${T}0
2${T}final${T}$B${T}pin${T}zlib${T}1.3.2-r1${T}0" \
    "$A
RUN apk add --no-cache bash \\
    \"vim=9.2.1202-r0\" \\
    # a comment inside a continuation is dropped
    'zlib=1.3.2-r1' jq" || return 1
  table "apk del && apk add --upgrade, then a second apk add (upgrade does not leak)" \
    "2${T}final${T}$B${T}pin${T}zlib${T}1.3.2-r1${T}1
2${T}final${T}$B${T}pin${T}vim${T}9.2.1202-r0${T}0" \
    "$A
RUN apk del --no-cache curl && apk add --no-cache --upgrade zlib=1.3.2-r1 && apk add vim=9.2.1202-r0" || return 1
  table "apk in a later stage; the first stage (no apk) has none" \
    "4${T}serve${T}$B${T}pin${T}zlib${T}1.3.2-r1${T}0" \
    "FROM python:3.12-slim@sha256:bbbb AS build
RUN pip install x
FROM $B AS serve
RUN apk add zlib=1.3.2-r1" || return 1
  table "FROM <stage> inherits that stage's base" \
    "2${T}tools${T}golang:1.26@sha256:cccc${T}pin${T}chromium${T}155.0.8059.84-r0${T}0
4${T}build${T}golang:1.26@sha256:cccc${T}pin${T}jq${T}1.7-r0${T}0" \
    "FROM golang:1.26@sha256:cccc AS tools
RUN apk add chromium=155.0.8059.84-r0
FROM tools AS build
RUN apk add jq=1.7-r0" || return 1
  table "exec form" "2${T}#1${T}$B${T}pin${T}vim${T}9.2.1202-r0${T}0" \
    "FROM $B
RUN [\"apk\", \"add\", \"vim=9.2.1202-r0\"]" || return 1
  table "--platform flag on FROM; redirection and --virtual do not become pins" \
    "2${T}x${T}$B${T}pin${T}vim${T}9.2.1202-r0${T}0" \
    "FROM --platform=linux/amd64 $B AS x
RUN apk add --virtual .build-deps vim=9.2.1202-r0 2>/dev/null" || return 1
  # every violation kind is pinned by the table (what the parser emits, not only what the verdict says)
  table "every violation kind and a pin, one per line" \
    "2${T}final${T}$B${T}range${T}-${T}vim>=9.2${T}0
3${T}final${T}$B${T}edge${T}-${T}vim@edge${T}0
4${T}final${T}$B${T}repo${T}-${T}-X https://m.example/c${T}0
5${T}final${T}$B${T}var${T}-${T}vim=\${V}${T}0
6${T}final${T}$B${T}bad${T}-${T}vim=${T}0
7${T}final${T}$B${T}untrusted${T}-${T}--allow-untrusted${T}0
8${T}final${T}$B${T}pin${T}chromium${T}155.0.8059.84-r0${T}0
9${T}final${T}$B${T}reposfile${T}-${T}COPY ... /etc/apk${T}0
10${T}final${T}$B${T}keysfile${T}-${T}/etc/apk/keys/${T}0" \
    "$A
RUN apk add 'vim>=9.2'
RUN apk add vim@edge
RUN apk add -X https://m.example/c vim
RUN apk add vim=\${V}
RUN apk add vim=
RUN apk add --allow-untrusted vim
RUN apk add chromium=155.0.8059.84-r0
COPY conf /etc/apk/
RUN cp k.pub /etc/apk/keys/" || return 1
  table "an option with an argument before add (-p dir) and a redirect: one pin, no violation" \
    "2${T}final${T}$B${T}pin${T}vim${T}9.2.1202-r0${T}0" \
    "$A
RUN apk -p /sysroot add vim=9.2.1202-r0 2>/dev/null" || return 1
  table "a read of /etc/apk/repositories under if grep (and 2>/dev/null) is not a write" \
    "2${T}final${T}$B${T}pin${T}vim${T}9.2.1202-r0${T}0" \
    "$A
RUN if grep -q x /etc/apk/repositories 2>/dev/null; then apk add vim=9.2.1202-r0; fi" || return 1
  table "an indented FROM and RUN" \
    "2${T}x${T}$B${T}pin${T}vim${T}9.2.1202-r0${T}0" \
    "  FROM $B AS x
  RUN apk add vim=9.2.1202-r0" || return 1

  # planted defects: each one alone must be red (and the clean case must be green)
  planted "a pin that is in the base's index passes" 0 "$A
RUN apk add --no-cache vim=9.2.1202-r0 chromium=155.0.8059.84-r0 jq" || return 1
  planted "the pinned version of the installed base package passes (zlib r0 is installed)" 0 "$A
RUN apk add --no-cache --upgrade zlib=1.3.2-r0" || return 1
  planted "a pinned version that left the index (vanished)" 1 "$A
RUN apk add --no-cache vim=9.2.1100-r0" || return 1
  planted "the vanished version is on a \\ continuation line, a good one before it" 1 "$A
RUN apk add --no-cache chromium=155.0.8059.84-r0 \\
    vim=1.0.0-r0" || return 1
  # D1: each fixture carries a good pin (G), so none of them is red for 'no pin', and each
  # must be red for the intended reason (the message names it).
  G=chromium=155.0.8059.84-r0
  planted "a version range >=" 1 "$A
RUN apk add --no-cache $G 'vim>=9.2'" "a version range" || return 1
  planted "a version range ~" 1 "$A
RUN apk add --no-cache $G vim~9.2" "a version range" || return 1
  planted "a version range =~ (fuzzy)" 1 "$A
RUN apk add --no-cache $G vim=~9.2" "a version range" || return 1
  planted "@edge tag" 1 "$A
RUN apk add --no-cache $G vim@edge" "a repository tag" || return 1
  planted "--repository" 1 "$A
RUN apk add --no-cache $G --repository https://dl-cdn.alpinelinux.org/alpine/edge/community vim" "another repository" || return 1
  planted "a version from a shell variable" 1 "$A
RUN apk add --no-cache $G vim=\${VIM_VERSION}" "shell variable" || return 1
  planted "name= with no version" 1 "$A
RUN apk add --no-cache $G vim=" "with no version" || return 1
  planted "no pin at all (bare names only): looked at nothing" 1 "$A
RUN apk add --no-cache vim jq" || return 1
  planted "no apk at all in the file" 1 "FROM $B
RUN echo hello" || return 1
  planted "the base has no apk index to check (scratch)" 1 "FROM scratch
RUN apk add vim=9.2.1202-r0" || return 1
  planted "FROM an unresolvable \${ARG}" 1 "ARG BASE
FROM \${BASE}
RUN apk add vim=9.2.1202-r0" || return 1
  planted "a bad pin among good ones is red even if the others pass" 1 "$A
RUN apk add --no-cache vim=9.2.1202-r0 \\
    chromium=0.0.0-r0 jq" || return 1
  # ADR-0036 security condition F4 (app#382): where the packages come from and whether they
  # are verified. Each fixture also carries a good pin, so none of them is red for 'no pin'.
  planted "-X short form of --repository" 1 "$A
RUN apk add --no-cache -X https://dl-cdn.alpinelinux.org/alpine/edge/community vim=9.2.1202-r0" "another repository" || return 1
  planted "-X as a global option before add" 1 "$A
RUN apk -X https://dl-cdn.alpinelinux.org/alpine/edge/community add vim=9.2.1202-r0" "another repository" || return 1
  planted "--allow-untrusted on add" 1 "$A
RUN apk add --no-cache --allow-untrusted vim=9.2.1202-r0" "signature verification" || return 1
  planted "--allow-untrusted as a global option" 1 "$A
RUN apk --allow-untrusted add vim=9.2.1202-r0" "signature verification" || return 1
  planted "--allow-untrusted on another sub-command" 1 "$A
RUN apk add vim=9.2.1202-r0 && apk fix --allow-untrusted" "signature verification" || return 1
  planted "echo >> /etc/apk/repositories" 1 "$A
RUN echo https://dl-cdn.alpinelinux.org/alpine/edge/community >> /etc/apk/repositories && apk add vim=9.2.1202-r0" "repository list" || return 1
  planted "sed -i on /etc/apk/repositories" 1 "$A
RUN sed -i 's/v3.24/edge/' /etc/apk/repositories \\
 && apk add vim=9.2.1202-r0" "repository list" || return 1
  planted "tee -a /etc/apk/repositories" 1 "$A
RUN echo https://mirror.example/alpine | tee -a /etc/apk/repositories && apk add vim=9.2.1202-r0" "repository list" || return 1
  planted "COPY onto /etc/apk/repositories" 1 "$A
COPY repositories /etc/apk/repositories
RUN apk add vim=9.2.1202-r0" "repository list" || return 1
  planted "cp into /etc/apk/keys" 1 "$A
RUN cp key.rsa.pub /etc/apk/keys/ && apk add vim=9.2.1202-r0" "trusted keys" || return 1
  planted "wget -O into /etc/apk/keys" 1 "$A
RUN wget -O /etc/apk/keys/x.rsa.pub https://mirror.example/x.rsa.pub && apk add vim=9.2.1202-r0" "trusted keys" || return 1
  planted "ADD onto /etc/apk/keys" 1 "$A
ADD https://mirror.example/x.rsa.pub /etc/apk/keys/x.rsa.pub
RUN apk add vim=9.2.1202-r0" "trusted keys" || return 1
  planted "-X attached to its URL" 1 "$A
RUN apk add --no-cache $G -Xhttps://dl-cdn.alpinelinux.org/alpine/edge/community vim" "another repository" || return 1
  planted "-X inside a short cluster (-uX url)" 1 "$A
RUN apk add --no-cache $G -uX https://dl-cdn.alpinelinux.org/alpine/edge/community vim" "another repository" || return 1
  planted "--repository=URL attached" 1 "$A
RUN apk add --no-cache $G --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community vim" "another repository" || return 1
  planted "--repositories-file=FILE attached" 1 "$A
RUN apk add --no-cache $G --repositories-file=/tmp/r vim" "another repository" || return 1
  planted "--keys-dir DIR" 1 "$A
RUN apk --keys-dir /tmp/keys add --no-cache $G" "trusted keys" || return 1
  planted "--keys-dir=DIR attached" 1 "$A
RUN apk --keys-dir=/tmp/keys add --no-cache $G" "trusted keys" || return 1
  planted "COPY onto /etc/apk itself" 1 "$A
COPY conf /etc/apk
RUN apk add $G" "repository list" || return 1
  planted "COPY into /etc/apk/ (trailing slash)" 1 "$A
COPY conf/ /etc/apk/
RUN apk add $G" "repository list" || return 1
  planted "cp -r onto /etc/apk" 1 "$A
RUN cp -r conf /etc/apk && apk add $G" "repository list" || return 1
  planted "RUN --mount of /etc/apk" 1 "$A
RUN --mount=type=bind,source=conf,target=/etc/apk apk add $G" "repository list" || return 1
  planted "a redirect into /etc/apk/repositories by a command that normally only reads (cat >)" 1 "$A
RUN cat extra > /etc/apk/repositories && apk add $G" "repository list" || return 1
  planted "a plain read of /etc/apk/repositories is not a write" 0 "$A
RUN cat /etc/apk/repositories && apk add vim=9.2.1202-r0" || return 1
  planted "if grep on /etc/apk/repositories with 2>/dev/null is not a write" 0 "$A
RUN if grep -q x /etc/apk/repositories 2>/dev/null; then apk add vim=9.2.1202-r0; fi" || return 1
  planted "apk -p DIR add (an option with an argument) is read and passes the coverage check" 0 "$A
RUN apk -p /sysroot add vim=9.2.1202-r0" || return 1
  planted "apk --root DIR add passes the coverage check" 0 "$A
RUN apk --root /sysroot add vim=9.2.1202-r0" || return 1
  # a form the parser does not read must not become a silent green (the coverage cross-check)
  planted "apk add inside a heredoc RUN" 1 "$A
RUN apk add $G
RUN <<EOF
apk add vim=9.2.1202-r0
EOF" "parser read" || return 1
  planted "apk add inside sh -c" 1 "$A
RUN apk add $G
RUN sh -c \"apk add vim=9.2.1202-r0\"" "parser read" || return 1

  # ADR-0031 V9: the two planted-bad fixtures keep their meaning (two pins each, the bad one red)
  for fx in e2e-pin-BAD e2e-pin-BAD-continued; do
    n=$((n + 1))
    got="$(parse "scripts/testdata/$fx.txt" | awk -F'\t' '$5 == "pin" { print $6 "=" $7 }' | sort | tr '\n' ' ')"
    [ "$got" = "chromium=1.0.0-r0 font-wqy-zenhei=0.9.46-r0 " ] || { echo "FAIL: selftest: fixture $fx parses to '$got'"; return 1; }
    check_files "scripts/testdata/$fx.txt" >"$tmp/out" 2>&1; rc=$?
    if [ "$rc" -ne 1 ] || ! grep -q 'chromium=1.0.0-r0 is not in the index' "$tmp/out" || ! grep -q 'bump the pin' "$tmp/out"; then
      echo "FAIL: selftest: fixture $fx exited $rc"; cat "$tmp/out"; return 1
    fi
    echo "  fixture ($fx): 2 pins read, chromium=1.0.0-r0 red, exit 1"
  done
  # the wrapper without an argument checks Dockerfile.e2e only (a stand-in docker that prints nothing: every pin is 'gone')
  n=$((n + 1))
  mkdir -p "$tmp/bin"; printf '#!/bin/sh\nexit 0\n' >"$tmp/bin/docker"; chmod +x "$tmp/bin/docker"
  PATH="$tmp/bin:$PATH" ./scripts/check-e2e-pins.sh >"$tmp/out" 2>&1; rc=$?
  if [ "$rc" -ne 1 ] || ! grep -q '^FAIL: Dockerfile.e2e:' "$tmp/out" || grep -q 'images/' "$tmp/out"; then
    echo "FAIL: selftest: check-e2e-pins.sh without an argument did not check Dockerfile.e2e alone (exit $rc)"; cat "$tmp/out"; return 1
  fi
  echo "  wrapper (check-e2e-pins.sh, no argument): Dockerfile.e2e only, exit 1"
  # the stub index is per base only in the sense that it returns the same text; per-base
  # attribution is covered by the parse tables above.

  # a base without apk is a verdict (exit 1), not trouble
  query_index() { return 3; }
  planted "the base has no apk (query_index rc 3)" 1 "$A
RUN apk add vim=9.2.1202-r0" "has no apk" || return 1
  # the stand-in for 'docker is missing' must be exit 2, not a pass
  query_index() { echo "docker is not installed (stub)" >&2; return 2; }
  planted "docker/network trouble is exit 2, not 0" 2 "$A
RUN apk add vim=9.2.1202-r0" || return 1
  echo "ok: selftest — $n checks (parse tables, planted defects red, clean cases green, --lint goes red on a planted grammar / no-pin / coverage defect)"
  return 0
}

# --- entry ------------------------------------------------------------------------------
case "${1:-}" in
  --selftest) selftest; exit $? ;;
  --lint)
    shift
    if [ "$#" -eq 0 ]; then
      files=(); while IFS= read -r f; do files+=("$f"); done < <(tracked)
      [ "${#files[@]}" -gt 0 ] || { echo "FAIL: no tracked Dockerfile (a check that looked at nothing is not a pass)"; exit 1; }
    else
      for f in "$@"; do [ -f "$f" ] || { echo "FAIL: check-apk-pins --lint: $f not found"; exit 1; }; done
      files=("$@")
    fi
    lint_files "${files[@]}"; rc=$?
    [ "$rc" -eq 2 ] && exit 2
    exit "$rc" ;;
  --parse)
    shift
    if [ "$#" -eq 0 ]; then
      files=(); while IFS= read -r f; do files+=("$f"); done < <(tracked)
      [ "${#files[@]}" -gt 0 ] || { echo "FAIL: no tracked Dockerfile" >&2; exit 1; }
      parse "${files[@]}"
    else
      for f in "$@"; do [ -f "$f" ] || { echo "check-apk-pins: $f not found" >&2; exit 1; }; done
      parse "$@"
    fi
    exit $? ;;
  -*) echo "usage: $0 [--parse|--lint|--selftest] [FILE...]" >&2; exit 2 ;;
esac

if [ "$#" -gt 0 ]; then
  for f in "$@"; do [ -f "$f" ] || { echo "check-apk-pins: $f not found" >&2; exit 1; }; done
  check_files "$@"
else
  files=(); while IFS= read -r f; do files+=("$f"); done < <(tracked)
  [ "${#files[@]}" -gt 0 ] || { echo "FAIL: no tracked Dockerfile (a check that looked at nothing is not a pass)"; exit 1; }
  check_files "${files[@]}"
fi
exit $?
