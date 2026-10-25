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
# Fails on a range (`>=` `>` `<` `<=` `~`), a repository tag (`name@edge`), `--repository` /
# `-X` / `--repositories-file`, `--allow-untrusted`, a write to /etc/apk/repositories or
# /etc/apk/keys (a RUN command that names the path and is not a plain read — cat grep head
# tail wc ls stat test diff — or has a `>`; any COPY / ADD naming it), and on a version or
# package taken from a shell variable (not checkable). A bare `apk add name` is allowed.
# The path rule is a net, not a proof: `cd /etc/apk && echo x > repositories` is not seen. Reads: `\` continuations, quotes, several commands in one RUN
# (`apk del ... && apk add ...`), `--upgrade`, `RUN ["apk","add",...]`, apk in a
# non-first stage, `FROM <stage>` inheritance. It does NOT read heredoc RUNs.
#
#   scripts/check-apk-pins.sh               every tracked *Dockerfile* (derived)
#   scripts/check-apk-pins.sh FILE...       just these (the planted fixtures under
#                                           scripts/testdata/e2e-pin-*.txt are not
#                                           Dockerfiles, so the derivation never sees them)
#   scripts/check-apk-pins.sh --parse [FILE...]   print the parse table (TSV) and exit 0;
#                                           offline, for fixtures and for later checks
#   scripts/check-apk-pins.sh --selftest    offline: planted defects must fail, the real
#                                           tree's grammar must pass
#
# Needs Docker and network (not --parse / --selftest). No Docker is a FAIL (exit 2) with
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
    # apk options that change where packages come from or whether they are verified:
    # called on t[k]; returns how many following tokens it consumed.
    function apk_opt(k,    p) {
      p = t[k]
      if (p == "--allow-untrusted") { emit("untrusted", "-", p, 0); return 0 }
      if (p == "-X" || p == "--repository" || p == "--repositories-file") { emit("repo", "-", p " " t[k + 1], 0); return 1 }
      if (p ~ /^--repository=/ || p ~ /^--repositories-file=/) { emit("repo", "-", p, 0); return 0 }
      return 0
    }
    # A command (segment) that mentions apk'"'"'s repository list or key directory and is not a
    # plain read is a write to it: echo/printf/sed -i/tee/cp/mv/wget/curl/... or any `>`.
    function seg_flush() {
      if (sr != "" && (!(sf in ro) || sg)) emit("reposfile", "-", sr, 0)
      if (sk != "" && (!(sf in ro) || sg)) emit("keysfile", "-", sk, 0)
      sf = ""; sg = 0; sr = ""; sk = ""
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
              if (t[j] == "-p" || t[j] == "--root" || t[j] == "--arch" || t[j] == "--keys-dir" || \
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
      # second pass over the same tokens: writes to apk'"'"'s repository list / keys
      sf = ""; sg = 0; sr = ""; sk = ""
      for (k = 1; k <= n + 1; k++) {
        tok = (k <= n ? t[k] : ";")
        if (tok == "") continue
        if (tok == ";") { seg_flush(); continue }
        if (sf == "") sf = tok
        if (index(tok, ">") > 0) sg = 1
        if (index(tok, "/etc/apk/repositories") > 0) sr = tok
        if (index(tok, "/etc/apk/keys") > 0) sk = tok
      }
    }
    function instr_done(s,    w) {
      w = s; sub(/^[ \t]+/, "", w); sub(/[ \t].*$/, "", w); w = toupper(w)
      if (w == "FROM") from_instr(s)
      else if (w == "RUN") run_instr(s)
      else if (w == "COPY" || w == "ADD") {                        # also a way to write them
        if (index(s, "/etc/apk/repositories") > 0) emit("reposfile", "-", w " ... /etc/apk/repositories", 0)
        if (index(s, "/etc/apk/keys") > 0) emit("keysfile", "-", w " ... /etc/apk/keys", 0)
      }
    }
    BEGIN { split("cat grep head tail wc ls stat test [ diff", ro_words, " "); for (w in ro_words) ro[ro_words[w]] = 1 }
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
coverage() { # rows-file, files...
  local rows="$1" text parsed f
  shift
  text=0
  for f in "$@"; do
    text=$((text + $({ grep -vE '^[[:space:]]*#' "$f" | grep -oE 'apk[[:space:]]+(-[^[:space:]]+[[:space:]]+)*add([[:space:]]|$)' || true; } | wc -l)))
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

# --- the check --------------------------------------------------------------------------
# check_files FILE... : prints findings, returns 0 / 1 / 2 (see the header).
check_files() {
  local rows tmp status infra files_n pins_n cov text_n parsed_n base names policy qrc
  local file line stage kind name version listed bases_n bases idx
  status=0; infra=0
  files_n=$#
  tmp="$(mktemp -d)" || return 2
  rows="$tmp/rows"
  parse "$@" >"$rows" || { echo "FAIL: the parser failed" >&2; rm -rf "$tmp"; return 2; }

  # grammar (D1)
  while IFS=$'\t' read -r file line stage _ kind _ version _; do
    case "$kind" in
      range) echo "FAIL: $file:$line [$stage] '$version' — a version range; the only version syntax is exact name=version (ADR-0036 D1)"; status=1 ;;
      edge)  echo "FAIL: $file:$line [$stage] '$version' — a repository tag (@edge etc.) is not allowed (ADR-0036 D1)"; status=1 ;;
      repo)  echo "FAIL: $file:$line [$stage] '$version' — another repository is not allowed (ADR-0036 D1)"; status=1 ;;
      untrusted) echo "FAIL: $file:$line [$stage] '$version' — turns off signature verification (ADR-0036 security condition F4)"; status=1 ;;
      reposfile) echo "FAIL: $file:$line [$stage] '$version' — writes apk's repository list, which decides where every unpinned package comes from (ADR-0036 security condition F4)"; status=1 ;;
      keysfile)  echo "FAIL: $file:$line [$stage] '$version' — writes apk's trusted keys (ADR-0036 security condition F4)"; status=1 ;;
      var)   echo "FAIL: $file:$line [$stage] '$version' — a shell variable in apk add cannot be checked against the index"; status=1 ;;
      bad)   echo "FAIL: $file:$line [$stage] '$version' — name= with no version (or no name)"; status=1 ;;
    esac
  done <"$rows"

  # fail-closed: a check that looked at nothing is not a pass
  pins_n="$(awk -F'\t' '$5 == "pin"' "$rows" | wc -l | tr -d ' ')"
  if [ "$pins_n" -eq 0 ]; then
    echo "FAIL: no apk exact pin found in $files_n file(s) (a check that looked at nothing is not a pass)"
    status=1
  fi
  cov="$(coverage "$rows" "$@")"
  text_n="${cov% *}"; parsed_n="${cov#* }"
  if [ "$text_n" != "$parsed_n" ]; then
    echo "FAIL: the text has $text_n 'apk add' occurrence(s) but the parser read $parsed_n; a form it does not read can hide a pin — extend parse() in $0"
    status=1
  fi

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
  local tmp n rc realfiles cov f
  tmp="$(mktemp -d)" || return 2
  trap 'rm -rf "$tmp"' RETURN
  n=0
  # A stand-in index (no docker, no network). Each `apk policy` block is what Alpine prints.
  POLICY_TEXT="$(printf '%s\n' \
    'vim policy:' '  9.2.1202-r0:' '    https://dl-cdn.alpinelinux.org/alpine/v3.24/community' \
    'zlib policy:' '  1.3.2-r0:' '    lib/apk/db/installed' '  1.3.2-r1:' '    https://dl-cdn.alpinelinux.org/alpine/v3.24/main' \
    'chromium policy:' '  155.0.8059.84-r0:' '    https://dl-cdn.alpinelinux.org/alpine/v3.24/community')"
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

  # the real tree: grammar holds, something was found, the parser sees every `apk add`
  # (offline: the index is the stub, so only the vanished-version rows may be red)
  realfiles=()
  while IFS= read -r f; do realfiles+=("$f"); done < <(tracked)
  [ "${#realfiles[@]}" -gt 0 ] || { echo "FAIL: selftest: no tracked Dockerfile"; return 1; }
  parse "${realfiles[@]}" >"$tmp/real"
  if awk -F'\t' '$5 ~ /^(range|edge|repo|var|bad|untrusted|reposfile|keysfile)$/' "$tmp/real" | grep -q .; then
    echo "FAIL: selftest: the real tree has a grammar violation"; awk -F'\t' '$5 ~ /^(range|edge|repo|var|bad|untrusted|reposfile|keysfile)$/' "$tmp/real"; return 1
  fi
  [ "$(awk -F'\t' '$5 == "pin"' "$tmp/real" | wc -l | tr -d ' ')" -gt 0 ] || { echo "FAIL: selftest: the real tree yields no pin"; return 1; }
  cov="$(coverage "$tmp/real" "${realfiles[@]}")"
  [ "${cov% *}" = "${cov#* }" ] || { echo "FAIL: selftest: the real tree: text has ${cov% *} apk add, parser read ${cov#* }"; return 1; }
  echo "  real tree: $(awk -F'\t' '$5 == "pin"' "$tmp/real" | wc -l | tr -d ' ') pin(s) in $(awk -F'\t' '{print $1}' "$tmp/real" | sort -u | wc -l | tr -d ' ') file(s), grammar clean, ${cov% *} apk add read"

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
  planted "a version range >=" 1 "$A
RUN apk add --no-cache 'vim>=9.2'" || return 1
  planted "a version range ~" 1 "$A
RUN apk add --no-cache vim~9.2" || return 1
  planted "a version range =~ (fuzzy)" 1 "$A
RUN apk add --no-cache vim=~9.2" || return 1
  planted "@edge tag" 1 "$A
RUN apk add --no-cache vim@edge" || return 1
  planted "--repository" 1 "$A
RUN apk add --no-cache --repository https://dl-cdn.alpinelinux.org/alpine/edge/community vim" || return 1
  planted "a version from a shell variable" 1 "$A
RUN apk add --no-cache vim=\${VIM_VERSION}" || return 1
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
  planted "a plain read of /etc/apk/repositories is not a write" 0 "$A
RUN cat /etc/apk/repositories && apk add vim=9.2.1202-r0" || return 1
  # the stub index is per base only in the sense that it returns the same text; per-base
  # attribution is covered by the parse tables above.

  # the stand-in for 'docker is missing' must be exit 2, not a pass
  query_index() { echo "docker is not installed (stub)" >&2; return 2; }
  planted "docker/network trouble is exit 2, not 0" 2 "$A
RUN apk add vim=9.2.1202-r0" || return 1
  echo "ok: selftest — $n checks (parse tables, planted defects red, clean cases green, real tree grammar clean)"
  return 0
}

# --- entry ------------------------------------------------------------------------------
case "${1:-}" in
  --selftest) selftest; exit $? ;;
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
  -*) echo "usage: $0 [--parse|--selftest] [FILE...]" >&2; exit 2 ;;
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
