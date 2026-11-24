# 50 — nimbus-desk Triage (調査 A)

防御側シナリオ (モジュール `scenarios/ir-nimbus-desk/`) の最初の調査型の課題
(ADR-0056 の `type: investigate`)。参加者は、架空の事案で保全された痕跡
(`/srv/ir/evidence/`) を読み、portal の回答欄で 4 問に答える。全問正解で solve。
攻撃の操作はしない。Falco のルールも発火させない。

## 設問と答えの出どころ

| id | format | 席ごと | 答えの出どころ |
|---|---|---|---|
| `first-shell` | `timestamp` (窓 600 秒) | 可 | `falco-events.jsonl` の Run shell untrusted のうち、`container.name` が nimbus-desk の行の最も早い `time` |
| `cred-file` | `path` | 可 | 同じ container の Read sensitive file untrusted 2 件のうち、設定 (`conf/`) でない方の `fd.name` |
| `bundle-file` | `path` | 可 | `fs-inventory.tsv` で、資格情報の読み取り (17:19 台) と最初の送信の拒否 (17:23 台) の間に mtime がある file。size は読まれた 2 file の和 |
| `event-order` | `sequence` (7 から 6) | 不可 | 固定: 下の時系列。`binary-drop` は起きていない (その rule は別の container の build-runner だけ) |

答えの値は、ここにも journey にも書かない。練習版の値は `edition/practice/answers.tsv`
(`make edition-practice CID=50-nimbus-desk-triage` の生成物)、イベント版の値は platform 側の
render で席ごとに作る (ADR-0056 D8 / D12)。

## 想定解 (手順)

```bash
cd /srv/ir/evidence
cat preservation-note.txt
# Q1
jq -r 'select(.rule == "Run shell untrusted" and .output_fields["container.name"] == "nimbus-desk") | .time' falco-events.jsonl | sort | head -n 1
# Q2
jq -r 'select(.rule == "Read sensitive file untrusted" and .output_fields["container.name"] == "nimbus-desk") | [.time, .output_fields["fd.name"]] | @tsv' falco-events.jsonl
# Q3
sort -t "$(printf '\t')" -k2,2 fs-inventory.tsv | grep -v '^#'
grep 'verdict=deny' egress-gateway.log | grep nimbus-desk
# Q4: 各出来事の根拠の時刻を並べる
jq -r 'select(.output_fields["container.name"] == "nimbus-desk") | [.time, .rule] | @tsv' falco-events.jsonl | sort
grep -E 'level=(fatal|error)|starting' nimbus-desk.log
```

## 練習版の時系列 (固定の部分)

時刻は `time.base` = 2026-10-21T17:00:00Z からの位置。最初の shell (Q1) だけが席ごとの値で、
[17:00:00, 17:10:00) の中にある。以後の出来事はすべて 17:10 より後の固定の時刻なので、
順序は値に依存しない。

1. `shell-start` — Run shell untrusted (nimbus-desk、親 nimbus-desk)。Q1 の時刻。続けて 17:11:48・17:14:07 にも同じ rule
2. `api-probe` — 17:15:32 Contact K8S API Server From Container (nimbus-desk、wget、親 sh)。目録の `/home/desk/.wget-hsts` も同じ時刻
3. `secret-read` — 17:18:44 設定、17:19:02 資格情報 (Read sensitive file untrusted、cat、親 sh)
4. `bundle-write` — 17:21:16 (目録の mtime だけ。アラートなし、container の log にも対応する行なし)
5. `egress-fail` — 17:23:40〜17:24:11 egress gateway の deny (宛先は文書用の範囲の address と `.example` の名前)
6. `app-restart` — 17:31:09 fatal と desk-init の再起動、17:31:12 starting (process-list の STARTED も同じ)

## 囮とノイズ (設計)

- Q1: 同じ 10 分の窓に、別の container のアラート 10 件 (legacy-status の Run shell untrusted、
  node-metrics の Contact K8S API Server From Container、desk-keyrotate の読み取り、desk-logship、
  build-runner)。export は node ごとに連結され、時刻順でない。
- Q2: 資格情報の file の候補 11 個 (答え + 囮 10) が目録にあり、うち 4 個はサイドカー
  desk-keyrotate (別の container) が読んでアラートになっている。
- Q3: /tmp の候補 11 個。囮 10 個は incident の外の時刻に web service 自身が書いた一時 file で、
  container の log に対応する行がある。
- 席ごとの format (timestamp・path) の別々の token は、束 1 つに 50 個を超える (log・目録・アラート)。

## 解説

- L1: アラートは「何の rule が・どの container で・どの process (親子) に」出たかを、
  output_fields で絞って読む。DaemonSet の Falco は node ごとに記録するので、export は時刻順でない。
- L2: 内容をまとめる操作 (Collection) はアラートにならない。目録の mtime / size と、
  アプリの log に「対応する行が無い」ことから見つける。
- 運用の設定 (preservation-note.txt): nimbus-desk を「shell を起こしてはならない process」の list に、
  設定と資格情報の file を sensitive な file の list に足してある。default の rule は、
  サイトの list を足して初めてこのサービスに効く。一方で desk-keyrotate の読み取りは除外されて
  おらず、ノイズになっている (除外を足すと、その穴は攻撃者にも開く)。
