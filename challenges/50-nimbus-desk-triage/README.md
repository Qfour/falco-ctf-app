# 50 — nimbus-desk Triage (調査 A)

防御側シナリオ (モジュール `scenarios/ir-nimbus-desk/`) の最初の調査型の課題
(ADR-0056 の `type: investigate`)。参加者は、架空の事案で保全された痕跡
(`/srv/ir/evidence/`) を読み、portal の回答欄で 4 問に答える。全問正解で solve。
攻撃の操作はしない。Falco のルールも発火させない。

## 設問と答えの出どころ

| id | format | 席ごと | 答えの出どころ |
|---|---|---|---|
| `first-shell` | `timestamp` (窓 600 秒) | 可 | `falco-events.jsonl` の Run shell untrusted のうち、`container.name` が nimbus-desk の行の最も早い `time` |
| `cred-file` | `path` | 可 | Read sensitive file untrusted のうち、親 (`proc.pname`) が sh の 2 件 (侵入者の読み取り) で、設定 (`conf/`) でない方の `fd.name` |
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
jq -r 'select(.rule == "Read sensitive file untrusted" and .output_fields["proc.pname"] == "sh") | [.time, .output_fields["fd.name"]] | @tsv' falco-events.jsonl
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
6. `app-restart` — 17:31:09 fatal と desk-init の再起動 (17:31:10〜11 に desk-migrate の確認)、17:31:12 starting (process-list の STARTED も同じ)

## `time.base` を動かさない (イベント版を作るときも)

template の時刻のうち、席ごとに値が変わるのは Q1 の slot `first` だけで、残りは書いてある文字列の
まま。`time.base` だけを後ろにずらすと、shell の起動が後ろの固定の event を追い越し、`event-order`
の固定の答えが証拠と矛盾する (誰も正答できない)。これを捕まえる機械は無い。

- **`time.base` は据え置く。変えるなら、template の全部の時刻を同じだけずらす。**
- この版の窓: `time.base` = 2026-10-21T17:00:00Z、`window: {from: 0, to: 600}` = **17:00:00〜17:09:59**
  (UTC、600 秒)。
- 窓の後の固定の event (nimbus-desk の container): 2 回目の Run shell untrusted が **17:11:48**
  (Q1 の「最初」の条件。窓の終わりとの差は 108 秒)、`api-probe` が **17:15:32** (`event-order`
  の順序の条件)。どちらも窓の全範囲より後。
- 窓の前の固定の記録: container の log の通常と違う要求の始まりが 16:55:12 (物語だけで、設問の
  順序には効かない)。窓は「通常と違う要求の後、2 回目の shell の前」に収まる。
- 機械で確かめる案 (未実装): `internal/edition` に、実課題の練習版について「`time.base` + `to` − 1 秒 <
  nimbus-desk の固定の Run shell untrusted の最も早い時刻」を、edition.yaml と
  `template/falco-events.jsonl` から計算して確かめる test を足す (課題に固有の test なので、
  `render_golden_test.go` の隣に新しい file を置くのがよい)。

## 囮とノイズ (設計)

- Q1: 同じ 10 分の窓に、**同じ rule** (Run shell untrusted) の別の container のアラートが 10 件
  (legacy-status・status-page・docs-portal の httpd の下の health / 保守の script)。窓の前にも
  legacy-status の 1 件。container で絞らないと、最も早いものは答えにならない。export は node
  ごとに連結され、時刻順でない。
- Q2: 資格情報の file の候補 11 個 (答え + 囮 10) が目録にあり、囮 10 個はすべて、同じ Pod の中で
  読まれてアラートになっている: 7 個はサイドカー desk-keyrotate (別の container、読み取りの時刻が
  侵入者の読み取りに近いものを含む)、3 個は再起動の時の desk-migrate (**同じ container**、親
  desk-init)。container で絞っても足りず、親 (sh) まで見ないと区別できない。
- Q3: /tmp の候補 11 個。囮 10 個は、すべて同じ時間帯 (17:00〜17:29) に web service 自身が書いた
  一時 file で、読み取りから拒否までの間 (17:19:02〜17:23:40) の外にあり、container の log に
  同じ時刻・同じ bytes の行がある。直前と直後の囮は答えから 1〜3 分しか離れていない。
- 席ごとの format (timestamp・path) の別々の token は、束 1 つに 50 個を超える (log・目録・アラート)。

## 解説

- L1: アラートは「何の rule が・どの container で・どの process (親子) に」出たかを、
  output_fields で絞って読む。DaemonSet の Falco は node ごとに記録するので、export は時刻順でない。
- L2: 内容をまとめる操作 (Collection) はアラートにならない。目録の mtime / size と、
  アプリの log に「対応する行が無い」ことから見つける。
- 運用の設定 (preservation-note.txt): nimbus-desk を「shell を起こしてはならない process」の list に、
  設定と資格情報の file を sensitive な file の list に足してある。default の rule は、
  サイトの list を足して初めてこのサービスに効く。一方で desk-keyrotate と desk-migrate の読み取りは
  除外されておらず、ノイズになっている (除外を足すと、その穴は攻撃者にも開く)。
