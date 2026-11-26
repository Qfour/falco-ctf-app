# 50 — nimbus-desk Triage (調査 A)

防御側シナリオ (モジュール `scenarios/ir-nimbus-desk/`) の最初の調査型の課題
(ADR-0056 の `type: investigate`)。参加者は、架空の事案で保全された痕跡
(`/srv/ir/evidence/`) を読み、portal の回答欄で 4 問に答える。全問正解で solve。
攻撃の操作はしない。Falco のルールも発火させない。

## 設問と答えの出どころ

| id | format | 席ごと | 答えの出どころ |
|---|---|---|---|
| `first-shell` | `timestamp` (窓 2520 秒) | 可 | `falco-events.jsonl` の Run shell untrusted のうち、`container.name` が nimbus-desk の行の最も早い `time` |
| `cred-file` | `path` | 可 | Read sensitive file untrusted のうち、親 (`proc.pname`) が sh の 2 件 (侵入者の読み取り) で、設定 (`conf/`) でない方の `fd.name` |
| `bundle-file` | `path` | 可 | `fs-inventory.tsv` で、資格情報の読み取り (17:19 台) と最初の送信の拒否 (17:23 台) の間に mtime がある file。size は読まれた 2 file の和 |
| `survey-file` | `path` | 可 | `fs-inventory.tsv` で、最初の shell (Q1) と設定の file の読み取り (17:18:44) の間に mtime があり、`nimbus-desk.log` に同じ時刻の行が無い file |

4 問とも席ごとの値で、固定の設問は無い。`survey-file` は、以前の固定の `event-order`
(`sequence`) の置き換えである (ADR-0056 追補 26: 固定の設問の答えは、イベント版で練習版と違う値に
できる形に限る。物語の順そのものを答えにする `sequence` は、その形にならない)。出来事の順序を再構成
する学び (L1) は、`survey-file` の答えを特定する過程に残した: アラートの時刻を区切りにして、目録と
container の log を同じ 1 本の時系列に並べないと、囮と区別できない。

設計の前提 (ADR-0056 追補 27): template は公開で、render は行を並べ替えないので、練習版では公開の
template から答えの行の位置が分かる (この README の想定解と同じく、練習版の解き方は公開である)。
イベント版は原稿の構造を変える (B4 (2) が写しを、B18 が答えの行の形の流用を拒否する)。

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
# Q3 / Q4: 目録を mtime で並べ、アラートの時刻と container の log の時刻を重ねる
sort -t "$(printf '\t')" -k2,2 fs-inventory.tsv | grep -v '^#'
grep 'verdict=deny' egress-gateway.log | grep nimbus-desk
jq -r 'select(.output_fields["container.name"] == "nimbus-desk") | [.time, .rule] | @tsv' falco-events.jsonl | sort
```

## 練習版の時系列

時刻は `time.base` = 2026-10-21T16:28:00Z からの位置。最初の shell (Q1) だけが席ごとの時刻で、
窓 [16:28:00, 17:10:00) の中にある。事案の始まりはその前の固定の時刻、以後の出来事はすべて
17:10 より後の固定の時刻なので、順序は値に依存しない。

0. 事案の始まり — 16:15:12 container の log に通常と違う要求 (preview の 500) が始まる。16:27 まで
   固定の時刻で続き、窓の中にも filler の時刻で続く。16:15〜16:19 に web service 自身が
   /home/desk の下に file を 9 個書く (Q4 の囮の A 組。log に行が無い)
1. 最初の shell — Run shell untrusted (nimbus-desk、親 nimbus-desk)。Q1 の時刻。続けて 17:11:48・17:14:07 にも同じ rule
2. API server への接続 — 17:15:32 Contact K8S API Server From Container (nimbus-desk、wget、親 sh)
3. 調べた結果の書き出し — 17:16:51 (目録の mtime だけ。アラートなし、container の log にも対応する行なし)。Q4
4. 読み取り — 17:18:44 設定、17:19:02 資格情報 (Read sensitive file untrusted、cat、親 sh)。Q2
5. まとめた file — 17:21:16 (目録の mtime だけ)。Q3
6. 送信の拒否 — 17:23:40〜17:24:11 egress gateway の deny (宛先は文書用の範囲の address。接続の時点で拒否したので host 名は記録に無い = `dst_name=-`。host 名は調査 B = 51 の設問で、この束からは導けない)
7. 異常終了と再起動 — 17:31:09 fatal と desk-init の再起動 (17:31:10〜11 に desk-migrate の確認)、17:31:12 starting (process-list の STARTED も同じ)

## `time.base` と窓 (ADR-0056 追補 26 の B16)

- この版の窓: `time.base` = 2026-10-21T16:28:00Z、`window: {from: 0, to: 2520}` = **16:28:00〜17:09:59**
  (UTC、2520 秒 = 42 分)。幅の計算: 設計の席の数 60 × 2 × 21 (答えと囮 K = 20。Q1 を block にする
  後の PR で、組の値が席の間で重ならない下限 S ≥ 2N(K + 1) = B8 (a2) になる。ADR-0056 追補 29)。
  `catalog` の `params.windowSeconds` も 2520 (E2: 答えの窓の幅と一致)。窓の `from` は 0 以上
  (E1: `spec.go` の `validateWindow`) なので、`time.base` を窓の始まりに置く。
- 窓の中に、この課題と 51 (時系列を共有する) の template の literal の時刻は 1 つも無い。窓の中の
  雑音 (ほかの container のアラート 9 件、container の log の 16 行、そのうち 4 行と同じ時刻を持つ
  Q3 の囮の mtime 4 件) は、filler の slot `q1w-*` で書いている。filler はそれぞれ窓の中の小さな窓を
  持ち、log の行の順と、Q3 の囮と log の行の時刻の一致は保つ。51 の束には、この窓の時刻が 1 つも無い
  (filler も置かない。B13: Q1 の答えの時刻が 51 の束に現れないため)。そのため 51 の記録と
  共有の `egress-gateway.log` は、16:27:13 から 17:10:00 まで行が無い。
- 窓を 600 秒から広げたとき、窓に入った固定の記録は 3 通りに直した。(a) 50 だけの記録 (log の
  health check 3 行、ほかの container のアラート 4 件) は filler にした。(b) 共有の gateway の記録か
  51 の記録と組の記録 (webhook・mail・backup・legacy-status の確認・link の確認とその取得・docs の
  取得、T-48801 の comment、/api/tickets の要求、legacy-status の shell のアラート) は、両課題で同じ
  文字列のまま、窓の前の 16:10:00〜16:27:13 に動かした (共有の file は印を持てない: B14。51 の
  literal の時刻は 50 の literal の時刻: B15)。node-metrics の 1 件の接続とその問い合わせは消した。
  (c) 事案の始まりの記録 (preview の 500 と render の失敗の 6 行) と Q4 の A 組の mtime 9 件は、
  40 分前 (16:15〜16:19) に動かした (間隔は変えない)。窓の中で preview の要求が続くように、
  filler の行を 4 行 (preview 3・render の失敗 1)、窓の前に literal の行を 2 行足した。
- 窓の後の最初の固定の event (nimbus-desk の container): 2 回目の Run shell untrusted が **17:11:48**
  (Q1 の「最初」の条件。窓の最後の秒との差は 109 秒)。
- 窓の前の固定の記録: container の log の通常と違う要求の始まりが 16:15:12。Q4 の囮の A 組
  (16:15〜16:19) は、その後で窓の前にある (どの席の最初の shell よりも前)。
- イベント版は、この template を写さない (B4 (2) が写しを、追補 27 の B18 が答えの行の形の流用を
  拒否する)。イベント版の原稿は書き直しが前提。`time.base` を
  動かすなら、この課題と 51 の template の literal の時刻をすべて同じだけずらし、51 の `time.base` も
  同じ値にする。ずらさずに `time.base` だけを動かすと、窓が literal の時刻を含み、B16 で止まる
  (`edition check` の B16 が検査する。A7-x の PR 3)。窓の幅を変えるとき (席の数が変わるとき) も、
  窓の端を固定の時刻の前後に保つ: 窓の前に事案の始まりと Q4 の A 組、窓の後に 2 回目の shell。

## 51 と揃えているもの (追補 26 の B13〜B15)

- B13: この課題の席ごとの答え (最初の shell の時刻、資格情報・まとめた file・調べた結果の file の
  path) は、51 の束に出ない。51 の答え (host 名) は、この束に出ない。
- B14: `egress-gateway.log` は 51 と byte で同じ内容で、slot の印を持たない。宣言
  (`investigate.evidence.shares`) は 51 の側に在る (A7-x の PR 3)。ただし、この課題の `falco-events.jsonl`
  と 51 の `falco-alerts.jsonl` が同じアラートの行を逐語で持ち、B14 の shingle の規則を満たさない
  (既知の違反。51 の書き直し = PR 6 で直す)。
- B15: 51 の template の literal の時刻は、すべてこの template の literal の時刻のどれかと同じ文字列。

## 囮とノイズ (設計)

- Q1: 同じ 42 分の窓に、**同じ rule・同じ node** (node-b) の別の Pod のアラートが 10 件
  (legacy-status・status-page・docs-portal の httpd の下の health / 保守の script)。窓の前にも
  legacy-status の 1 件。node や rule だけでは絞れず、container で絞って初めて決まる。container
  だけで「最も早い」を取ると、16:00 の desk-migrate の読み取りになる (rule も要る)。export は
  時刻順でない。
- Q2: 資格情報の file の候補 11 個 (答え + 囮 10) が目録にあり、11 個とも、同じ Pod の中で何度も
  読まれてアラートになっている: desk-migrate (**同じ container**、親 desk-init) が 16:00 と再起動の時に
  11 個すべて、サイドカー desk-keyrotate が侵入者の読み取りの約 1 分後の sweep で 11 個すべて。
  node・container・rule・時刻のどれ 1 つで絞っても 11 個が残り、親 (sh) まで見て初めて決まる。
- Q3: /tmp の候補 11 個。囮 10 個は、すべて同じ時間帯 (17:00〜17:29) に web service 自身が書いた
  一時 file で、読み取りから拒否までの間 (17:19:02〜17:23:40) の外にあり、container の log に
  同じ時刻・同じ bytes の行がある。直前と直後の囮は答えから 1〜3 分しか離れていない。
- Q4: /home/desk の下の候補 21 個 (答え + 囮 20)。囮は web service 自身の file で、3 組に分けた。
  (A) log の最初の異常な要求 (16:15:12) から 16:20 までの 9 個 (事案の始まりの後、どの席の最初の
  shell よりも前 = Q1 の窓の始まり 16:28 より前)、log に行が無い。間隔は揃えていない。(B) API server への接続 (17:15:32) から設定の
  読み取り (17:18:44) までの 9 個 (どの席でも最初の shell の後)、それぞれ container の log に同じ
  時刻・同じ bytes の行がある。(C) 最初の送信の拒否 (17:23:40) より後の 2 個、log に行が無い。
  Q3 の間 (17:19:02〜17:23:40) には Q4 の候補を置いていない (Q3 の一意性は変わらない)。log に行が無い
  `/srv/nimbus-desk/run/*.state` の 6 個 (17:24〜17:31、固定の行) も足した。以前の目録にあった
  `/home/desk/.wget-hsts` (wget が自分で書く file) は、Q4 の答えと紛れるので外した。
- 席ごとの format (timestamp・path) の別々の token は、束 1 つに 50 個を超える (log・目録・アラート)。
- アラートの export は `tags` を持たない (全部の行。51 の束も同じ)。default の rule の tags には
  ATT&CK の Tactic の名前が入り、51 の「Tactic から段を決める」が grep 1 回で済んでしまうため。

### 手がかり 1 つだけで絞ったときに残る候補 (答えを含む件数)

| 手がかり | Q1 first-shell | Q2 cred-file | Q3 bundle-file | Q4 survey-file |
|---|---|---|---|---|
| node だけ (node-b) | 11 (窓の中の shell の起動) | 11 | — (目録は 1 container) / 11 | — / 21 |
| container だけ (nimbus-desk) | 11 以上 (別々の時刻) | 11 | 11 | 21 |
| rule の種類だけ | 11 (窓の中) | 11 | — (アラートなし) / 11 | — (アラートなし) / 21 |
| 時刻の窓だけ (Q1 は答えの窓 16:28〜17:10、ほかは 17:00〜17:31) | 20 (窓の中のアラート) | 11 (sweep) | 11 | 12 |
| path の dir だけ | — | 11 (conf でない) | 11 (/tmp の下) + 1 | 21 (/home/desk の下の同じ形) + 1 (.profile) |
| container の log に行が無いことだけ | — | — | 1 + 12 (Q4 の候補) + 6 (run の state) | 12 + 1 (Q3 の答え) + 6 |

Q4 は、固定の時刻を起点にした「その時刻より後 / 前」と手がかりの組を、起点ごとに全部数えた
(/home/desk の下の同じ形の path。答えを含む件数。prompt の条件は「設定の読み取りより前」)。

| 起点 | 単独 | + log に行が無い | + prompt | + 最初の拒否より前 | + prompt + log 無し |
|---|---|---|---|---|---|
| 事案の始まり (16:15:12) より後 | 21 | 12 | 19 | 19 | 10 |
| 最初の shell (Q1)・2 回目の shell・17:14:07 の shell・API server への接続より後 | 12 | **3** | 10 | 10 | **1** |
| 設定 / 資格情報の読み取り・最初の拒否より前 | 19 | 10 | 19 | 19 | 10 |
| 保全 (17:49:50) より前 | 21 | 12 | 19 | 19 | 10 |
| (起点なし) dir だけ | 21 | 12 | 19 | 19 | 10 |
| (起点なし) 時刻の窓 17:00〜17:31 | 12 | **3** | 10 | 10 | **1** |
| (起点なし) Q1 の答えの窓の始まり (16:28) より後 | 12 | **3** | 10 | 10 | **1** |

dir を使わないとき (全部の path): 「侵入者の段より後 + log に行が無い」で 10 (答え、C の 2、Q3 の
答え、run の state 6)。10 件未満の組は、どれも **侵入者の段の後 (最初の shell との前後、またはそれより
後の段) と、log の突き合わせ (同じ時刻・同じ bytes の行が無い)** の両方を使っていて、これが決め手で
ある。17:00 からの窓と、Q1 の答えの窓の始まり (16:28) からの窓は、どちらも A 組 (16:15〜16:19) だけを
外し、最初の shell より後と同じ 12 件を残す (Q4 の候補は 16:20〜17:15 に 1 つも無い。B 組と答えは
17:15:41 以後で、どの席の最初の shell よりも後)。つまり同じ順序の手がかりにあたる。窓を 600 秒から
2520 秒に広げても、この表の数は変わらない (A 組を窓の前に動かしたため)。

1 つで決まってしまう手がかり (残り): Q2 の `proc.name` (cat) は親の process と同じ系統の手がかり。
Q3 の「読み取りから拒否までの間」は、順序の再構成 (L1) の学びそのもの (意図して残している)。
以前は Q3 の「log に行が無い」が 1 つで決まる手がかりだったが、Q4 の候補と run の state も log に
行が無いので、今は dir と組み合わせて決まる。

## 解説

- L1: アラートは「何の rule が・どの container で・どの process (親子) に」出たかを、
  output_fields で絞って読む。DaemonSet の Falco は node ごとに記録するので、export は時刻順でない。
  アラートの時刻を区切りにして、目録と container の log を 1 本の時系列に並べると、アラートの
  あいだに挟まった出来事 (Q4) が見える。
- L2: 内容をまとめる操作 (Collection) や、調べた結果を書き出す操作はアラートにならない。目録の
  mtime / size と、アプリの log に「対応する行が無い」ことから見つける。
- 運用の設定 (preservation-note.txt): nimbus-desk を「shell を起こしてはならない process」の list に、
  設定と資格情報の file を sensitive な file の list に足してある。default の rule は、
  サイトの list を足して初めてこのサービスに効く。一方で desk-keyrotate と desk-migrate の読み取りは
  除外されておらず、ノイズになっている (除外を足すと、その穴は攻撃者にも開く)。
