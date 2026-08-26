# 13 — Archive Loot (収集データの圧縮検知 / bonus)

本編 01–10 とは独立した **ボーナス課題** (11-cloud-cred-hunt / 12-cover-tracks
と同型)。テーマは MITRE ATT&CK **Collection / T1560.001** (Archive Collected
Data: Archive via Utility) — 侵入者がホスト上のあちこちから漁り集めたファイルを、
持ち出しやすくするために1本のアーカイブへまとめる典型的な動作を、新規の
custom Falco ルール `Archive Collected Data` (ADR-0017) で検知する。upstream
の default ruleset には Collection (T1005/T1560) をカバーするルールが無いため
(architect による実測、`falcosecurity/rules` タグ `falco-rules-3.0.1` を
grep して 0 件確認済み — 詳細は ADR-0017 Context)、project 史上 2 件目の
`customRules` 新設で成立している (1 件目は mission05, ADR-0008)。

## ゴール (operator view)

Falco ルール `Archive Collected Data` を発火させる。Rule の condition:

```
open_read
and collection_target_dir   # fd.name startswith "/opt/ctf/missions/13-archive-loot/fixtures/loot/"
and archive_tool_procs      # proc.name in (tar, gzip, gunzip, bzip2, bunzip2, xz, unxz, zip, unzip, 7z, 7za, cpio)
```

判定条件の要点 (`rule.yaml` に実クラスタ抽出の全文あり):

- 対象ファイルが staged collection ディレクトリ (`fixtures/loot/` 配下) に
  あること **かつ** それを archive/圧縮ユーティリティが読み取りモードで
  open したこと (AND 条件 — どちらも必須)
- 判定は **`fd.name` という syscall の外形的事実**(実際にどのファイルを
  open したか)のみに依存する。コマンドライン引数の文字列一致には依存しない
  ため、絶対パス指定・`cd` してからの相対パス指定・glob のいずれでも同じ
  ように発火する (kernel が dirfd 解決を経て `fd.name` を絶対パスとして
  評価するため)

## 想定解

```bash
# 絶対パス指定
tar czf /tmp/loot.tar.gz /opt/ctf/missions/13-archive-loot/fixtures/loot/

# cd してからの相対パス指定でも同じ判定になる (kernel が絶対パスへ解決する)
cd /opt/ctf/missions/13-archive-loot/fixtures/loot && tar czf /tmp/loot.tar.gz .
```

いずれも `archive_binaries` list のツールで対象ディレクトリを読み取れば発火する。
次の操作では **発火しない** (fixtures/welcome.txt にも案内):

```bash
# 覗くだけ (archive ツールを使っていない) — 不発火
cat /opt/ctf/missions/13-archive-loot/fixtures/loot/customer-roster.csv

# 無関係なディレクトリへの archive — 不発火
mkdir -p /tmp/other && tar czf /tmp/x.tar.gz /tmp/other
```

## 仕組みの解説 (講評用)

- `open_read` (upstream macro) — 「ファイルが実際に読み取りモードで open
  された」という外形的 syscall 事実。`proc.args` のような攻撃者が完全に
  制御できる文字列より偽装しにくい。
- `collection_target_dir` — 対象をこの課題専用の staged ディレクトリに絞る。
  末尾に `/` を付けて `startswith` の prefix collision (`.../loot-backup/`
  のような兄弟ディレクトリへの誤マッチ) を避けている。
- `archive_tool_procs` — 「`cat`/`less` で loot を覗くだけ」の honest な
  探索操作を除外する唯一の gate。**除外リストではなく成立条件側の gate**
  である点が、他の evade 型ルール (除外リストで honest path を通す形) と
  逆になっている。
- 3 条件 (`open_read` × 対象ディレクトリ × archive ツール識別) の AND で、
  除外/exception 節を持たない — 単純な AND 3 項で十分に絞れているため。

## 本課題の位置づけ

- **type: trigger**。`expectedRules: [Archive Collected Data]` のみ。
  発火 = solve (提出操作は不要)。flag/plant.sh/values.yaml は一切不要
  (trigger 型は attempt スコープ外で無条件 solve — ADR-0017 Decision (2))。
- **本課題は特定シナリオに編入しない (独立ボーナス課題)** — `scenarios/
  nimbusbreach-full/scenario.yaml` にも `scenarios/tutorial-intro/
  scenario.yaml` にも追加しない (11-cloud-cred-hunt / 12-cover-tracks と
  同型)。既存 10 課題の並び順・killchain の物語性は不変。`SCENARIO_FILE`
  未指定 = 全課題モードでは 13 も出る。
- evade ではないので ADR-0001 の flag isolation を緩める対象がそもそも
  存在しない。

## ATT&CK

`T1560.001` (Archive Collected Data: Archive via Utility)。検知の核が
「CLI アーカイブユーティリティ (`tar` 等) の呼び出し」という具体的な技法
なので、親カテゴリの粗い `T1560` ではなく、また T1560.002 (Archive via
Library) や T1560.003 (Archive via Custom Method) とも区別できる
(02-credential-files / 12-cover-tracks が upstream の粗いタグを実際の
condition に基づいて再マッピングした precedent と同じ規律)。

## 実世界の背景

侵入者がホストへの足がかりを得たあと、機密性のありそうなファイル・
設定ファイル・データベースのエクスポートなど「使えそうなもの」を
あちこちから漁り集めるのは Collection フェーズの典型的な振る舞い。
持ち出す (exfiltrate) 前に、転送を1回で済ませ検知の機会を減らすため
`tar`/`zip` 等で1本のアーカイブにまとめるのは、ランサムウェアグループの
二重恐喝 (暗号化前にデータを盗む) や標的型侵入の事例で繰り返し観測される
実務的なステップ。「何を集めたか」ではなく「集めたものをまとめようとした」
という **行動そのもの** を検知する、という点が本課題の学習価値。

## 本番ではどう守るか (Sysdig)

このミッションが検知するのは「アーカイブツールが staged ディレクトリ配下の
ファイルを読み取った」という単発の syscall イベント。本番の防御はここで
終わらない — Sysdig Secure はこのイベントを Falco (runtime) の 1 点としてだけ
でなく、同じホスト/コンテナで直前に何が起きたか (不審な探索コマンド・
権限昇格・その後のネットワーク接続) と結び付けて「収集 → アーカイブ →
持ち出し」の一連の流れとして相関させる。ホスト内 Falco (何が起きたかの観測)
と Sysdig の相関/可視化 (それがインシデントの一部かどうかの判断) の二層が
本番の守り方。

## ヒント (難易度別)

1. (易) 持ち出す前に、漁った戦利品を1つにまとめておきたい。アーカイブ/
   圧縮系のコマンド (`tar` 等) を試してみよう。
2. (中) 対象は `fixtures/loot/` 配下のファイル群。ディレクトリを丸ごと
   指定すれば十分。
3. (難) 絶対パス指定でも、`cd` してから相対パスで指定しても、同じ判定に
   なる — 何のファイルを実際に open したかで判定されているためで、
   コマンドライン引数の文字列そのものは見ていない。

## 検証 (ADR-0017 Verification (a-2)/(a-3))

disposable colima profile (`ctf-adr0017-verify`、検証後に削除) に、
platform の customRules (`Archive Collected Data`, ADR-0017) をデプロイした
Falco を実際に sync し、alpine:3.22 ベースの mutation-test pod (この課題の
fixtures と同一パス・同一ツール構成) で 4 パターンを実測した
(falcosidekick `/metrics` の `falcosecurity_falcosidekick_falco_events_total{rule="Archive Collected Data"}` カウンタで確認):

| # | 操作 | 期待 | 実測 |
|---|---|---|---|
| 1 | `tar czf /tmp/loot1.tar.gz /opt/ctf/missions/13-archive-loot/fixtures/loot/` (絶対パス) | FIRE | ✅ FIRE (2 events, ファイルごとに1件) |
| 2 | `cd .../loot && tar czf /tmp/loot2.tar.gz .` (相対パス、`cd` 後 — Option 3 [不採用] が落とすはずだったケース) | FIRE | ✅ FIRE (2 events) |
| 3 | `cat` で loot ファイルを読むだけ (探索のみ) | NO FIRE | ✅ NO FIRE (カウンタ不変) |
| 4 | `mkdir -p /tmp/other && tar czf /tmp/x.tar.gz /tmp/other` (無関係ディレクトリ) | NO FIRE | ✅ NO FIRE (カウンタ不変) |

実際の Falco 出力 (#1 の1件目):

```json
{"output":"12:55:50.866102345: Notice Archive utility read file under staged collection target file=/opt/ctf/missions/13-archive-loot/fixtures/loot/customer-roster.csv tool=tar command=tar czf /tmp/loot1.tar.gz /opt/ctf/missions/13-archive-loot/fixtures/loot/ user=root k8s.ns=ctf-adr0017-verify k8s.pod=mutation-test ...","priority":"Notice","rule":"Archive Collected Data", ...}
```

Falco DaemonSet は `Running` のまま 0 restarts、起動ログにルール読み込みエラー
無し (schema validation: ok)。colima profile は検証後に stop/delete 済み。
