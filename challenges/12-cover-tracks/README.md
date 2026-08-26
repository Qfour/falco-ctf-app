# 12 — Cover Tracks (ログ消去検知 / bonus)

本編 01–10 とは独立した **ボーナス課題** (11-cloud-cred-hunt と同型)。テーマは
MITRE ATT&CK **Defense Evasion / T1070.002** (Indicator Removal: Clear Linux or
Mac System Logs) — 侵入の証跡であるログファイルを消去する典型的な「後片付け」
動作を、upstream default rule `Clear Log Activities` で検知する。**custom rule
新設は不要** — 既存の default ruleset だけで完結することを実クラスタで確認済み。

## ゴール (operator view)

Falco ルール `Clear Log Activities` を発火させる。Rule の condition:

```
open_write
and access_log_files   # fd.directory in (/var/log, /dev/log) or fd.filename in (定番ログ名)
and evt.arg.flags contains "O_TRUNC"
and not containerd_activities
and not trusted_logging_images
and not allowed_clear_log_files
```

判定条件の要点 (`rule.yaml` に実クラスタ抽出の全文あり):

- 対象パスが `/var/log` / `/dev/log` 配下 **または** ファイル名が定番のログ名
  (`syslog` / `auth.log` / `secure` / `kern.log` / `cron` / `user.log` /
  `access_log` / `mysql.log` 等) の **いずれか** (OR 条件 — ディレクトリと
  ファイル名、どちらか一方が一致すれば十分)
- 書き込みが `O_TRUNC` (truncate open = 上書きモード) であること。`>>` の
  追記 (`O_APPEND` のみ) では発火しない

## 想定解

```bash
# 定番ログディレクトリに新規ファイルを truncate-write で作る (ファイル名は任意)
echo pwned > /var/log/whatever123.txt

# 定番ログ名なら /var/log の外でも発火する (OR 条件 — ディレクトリ一致は必須ではない)
echo pwned > /tmp/evil/auth.log
```

いずれも `>` (truncate open, `O_TRUNC`) を使う。次の操作では **発火しない**
(fixtures/welcome.txt にも案内):

```bash
# 追記のみ (O_APPEND) — O_TRUNC が付かないので不発火
printf "hello\n" >> /var/log/pureappend.txt

# 非ログ path・非ログ名 — access_log_files の OR 条件どちらにも一致しない
echo hello > /tmp/scratch/notes.txt
```

## 実世界の背景

侵入者が SSH ブルートフォースや漏洩クレデンシャルで Linux ホストへ足がかりを
得たあと、`/var/log/auth.log`・`/var/log/secure` (認証試行ログ) や
`/var/log/syslog`・`/var/log/cron` を truncate して自分のログイン試行・実行した
コマンドの証跡を消すのは、インシデントレスポンス報告で繰り返し観測される
典型的な後片付け (anti-forensics) の動作。ランサムウェアの実行前後にも、暗号化や
lateral movement の痕跡を消すため同様にログを消去する事例が多数報告されている。
「攻撃そのもの」ではなく「攻撃の**後始末**」を検知する、という点で 01–11 の
どの課題とも異なる学習価値を持つ (侵入検知だけでなく、侵入後の evidence
tampering も Falco の観測範囲に入っていることを示す)。

## ATT&CK

`T1070.002` (Indicator Removal: Clear Linux or Mac System Logs)。upstream の
rule tag は親カテゴリの粗い `T1070` (Indicator Removal 全般 — Windows Event Log
消去やタイムスタンプ改変も含む) だが、実際の condition が「Linux システムログの
truncate」そのものを検知しているため `T1070.002` が正直なマッピング
(`challenges/02-credential-files` が upstream の粗いタグを実際の condition に
基づいて再マッピングした precedent と同じ規律)。

## 採点・境界メモ

- type: trigger。`expectedRules: [Clear Log Activities]` のみ。**発火 = solve
  (提出操作は不要)**。既存 01–11 の expected/forbidden とルール名が重複しないため
  採点衝突なし。
- 本課題は scenario `nimbusbreach-full` (01–10 固定) にも `tutorial-intro` にも
  **編入しない** (独立ボーナス課題として単体 launch する想定 — 11 と同型)。
  `SCENARIO_FILE` 未指定 = 全課題モードでは 12 も出る。既存 10 課題の並び順・
  killchain の物語性は不変。
- `challenges/custom-falco-rules.txt` への追記は **不要** — upstream default
  rule のみで発火することを実クラスタ (disposable colima profile) で確認済み。
- evade ではないので `plant.sh` / `values.yaml` / フラグ注入は一切不要。
  参加者が**自分で新規作成する rootfs 上のファイル**への書き込みで発火する
  ため、plant 経由の読み取り専用 bind mount には依存しない —
  ADR-0001 の flag isolation (plant initContainer 経由のみ) を一切緩めない。

## 本番ではどう守るか (Sysdig)

このミッションが検知するのは「ホスト内で 1 個のログファイルが truncate された」
という単発の syscall イベント。本番の防御はここで終わらない — Sysdig Secure は
このイベントを **Falco (runtime) の 1 点** としてだけでなく、同じホスト/コンテナで
直前に何が起きたか (異常な cmdline・不審な子プロセス・ネットワーク接続) と結び付けて
「侵入 → 後始末」の一連の流れとして相関させる。加えて、ログ消去そのものを
signal として扱う (「このホストの証跡が急に減った」ことをアラートにする)
ことで、検知漏れではなく **検知後の evidence が消される** リスクを別レイヤーで
補う。ホスト内 Falco (何が起きたかの観測) と Sysdig の相関/可視化 (それが
インシデントの一部かどうかの判断) の二層が本番の守り方。

## ヒント (難易度別)

1. (易) ログファイルへの「上書き」(truncate) が怪しい。`echo "x" > /var/log/なにか`
   を試してみよう。
2. (中) ファイル名自体が `/var/log` 以外の場所でも、`auth.log` や `syslog` のような
   **定番のログ名** であれば検知対象になる (ディレクトリとファイル名は OR 条件)。
3. (難) `>>` の追記だけでは発火しない — 上書きモード (`O_TRUNC`) であることが
   条件。何のシステムコール引数フラグを見ているかを `rule.yaml` で確認しよう。
