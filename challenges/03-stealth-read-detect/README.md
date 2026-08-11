# 03 — Stealth Read (Detect)

Mission 03 (evade) の **防御側ツイン**。参加者は攻撃者ではなく **SOC 側** として、
03 で使われた `/proc/self/root/etc/shadow` 回避を取り逃さない Falco の
**`condition:` だけ** を書いて提出する。type = `detect`。

## ゴール (operator view)

参加者が提出した condition を固定ルール `participant_detect` に埋め込み、
2 本の録画に対して **capture replay** で採点する:

- `detect/evasion.scap` — 回避挙動 (`cat /proc/self/root/etc/shadow`) → **発火必須**
- `detect/benign.scap` — 正常業務 look-alike → **発火ゼロ必須**
- `pass = (evasionFires > 0) AND (benignFires == 0)`

flag も clean-window も無い。採点は (static capture, 提出 condition) の純粋関数で
決定的 (design §2)。実採点は 44.0 detect エンジン + 44.1 K8sJob grader が担う。

## 検知アイデア (この課題が教えること)

- 03 で抜けられた `Read sensitive file untrusted` は `fd.name startswith /etc`
  (= `sensitive_files` マクロ) で判定していた。**path 文字列の先頭**に依存するのが穴。
- 正解方向は path の先頭ではなく **末尾/実体** を手掛かりにすること。design §8.2 で
  実証済みの PASS 例は `open_read and fd.name endswith "/shadow"` (evasion 2 発火 /
  benign 0 発火)。`/etc/shadow` でも `/proc/self/root/etc/shadow` でも同じ判定になる。
- **allowedMacros はあえて `open_read` だけ**。`sensitive_files` を渡さないのは、
  それ自体が壊れた側 (path 先頭マッチ) で、渡すと壊れたルールを再現できてしまうから。
  参加者に「先頭以外の判別軸」を自力で選ばせるのが学習目標。

> solution reveal はしない。grader は正解 condition を返さず、README のこの節も
> 「方向」までで、参加者向け journey には出さない (operator 専用 = admin ページ)。

## Capture (operator が録画 — この branch には未同梱)

`.scap` 実体はこの branch では**作らない**。falco-rule.yaml が参照する path
(`detect/evasion.scap` / `detect/benign.scap`) を定義するだけ。録画手順は
[`docs/detect-capture-recording.md`](../../docs/detect-capture-recording.md) が正典:

- evasion 録画では **fake shadow (実 flag/secret を含めない)** を読むこと (I10)。
- 録画後に `strings <scap> | grep -E 'FALCO\{|AKIA|PRIVATE KEY'` 等で漏えい検査必須。
- benign 録画は「唯一のクリーンな判別軸 = 意図した検知アイデアだけ」になるよう設計
  (design §10.6 anti-cheat)。
- Falco version bump 時は全 capture 再録画 + grader image digest 再解決 + macros
  lockstep をセットで (runbook のチェックリスト参照)。

## 並び順 / scenario

- 既存 10 課題の**並び順・scored scenario は不変**。`nimbusbreach-full` には
  **編入しない** (design §0 / task 制約)。dir 名 `03-stealth-read-detect` は
  `03-stealth-read` の直後にソートされ、docs のミッション一覧でも隣接する。
- この dir を追加すると catalog は `type: detect` を load するが、capture 実体が
  無い間は採点不能。よって本課題は **operator 録画 + resolveCapture の存在検証
  (app-lead) + catalog 登録が揃うまで merge しない draft**。

## 本番防御 — あなたが書いた検知を「書かずに」持つ (Sysdig)

参加者向けの締め (journey 末尾ステップと同趣旨)。全 detect 課題で共通:
正典は [`../DETECT-SYSDIG-PITCH.md`](../DETECT-SYSDIG-PITCH.md)。

この課題で書いた「path 先頭に依存しない機密ファイル読取検知」と同等のカバレッジを、
Sysdig のマネージドルールは書かずに提供する。inode 迂回や `/proc` 経由の派生も
上流でメンテされ、Falco バージョンが上がっても追随する。OSS Falco では condition を
自分で保守する — その保守コストを肩代わりするのがマネージドルールだ。検知エンジン
そのものは同じ Falco で、今日学んだ「検知の書き方・回避の捕まえ方」はどちらでも生きる。
