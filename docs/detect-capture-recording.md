# Detect capture 録画 runbook (operator ハンドオフ)

`type: detect` 課題の採点は **capture replay**。参加者が書いた Falco condition を、
operator が事前に録った 2 本の `.scap` に再生して発火回数を数える
(`pass = evasionFires > 0 AND benignFires == 0`)。この runbook は、その `.scap` を
**operator が人手で録る**手順の正典。設計の正典は `docs/detect-challenge-design.md`
§5 (録画・保存) / §8 (spike 実測) / §10.6 (anti-cheat)。

> **この runbook 時点では実 capture は録らない** (44.2 は手順書まで)。実録画は
> operator ハンドオフのタスク。下記「operator に残すタスク」を参照。

---

## 0. 前提 (録画ホスト)

- **Linux ホスト + kernel 6.8 以降 + BTF** (colima の Lima VM で可。spike は
  colima Docker 29.2.1 / kernel 6.8 + BTF で実証済み — design §8)。macOS 直では
  録れない (syscall source が要る)。
- Falco image は **grader と同一 digest pin** の version を使う
  (spike: `falcosecurity/falco:0.43.1`)。録画と採点で version がズレると
  capture format / フィールド意味が食い違う。
- **prod は一切触らない**。ephemeral container / volume だけで完結させ、後片付けする。

各課題の capture 対象・fake データ・唯一のクリーン判別軸は課題ごとに違う。
本 runbook は **03-stealth-read-detect** を具体例に手順を示す。他 detect 課題は
「§4 課題別の録画対象」に追記していく。

---

## 1. 録画用 Falco 設定 (modern_ebpf + capture)

録画は **modern_ebpf + capture.enabled** で行う (privileged。operator の録画ホスト
のみ。採点側の replay は driverless で privilege 不要 — design §8.1)。

`record-falco.yaml` (要点):

```yaml
engine:
  kind: modern_ebpf          # kernel 6.8 + BTF で load
capture:
  enabled: true
  mode: all_rules            # 関連 window を .scap に書き出す
```

catch-all ルール (録画中に広く syscall を拾って `.scap` に残すため):

```yaml
# catchall.yaml — 録画専用。採点には使わない。
- rule: catch_all_open
  desc: record window
  condition: (evt.type in (open,openat,openat2))
  output: "%evt.type %fd.name %proc.name"
  priority: INFO
```

起動 (録画ホスト):

```sh
falco -c record-falco.yaml -r catchall.yaml
#   → capture.file_path (設定) に *.scap chunk が書かれる (spike: 300–740 KB/chunk)
```

---

## 2. evasion capture を録る — **fake shadow を読む (I10 必須)**

**実 flag / secret / 実 /etc/shadow を絶対に録画対象にしない**。capture は録画中の
**実ホスト syscall を記録する** ので、対象ファイルの中身も痕跡が残りうる。必ず
**fake の機密ファイル**を用意し、それを回避経路で読む。

03-stealth-read-detect の場合 (回避挙動 = `/proc/self/root` 経由の shadow 読取):

```sh
# ephemeral container 内で fake shadow を用意 (実 flag を含めない)
docker run --rm -it alpine:3.22 sh
  # 中で:
  printf 'root:x:0:0:::\n# NOT-A-REAL-FLAG-placeholder\n' > /tmp/fake-shadow
  # 回避経路を再現 (path 先頭が /etc にならない読み方)
  cat /proc/self/root/tmp/fake-shadow    # ← evasion action (fake 対象)
```

- 攻撃の**本質** (path 先頭に依存しない読取) が capture に入っていればよい。
  実際の `/etc/shadow` を読む必要はない。fake ファイルへの回避経路読取で十分。
- 録画ホストで上記 action の window を含む chunk を `evasion.scap` として確保。

---

## 3. benign capture を録る — 唯一のクリーン判別軸だけを残す (design §10.6)

benign capture の設計原則: **「攻撃だけを分ける唯一のクリーンな軸 = 意図した検知
アイデア」以外の差を残さない**。さもないと参加者が incidental な差 (pid・timestamp・
無関係な proc 名) にキーした condition で「benign で無発火・evasion で発火」を
ズルできてしまう (anti-cheat)。

原則:

- benign は **evasion と同じくらい『機密ファイルの読取』に近い正常業務**にする
  (例: 正規プロセスによる `/etc/hostname` や許可された設定ファイルの読取)。
  「読み取りが一切無い benign」だと、単に `open_read` と書くだけで通ってしまい
  学習にならない。
- 攻撃と benign の差が **意図した検知アイデア (path 先頭ではなく実体で shadow を
  判定) の一点だけ**になるよう action を選ぶ。
- benign 側に fake shadow / それらしき機密名を**混ぜない** (混ぜると正解 condition
  でも FP になり採点が壊れる)。

03-stealth-read-detect の benign 例:

```sh
docker run --rm -it alpine:3.22 sh
  # 正常業務っぽい読取 (機密でない設定ファイル) を複数
  cat /etc/hostname; cat /etc/hosts; cat /etc/resolv.conf
  # shadow / fake-shadow は読まない
```

---

## 4. 課題別の録画対象 (対象が増えたら追記)

| 課題 | evasion action (fake 対象) | benign action | 唯一のクリーン判別軸 |
|---|---|---|---|
| 03-stealth-read-detect | `cat /proc/self/root/<fake-shadow>` (path 先頭迂回) | 機密でない `/etc/*` 設定ファイル読取 | path 先頭ではなく shadow 実体/末尾で判定 |
| _(05 / 10 detect は将来)_ | — | — | — |

---

## 5. 録画後の必須検査

### 5.1 漏えい検査 (I10 — public repo)

commit 前に **必ず**実 flag / クラウド鍵 / 秘密鍵の痕跡が無いことを検査する:

```sh
strings evasion.scap benign.scap | grep -E 'FALCO\{|AKIA|BEGIN [A-Z ]*PRIVATE KEY|-----BEGIN' && \
  echo "LEAK — 破棄して録り直す" || echo "clean"
```

- ヒットしたら **その capture は破棄**し、fake データを見直して録り直す。
- placeholder (`FALCO{dev-...}`) すら capture に入れない (fake shadow に flag 風
  文字列を書かない — 上の例の `NOT-A-REAL-FLAG-placeholder` のように無害な語にする)。
- 検査を通ったことを PR / ハンドオフに明記する (flag-guard は tracked テキストの
  `FALCO{...}` を見るが、`.scap` は binary なので strings 検査が人手の追加ゲート)。

### 5.2 size trim

- chunk は 300–740 KB (spike 実測)。**関連 window を含む最小 chunk** に trim して
  committ する。無関係に大きい `.scap` は repo を膨らませ、漏えい面も広げる。
- 目安: evasion / benign 各 1 chunk (数百 KB)。

### 5.3 grade 動作確認 (録画が採点に耐えるか)

正解方向の condition と、明らかに広い/外した condition で replay して、design §8.2 の
分離が出ることを確認してから commit する:

```sh
# 正解方向 (例)  → evasion で発火・benign で 0
# 広すぎ (any open_read) → benign でも大量発火 (FAIL 側が FAIL になること)
# 外し           → evasion で 0 (FAIL 側が FAIL になること)
falco -c replay-evasion.yaml -r participant.yaml --json | grep -c '"rule":"participant_detect"'
falco -c replay-benign.yaml  -r participant.yaml --json | grep -c '"rule":"participant_detect"'
```

`replay-*.yaml` は `engine.kind: replay` + `engine.replay.capture_file: <scap>`
(driverless。design §8.4)。

---

## 6. 保存 & commit

- 置き場所: `challenges/<NN>-<slug>-detect/detect/{evasion,benign}.scap`
  (falco-rule.yaml の `detect.evasionCapture` / `benignCapture` が参照する path)。
- catalog の `resolveCapture` は **path 文字列のみ**を load 時に検証する
  (相対・エスケープ無し)。**ファイルの実在は検証しない** → capture が無くても
  catalog load は通るが、grader (replay) は capture 不在で fail-closed (grade.sh
  exit 4)。よって capture を置いて初めて採点可能になる。
- capture を commit したら app-lead に「resolveCapture の存在検証 (実在チェック)
  + catalog 登録 + catalog_test の challenge 数 pin 更新」を依頼する (Go 領域)。

---

## 7. Falco version bump チェックリスト (lockstep)

Falco の version を上げるときは、以下を**セットで**やる (どれか 1 つでも欠けると
採点が壊れる):

- [ ] **全 detect 課題の capture を再録画** (`.scap` format / フィールド意味が
      version で変わりうる — design §5 末尾)。§2/§3 を新 version の Falco で再実行。
- [ ] **grader image の digest 再解決** (`falcosecurity/falco:<新version>` の
      index digest を取り直して pin — conventions「digest の bump 手順」に準拠)。
- [ ] **allowedMacros の lockstep 確認**: 各課題 falco-rule.yaml の
      `detect.allowedMacros` が新 version の Falco ルールセットに実在するマクロか
      再確認 (マクロ定義自体が変わっていないかも。03 は `open_read` のみ)。
- [ ] **表示用 rule.yaml の再抽出** (conventions「課題ドキュメント用 rule.yaml」— 
      condition/output が変わるため)。
- [ ] 再録画 capture で §5.1 漏えい検査 + §5.3 grade 動作確認をやり直す。
- [ ] `check-challenge-rules.sh` の `FALCO_RULES_REF` pin も同じ version に合わせる。

---

## operator に残すタスク (44.2 ハンドオフ)

1. **録画対象**: 03-stealth-read-detect の `evasion.scap` (§2: fake shadow を
   `/proc/self/root` 経由で読む) と `benign.scap` (§3: 機密でない `/etc/*` 読取)。
2. **検査**: §5.1 漏えい検査 (strings grep) を通し、通過を記録。§5.3 grade 動作確認。
3. **配置 & commit**: §6 の path に置く。
4. **app-lead へ依頼**: resolveCapture の実在検証追加 + catalog 登録 +
   `catalog_test.go` の challenge 数/ID pin 更新 (現状 10 で pin。detect 課題は
   Go 領域なので content-lead は触らない)。
5. capture が揃うまで、この detect 課題を含む branch は **draft** のまま
   (capture 不在 = grade.sh exit 4 fail-closed のため merge しない)。
