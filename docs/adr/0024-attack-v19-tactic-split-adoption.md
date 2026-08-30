# ADR-0024: ATT&CK v19 Defense Evasion 分割 (Stealth / Defense Impairment) の採用と version pin bump

- Status: Accepted
- Date / Deciders: 2026-08-31 / architect (起草・調査)、VP (実装・検証)、CEO (adopt 承認 2026-08-31)
- 関連: Issue #249 (VP 起票、束C #246 の scope 外で検出した副次的発見のフォローアップ)、
  Issue #246 / PR #250 (01/03/05 の technique remap。本 ADR はその続き)、
  `scripts/gen-attack-layer.py` (Navigator layer / coverage table 生成器)、
  ADR-0015〜0018 (同型の ATT&CK マッピング判断フォーマット)

## Context

- MITRE ATT&CK **v19 (2026-04-28 リリース)** で tactic `TA0005 Defense Evasion` が
  **`Stealth` (TA0005 の ID を継承) と `Defense Impairment` (新設 TA0112)** に分割された
  (WebSearch で複数の一次情報ベンダー記事と `attack.mitre.org/tactics/TA0112/` で確認)。
- `challenges/*/falco-rule.yaml` の `attack:` block で `tactic: "Defense Evasion"` を
  使っているのは **4 件のみ**: `03-stealth-read` (T1564)、`05-silent-search`
  (T1027.010)、`09-hidden-cache` (T1564)、`12-cover-tracks` (T1070.002)
  (`grep -l 'Defense Evasion' challenges/*/falco-rule.yaml` で実測、対象はこの 4 件で全数)。
  他 10 件の tactic (`Discovery` / `Credential Access` / `Execution` /
  `Command and Control` / `Exfiltration` / `Collection`) は v19 で変更されていない
  (`attack.mitre.org/tactics/enterprise/` の全 15 tactic 一覧を確認。変わったのは
  TA0005 のみ)。
- **Navigator layer JSON (`challenges/attack-navigator-layer.json`) は tactic を
  一切シリアライズしない** (`scripts/gen-attack-layer.py` の `build_layer()` を実読 —
  `techniques[]` は `techniqueID`/`score`/`color`/`comment`/`enabled` のみ)。tactic の
  列描画は Navigator 本体が `versions.attack` で指定した STIX バンドルから技術ID→tactic
  を都度解決する。したがって **`tactic:` フィールドの変更自体は JSON layer を壊さない**
  — 影響するのは我々が生成する `ATTACK-COVERAGE.md` の tactic 列という自前ドキュメントのみ。
- 一方 `versions.attack` (`ATTACK_VERSION = "15"`, `gen-attack-layer.py:34`) は
  Navigator が読み込む STIX バンドルの版を固定する実質的なメタデータであり、
  「v15 のタクソノミーなのに v19 由来の tactic 名 (`Stealth`) を書く」は
  **アーティファクト内で自己矛盾する** (v15 の STIX には `Stealth` という tactic 名が
  存在しない)。tactic 名を更新するなら version pin も一致させる必要がある。
- **version pin を "19" に上げる場合、既存 14 件全てのを techniqueId が v19 で
  引き続き有効か (deprecated/redirect されていないか) を検証する必要がある** —
  「一部だけ確認して version だけ上げる」は spec に嘘を書くのと同型の失敗モード。
  本 ADR 執筆時点で **全 14 件を実機確認済み** (下記 Decision 参照)。

## Options

### A. 追従 (tactic ラベルを v19 に更新 + version pin bump)
- 変更点: 4 件中 3 件 (03/05/09) は `tactic: "Defense Evasion"` →
  `"Stealth"` へのラベル変更のみ (techniqueId 不変)。**12-cover-tracks は
  techniqueId 自体の変更が必要** (下記 Decision 参照)。`ATTACK_VERSION` を
  `"15"` → `"19"` に bump。
- コスト: 4 ファイルの編集 + `gen-attack-layer.py` の定数 1 行 + `make gen-attack`
  再生成。12-cover-tracks は #246 と同型の remap 理由コメントが追加で必要。
  検証コストは本 ADR で払い済み (14 件全数 WebFetch/curl 確認済み)。
- リスクと可逆性: 低リスク・完全可逆 (yaml コメント + 定数のみ、採点非影響)。
  Navigator JSON 自体は tactic を持たないため描画バグのリスクは無い。
- 効き始める閾値: 即時 (次に誰かが Navigator に layer を読ませた瞬間、または
  誰かがこのリポの ATT&CK マッピングを外部に説明する瞬間に「v15 なのに v19 の
  tactic 名」という矛盾が解消される)

### B. 据え置き (現状の "Defense Evasion" ラベル + version pin "15" のまま)
- 変更点: 無し。
- コスト: 追従コストは払わないが、**"Defense Evasion" は v19 の attack.mitre.org
  上にはもう存在しない tactic 名**であり、`ATTACK-COVERAGE.md` の tactic 列を
  読者が attack.mitre.org と突き合わせた瞬間に「無い tactic」に見える。
  ドキュメントとしての鮮度が v19 リリース (2026-04-28) 以降ずっと劣化し続ける。
- リスクと可逆性: リスクは低い (採点非影響) が、据え置く理由が「まだ確認していない」
  ではなく「確認した上で古いままにする」だと、次に技術を追加する Engineer が
  古い tactic 名を模倣し続け、drift が拡大する。
- 効き始める閾値: 外部の読者/CTF 参加者が Navigator に layer を読み込んで
  tactic 列と実際の Navigator 表示 (v19 taxonomy 前提) の食い違いに気づいたとき

## Decision

**Option A (追従) を採用する。** 根拠: (1) tactic はコード的な契約ではなく表示用
メタデータなので追従コストが低い、(2) Navigator JSON 自体は tactic を持たないため
壊れるものが無い、(3) 「v15 pin のまま v19 由来の tactic 名を書く」という自己矛盾を
放置する理由が無い、(4) 全 14 件の techniqueId を実際に検証済みで version bump の
安全性を裏付けられる状態にある。

**14 件の再配置表 (2026-08-31 実機確認、`attack.mitre.org` 直読み — WebFetch summarizer
が空応答を返した ID は raw `curl` で HTTP 応答を直接検査):**

| 課題 | 現行 tactic / techniqueId | v19 該当 tactic | v19 techniqueId | 変更要否 |
|---|---|---|---|---|
| 00-tutorial | Execution / T1059.004 | Execution (不変) | T1059.004 (不変) | 無 |
| 01-initial-recon | Discovery / T1613 | Discovery (不変) | T1613 (不変) | 無 (#250 で remap 済み) |
| 02-credential-files | Credential Access / T1003.008 | 不変 | 不変 | 無 |
| **03-stealth-read** | Defense Evasion / T1564 | **Stealth** | T1564 (不変) | **tactic ラベルのみ** |
| 04-key-search | Credential Access / T1552.001 | 不変 | 不変 | 無 |
| **05-silent-search** | Defense Evasion / T1027.010 | **Stealth** | T1027.010 (不変) | **tactic ラベルのみ** |
| 06-web-rce-shell | Execution / T1059.004 | 不変 | 不変 | 無 |
| 07-persist | Execution / T1204.002 | 不変 | 不変 | 無 |
| 08-c2-beacon | Command and Control / T1095 | 不変 | 不変 | 無 |
| **09-hidden-cache** | Defense Evasion / T1564 | **Stealth** | T1564 (不変) | **tactic ラベルのみ** |
| 10-final-exfil | Exfiltration / T1041 | 不変 | 不変 | 無 |
| 11-cloud-cred-hunt | Credential Access / T1552.001 | 不変 | 不変 | 無 |
| **12-cover-tracks** | Defense Evasion / T1070.002 | **Defense Impairment** | **T1685.006** (ID 変更) | **techniqueId + techniqueName + tactic** |
| 13-archive-loot | Collection / T1560.001 | 不変 | 不変 | 無 |

**12-cover-tracks は他 3 件と異なり techniqueId 自体の変更が必要。** raw HTTP で
`attack.mitre.org/techniques/T1070/002/` を直接取得すると本文が無く、67 byte の
`<meta http-equiv="refresh" content="0; url=/techniques/T1685/006"/>` のみが
返る (WebFetch の要約ツールが「コンテンツが無い」と応答したのはこの空リダイレクト
ページを正しく反映した結果であり、ツール障害ではなかった)。さらに
`attack.mitre.org/techniques/T1070/` (parent) の現行ページを実取得すると
sub-technique は `.003 .004 .005 .006 .007 .008 .009 .010` のみで **`.001`/`.002`
が存在しない** — v19 で T1070.002 は完全に retired し、**T1685.006
"Disable or Modify Tools: Clear Linux or Mac System Logs"** (tactic:
Defense Impairment, platform: Linux/macOS) に統合された。definition は
「Adversaries may clear system logs to hide evidence of an intrusion...
majority of native system logging is stored under `/var/log/`」で
T1070.002 時代の記述とほぼ同一 — `Clear Log Activities` rule (open_write +
O_TRUNC + 既知ログ path/filename) の検知内容との適合性は変わらない。

**gen-attack-layer.py への必要変更:**
- `ATTACK_VERSION = "15"` → `"19"` (`scripts/gen-attack-layer.py:34` 付近)。
  コメント「Bump together with any technique-id review」に従い、本 ADR
  (2026-08-31, 14件全数確認済み) を bump の根拠として追記する
- コード構造自体の変更は不要 (`tactic:` は自由文字列として読むだけで、
  Navigator の tactic ID とのマッピングテーブルをこの repo 側で持っていない
  ため、ハードコードされた tactic 順序/ID は存在しない — `read_attack()` /
  `build_layer()` を実読して確認済み)

**falco-rule.yaml への remap 理由コメント案 (content-engineer が転記):**

`03-stealth-read` / `09-hidden-cache` (tactic 行のみ差し替え、techniqueId 行は不変):
```
# ATT&CK v19 (2026-04-28) split TA0005 "Defense Evasion" into "Stealth" (TA0005)
# and "Defense Impairment" (TA0112, new). T1564 stayed under Stealth — verified
# attack.mitre.org (ADR-0024). techniqueId/Name unchanged, tactic label only.
attack:
  tactic: "Stealth"
  techniqueId: "T1564"
  techniqueName: "Hide Artifacts"
```

`05-silent-search` (tactic 行のみ差し替え):
```
# ATT&CK v19 (2026-04-28) split TA0005 "Defense Evasion" into "Stealth" (TA0005)
# and "Defense Impairment" (TA0112, new). T1027.010 stayed under Stealth —
# verified attack.mitre.org (ADR-0024). techniqueId/Name unchanged, tactic
# label only.
attack:
  tactic: "Stealth"
  techniqueId: "T1027.010"
  techniqueName: "Command Obfuscation"
```

`12-cover-tracks` (techniqueId ごと変更。既存コメント全体を置換):
```
# ATT&CK mapping — canonical source for docs/Navigator layer (make gen-attack).
# T1070.002 (previous mapping) was retired in ATT&CK v19 (2026-04-28) — the
# URL now 302s to T1685.006 and the T1070 parent's current sub-technique list
# no longer includes .001/.002 (verified attack.mitre.org, ADR-0024). Remapped
# to T1685.006 "Disable or Modify Tools: Clear Linux or Mac System Logs"
# (tactic: Defense Impairment / TA0112, platform: Linux/macOS) — same
# definition (clearing /var/log to hide intrusion evidence), same fit for the
# rule's open_write+O_TRUNC-against-known-log-path condition.
attack:
  tactic: "Defense Impairment"
  techniqueId: "T1685.006"
  techniqueName: "Disable or Modify Tools: Clear Linux or Mac System Logs"
```

## Consequences

- 何を諦めたか: 何も諦めていない (表示/ドキュメントメタデータの是正のみ、採点・API・
  契約に影響しない)
- 新たに守る invariant: 無し (Hard Invariant への昇格対象ではない — 下記 Verification
  「無し」の通り)
- runbook への影響: 無し
- **今後 technique を追加/変更する Engineer への申し送り**: `tactic:` フィールドの
  自由文字列は、attack.mitre.org の現行タクソノミーと乖離しやすい (v19 の前例が示す
  通り、MITRE は tactic 自体を分割/改名することがある)。次に ATT&CK が大きな
  改版をしたときは、この ADR と同じ手順 (現行 14 件を全数 `attack.mitre.org` で
  実機確認 → 変更が必要な件だけ remap) を踏む

## Signposts

- ATT&CK が次のメジャー版 (v20+) で TA0005 "Stealth" や TA0112
  "Defense Impairment" をさらに改名/再分割したとき — 同じ手順で 4 件
  (03/05/09/12) を再確認する
- `attack.mitre.org/techniques/T1685/006/` が将来的に再度 retire/redirect
  されたとき (MITRE は稀に再編を繰り返す) — その時点で 12-cover-tracks を
  再remap
- Navigator layer format 自体 (`layer: "4.5"`) が改版され、tactic を JSON に
  含める形式に変わったとき — その時点で `build_layer()` の実装を見直す
  必要がある (現状は tactic 非対応で安全だが、将来の layer format 前提が変わる)

## Verification

無し (機械検査は無い。`make gen-attack` の再実行が diff ゼロ = 生成物が
`attack:` block と同期していることのみ確認できるが、tactic 名の attack.mitre.org
との整合性そのものを検査する CI は無い — 表示メタデータであり Hard Invariant に
昇格させる対象ではないため、意図的に持たない)

## Advice

- 助言者: 無し (本 ADR は architect 単独の実機調査に基づく起草。VP へは実装可否の
  判断を仰ぐ)
