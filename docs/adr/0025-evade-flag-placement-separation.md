# ADR-0025: evade 課題のフラグ配置分離 — mission03/10 を専用 vault ディレクトリへ retarget (dir-prefix customRule 1本)、mission02 は `/etc/shadow` の loud baseline のまま維持

- Status: **Proposed**
- Date / Deciders: 2026-09-01 / architect (起草・改訂)、VP (customRule を dir-prefix 形へ変更、承認待ち)、
  CEO (Class-2 — Falco custom rule / cross-repo 契約 / 採点ロジックに触れるため merge は CEO のみ。
  **Option 2 [mission03/10 両方移動] を選択、architect 初稿の Option 1 [mission10 のみ] を却下**)
- 関連: ADR-0001 (flag plant initContainer 機構、I12)、ADR-0007 (plant mount directory
  granularity)、ADR-0003 (evade clean gate attempt scope、I11)、ADR-0008 (mission05
  positive-proof gate — `customRules` append の project 初 precedent)、ADR-0017
  (mission13 custom rule — `customRules` 2 件目、trigger 型)。本 ADR は `customRules`
  **3 件目**

## Context

- CEO 決定 (確定済み、2026-09-01 セッション、初稿からの改訂を含む): (1) mission10 のフラグを
  「専用ファイルに flag だけ」置く形に変える (`cat <file>` で flag だけが出る見せ方)。
  (2) 02/03/10 が全て `/etc/shadow` を使っており「答えが同じファイルだとバレやすい」ので
  課題ごとにファイルを分離したい。**(3) [本改訂で追加] architect 初稿は (2) への対応として
  「mission10 のみ移動、mission03 は 02 と `/etc/shadow` を共有したまま」を推奨したが、CEO は
  これを採らず「mission03 も専用 vault へ分離する」(初稿 Option 2) を選択した。** 理由:
  CEO の要望 (2) は「evade flag を専用ファイルで分かりやすく」「`/etc/shadow` の重複でバレやすいのを
  解消」であり、この要望は mission10 だけでなく mission03 にも等しく当てはまる — mission10 のみを
  動かす案は mission03 の「バレやすさ」懸念を未解消のまま残す。
- **改訂で確定した配置 (実装 diff で実測、2026-09-01 時点で app/platform 両リポとも
  作業ツリーに反映済み・未コミット)**:

  | 課題 | type | 配置 (改訂後) | file:line |
  |---|---|---|---|
  | 02-credential-files | trigger (flag なし) | `/etc/shadow` — **無変更**。loud baseline として単独で残る | `challenges/02-credential-files/README.md` (無変更) |
  | 03-stealth-read | evade | `/opt/nimbus/vault/creds.recover` (flag-only、`plant-target-type: dir` で `/opt/nimbus/vault` 自体を mount) | `challenges/03-stealth-read/plant.sh:1-2,50-51` |
  | 10-final-exfil | evade (capstone) | `/opt/nimbus/vault/master.key` (flag-only、同じく `plant-target-type: dir`) | `challenges/10-final-exfil/plant.sh:1-2,38-39` |
  | 05-silent-search | evade | `/root/.ssh` 維持、flag clarity のみ改善 (本 ADR の scope 外) | — |

  **02↔03 の同一ファイル pairing は破棄する。** 02 が `/etc/shadow` に loud baseline として
  単独で残るため、「sensitive file を読むと発火する」(02) と「`/proc/self/root` で回避する」(03)
  という**技法**そのものの学習導線は保たれる — 技法はファイル非依存であり、実装は既に 03 の
  README/journey.yaml をこの前提で書き換え済み (`challenges/03-stealth-read/README.md`:
  「02 で `/etc/shadow` を読んで発火することを学んだ。同じ検知は `/etc/shadow` 専用ではない…」
  という導入に変更、`journey.yaml` の briefing/steps も同型に更新)。
  `challenges/02-credential-files/README.md:20-21` の「これが 03 の核心 (同 inode を別 path で
  開けば抜けられる)」という文も、02/03 が同一 inode を もはや共有しないため事実として
  不成立になっていた点を **実装済み** (commit `6dca49d` で「03 はこの原理を利用する:
  同じ Falco ルールが監視している別のファイルに、検知されない path 経由で到達する」へ
  書き換え済み。Consequences 参照)。
- **改訂前の実配置** (baseline として記録):

  | 課題 | type | 改訂前 file:line | flag 埋め込み |
  |---|---|---|---|
  | 02-credential-files | trigger (flag なし) | `challenges/02-credential-files/falco-rule.yaml:1-4` | — (`/etc/shadow` を大きな音で読ませるだけ) |
  | 03-stealth-read | evade | `challenges/03-stealth-read/plant.sh:1-4,39` (改訂前) | `/etc/shadow` 末尾に `# FALCO{...}` を `>>` 追記 |
  | 10-final-exfil | evade (capstone) | `challenges/10-final-exfil/plant.sh:1-3,20` (改訂前) | `/etc/shadow` 末尾に `# CTF_MASTER_KEY: FALCO{...}` を `>>` 追記 |

  02/03/10 の 3 課題が同一ファイル (`/etc/shadow`) を共有しており、03/10 は plant.sh の
  `plant-seed-source: /opt/ctf/plant-seed/etc` 経由で **同一 `/etc` mount dedupe group**
  (`gen-values.sh` の mount dedupe 相乗り、03 が「sort order で最初に declare した mission」
  として `readOnly:false` を代表宣言) を共有していた。**この `readOnly:false` 宣言は
  mission09 (`09-hidden-cache`、plant.sh を持たず `/etc/sudoers` を image に直接焼き込み) の
  `ln /etc/sudoers /etc/.cache.bak` が書き込み可能な `/etc` を要求するために存在していた。**
- **02↔03 の共有は事故ではなく意図的な教育装置だった (改訂前の前提)**:
  `challenges/02-credential-files/README.md:20-21` (改訂前) 「ファイル中身ではなく
  path 文字列をルールが見ている / これが 03 の核心 (同 inode を別 path で開けば抜けられる)」。
  `challenges/03-stealth-read/README.md` (改訂前) も 02 を明示的に前提にした導入文。
  **本改訂により、この「同一 inode」ペアリングは破棄される** — 技法の実演は 02/03 それぞれが
  別ファイル (02: `/etc/shadow`、03: `/opt/nimbus/vault/creds.recover`) に対して同じ
  path-string 判定の性質 (「発火は中身ではなく path を見る」) を独立に示す形に変わる
  (03/02 双方とも実装済み — commit `6dca49d`、上記参照)。
- **Falco 側の制約 (private 正典 `falco-ctf-platform/docs/falco-detection-conditions.md` §1
  で実測済み)**: `sensitive_files` マクロは `fd.name in (sensitive_file_names) or fd.directory
  in (/etc/sudoers.d, /etc/pam.d)`、`sensitive_file_names` = `/etc/shadow`, `/etc/sudoers`,
  `/etc/pam.conf`, `/etc/security/pwquality.conf` の**閉じた完全一致リスト**
  (`challenges/03-stealth-read/rule.yaml:19-20,212-215` — 2026-08-26 に `startswith /etc` 節が
  無いことへ訂正済み、app#179。platform 側 `helmfile/releases/falco/values.yaml.gotmpl` の
  新 customRules コメントも falcosecurity/falco:0.43.1 の実イメージから再確認済み)。
  **`/opt/nimbus/vault/...` はこのリストに無い** — 何もしなければ vault 配下のファイルは
  `Read sensitive file untrusted` を一切発火させず、mission03/10 双方の forbiddenRules ゲートが
  このパスに関して無力化し、「発火させずに読む」という要件が自明に (evasion 技法を使わずとも)
  成立してしまう — 採点の意図的な難度が抜け落ちる。
- **customRule の形は VP 判断で exact match から dir-prefix match へ変更**: architect 初稿
  (mission10 のみが対象だった段階) は `fd.name = "/opt/acme/vault/master.key"` の完全一致を
  提案したが、VP は mission03/10 の**2 課題**を同一 customRule でカバーする必要が生じたため、
  `fd.name startswith "/opt/nimbus/vault/" and container.name != "plant"` という
  **ディレクトリ prefix 一致**へ変更した。理由: (a) `/opt/nimbus/vault/` は CTF 専有の
  namespace であり、クラスタ内の他ワークロードに衝突するパスが存在しない (mission13 の
  `collection_target_dir` が `/opt/ctf/missions/...` prefix を同じ発想で専有している前例と同型)、
  (b) customRule エントリが 1 本で済み、mission03/10 それぞれに個別の append を書く必要がない、
  (c) 将来 vault 配下にファイルが増えても (例: 別課題が同じ vault namespace を使う設計になっても)
  rule 側の変更が不要になる。**実装は platform 側 `values.yaml.gotmpl` に
  `rules-nimbus-vault-sensitive-file.yaml` として既に反映済み**
  (`helmfile/releases/falco/values.yaml.gotmpl:192-274`、この判断の根拠コメントも同ブロックに
  記録されている)。**vault ディレクトリ名も `/opt/nimbus/vault/` に変更** (Operation
  NimbusBreach という narrative に合わせる。初稿の `/opt/acme/` から改称)。
- **ADR-0007 の mount granularity 制約と、実装が選んだ dir-type 共有の形**: file 種別の
  plant-target はその**enclosing directory**を、dir 種別の plant-target はそのディレクトリ
  自体を mount 対象にする。**実装は mission03/10 双方を `plant-target-type: dir`・
  `plant-target: /opt/nimbus/vault` として宣言し (mission05 の `/root/.ssh` と同型)、
  同一ディレクトリを 2 課題で共有する** (architect 初稿で想定していた「file 種別 + 別ファイル名」
  ではなく、`gen-values.sh` の既存 mount dedupe 機構が `/opt/nimbus/vault` を 1 つの mount
  エントリとして束ね、各 plant.sh はその中の別ファイル [`creds.recover` / `master.key`] へ
  それぞれ書き込む形)。旧 `/etc` group と構造的に同型 (今度は 03+10 のみ、02 を含まない)。
  `plant-seed-source` 宣言は不要 (mission05 と同じ理由 — 真新しいディレクトリで復元すべき
  既存データがない)、`plant-mount-readonly` override も不要 (vault への実行時書き込みが
  無いため fail-closed 側の `readOnly:true` のまま)。
- **旧 `/etc` mount group の消滅とmission09への影響**: 03/10 が `/etc/shadow` を離れると、
  **02 は plant.sh を持たない**ため、`/etc` を plant-target として宣言する mission が 1 件も
  残らなくなる。旧 `readOnly:false` 宣言 (mission09 の hardlink 用) は 03 の plant.sh ヘッダに
  同居していただけで、**mission09 自体は plant.sh を持たず `/etc` の subPath mount にも
  依存していない** — 09 が要求しているのは「`/etc` が書き込み可能であること」であり、`/etc` に
  対する subPath mount が一切発生しなければ `/etc` は challenge コンテナ自身の (root・
  `readOnlyRootFilesystem` 制約なしの) ネイティブなファイルシステムのままなので、
  **09 の `ln /etc/sudoers /etc/.cache.bak` は mount 自体が無くなることで引き続き成立する**。
  実装は `challenges/gen-values.sh` の ADR-0007 Verification 2 (negative test) にもこの変化を
  明示的に反映済み (`/etc/shadow` は現在どの plant.sh からも file-type target として宣言されて
  いないため、negative test は synthetic override として `/etc/shadow` を明示的に注入する形へ
  改修されている — `challenges/gen-values.sh` の `check_mount_granularity()`/`verify_negative_test()`
  diff 参照。これはテストの検証対象 [rejection logic 自体] を変えるものではなく、入力データの
  出所を「live catalog」から「synthetic override」へ変えるだけ)。これは新しいリスクではなく、
  旧機構が丸ごと不要になる**単純化**である。
- **I12 (flag isolation) は plant.sh の header 宣言から allowlist を動的に導出する構造**
  (`scripts/check-flag-isolation.sh:75-96,117-133`、`challenges/gen-values.sh:18-67`) —
  新しい plant-target を追加しても、両スクリプトの改修は不要 (header を正しく宣言すれば
  機械強制が自動的に追随する)。

## Options

### Option 1 (却下) — mission10 のみ `/opt/.../vault/master.key` へ retarget、mission03 は `/etc/shadow` に残す (architect 初稿の推奨)

**変更点**: mission10 のみを専用 vault ファイルへ retarget し、mission03 は `/etc/shadow` に
残して 02↔03 のペアリングを維持する。customRule は exact match 1 本 (mission10 分のみ)。

**コスト**: 最小 (plant.sh 1 本の retarget、customRules 1 本、README/journey 1 課題ぶんの更新)。

**リスクと可逆性**: 完全に可逆。**却下理由 (CEO 判断)**: mission03 の「バレやすさ」懸念
(02/03/10 が同じファイルに収束して見える、という CEO 原懸念の実質) が mission03 について
未解消のまま残る。architect 初稿は「02↔03 のペアリングという教育装置を壊すコストが懸念解消の
便益を上回る」と判断したが、CEO は「evade flag は専用ファイルで分かりやすく」という要望を
mission03 にも一律に適用することを優先した。02 単独で `/etc/shadow` の loud baseline を保てば
「path 文字列判定」という技法自体の学習は 02/03 が別ファイルでも成立する、というのが CEO/VP の
判断。

**効き始める閾値**: 採らない。ただし将来 customRules の数を最小化したい・vault namespace の
運用コストを避けたいという別の力学が生じた場合、この案 (mission03 は現状維持) へ戻す余地はある。

### Option 2 (採用・実装済み) — mission03/10 双方を `/opt/nimbus/vault/` 配下の専用 flag-only ファイルへ retarget、単一 customRule (dir-prefix append) で両方をカバー、mission02 は `/etc/shadow` の loud baseline を維持

**変更点 (2026-09-01 時点で app/platform 両リポの作業ツリーに実装済み、未コミット)**:
- `challenges/03-stealth-read/plant.sh`: header を `plant-target: /opt/nimbus/vault` /
  `plant-target-type: dir` に変更 (mission05 と同型、mount はディレクトリ自体)。
  `plant-seed-source` / `plant-mount-readonly` 宣言は不要 (真新しいディレクトリなので snapshot
  復元対象なし、readOnly:false override も不要)。本文は `mkdir -p
  "${PLANT_SEED_ROOT}/opt/nimbus/vault"` の後、`printf '%s\n'
  "${CTF_FLAG_03_STEALTH_READ:?...}" > "${PLANT_SEED_ROOT}/opt/nimbus/vault/creds.recover"`
  — ファイルは flag 1 行のみ (`cat` で flag だけが出る見せ方、CEO 指定)。
- `challenges/10-final-exfil/plant.sh`: 同様に `plant-target: /opt/nimbus/vault` /
  `plant-target-type: dir`。本文は `printf '%s\n' "${CTF_FLAG_10_FINAL_EXFIL:?...}" >
  "${PLANT_SEED_ROOT}/opt/nimbus/vault/master.key"`。**03 と全く同じディレクトリ
  (`/opt/nimbus/vault`) を plant-target として共有する**ため、`gen-values.sh` の mount dedupe
  が両者を単一の mount エントリに束ねる (`mkdir -p` は sort order で最初に実行される側 [= 03]
  が代表するが、両者とも独立ファイルへの書き込みなので相互干渉なし — 旧 `/etc` group と同型の
  **共有 dedupe group**、02 を含まない 2 課題構成)。
- `challenges/{03,10}-*/falco-rule.yaml`: **無変更**。`forbiddenRules` は引き続き
  `Read sensitive file untrusted` を含む既存の rule 名集合 (rule 名は不変、条件だけが
  platform 側 customRules で広がる)。
- platform `helmfile/releases/falco/values.yaml.gotmpl` の `customRules` に 3 件目の
  エントリ `rules-nimbus-vault-sensitive-file.yaml` を追加済み (`values.yaml.gotmpl:192-274`)。
  ADR-0008 の「rule に `append: true` で OR 節を足す」パターンを踏襲するが、**condition は
  exact match ではなく dir-prefix match** (VP 判断、Context 参照):

  ```yaml
  - rule: Read sensitive file untrusted
    append: true
    condition: >
      or (open_read and fd.name startswith "/opt/nimbus/vault/" and
          container.name != "plant")
  ```

  `container.name != "plant"` は mission05 の同型ルール (`values.yaml.gotmpl:127`) と
  同じ防御的 gate (plant initContainer は `$PLANT_SEED_ROOT/opt/nimbus/vault/...` にしか
  書き込まず実パスに触れないため理論上不要だが、precedent と揃えて安全側に倒す)。
- `challenges/custom-falco-rules.txt`: **追記不要** — 新設するのは既存 upstream rule 名
  (`Read sensitive file untrusted`) への append であり、新しい rule 名を導入しないため
  (`check-challenge-rules.sh` の allowlist は「upstream に無い名前」だけを対象とする)。
- `challenges/{03,10}-*/README.md` / `journey.yaml`: **実装済み**。Flag / 想定解セクションを
  vault ファイル基準に書き換え済み。03 は `cat /proc/self/root/opt/nimbus/vault/creds.recover`、
  10 は `cat /proc/self/root/opt/nimbus/vault/master.key` を想定解として明記。03 の README は
  「02 で `/etc/shadow` を読んで発火することを学んだ。同じ検知は `/etc/shadow` 専用ではない —
  vault ファイルにも同じルールが効いている」という導入に書き換え、02 への依存関係を「同一ファイル」
  ではなく「同じ path-string 判定の性質」として再定義している。
- `challenges/02-credential-files/README.md`: **実装済み (commit `6dca49d`)**。「これが 03 の核心
  (同 inode を別 path で開けば抜けられる)」の文 (旧 `README.md:20-21`) は 02/03 がもはや同一 inode
  を共有しないため事実として成立しなくなっていたが、「path 文字列判定という Falco の性質」自体の
  解説は残しつつ「03 はこの原理を利用する: 同じ Falco ルールが監視している別のファイルに、検知
  されない path 経由で到達する」という記述へ書き換え済み。
- `challenges/{03,10}-*/plant.sh` のコメント: **実装済み**。旧 `/etc` mount 共有・mission09 向け
  `readOnly:false` override への言及は新しいコメントから除去され、`/opt/nimbus/vault` を
  03/10 で共有するモデルの説明に置き換わっている。
- `challenges/gen-values.sh`: ADR-0007 Verification 2 (negative test) が `/etc/shadow` を
  synthetic override として明示注入する形へ改修済み (Context 参照。テストの検証対象自体は
  変わらない)。
- `challenges/{03,10}-*/rule.yaml` (docs 表示用抜粋): 再抽出は既存の運用限界と同型
  (mission05 の `Shell Redirected Private Key Read` append も `rule.yaml` には反映されて
  いない実測 — 表示用抜粋は upstream rule 本体のみを抜粋する既存慣行のまま。新しい
  regression ではない)。

**コスト**: Option 1 より高いが中程度。plant.sh 2 本の retarget、platform 側 customRules
追記 1 本 (dir-prefix なので mission 追加あたりのコスト増分はゼロ)、README/journey は
03/10/02 いずれも実装済み (commit `6dca49d`)。**forbiddenRules/expectedFlag のスキーマは無変更**なので
catalog/scoring/API 側の変更は一切不要。**旧 `/etc` mount group の消滅により `gen-values.sh`
が生成する `plant.mounts` は 1 エントリ減る**(単純化)。

**リスクと可逆性**: 完全に可逆 (customRules エントリを削除すれば upstream 相当に戻る、
plant-target も 1 行の header 差し替えで戻せる)。**残余リスク**: dir-prefix match は
exact match より広いブラスト半径を持つが、`/opt/nimbus/vault/` はクラスタ内で this-CTF
専有の namespace であり他ワークロードとの衝突は実効的に低い (Context 参照)。
**02↔03 のペアリングは失われる** — これが Option 1 との唯一の本質的なトレードオフであり、
CEO はこれを承知の上で受け入れた (Decision 参照)。

**効き始める閾値**: 実クラスタで customRules append 後、`cat /opt/nimbus/vault/creds.recover`
と `cat /opt/nimbus/vault/master.key` (どちらも素朴解) で `Read sensitive file untrusted` が
発火し、`cat /proc/self/root/opt/nimbus/vault/{creds.recover,master.key}` (回避) で発火しない
ことを両課題分実測できた時点 (2026-09-03 の次 stand-up で予定、Verification 参照)。

## Decision

**Option 2 を採る (CEO 選択、architect 初稿の推奨を上書き)。**

architect 初稿は「02↔03 の同一ファイル pairing という教育装置を壊すコストが、mission03 単体の
懸念解消の便益を上回る」と判断し Option 1 を推奨したが、CEO は「evade flag は専用ファイルで
分かりやすく」「`/etc/shadow` の重複でバレやすいのを解消したい」という要望をより広く解釈し、
mission03 にもこれを一律適用することを選択した。02↔03 の「同一 inode・別 path」という pairing
が失われても、**技法そのもの (Falco が path 文字列で判定する性質) はファイルに依存しない** ので、
02 (`/etc/shadow` を loud に読ませる) と 03 (vault ファイルを `/proc/self/root` 経由で stealth に
読む) をそれぞれ独立した教材として書き直せば、「sensitive file を読むと発火する」+
「`/proc/self/root` で回避する」という 2 つの学習ポイントは個別に保たれる (03/02 いずれも
README/journey の書き換えで実装済み — commit `6dca49d`、Consequences 参照)。

customRule は VP 判断で dir-prefix match (`fd.name startswith "/opt/nimbus/vault/"`) を採る。
mission03/10 の 2 課題を同一 customRule でカバーでき、将来 vault namespace にファイルが増えても
rule 側の変更が不要になる — exact match を課題数ぶん積み上げるより保守コストが低い。

## Consequences

- **手放すもの**: 02↔03 の「同一ファイルへの loud/stealth 対比」という教育装置。
  `challenges/02-credential-files/README.md:20-21` の「これが 03 の核心」という文は事実として
  成立しなくなるため実装 PR で書き換えた (**実装済み — commit `6dca49d`。「03 はこの原理を
  利用する: 同じ Falco ルールが監視している別のファイルに、検知されない path 経由で到達する」
  へ更新**)。architect 初稿はこの装置の保持を最優先したが、CEO はこれを手放す判断を明示的に
  行った。
- **手放すもの (2)**: 「vault ファイルを upstream の閉じた `sensitive_file_names` リストへ
  追加する」という更に単純な代替 (macro append) は採らない — マクロは他の upstream ルールからも
  参照されうる共有資産であり、rule 直下への append の方がブラスト半径が狭く、ADR-0008 の
  precedent とも一致する。
- **手放すもの (3)**: customRule の exact match (初稿) より広い dir-prefix match を採用する —
  `/opt/nimbus/vault/` 配下の**任意の**将来ファイルが自動的に sensitive 扱いになる
  (Context の残余リスク評価どおり、this-CTF 専有 namespace なので実効リスクは低いと判断)。
- **新たに守る事実**: `/opt/nimbus/vault/` 配下のファイルは project 固有 customRules
  (rule-level append、dir-prefix match、`rules-nimbus-vault-sensitive-file.yaml`) によって
  のみ sensitive 扱いになる — upstream の `sensitive_file_names` には含まれない。Falco chart /
  customRules 機構を将来作り直すときは、この append が消えると mission03/10 双方のフラグ読み取り
  が無検知になる (evade の意味が失われる) ことに注意する。
- **新たに守る事実 (2)**: mission03/10 は `/opt/nimbus/vault` という**共有 mount ディレクトリ**
  を dedupe group として共有する (旧 `/etc` group と同型、ただし 02 を含まない 2 課題構成、
  かつ両者とも `plant-target-type: dir` — 個別の enclosing directory 経由ではなく mount 対象
  そのものを共有する形)。将来どちらかの plant-target をさらに動かす場合、この共有関係を
  意識すること (`gen-values.sh` の mount dedupe ロジックが対象)。
- **旧機構の単純化**: 03/10 が `/etc/shadow` を離れることで、`/etc` を plant-target とする
  mission が 0 件になり、旧 `/etc` mount group と mission09 向け `readOnly:false` override が
  丸ごと不要になった (Context 参照。実装済み)。mission09 自体の挙動
  (`ln /etc/sudoers /etc/.cache.bak`) は無変更 — `/etc` がネイティブな (subPath mount
  されない) 書き込み可能領域に戻るだけ。ADR-0007 Verification 2 の negative test は、この
  変化により live catalog データではなく synthetic override で `/etc/shadow` を注入する形へ
  改修されている (検証対象の rejection logic 自体は不変)。
- **クロスリポ影響**: platform 側 `customRules` への追記と app 側 `plant.sh`/`README`/
  `journey.yaml` の変更は**両リポ同時 PR + 相互リンク必須** (Falco custom rule override
  は Cross-repo 契約表に既存の行がある — `.claude/rules/falco-ctf-app-conventions.md`
  「Falco custom rule override (ADR-0008)」行、この PR で本 ADR への参照を追記する)。
- **デプロイ順序 (ADR-0008/0017 と同じ拘束、platform-first)**: platform 側 customRules
  append が実クラスタで稼働する**前**に app 側 mission03/10 の新 plant-target を有効化すると、
  `cat /opt/nimbus/vault/...` が無検知になり、mission03/10 が「evasion 技法なしで自明に解ける」
  状態になる (softlock ではなく **free-win** — ADR-0008 のケースとは逆方向の失敗モード。
  deploy 順序を守らないと発現する)。**platform → app の順を守る** (platform 側の diff コメント
  にもこの依存が明記済み)。
- **参加者向け runbook**: reset-dirty の対象は不変 (forbiddenRules の集合が変わらないため)。
  新規の案内文言は不要。
- **rule.yaml 表示excerptの既知の限界を継承**: mission05 と同様、append 分は
  `challenges/{03,10}-*/rule.yaml` に反映されない (upstream rule 本体のみ表示)。
  新しい regression ではなく既存の運用慣行 (デプロイ済みルールセットからの再抽出は
  upstream 部分のみを対象にしてきた) の継続。
- **実機検証は次 stand-up (2026-09-03) に持ち越し**: platform 側 diff コメントに明記されている
  とおり、colima/dev cluster は現在立ち下げられており、DaemonSet-restart-free load と
  fire/no-fire mutation test は 2026-09-03 の次 stand-up で確認する。それまで本 ADR は
  Verification (a)(b) が blocking のまま「検証済み」と書かない (ADR-0008/0017 の Key Guards
  規律を継承)。

## Signposts

1. **将来 02/03 に相当する「同一 inode 越しの path-string 判定」という技法を再導入したい
   計画が生まれた場合** — 02 と別の課題 (03 とは限らない) を新たにペアリングする設計を
   個別に評価する。今回失った教育装置を無条件に復元しようとしない (CEO が明示的に手放す
   判断をしたため)。
2. **`/opt/nimbus/vault/` という prefix が将来別の課題やクラスタ内の何かと衝突した場合** —
   dir-prefix append ではなく専用 macro (`vault_sensitive_files`) へ切り出し、他ルールからの
   再利用や名前空間の明示化、あるいは exact match への回帰を検討する。
3. **Falco のメジャーバージョンが上がり `append: true` が hard error になった場合**
   (platform CLAUDE.md に既存の gotcha として記録済み) — `override: {condition:
   append}` 形へ mission05/mission03/10 すべての append を同時に移行する。
4. **participant から「vault ファイルの中身がそっけない」というフィードバックが
   複数回来た場合** — CEO 指定の「flag だけ」から、realism を足した内容 (例: JSON 形式の
   偽 credential ラッパ) への変更を検討する。ただし `cat` 一発で flag が読める体験
   (CEO 決定) を損なわない範囲に限る。
5. **vault 配下のファイル数が今後さらに増える計画が生まれた場合** (3件目以降の共有) —
   dir-prefix match は課題追加コストをゼロに保つ設計上の意図どおりだが、単一ディレクトリに
   複数課題が集中しすぎると mount dedupe group の可読性が下がる。3課題目が生じた時点で
   サブディレクトリ分割 (`/opt/nimbus/vault/<mission-id>/`) を再検討する。
6. **将来 `plant-target-type: file` を持つ課題が再導入された場合** (本 ADR で 03/10 が
   `file` → `dir` へ移行した結果、2026-09-01 時点でカタログ全体に `file`-type plant-target が
   0 件になり、`challenges/gen-values.sh` の ADR-0007 Verification 2 negative test は
   live catalog データではなく synthetic override (`check_mount_granularity()` の第 4 引数)
   で `/etc/shadow` を注入する形に変わっている) — **synthetic override だけでなく、
   `file_type_mount_targets()` が実データ (`plant_target_type "${id}/plant.sh"` の実際の
   宣言) から正しく非空集合を抽出する配線も再確認すること**。synthetic override の
   rejection logic 自体は生きているが、それは「実カタログにファイル種別が存在するときに
   `file_type_mount_targets()` が正しく拾えるか」という別の経路を検査しない
   (`gen-values.sh` の `file_type_mount_targets()` コメント、`scripts/check-flag-isolation.sh`
   の `plant_target_file_allowlist()` も同型の理由で 2026-09-01 時点は空集合)。新規
   `file`-type 課題を追加した PR では、`./challenges/gen-values.sh --check` が
   その課題の plant-target を正しく `plant.mounts` の dirname として反映しているかを
   diff で目視確認すること。

## Verification

- **(a) [blocking・実機・未実施 — 次 stand-up 2026-09-03] customRules ロード確認**: 新 append を
  含む Falco Helm values を colima/dev cluster に sync し、DaemonSet が `Running` のまま再起動
  せず、起動ログにルール読み込みエラーが無いこと (ADR-0008/0017 Verification (a-1) と同型)。
  現状 colima cluster は立ち下げられているため未実施 (platform 側 diff コメントに明記)。
- **(b) [blocking・実機・未実施 — 次 stand-up 2026-09-03] fire/no-fire mutation test (両課題分)**:
  `cat /opt/nimbus/vault/creds.recover` と `cat /opt/nimbus/vault/master.key`
  (いずれも素朴解) で `Read sensitive file untrusted` が発火すること、
  `cat /proc/self/root/opt/nimbus/vault/{creds.recover,master.key}` (03 の技法の再利用、10 でも
  成立するはず) で発火しないことの両方を、**03/10 それぞれについて**実測する (ADR-0017
  Verification (a-2)/(a-3) と同型)。
- **(c) [`make test`, 必須] catalog/API 回帰**: `internal/catalog` の交差テストと
  `internal/apispec` の parity テストが既存のまま green であること (falco-rule.yaml の
  スキーマ・フィールド集合を変えないため、新規テスト追加は不要 — 回帰確認のみ)。
- **(d) [必須] I12 flag isolation 回帰**: `make check-flag-isolation`
  (`scripts/check-flag-isolation.sh`) が green であること。plant.sh の header 宣言のみで
  allowlist が自動追随することを、新 plant-target 追加時点で確認する。
- **(e) [必須] challenge-rules CI ゲート**: `make check-rules` が green であること。
  `custom-falco-rules.txt` への追記が不要であることを本 ADR が主張しているため、
  無追記のまま green になることを実装 PR で確認する (追記が必要だった場合は本 ADR の
  Decision を見直す)。
- **(f) [必須] mount dedupe / ADR-0007 Verification 回帰**: `make gen-values`
  (`challenges/gen-values.sh --check`) が green であること。03/10 の共有 `/opt/nimbus/vault`
  mount エントリが 1 本に dedupe され、旧 `/etc` mount エントリが `plant.mounts` から消えている
  ことを実装 PR の diff で確認する。ADR-0007 Verification 2 の negative test (synthetic
  `/etc/shadow` override 経由) も green であること。
- **(g) [必須・実装済み] 02 README 整合性**: `challenges/02-credential-files/README.md` の
  「これが 03 の核心」文が書き換えられ、02/03 が別ファイルであることと矛盾しないことを
  review-5x で確認済み (commit `6dca49d`、Consequences 参照)。
- **(h) 本 ADR は Hard Invariant を新設しない**。I13a/I13b の対象候補集合への追加是非は
  実装 PR のタイミングで判断する (ADR-0008/0017 と同じ「実機 cluster 実測が残 gate」の
  未昇格候補として扱う)。

## Advice

- **falco-rules-expert skill (2026-08-31 相当)**: `fd.name` はパス文字列であって
  中身を見ないこと、除外は「バイナリ名だけ」ではなく gate 条件を厚くすること、
  完全一致 vs `startswith` の prefix collision リスクを確認した (非拘束の技術助言)。
  この助言が「upstream の `sensitive_file_names` は完全一致で書かれている」という事実確認、
  および dir-prefix match を採用する際の残余リスク評価 (this-CTF 専有 namespace ゆえ
  実効リスク低) の根拠になった。
- **falco-rules / falco-k8s skill (workspace 特化)**: ADR-0007 の mount granularity
  制約 (dir 種別は plant-target 自体を mount、file 種別は enclosing directory を
  mount) と、I12 の allowlist が header 宣言から動的導出されるため新規パス追加時の
  スクリプト改修が不要であることの確認に使用。
- **private 正典 `falco-ctf-platform/docs/falco-detection-conditions.md`**:
  `sensitive_files` マクロの実際の (2026-08-26 訂正後の) 完全一致定義を確認する
  唯一の情報源として使用。これが無ければ「vault ファイルは何もしなくても sensitive
  扱いになる」という誤った前提で設計してしまうところだった。
- **VP (2026-09-01)**: 初稿の exact match customRule (mission10 のみ対象) を、
  mission03/10 双方をカバーする dir-prefix match (`fd.name startswith
  "/opt/nimbus/vault/"`) へ変更する判断を下した。理由は「1 件の customRule で
  2 課題をカバーできる」「将来ファイル追加時に rule 無変更で済む」の 2 点
  (Context/Options に反映済み、非拘束の助言として記録)。実装はこの判断を
  `rules-nimbus-vault-sensitive-file.yaml` として platform 側に反映済み。
- **CEO (2026-09-01)**: architect 初稿 (Option 1: mission10 のみ移動) を却下し、
  Option 2 (mission03/10 両方移動) を選択。02↔03 のペアリング教育装置を手放す
  トレードオフを明示的に受け入れた (Decision 参照)。
