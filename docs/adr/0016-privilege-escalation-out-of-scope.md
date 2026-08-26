# ADR-0016: Privilege Escalation (MITRE ATT&CK TA0004, T1548/T1611) は challenge の模擬対象から除外する

- Status: Accepted (2026-08-26, VP 承認)
- Date: 2026-08-26
- Deciders: security-engineer (判断・提案), architect (技術裏書き), VP (承認済み)
- 関連: REFACTORING.md P27 の ATT&CK 成長優先順位表 (「Privilege Escalation (T1548/T1611) |
  除外検討」行)。ADR-0015 (Initial Access 除外) と同じ検討サイクルで並走判断。
  新規 ADR — 他 ADR を supersede しない。

## Context

REFACTORING.md P27 の成長優先順位表は Privilege Escalation (TA0004) を
「除外検討 (security-engineer 判断)」としていた。security-engineer が調査し、
以下の判断を返した (VP 経由、2026-08-26):

- **T1548 系 (Setuid/Setgid, Sudo など)**: 除外妥当。理由 — challenge コンテナは
  常時 root で、参加者が操作可能な non-root の起点が構造上存在しない
  (ttyd は kubectl exec 相当で root の challenge コンテナへ直接入る)。
- **T1611 (Escape to Host)**: 除外妥当。ただし T1548 とは別種の理由 —
  単一 Pod 隔離という本プロジェクトの防御境界そのもの (privileged 未使用・
  hostPath/docker.sock 非マウント・追加 capability 無し・Pod レベル
  `seccompProfile: RuntimeDefault`・`automountServiceAccountToken: false`)
  が構造的に阻止済み。

architect が実測で裏書きした (`.claude/rules/falco-ctf-app-conventions.md:14`,
`charts/ctf-user/templates/pod.yaml`):

- UID 表 (`falco-ctf-app-conventions.md:14`) — challenge コンテナは
  **root (0) が意図的** (CTF realism)。T1548 系は「non-root → root」の
  before/after 差分が無ければ技術的に無意味だが、その差分を生む起点が
  参加者に与えられていない。
- `charts/ctf-user/templates/pod.yaml` の `challenge` コンテナ block を実測
  (grep): container-level `securityContext` は一切存在しない
  (`privileged: true` 無し、追加 capability 無し)。Pod レベル
  `seccompProfile: {type: RuntimeDefault}` (`pod.yaml:75` 系) を
  フィールド単位継承で受ける (`## SecurityContext` 節)。
- `hostPath` / `docker.sock` は `charts/ctf-user/` ツリーに 1 件も出現しない
  (grep 実測、ゼロ件)。
- `pod.yaml:62` — `automountServiceAccountToken: false` (Pod レベル)。

ADR-0015 (Initial Access 除外) が辿った「境界の外側が構造的に観測不能」という
論法とは異なり、本件は 2 つの異質な論拠を束ねている点に注意が必要:

1. T1548 は **起点の欠如** (before/after を作れない) — ADR-0015 と同種の
   「構造的に表現不能」。
2. T1611 は **防御の成功** (脱出を試みても機構が阻止する) — challenge が
   「境界内で完結している」ことの積極的な証明であり、観測不能ではなく
   むしろ「試みれば阻止イベントが観測できるかもしれないが、それは
   Impact 相当の破壊的検証コストを伴い CTF 環境の保護方針
   (`ATTACK-COVERAGE.md` の Impact 除外理由) と衝突する」という別種の論拠。

この異質性を 1 つの理由文で束ねると、将来の読み手が「なぜ T1548 と T1611 が
同じ扱いか」を誤解する (どちらも「除外」だが、除外の**理由**が違う)。

## Options

1. **T1548/T1611 それぞれについて個別の新規 challenge を検討する**
   - 変更点: T1548 用に「non-root 起点を人工的に用意する」challenge、T1611 用に
     「実際に脱出を試みさせる」challenge を追加する。
   - コスト: 高。T1548 は non-root 起点を作るために UID 表 (I2 と同型の規約) を
     challenge 単位で崩す必要があり、CTF 全体の realism 前提 (challenge=root) と
     矛盾する。T1611 は実際に脱出させる検証には privileged 相当の緩和が要り、
     防御境界そのものを緩めることになる。
   - リスク: 高。T1611 challenge が「本当に脱出できる」ようにすると、それは
     単一 Pod 隔離という設計の根幹 (`## SecurityContext` 節) を弱めることになり、
     CTF 環境の共有基盤としての安全性を損なう。「脱出に見せかけて実際は
     脱出できない」fixture にすると、06 と同型の「narrative のみ・detection
     は別技術の言い換え」に帰結し、Option 3 と実質同じになる。
   - 効き始める閾値: 単一 Pod 隔離モデル自体を変更する決定が別途下った場合。
2. **T1548/T1611 を除外はするが、理由を1行に圧縮して ADR-0015 に追記する**
   - 変更点: ADR-0015 の Context/Options に T1548/T1611 の節を追加する。
   - コスト: 低いが、ADR-0015 は Initial Access という別タクティクの決定であり、
     Accepted 化後の追記は「navigational なポインタ」「非決定的な事実訂正」の
     例外にも当たらない (`docs/adr/README.md:30-38` の規律)。決定内容の追加は
     supersede 相当になり、規律違反になる。
   - リスク: 中。2 つの異質な論拠 (起点欠如 / 防御成功) を圧縮すると、
     Signposts が対応づけられなくなる (T1548 の再訪条件と T1611 の再訪条件は
     全く別物)。
3. **(推奨) 独立した ADR (本 ADR) として、T1548/T1611 を除外判定する。
   `ATTACK-COVERAGE.md` の「意図的に扱わない領域」表に追記する**
   - 変更点: `scripts/gen-attack-layer.py` の `INTENTIONAL_GAPS` リストに
     T1548/T1611 の行を追加 (実装は該当 Engineer)。REFACTORING.md P27 表を
     「除外判定済み」に更新 (VP 記帳)。
   - コスト: 最小 (生成器への行追加 + ドキュメント更新)。
   - リスク: 低。可逆 (Signposts に従い再訪可能)。
   - 効き始める閾値: 即時。

## Decision

**Option 3。**

理由: T1548 (起点の構造的欠如) と T1611 (防御境界の構造的成功) は除外の**結論**
は同じだが**論拠**が異質であり、ADR-0015 (Initial Access — 境界外部の観測不能)
とも異質である。ORGANIZATION.md の ADR 作成基準⑤ (「やらないこと」の追加) は
Initial Access と全く同じ条件でこの決定にも当たるため、口頭記録や別 ADR への
圧縮追記ではなく独立した ADR として正典化する。新規 challenge の追加 (Option 1)
は、T1548 側では CTF の root-realism 前提と矛盾し、T1611 側では単一 Pod 隔離
という防御の根幹を緩めるリスクを伴うため見送る。

## Consequences

- 何を諦めたか: ATT&CK Enterprise の TA0004 (Privilege Escalation) カバレッジ。
  `attack-navigator-layer.json` は Privilege Escalation が赤く塗られないままになる。
- 新たに守る invariant: なし。Hard Invariant への昇格は行わない (既存の
  UID 表・SecurityContext 規約の帰結を明文化するだけであり、新しい機械強制
  対象ではない)。
- runbook への影響: `ATTACK-COVERAGE.md` の「意図的に扱わない領域」表への
  行追加 (生成器経由)。既存 challenge のタグ・chart は無変更。

## Signposts (この決定を覆す観測可能な信号)

- T1548: 将来 challenge の realism 前提が「参加者は non-root で開始し、
  何らかの手段で root を得る」という別モデルに変わった場合 (現行の
  root-realism 前提が CEO 判断で変更された場合) → 本 ADR の T1548 部分を再訪する。
- T1611: 単一 Pod 隔離モデル自体が変更される決定 (multi-pod / 特権コンテナを
  challenge に許可する等) が下った場合 → 本 ADR の T1611 部分を再訪する
  (P27 成長優先順位表の Lateral Movement 項目 [T1021 系, multi-pod 前提] が
  実装されるタイミングで再検討が自然)。
- `charts/ctf-user` の challenge コンテナに container-level `securityContext`
  が新設され、かつそれが `privileged` / capability 追加 / `seccompProfile`
  緩和のいずれかを含む場合 → 即時再訪 (このような変更自体が本 ADR の
  前提事実を壊すため、実装 PR のレビューで検知されるべき)。
- ATT&CK coverage の外部提示 (監査対応・認定要件・セールス資料) で
  「Privilege Escalation を含む全 tactic 網羅」が要件化された場合 →
  Option 1 のコスト再評価が必要になる。

## Verification

無し。本決定はドキュメント/生成器の定義変更のみであり、「決定が守られているか」
を機械的に検査する対象が存在しない (Hard Invariant への昇格は行わない —
ADR-0015 と同じ歯止め規則に従う)。

## Advice

- security-engineer (2026-08-26): T1548/T1611 の除外判断本体。T1548 =
  非root起点の構造的欠如、T1611 = 単一Pod隔離という防御境界そのものが
  阻止済み、という二分をそのまま採用した (原文は VP 経由で受領)。
- architect (2026-08-26, 本ADR起票者): security-engineer の判断を
  `.claude/rules/falco-ctf-app-conventions.md:14` の UID 表と
  `charts/ctf-user/templates/pod.yaml` の実装 (container-level
  securityContext 不在・hostPath/docker.sock 不在・Pod レベル
  automountServiceAccountToken:false) で実測裏書きした。2 つの理由を
  1 つの ADR に同居させつつ Signposts を別々に立てることで、将来
  どちらか一方だけが再訪対象になった場合の追跡可能性を確保した。
