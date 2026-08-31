# ADR-0018: Lateral Movement (MITRE ATT&CK TA0008, T1021 系) は challenge の模擬対象から除外する

- Status: Accepted (2026-08-27, VP 承認 — ADR-0015/0016 と同一運用の除外判定として委任済み)
- Date / Deciders: 2026-08-27 / architect (提案・技術判断), VP (承認)
- 関連: REFACTORING.md P27 の ATT&CK 成長優先順位表 (`REFACTORING.md:1393`
  「中〜高 (要 cluster, 旧 P14-B) | Lateral Movement (T1021系) | multi-pod/SA token
  境界の設計変更が前提、コスト大。未着手」行)。ADR-0015 (Initial Access 除外)・
  ADR-0016 (Privilege Escalation 除外) と同じ検討フォーマット。ADR-0016 の
  Signpost「単一 Pod 隔離モデル自体が変更される決定が下った場合…P27 成長優先順位表の
  Lateral Movement 項目 [T1021系, multi-pod 前提] が実装されるタイミングで再検討が
  自然」(`docs/adr/0016-privilege-escalation-out-of-scope.md:115-118`) が予告していた
  再訪そのもの。新規 ADR — 他 ADR を supersede しない。2026-09-01 時点の EKS 実体
  (NetworkPolicy enforcement = 方式A) を反映するため、workspace
  `docs/adr/0005-eks-networkpolicy-enforcement.md` (ADR-WS-0005, Accepted) を根拠3
  (egress lockdown) の正典として参照するよう更新 (workspace#22 security 監査 →
  workspace#23 task brief)。

## Context

`scripts/gen-attack-layer.py:48-50` は Lateral Movement を既に `INTENTIONAL_GAPS`
に「未カバー — 単一 Pod 侵入シナリオのため横展開は物語の範囲外」として理由付き除外して
いるが、**ADR 引用が無い**唯一の行だった (`challenges/ATTACK-COVERAGE.md:31` も同じ
文言・ADR 引用無し)。Initial Access (`ATTACK-COVERAGE.md:33`, ADR-0015 引用) /
Privilege Escalation (`ATTACK-COVERAGE.md:34-35`, ADR-0016 引用) は既に正典化済みで、
`ATTACK-COVERAGE.md:35` は Privilege Escalation (T1611) の理由の末尾で
「Lateral Movement の除外 (単一 Pod シナリオ) とも表裏一体」と自ら明記している。
本 ADR はこの既存の暗黙合意を、ADR-0015/0016 と同水準の実測・厳密さで正典化する。

**アーキテクチャの実測 (仮説「Initial Access/PrivEsc と同じ壁に当たる」を検証)**:

- **1 参加者 = 1 Pod、複数 Pod を持つ参加者は存在しない**
  (`charts/ctf-user/templates/pod.yaml:1-4` のコメント、および本タスクの前提記述)。
  T1021 系 (Remote Services) は定義上「侵害済みホストから別のリモートホスト/サービスへ、
  正規の認証情報で移動する」行為であり、**移動先となる「別の到達可能な principal」が
  構造的に存在しない**。
- **ttyd の SA は自分自身の Pod にしか到達できない**: `charts/ctf-user/templates/role.yaml:11-19`
  の `Role` は `resourceNames: ["workspace"]` 固定で `pods`/`pods/exec` の `get`/`create`
  のみ。同一 namespace の他 Pod や他 namespace への `list`/`get`/`exec` 権限は一切無い。
  `plant`/`challenge` コンテナは `automountServiceAccountToken: false`
  (`pod.yaml:81`) でトークンそのものを持たない。
- **egress lockdown (P11.5) が cloud/他ホストへの到達も塞ぐ (根拠3、補強)**: `CLAUDE.md:71`
  「collector を参加者向け単一入口にする」。NetworkPolicy enforcement の機構は
  substrate 依存 (EKS: VPC CNI NetworkPolicy agent [方式A] / k3s: Calico) であり、
  正典は workspace `docs/adr/0005-eks-networkpolicy-enforcement.md` (ADR-WS-0005,
  Accepted 2026-09-01)。既存 mission 11 (`challenges/11-cloud-cred-hunt/README.md:3-4`)
  は「実 AWS 接続・実クレデンシャル・実 API 呼び出しは一切無い」ことを設計上の前提として
  明言済み — これは T1021.007 (Cloud Services) が要求する「実際に別のクラウド resource
  へ到達する」行為が、既存の運用制約下で不可能であることの既存の実例である。
  **この根拠は補強材料であり、下記「結論の dispositive 性」に示すとおり、根拠3
  自体の実効性 (2026-09-01 時点で ADR-WS-0005 の netpol-probe 実測待ち、下記
  Verification 節参照) に結論そのものは左右されない。**
- **upstream `falcosecurity/rules` (pin `falco-rules-3.0.1`) に T1021 系の default rule は
  無い** (`falco_rules.yaml` を実 fetch し実測: SSH に言及する rule は 3 本
  [`Disallowed SSH Connection Non Standard Port` / `Run shell untrusted` /
  `System user interactive`] のみで、いずれも `mitre_execution`/`T1059` タグであり
  横展開の検知を意図していない。SSH 以外の RDP/SMB/WinRM への言及は 0 件)。
  ADR-0017 と同じ discipline (upstream を実際に fetch して確認、仮説のまま進めない) で
  確認した。

**結論の dispositive 性 (根拠3 の状態に結論が左右されない構造)**:

上記 4 根拠のうち、**根拠1 (単一 Pod topology) と根拠2 (RBAC resourceNames scope)
の 2 つだけで、結論 (T1021 構造的に不可) は独立に dispositive に成立する**。T1021
(Remote Services) の定義上の要件は「侵害済みホストから、窃取済みの正規認証情報で
認証して、別の到達可能な principal へ移動する」ことであり、根拠1 が示す「移動先と
なる第二の到達可能な principal が構造的に存在しない」時点でこの要件は満たされない。
根拠2 (`role.yaml:11-19` の `resourceNames: ["workspace"]` 固定 RBAC scope) は
その構造が SA token 経由でもバイパスできないことを裏付ける。この 2 つは
NetworkPolicy enforcement 機構 (根拠3) にも upstream ruleset の状態 (根拠4) にも
依存しない、Pod トポロジと K8s RBAC という enforcement レイヤ非依存の事実である。

根拠3 (egress lockdown) と根拠4 (upstream ruleset) は補強材料であり、結論を成立
させる単独の必要条件ではない。根拠3 は 2026-09-01 時点で EKS 実体において暫定状態
にある (ADR-WS-0005 の netpol-probe 実測待ち — 下記 Verification 節参照) が、この
暫定性は結論そのものの成否には影響しない (security-engineer 監査 workspace#22、
PASS with conditions)。

**Sub-technique 別の判定**:

| Sub-technique | 判定 | 根拠 |
|---|---|---|
| T1021.001 (RDP) | 不成立 | Linux コンテナ環境に RDP サーバは存在せず (image に無い)、技術的に意味を持たない。Windows 前提の技術 |
| T1021.002 (SMB/Windows Admin Shares) | 不成立 | 同上。Samba を追加インストールしても「移動先」の別ホストが構造的に無い (下記) |
| T1021.004 (SSH) | 構造的に不成立 (根拠1・根拠2 で dispositive) | 移動先となる第二の到達可能な Pod/ホストが構造的に存在しない (根拠1)。SA token は自身の Pod のみに scope される (根拠2, `role.yaml:11-19`)。egress lockdown (根拠3、補強・正典 ADR-WS-0005) が sshd を持つ他ホストへの到達も塞ぐ |
| T1021.007 (Cloud Services) | 構造的に不成立 (根拠1・根拠2 で dispositive) | 移動先となる別の到達可能な principal が構造的に存在しない (根拠1・根拠2)。egress lockdown (根拠3、補強・正典 ADR-WS-0005。EKS では方式A の netpol-probe 実測待ち) が実クラウド API への到達も塞ぎ、mission 11 の既存設計判断 (「実 API 呼び出し無し」) と同じ壁に当たる |

**「同一 Pod 内コンテナ間の移動」を代替として使えるか (task 制約 (b) の検討)**:

ttyd → challenge の `kubectl exec` は、参加者が最初から持つ**正規のオンボーディング経路**
であり (`pod.yaml:1-4`)、参加者が「侵害によって新たに得た」到達性ではない。これを
Lateral Movement として再解釈すると、ADR-0015 が拒否した Option 2 と全く同じ誤り —
「実際に検出していない事象を検出したと主張する」spec の嘘と同型の問題 — を起こす。
加えて、この経路には principal/network boundary の変化が一切無い (同じ Pod ネットワーク
namespace内、認証情報の窃取や横取りも発生しない) ため、ATT&CK の Lateral Movement の
定義 (「別のシステム上へ移動する」) に技術的に一致しない。

## Options

### 1. multi-pod / SA token 拡張で本物の横展開を実現する

- **変更点**: 参加者ワークスペースに第二の到達可能な Pod (踏み台役) を追加し、
  SA token または NetworkPolicy を緩めて到達可能にする。
- **コスト**: 高。ctf-user chart 全体の再設計 (Pod トポロジ、RBAC、egress policy)。
  参加者数 × 2 Pod でクラスタリソースが倍増。
- **リスクと可逆性**: 高リスク・低可逆性の方向。ADR-0001 の SA token 隔離設計
  (`role.yaml:11-19` の `resourceNames: ["workspace"]` 固定) と P11.5 egress
  lockdown (NetworkPolicy enforcement — substrate により EKS: 方式A / k3s: Calico、
  正典 ADR-WS-0005) という、この CTF の**防御境界そのもの**を緩める。
  ADR-0016 が T1611 (Escape to Host) を除外した理由 (「単一Pod隔離という防御境界
  そのものが構造的に阻止済み」) の**逆側**を意図的に開けることになり、開けた瞬間に
  他の除外済み技術 (T1611 等) の再訪も避けられなくなる可能性がある。**Hard Invariant
  相当の境界変更**であり、architect 合意 + VP 承認だけでは足りず、CEO 判断が必要な
  規模の意思決定 (単一 Pod 隔離モデルの放棄) になる。
- **効き始める閾値**: 単一 Pod 隔離モデル自体を変更する決定が CEO レベルで別途下った
  場合 (ADR-0016 Signpost 2 と同じ条件)。

### 2. 同一 Pod 内コンテナ間の `kubectl exec` を横展開の代替表現として扱う

- **変更点**: ttyd→challenge の既存の exec 経路に新しい ATT&CK タグ (T1021 系) を
  付ける、または新規 trigger challenge でこの経路の利用を検知対象にする。
- **コスト**: 低い (既存経路の再タグ付けのみ)。
- **リスクと可逆性**: 可逆だが、上記 Context で示したとおり技術的に不正確
  (principal/network boundary の変化が無い正規オンボーディング経路を攻撃技術と
  ラベル付けする)。ADR-0015 が拒否した Option 2 と同型の「spec の嘘」問題を
  ATT&CK coverage 表に持ち込む。監査/セールス資料としてこの表を信じる読み手を
  誤導する。
- **効き始める閾値**: ATT&CK coverage の外部提示で「Lateral Movement を含む網羅」が
  要件化された場合でも、正確性を犠牲にする理由にはならない。事実上採らない。

### 3. (推奨) Lateral Movement は模擬不可と判定し、`ATTACK-COVERAGE.md` の
「意図的に扱わない領域」表に ADR 引用を追加する。既存の除外自体は変更しない

- **変更点**: `scripts/gen-attack-layer.py:48-50` の `INTENTIONAL_GAPS` の
  Lateral Movement 行に ADR-0018 の引用を追加 (既存の除外判定は正しかったので、
  理由文言そのものは維持しつつ出典を明示する) → `make gen-attack` で
  `challenges/ATTACK-COVERAGE.md:31` を再生成。REFACTORING.md P27 表
  (`REFACTORING.md:1393`) の「未着手」を「除外判定済み (ADR-0018)」に更新 (VP 記帳)。
- **コスト**: 最小 (既存の除外判定への出典追記のみ。実装は該当 Engineer)。
- **リスクと可逆性**: 低リスク・完全可逆 (Signposts に従い再訪可能)。
- **効き始める閾値**: 即時。

## Decision

**Option 3。**

理由: T1021 系はいずれの sub-technique も、この CTF の防御境界 (単一 Pod 隔離・
SA token 狭域スコープ・egress lockdown) そのものによって「移動先」が構造的に
存在しないため実現不可能であり、この結論は仮説どおり ADR-0015 (Initial Access —
境界外部の観測不能) と ADR-0016 (Privilege Escalation T1611 — 防御境界の構造的成功)
が辿った壁と同一である。新規 challenge の追加 (Option 1) は防御境界そのものを緩める
CEO レベルの決定を要し、既存経路の再解釈 (Option 2) は実際に検出していない事象を
検出したと主張する不正確な表示になる。`ATTACK-COVERAGE.md:35` が既に自認していた
「Lateral Movement の除外は T1611 の除外と表裏一体」という事実を、出典を明示して
正典化するのが最も安価かつ正確である。

## Consequences

- 何を諦めたか: ATT&CK Enterprise の TA0008 (Lateral Movement) カバレッジ。
  `attack-navigator-layer.json` は Lateral Movement が赤く塗られないままになる
  (INTENTIONAL_GAPS は coverage markdown のみに影響し、Navigator layer は不変 —
  ADR-0015/0016 と同じ挙動)。
- 新たに守る invariant: なし。Hard Invariant への昇格は行わない (既存の SA token
  隔離・egress lockdown 規約の帰結を明文化するだけであり、新しい機械強制対象では
  ない)。
- runbook への影響: `scripts/gen-attack-layer.py:48-50` の Lateral Movement 行に
  ADR-0018 引用を追加 → `make gen-attack` で `ATTACK-COVERAGE.md` 再生成
  (実装は該当 Engineer、Class-1 相当)。`REFACTORING.md:1393` の P27 成長優先順位表を
  「除外判定済み (ADR-0018)」に更新 (VP 記帳)。既存 challenge のタグ・chart は無変更。

## Signposts (この決定を覆す観測可能な信号)

- 単一 Pod 隔離モデル自体が変更される決定 (multi-pod ワークスペース・SA token の
  cross-pod 拡張・egress lockdown の緩和のいずれか) が CEO レベルで下った場合
  → 本 ADR を再訪する (ADR-0016 Signpost 2 がこの条件を先に立てていた)。
- `charts/ctf-user/templates/role.yaml` の Role が `resourceNames: ["workspace"]`
  固定を外れ、他 Pod/namespace への `get`/`list`/`exec` を許可するように変更された
  場合 → 即時再訪 (このような変更自体が本 ADR の前提事実を壊すため、実装 PR の
  レビューで検知されるべき)。
- Falco の公式ルールセットに T1021 系 (SSH/RDP/SMB/WinRM の横展開) 検知 default rule
  が追加され、custom rule 無しで実装コストが大幅に下がった場合 → コスト再評価
  (ただし「移動先が無い」という構造的問題自体は解決しない点に注意)。
- ATT&CK coverage の外部提示 (監査対応・認定要件・セールス資料) で
  「Lateral Movement を含む全 tactic 網羅」が要件化された場合 → Option 1 のコスト
  再評価が必要になる (CEO 判断が前提)。

## Verification

本決定 (Option 3: ドキュメント/生成器の定義変更のみ) 自体に対する機械検査対象は
無い (Hard Invariant への昇格は行わない — ADR-0015/0016 と同じ歯止め規則に従う)。
結論 (T1021 構造的に不可) は根拠1・根拠2 だけで dispositive に成立するため、
この判定は下記 Signpost の状態に関わらず揺るがない。

**根拠3 (egress lockdown) 限定の Signpost**: 根拠3 が主張する「egress lockdown が
cloud/他ホストへの到達を塞ぐ」の実効性は、ADR-WS-0005 (方式A: VPC CNI
NetworkPolicy agent) の実測ゲート — 次回 EKS stand-up での netpol-probe
(workspace→scoreboard 直 POST が timeout すること) + verify.sh / verify-auth.sh
フル green — に従属する。2026-09-01 時点でこの実測は未了 (prod cluster は
2026-08-17 teardown 済みで現在稼働クラスタ無し)。netpol-probe が green で実証
されるまで、根拠3 は「文言上は substrate 中立に記述されているが、EKS 上での
enforcement は未証明」の暫定状態として扱う (security-engineer 監査
workspace#22、PASS with conditions)。netpol-probe が green で実証された時点で
根拠3 は正式に成立へ格上げされる。regression した場合 (netpol-probe が期待どおり
timeout しない等) は ADR-WS-0005 の Signpost 1 (Calico policy-only fallback 検討)
に従う — その場合でも根拠1・根拠2 が dispositive であるため本 ADR の結論自体は
再訪不要。

## Advice

- 本タスクの発注者 (VP 相当、2026-08-27) からの仮説: 「Lateral Movement は定義上
  Pod/ホスト間を移動する行為であり、Initial Access/Privilege Escalation と同じ壁に
  当たる可能性が高い」— 結論を先取りしないことを条件に調査を発注された。実測の結果、
  この仮説は正しかった (T1021.004/.007 は構造的に不成立、T1021.001/.002 は Linux
  コンテナ環境で技術的に無意味)。
- ADR-0016 (security-engineer 判断・architect 実測裏書き、2026-08-26) が
  Signpost として「本 ADR の T1611 部分は Lateral Movement 項目が実装される
  タイミングで再検討が自然」と予告していた — 本 ADR はその予告どおりの再訪だが、
  再訪の結論は「実装しない」で確定した。
- security-engineer への確認を推奨: 本判断は ADR-0001 (SA token 隔離) と P11.5
  (egress lockdown) の帰結を辿った設計判断であり、新たなセキュリティ境界の変更では
  ない。ただし ATT&CK coverage 表が監査文書として外部利用される可能性を踏まえ、
  ADR-0016 と同様に追認を推奨する (非拘束の助言として記録。2026-08-27, architect)。
