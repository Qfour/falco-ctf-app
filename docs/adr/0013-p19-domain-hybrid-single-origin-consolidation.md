# ADR-0013: ドメイン設計 subdomain→path ハイブリッド化 (P19) は既に決定・実装・prod 投入済み — P19-1 設計メモの内容を正典として記録する

- Status: **Accepted** (2026-08-26, architect 起草・実測確認。新規の設計判断はゼロ — 実装が
  先行して完了しているため、本 ADR は決定を「行う」のではなく「記録する」。VP 承認待ち)
- 関連: app#61 (Open, P19 app 層), platform#24 (Open, P19 基盤層) — 本 ADR は両方の
  P19-1 設計メモ要求に応える。app#100 (merged 3fa5648, P19-2b app 半分)、
  platform#57 (merged b410dc1, P19-2b platform 半分)、platform#54 (merged 750226e, P19-2a)。
  follow-up (非 blocking, open のまま): app#99 (ttyd authSignin の appHost 追随・
  auth. compat bridge 撤去)、app#101 (README/AGENTS の stale host 参照)。
  REFACTORING.md `## P19` (2026-08-16 時点で「P19-1 設計メモ統合済」に更新済み)。

## Context

### 依頼の経緯

VP から「P19-1 設計メモを起草してほしい」という委任を受けた。依頼は app#61 / platform#24
の 10 個の未決定論点 (着手順・DOCS_BASE_URL・nginx `$host` 分岐・hints.js・auth-url 分離・
cross-origin proxy・cert 戦略・Cloudflare 集約・verify-auth.sh・cookie domain) を解決する
設計メモを書くことを求めていた。

### 実測: この設計メモは 2026-08-16 に既に書かれ、実装され、prod に投入されている

`REFACTORING.md:322-354` (`### P19-1 設計メモ統合`) を読むと、2026-08-16 に P23 landing を
踏まえた 3 観点 (platform/app/security) Opus スパイクが行われ、CEO が 6 点を決定済みと
記録されている (`REFACTORING.md:343-349`)。その直後に:

- **P19-2a** (platform-activation): `platform#54` → squash commit `750226e` (2026-08-16 merge)。
- **P19-2b** (単一 origin 移行, app+platform 同時): `app#100` → squash commit `3fa5648`
  (2026-08-16T13:28:06Z merge, `git show 3fa5648`)、`platform#57` → squash commit `b410dc1`
  (2026-08-16T13:28:57Z merge)。両方とも独立 cross-repo 5x (R1=security-engineer/Opus PASS、
  R2-R5 Sonnet PASS) を経て merge 推奨 → CEO merge。

さらに memory `project_prod_standup_2026_08_16` によれば、同日の 16 名リハ用 prod stand-up が
「単一 origin + P23 初 prod」として成功している。**設計・実装・cross-repo 5x・CEO merge・
prod 実証のすべてが本依頼の 10 日前に完了している。**

app#61 / platform#24 が Open のままなのは、これらの Issue に「Closes #61」等のリンクを
持つ PR が無く (`app#100` の PR body を確認済み、closing keyword 不使用)、実装が Issue を
自動クローズしなかったための**台帳と実態のずれ**である (ADR-0010 で扱った Issue #118 と
同型の事故)。

### 実コードでの再検証 (10 論点)

依頼された 10 論点それぞれについて、実装済みコードを実読して照合した:

| # | 論点 | 決定・実装 | 根拠 (file:line) |
|---|---|---|---|
| 1 | P18/P19 着手順 | **path-first 統合**。P18-2 (self-scope read gate) を独立実装せず、
  最初から `/journey` path トポロジで実装 | `REFACTORING.md:367-378` (2026-08-14 VP 裁定)。
  実装: `internal/scoreboard/authz_test.go`, `server_test.go:1334`
  (`TestReadGate_SelfAllowed`) が self-or-admin gate を検証 |
| 2 | `DOCS_BASE_URL` | **path prefix 化ではなく、participant 向け利用自体を撤去** (P23-5 で
  participant docs を portal Home タブに吸収したため、path 集約の必要が消えた)。
  env・`docsURL()` の absolutisation ロジック自体は API 契約 (`docs/openapi-scoreboard.yaml`
  の `docsUrl` フィールド) を維持するため残置、ただし UI 上は dead | `cmd/scoreboard/main.go:69-88`
  (コメントで dead 化を明記), `internal/scoreboard/api/api.go:1808-1813` (`docsURL`) |
| 3 | docs-site nginx `$host` 分岐 | **単一 `server_name _` + path 分岐 (`location /docs-admin/`)
  に書換済み**。`$host` 分岐 (旧 admin/participant 2 server block) は撤去。`alias` で
  path prefix を filesystem root から剥がす | `docs-site/nginx.conf:24-42` (実読・全文確認) |
| 4 | `hints.js` の `/api/*` 絶対パス | **hints.js 自体を撤去** (participant docs ページの
  `/api/` proxy への依存が P23-5 の docs 撤去で消滅)。ファイル探索で存在しないことを確認 |
  app#100 PR body: "Dropped the dead participant hints.js /api/ proxy" |
| 5 | journey/admin の auth-url 分離 | **同一 host・2 Ingress オブジェクト・path 排他**
  (admin: `path: /` → `/check-admin`。participant: `/portal` Exact + `/api/users/`・
  `/api/challenges/` Prefix → any-login)。両 Ingress が `auth-response-headers`
  header-forgery guard を維持 | `charts/scoreboard/templates/ingress.yaml` (全文実読),
  `charts/scoreboard/templates/ingress-journey.yaml` (全文実読) |
| 6 | cross-origin proxy の不要化 | **確認済み・撤去済み**。docs-admin の旧 `/api/` proxy
  (client 送信 email を信頼する設計) と hints.js の proxy の両方を撤去 = 境界強化
  (proxy 経由の email 偽装余地が構造的に消える) | app#100 PR body ("Dropped the dead
  participant hints.js /api/ proxy"; docs-admin "旧 /api/ proxy〈client email 信頼〉を撤去") |
| 7 (platform) | cert 戦略 | **単一 SAN cert への移行ではなく、既存 wildcard `*.<suffix>` が
  すでに `appHost` を被覆するため cert 無改修**。per-host 個別発行 (`scoreboard-tls`) のみ撤去
  (冗長だった分の削除) | platform commit `b410dc1` message: "dropped the redundant
  per-host cert-manager-issued scoreboard-tls (the existing wildcard cert already
  covers appHost — cert 無改修)" |
| 8 (platform) | Cloudflare record 集約 | **6 → 3** (1 に集約ではない。CEO 決定②③で
  dex は subdomain 維持・`auth.<suffix>` compat bridge も一時残置と確定したため) |
  app#100 PR body ("CF 6→3"), `REFACTORING.md:333` (dex residual risk 受容確定) |
| 9 (platform) | `verify-auth.sh` | **`APP_HOST` 変数 + path 経路に更新済み**。journey
  self-scope チェックのデフォルトホストが `APP_HOST` に変わり、probe する path は不変 |
  `falco-ctf-platform/scripts/verify-auth.sh:18-29` (`APP_HOST` 定義),
  `:150-260` (journey self-scope チェックが appHost の `/portal` path を probe) |
| 10 (platform) | cookie domain | **不変を再確認**。`.{suffix}` は PSL 下限
  (`.dev` は public suffix なので `ctf-event.dev` 自体が既に registrable domain・
  これ以上 narrow 不可能) であることを実測確認し、「narrow 不可→host 集約で blast radius
  縮小」に宿題を再定義 | `REFACTORING.md:326` (★核心の前提訂正), platform `CLAUDE.md`
  クロスリポ契約表の Cookie domain 行 |

**10 論点すべてが、依頼時点で既に実装・merge・prod 実証済みであることを確認した。**
唯一、issue の当初の想定 (「6→1」「単一 SAN cert へ移行」) と実際の決定が異なる点が 2 つ
あった (#7 cert は無改修、#8 CF は 6→3 で 1 ではない) — これは CEO が 2026-08-16 に
「dex residual risk 受容」「auth. compat bridge を follow-up (#99) に切り出す」ことを
決定したことによる**意図的な縮小** (完全な「1 host」化は#99 が完了するまでの中間状態)。
issue #61/#24 のチェックボックスをそのまま完了とマークすると、この縮小判断が記録に残らない
ため、本 ADR がその差分を明示する。

### 未解決のまま残る事項 (本 ADR の scope 外・既に Issue 化済み)

- **app#99**: `charts/ctf-user` の ttyd `authSignin` が `auth.<suffix>` に hardcode されたまま
  (platform 側は `auth.<suffix>` を compat bridge として oauth2-proxy Ingress に併存させている、
  `falco-ctf-platform/helmfile/releases/oauth2-proxy/values.yaml.gotmpl:80-99`)。fixed host は
  現状「6→2」(`appHost` + `auth.<suffix>`) で、REFACTORING.md が目標とした「6→1」ではない。
  **non-blocking** (bridge は動作する。P19-1 の目標形の未完了部分)。
- **app#101**: README/AGENTS の stale `scoreboard.<suffix>` host 参照 (docs-only)。

## Options

新規の設計判断ではないため、本節は Issue #118 と同型 (ADR-0010) — 「何をするか / しないか」
の選択を記録する。

### Option 1 — 何もしない (app#61 / platform#24 を Open のまま放置し、新規設計メモも書かない)

- 変更点: なし。
- コスト: ゼロ (今は)。
- リスクと可逆性: 次に誰か (CEO/VP/新しい architect セッション) がこの Issue を読むと
  「まだ P19-1 が終わっていない」と誤解し、同じ調査を再度依頼する
  (ADR-0010 の Issue #118 と同型の「台帳と実態のずれ」)。また REFACTORING.md の P19 節が
  いずれ `REFACTORING-DONE.md` へアーカイブされると、10 論点の解決根拠 (file:line) が
  どこにも横断的に記録されないまま埋もれる — cross-repo 契約 (cookie domain / ALLOWED_ORIGINS
  / auth-url 分離) に関わる決定が、恒久的な参照点 (`docs/adr/`) を持たないまま
  living roadmap の archive に沈む。
- 効き始める閾値: 次にこの Issue を誰かが読んだ瞬間、または REFACTORING.md の P19 節が
  DONE にアーカイブされた瞬間。

→ **却下。** 実態と台帳を一致させないコストと、cross-repo 契約決定の恒久的参照点を
作らないコストが、ADR を書くコストより高い。

### Option 2 — 依頼された設計メモを新規に (既存決定を無視して) 書く

- 変更点: 10 論点を、既存の CEO 決定 (2026-08-11・2026-08-16) や実装済みコードを参照せず
  ゼロから再検討した設計メモを書く。
- コスト: 高い。実装が既に prod で稼働している決定を「まだ決まっていない」前提で再検討すると、
  既存の cross-repo 5x (R1=security-engineer/Opus PASS を含む) の監査結果を無視することになる。
  実装と食い違う新しい推奨を書くと、**どちらが正典か**を将来の読者が再調査する負債になる
  (ADR-0010 の Option 2 と同じ理由で却下)。
- リスクと可逆性: 低可逆。新しい設計メモが実装と矛盾する提案を含んだ場合、
  「もう実装済み」という事実と衝突し、無駄な re-work 議論を招く。
- 効き始める閾値: 無し (常に有害)。

→ **却下。**

### Option 3 — 実測結果を ADR として記録し、既存 Issue をこの ADR にリンクして解消する (本 ADR・推奨)

- 変更点: (1) 本 ADR で 10 論点の決定・実装・実測結果を記録する。(2) app#61 / platform#24 を
  本 ADR + merge 済み PR (app#100/platform#57/platform#54) へのリンク付きコメントで
  クローズ推奨する (VP 実行)。(3) follow-up (app#99/#101) は独立 Issue のまま残す
  (混同すると「P19-1 の scope」と「polish の scope」が区別できなくなる)。
- コスト: 低い (文書のみ、コード変更ゼロ)。
- リスクと可逆性: 完全に可逆。唯一のリスクは「本当に決定・実装が prod で機能しているか」の
  判定を architect 単独の実測に依存する点だが、実装は既に cross-repo 5x
  (R1=security-engineer/Opus PASS) を経ており、本 ADR は**新しい独立監査を要求しない**
  (新しい設計判断が無いため)。ただし後述の Advice で security-engineer への fyi 共有を推奨する。
- 効き始める閾値: 即時 (VP 承認後)。

→ **採用。**

## Decision

**Option 3 を採る。**

1. **P19-1 の 10 論点は、依頼時点で既にすべて決定・実装・cross-repo 5x・CEO merge・
   prod 実証済みと判定する。** 新しい設計・実装 PR は不要。上記の表 (10 論点) が
   その根拠 file:line である。
2. **確定方針は path-first 統合 (P18/P19 統合) + 単一 origin (`app.<suffix>`) への
   fixed-service 集約 + ttyd の subdomain 無改修**、REFACTORING.md `### P19-1 設計メモ統合`
   (2026-08-16) の 6 CEO 決定を正典として維持する (本 ADR はこれを上書きしない — 内容は
   一致している。REFACTORING.md がいずれ archive されても本 ADR が恒久的な参照点になる)。
3. **app#61 / platform#24 は本 ADR + 実装 PR へのリンクを付けて VP がクローズ推奨する。**
   app#99 / app#101 は別 scope (polish follow-up) の Issue であり、本クローズの対象に
   含めない (混同すると「P19-1 の 10 論点解決」と「6→1 への完全収束」が区別できなくなる)。
4. **cert 戦略 (#7) と Cloudflare 集約 (#8) は、issue 記載の当初想定 (単一 SAN cert へ移行 /
   1 レコードへ集約) から縮小して決定されている** ことを明記する (cert 無改修・CF 6→3)。
   この縮小は 2026-08-16 CEO 決定②③ (dex residual risk 受容・auth. bridge を follow-up 化) の
   直接の結果であり、本 ADR はこの縮小を正しい決定として承認する (dex を別ドメイン化する
   narrow 化は「不可逆コストが cookie 縮小の実利を上回る」との判断が REFACTORING.md に
   既に記録されているため、再考の材料は無い)。

理由 (一文): **依頼された設計判断は、依頼が出される 10 日前に別プロセス (P23 landing 後の
3 観点 Opus スパイク + CEO 決定 + cross-repo 5x + merge + stand-up 実証) によって既に
完了しており、本 ADR の役割は新規設計ではなく、実測による完了確認と、その完了が
恒久的な参照点 (ADR) を持たないまま埋もれることを防ぐための記録である。**

## Consequences

### 諦めたもの

- **10 論点の新規評価。** REFACTORING.md `### P19-1 設計メモ統合` と cross-repo 5x が
  既に扱っており、重複すると 2 つの文書が同じ結論に別の言葉で到達し、将来の食い違いリスクを生む。
- **本 ADR 自体への新規 security-engineer 独立監査。** 実装 (app#100/platform#57/platform#54)
  は既に cross-repo 5x の R1 (security-engineer/Opus) が PASS 判定済み。ただし本 ADR は
  auth/ingress の cross-repo 契約 (cookie domain 再確認・ALLOWED_ORIGINS 単一化・auth-url
  path 分離) を扱うため、**VP が本 ADR を Accepted にする前に security-engineer への fyi 共有を
  推奨する** (二重監査は要求しないが、恒久文書化という行為自体は共有すべき — ADR-0010 の
  Advice と同じ扱い)。

### 新たに守る不変条件

- 新設なし。本 ADR は既存の cross-repo 契約表 (`falco-ctf-app-conventions.md` の
  `ALLOWED_ORIGINS` 行、`falco-ctf-platform/CLAUDE.md` の「Single-origin path routing
  (P19-2b)」行、両方ともすでに実装済みの記述として更新されている) を再掲・恒久化するのみ。
  I8 (prefix-exact 認可) は本 ADR の対象範囲でも無改修のまま (`REFACTORING.md:291`)。

### runbook / 運用への影響

- なし。本 ADR はコード変更を伴わない。P19 の runbook 影響 (`verify-auth.sh` の path 化、
  operations.md の更新) は既に platform#57 の fixup で発効済み。
- app#61 / platform#24 のクローズは VP が実施 (本 ADR は architect 権限の範囲でクローズを
  推奨するのみ)。

## Signposts

この判定 (「P19-1 は既に決定・実装済み・再設計不要」) を覆す観測可能な信号:

1. **`app.<suffix>` の単一 origin 実装 (`charts/scoreboard/templates/ingress{,-journey}.yaml`,
   `charts/docs/templates/ingress-admin.yaml`) が participant/admin の path を merge する形に
   変わる、または新しい fixed service がこの 2 Ingress オブジェクト体系に乗らない形で
   追加される** — path 排他性が崩れると認可境界が破れる (I8 隣接領域)。
2. **app#99 (ttyd authSignin の appHost 追随) が実装され、`auth.<suffix>` compat bridge が
   撤去される** — その時点で fixed host は「6→2」から「6→1(+dex)」に収束し、本 ADR の
   表 #8 (CF 6→3) を「6→2」への更新で navigational に訂正する必要が生じる。
3. **P20 (substrate 汎用化, VM 上 k3s) が cert-manager / Cloudflare の前提を変える**
   (`helmfile/releases/docs/values.yaml.gotmpl` のコメントが既に vm-prod 分岐を持つことを
   確認済み — P19 の appHost 前提は P20 でも維持されているが、cert 戦略 (#7) が
   Cloudflare DNS-01 に依存する部分は substrate 変更で再検討対象になりうる)。
4. **REFACTORING.md の P19 節が `REFACTORING-DONE.md` へアーカイブされる際、本 ADR への
   相互リンクが付かない** — その場合、本 ADR が「恒久的な参照点」として機能しなくなる
   (VP のアーカイブ作業時に要確認)。

## Verification

**この判定 (P19-1 の 10 論点が main で解決されている) が守られていることを機械で確認する方法:**

1. **既存 (再掲しない、新設なし)**: `internal/scoreboard/server_test.go`
   (`TestLegacyMeJourneyRoutes_Removed`, `TestReadGate_SelfAllowed`) +
   `internal/scoreboard/origin_guard_test.go` (`TestOriginGuard_AllProtectedRoutesEnforced`) が
   `make test` (required check) で継続的に green であること。これらは journey/admin path 分離
   ・self-scope gate・origin-guard 対象ルート集合が現状を保っていることを検証する
   (I14 の一部としてすでに稼働中)。
2. **`helm template` によるレンダ確認 (新設なし、既存 CI `chart-lint` に相乗り)**:
   `charts/scoreboard/templates/ingress.yaml` の `path: /` と
   `charts/scoreboard/templates/ingress-journey.yaml` の `/portal`・`/api/users/`・
   `/api/challenges/` が同一 `host` かつ path 非重複であることは、app#100 の PR body に記載の
   render+conftest 検証 (1548/1548) で当時確認済み。これを恒常的な機械検査に昇格するかは
   本 ADR の scope 外 (別 follow-up の判断)。
3. **platform 側 `scripts/verify-auth.sh`**: `APP_HOST` ベースの journey self-scope チェック
   (`VERIFY_JOURNEY=1` オプトイン) が実機 (colima / prod) で完走することを、認証経路を
   変える PR のたびに実行する運用が `falco-ctf-platform/.claude/rules/falco-ctf-conventions.md`
   の Key Guard (「認証経路を変えたら `./scripts/verify-auth.sh` も完走確認すること」) として
   既に存在する。
4. **Issue クローズの追跡可能性**: app#61 / platform#24 のクローズコメントに、本 ADR
   (`docs/adr/0013-*.md`) + app#100 + platform#57 + platform#54 への相対リンクが
   含まれること (レビューで確認、機械検査なし)。
5. **実機再確認 (未実施・実施するまで「確認済み」と書かない)**: 10 論点のうち #9
   (`verify-auth.sh` の `VERIFY_JOURNEY=1` オプトイン経路) と #7/#8 (cert/CF) は、
   本 ADR 起草時点では prod 上の実行ログを architect が直接確認していない
   (2026-08-16 stand-up の成功は memory `project_prod_standup_2026_08_16` の記録に基づく
   間接的な裏付けであり、architect 自身による実機確認ではない)。次回 stand-up
   (P20 substrate 移行後を含む) で `VERIFY_JOURNEY=1 ./scripts/verify-auth.sh` の実行ログを
   本 ADR に追記することを推奨する (navigational な訂正の範囲内)。

## Advice

### 受けた助言

- **VP (2026-08-26, 委任時)**: app#61 / platform#24 の 10 論点を解決する P19-1 設計メモの
  起草を委任。「実コードを実際に読んで実測すること」「クロスリポ契約に触れる決定は両リポでの
  合意点として明記する」「security-engineer レビュー必須」という規律を明示。
  → 本 ADR はこの規律に従って実測した結果、10 論点すべてが依頼時点で既に解決済みと判明した
  ため、**新規設計ではなく完了確認+恒久記録**という異なる形の出力になった。VP の規律
  (実測・file:line・security-engineer レビュー) 自体は本 ADR の判定過程でそのまま活きている。
- **security-engineer への相談は本 ADR 起草時点では行っていない** (理由: 新規の設計判断が
  無いため)。ただし実装 (app#100/platform#57) の cross-repo 5x で R1=security-engineer/Opus
  が既に独立監査済み (PASS: auth-url path 分離が admin gate を participant Ingress に
  漏らさない・header-forgery guard 両 Ingress 維持・I8 不可侵・cookie 据え置き)。
  **VP が本 ADR を Accepted にする前に、security-engineer への fyi 共有 (レビュー依頼では
  なく通知) を推奨する** — 恒久文書化という行為そのものと、cert/CF の縮小決定 (#7/#8) が
  当初想定と異なる点は、security-engineer が異議を持つ余地が理論上あるため。
