# ADR-0023: rate-limit キーを `CF-Connecting-IP` 優先に切り替える (XFF leftmost 偽装の是正、クロスリポ契約)

- Status: **Accepted** (2026-08-29。architect 起案 → security-engineer advisory で
  collector 経由の CF-Connecting-IP 偽装 (HIGH) を差し戻し → architect が D1b 追加 +
  C2/V4 是正 → security-engineer 再確認で「穴なし — 偽装経路が閉じる・既存ヘッダ処理と
  非干渉・V4 検出力・D1/D1b 同一 PR 制約と Signpost 5 の妥当性をすべて確認」→ objection
  なしにつき VP 時限自動承認。**下記の「Accepted ≠ 脆弱性解消済み」を必読**)
- **2026-08-29 追記 (security-engineer advisory 差し戻し 1 巡目)**: D1
  (`CF-Connecting-IP` 最優先化) 単体では **collector 経由の新規偽装経路
  (HIGH)** が開くことが判明 → D1b (collector 側の追加 strip) を追加、
  C2/V4 を是正した (下記)。**Accepted = 対処方針の確定であって、脆弱性が
  解消済みであることを意味しない。** V2 (実クラスタで `CF-Connecting-IP` が
  加工されず届くことの確認) と D1b の実装・landing が完了するまで、
  Issue #236 の脆弱性は実質的に未解消のまま。この状態を「Accepted だから
  もう直っている」と読み違えないこと。
- Date / Deciders: 2026-08-29 / architect (起案・契約確定)、platform-engineer
  (調査済み・ingress 側実装予定)、software-engineer (app 側実装予定 —
  D1 に加え D1b の collector 側修正も担当)、
  security-engineer (要確認 — origin-guard と同格の乱用対策境界に触れるため)、
  VP (承認予定)
- 関連: Issue #236 (本 ADR の発注元) / app#95 review-5x R1 (security-engineer が
  最初に指摘) / `internal/scoreboard/ratelimit` (正典パッケージ) /
  `falco-ctf-platform` `helmfile/releases/ingress-nginx/*` (ヘッダ供給元)
- フェーズ: P## 非該当

## Context

### C1. 実測 (platform-engineer 調査、2026-08-28)

`ratelimit.ClientIP` (`internal/scoreboard/ratelimit/ratelimit.go:114-126`) は
`X-Forwarded-For` の**leftmost エントリ**を無条件に信頼し、無ければ `RemoteAddr` へ
フォールバックする:

```go
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	... RemoteAddr fallback ...
}
```

**全環境で偽装可能**:

| 環境 | ingress-nginx 構成 (`falco-ctf-platform/helmfile/releases/ingress-nginx/`) | 偽装可能な理由 |
|---|---|---|
| **local** (colima) | `values-local.yaml.gotmpl` は `controller: {}` (無上書き)。`proxy-real-ip-cidr` はチャート既定の `0.0.0.0/0` のまま | 全 peer を信頼 → 誰でも任意の XFF leftmost を注入可能。**無条件偽装** |
| **prod (EKS+NLB) / vm-prod (k3s)** | `values-{prod,vm-prod}.yaml.gotmpl` は `proxy-real-ip-cidr` を VPC CIDR + (cloudflareEnabled 時) Cloudflare IPv4 レンジまで信頼するが、**Cloudflare は XFF を append-only で中継する** (クライアント指定値を上書きせず、自分の edge IP を末尾に追加するだけ) | ingress-nginx の `real_ip_recursive` は信頼レンジに達するまで右から左へ辿るが、**信頼レンジの手前 (= 攻撃者が注入した leftmost 値) で停止する**。信頼できるのは Cloudflare が上書き設定する `CF-Connecting-IP` (現状 `forwarded-for-header` は既定の `X-Forwarded-For` のまま、未使用) |

**代替の検討と却下 (platform-engineer)**: `X-Real-IP` も同じ `$remote_addr` 由来で同型の
脆弱性。`RemoteAddr` は ingress-nginx pod の IP になり per-client にならない。
**現行スタックに偽装不可能な per-client キーが存在しない。**

### C2. 影響範囲の実測 (issue の記述より広い — architect が `ratelimit.ClientIP` の
全呼び出し元を実 grep して確認)

| ルート | 呼び出し元 | 経路 | Cloudflare を経由するか |
|---|---|---|---|
| `POST /api/challenges/{cid}/submit` | `api.go:333` `submitMW` | journey UI ブラウザ fetch (主) + collector forward (curl) | **両経路とも対象、扱いが違う**: ブラウザ fetch は Cloudflare 経由 (`CF-Connecting-IP` 優先で閉じる)。**collector forward 経路 (workspace→collector は ClusterIP 直叩き) は Cloudflare を経由しない** — `internal/collector/collector.go` の `Director` が `X-Forwarded-For`/`X-Real-IP` は削るが `CF-Connecting-IP` を削らないため、⚠ **D1 単体ではこの経路に新規の偽装口が開く** (security-engineer HIGH finding、下記 D1b で是正) |
| `POST /api/challenges/{cid}/submit-detect` | 同上 (`submitMW` 共有) | journey UI ブラウザ fetch のみ (collector forward 対象外) | 経由する。collector forward 経路が無いので D1b の対象外 |
| `POST /api/users/{user}/display-name` (**参加者向け**。⚠ 旧版は本行を admin 専用と誤記していた — `api.go:497` で `h.setDisplayName` に配線され、**唯一の呼び手は collector forward** [`api.go:481-490` のコメント: 「No browser template in this repo fetches this participant-facing path directly」]。admin 専用の `POST /api/admin/users/{user}/display-name` [`api.go:367-370`] は別ハンドラ `h.adminSetDisplayName` で rate limiter 自体を持たず、`ratelimit.ClientIP` を呼ばないので本 ADR の対象外) | `api.go:334` `dnMW` | **collector forward (curl) のみ** — journey UI からの直接 fetch は存在しない | **経由しない** — submit の collector-forward 経路と同じ理由で ⚠ D1 単体では新規偽装口 (D1b で是正) |
| `POST /api/users/{user}/questions`, `.../messages` | `api.go:335` `questionMW` | journey UI ブラウザ fetch のみ (collector forward 対象外) | 経由する。collector forward 経路が無いので D1b の対象外 |
| `POST /csp-report` | `view.go:220` `cspReportLimiter` | ブラウザの CSP violation report beacon (**認可なし・rate limit が唯一の防御層**、app#95) | 経由する。collector forward 対象外 |
| `POST /falco/events` | `ingest.go:75` `h.limiter` | falcosidekick (**cluster 内部**、Falco DaemonSet の sidekick コンポーネント) | **経由しない** — ingress-nginx/Cloudflare を通らない内部呼び出し。本 ADR の修正の恩恵を受けない (下記 D5)。collector 経由でもない (falcosidekick は collector を通さず直接叩く) ので D1b の対象外 |

`POST /internal/exfil/{cid}` は `RateLimit: "none (the limit lives on the
collector front)"` (`api.go` コメント) — `ratelimit.ClientIP` を使わないので対象外
(collector forward 3 本のうち唯一 `ratelimit.ClientIP` を経由しないルート)。
collector 自身の limiter (`internal/collector/collector.go:118-121`) は
**意図的に `RemoteAddr` キー** (workspace が直接叩くため XFF を信用しない設計が
既に正しい) — 本 ADR の対象外。

**⚠ collector forward 経路の再評価 (security-engineer HIGH finding,
2026-08-29)**: 上表のとおり、collector が verbatim forward する 3 ルートの
うち **`submit` と `display-name` は `ratelimit.ClientIP` を経由し、
Cloudflare を経由しない**。旧版の本節はこれらを「XFF を削って再構成するので
対象外」と記していたが、それは**旧トラスト順序 (XFF leftmost のみ) を前提**
にした記述であり、D1 が `CF-Connecting-IP` を最優先にした後は
**前提が崩れる** — `collector.go` の `Director` が `CF-Connecting-IP` を
削らない限り、workspace は毎リクエスト任意の `CF-Connecting-IP` を送って
scoreboard 側の `submitLimiter`/`displayNameLimiter` (ルートごとに調整された
専用バケット) を無制限にバイパスできる。collector 自身の `remoteIP` キー
limiter (3 ルート共有・1 req/s burst 10) は正しく機能し続けるが、これは
`submitLimiter` (brute-force 対策そのもの) より粗い共有バケットであり、
scoreboard 側の防御が実質的に無効化される点は変わらない。→ **D1b で是正**。

### C3. なぜこれがクロスリポ契約変更 (ORGANIZATION §8 基準②) か

「ingress が渡す **ヘッダ名**」⇔「app が読む**ヘッダ名**」の対応は image tag /
webhook payload / cookie domain / `ALLOWED_ORIGINS` と同型の
**クロスリポ契約項目**である (app `.claude/rules/falco-ctf-app-conventions.md`
の Cross-repo 契約表と同じ形の合意)。片方だけ変えると (a) app だけ変えて
platform が `CF-Connecting-IP` を供給しなければ**何も変わらない** (常に fallback
経路に落ちるだけ)、(b) platform だけ変えて app が読むヘッダ名を変えなければ
**同じく何も変わらない** (app は依然 XFF leftmost を見る) — 少なくとも
**app 側の変更が無いと脆弱性は閉じない**という意味で両側必須。①クロスリポ契約の
新設・変更に該当し、②`ratelimit` パッケージ自身のコメントが明記する
「乱用対策の defense-in-depth 境界」(I8/origin-guard のような認可境界そのものでは
ない) にも隣接するため、architect 合意 + security-engineer 確認を要する。

## Options

### O1 (推奨). `CF-Connecting-IP` を最優先の信頼ヘッダとし、XFF leftmost は fallback として残す

- **変更点**:
  - **app** (`internal/scoreboard/ratelimit/ratelimit.go`): `ClientIP` を
    「`CF-Connecting-IP` が非空かつ構文的に valid な IP なら最優先 → 無ければ
    現行の XFF leftmost → 無ければ `RemoteAddr`」の 3 段に変更 (D1)。
  - **platform** (`helmfile/releases/ingress-nginx/values-{prod,vm-prod}.yaml.gotmpl`):
    `cloudflareEnabled` 時のみ `config.forwarded-for-header: "CF-Connecting-IP"` を
    追加し、ingress-nginx 自身の `$remote_addr`/realip 解決の信頼元を切り替える
    (D2)。**既存の `proxy-real-ip-cidr` の `{{ if .Environment.Values.cloudflareEnabled }}`
    条件分岐パターンをそのまま踏襲**するので新しい設計要素を持ち込まない。
  - **local**: 変更なし (D3、意図的)。
- **コスト**: app 側は 1 関数の分岐追加 (既存テスト非破壊)。platform 側は
  values ファイル 2 本への数行追加。新規依存ゼロ、新規 CI job ゼロ。
- **リスクと可逆性**: 完全可逆 (どちらの変更も単独 revert 可能)。
  **重要な実測上の性質 (下記 D4)**: app 側の変更単体で脆弱性は閉じる —
  ingress-nginx はデフォルトで未知のヘッダ (`CF-Connecting-IP` はチャートが
  特別扱いする管理下ヘッダの集合に無い) をバックエンドへそのまま透過するため、
  `forwarded-for-header` 設定を変えなくても `CF-Connecting-IP` 自体は
  scoreboard まで届く。platform 側の変更は ingress-nginx 自身の
  `$remote_addr` (アクセスログ・将来の nginx レベル per-IP 機能) の正確性を
  底上げする**独立した価値**であり、app 側修正の**前提条件ではない**
  (VP の「両側揃わないと無意味」という前提は、app が実際に読むヘッダが
  `CF-Connecting-IP` 自体である限り不正確 — D4 で訂正する)。とはいえ両方
  一緒に実装するのが一貫性・レビュー効率の面で妥当 (下記 3 の分担)。
- **効き始める閾値**: app 側 PR が landing した瞬間から (Cloudflare は既に
  `CF-Connecting-IP` を prod/vm-prod の両方で無条件に設定済み — オプトイン設定は
  不要、Cloudflare 側は変更ゼロ)。

### O2. ingress-nginx ネイティブの rate limit (`limit-rps` annotation 等) に丸ごと移す

- **変更点**: app 側の `ratelimit` パッケージを使わず、ingress-nginx の
  `nginx.ingress.kubernetes.io/limit-rps` 等の annotation で per-`$remote_addr`
  制限を ingress 層に移す。nginx 自身が解決した (Cloudflare 経由で正しく
  realip 解決済みの) `$remote_addr` を直接使うため、**app がどのヘッダも
  信用する必要が無くなる**という理論上の魅力がある。
- **コスト**: 極めて高い。(a) `allowSnippetAnnotations: false`
  (`values.yaml.gotmpl` — ingress-nginx admission webhook が
  `configuration-snippet` を CRITICAL 扱いするための cluster 全体無効化、
  AGENTS.md L168 境界) と衝突しないか annotation ごとに要検証。
  (b) nginx のデフォルト 429/503 応答は HTML/plain であり、ADR-0005 Decision 5
  が固定した `{"error": string}` の 1 形契約 (`Content-Type: application/json`) を
  壊す — 追加の `custom-http-errors` / error page 差し替え実装が要る。
  (c) ルートごとに違うバケットサイズ (submit vs csp-report vs questions vs
  falco/events) を ingress Ingress オブジェクト単位の annotation でどう表現
  するかは自明でない (現行は Go コード側で `ratelimit.New(rate, burst)` を
  ルートごとに呼び分けている)。(d) `/falco/events` はそもそも Cloudflare を
  経由しない内部呼び出しなので、この方式でも別枠の対策が要る (C2)。
- **リスクと可逆性**: 可逆性は中 (annotation の除去で戻せるが、app 側の
  ratelimit パッケージを一度剥がすと戻すコストが対称的に高い)。
- **効き始める閾値**: rate-limit ロジック全体を ingress 層に統一したい
  という**別の**設計欲求が生じたとき (本 issue のスコープを超える)。
  今回のスコープは「キーが偽装可能」の是正であり、機構の配置転換ではない。

### O3. 現状維持し、偽装可能性を「許容リスク」として明文化するだけに留める

- **変更点**: コードは変えず、`ratelimit` パッケージの doc コメントに
  「XFF leftmost は偽装可能。防御層は NetworkPolicy 等の他レイヤに委ねる」と
  明記するだけ。
- **コスト**: 最小。
- **リスクと可逆性**: **却下**。`/csp-report` は rate limit が**唯一の**防御層
  (app#95、認可なし・origin-guard なし) であり、この 1 ルートについては
  偽装可能性がそのまま「乱用対策が実質ゼロ」を意味する。C1 が示す通り
  修正は低コストで実現可能なので、「許容する」を選ぶ理由が無い。
- **効き始める閾値**: 該当なし (却下)。

## Decision

**O1 を採る。**

### D1. app 側の契約: `ratelimit.ClientIP` の優先順位

```
1. CF-Connecting-IP ヘッダが非空 かつ net.ParseIP で構文的に valid → それを採用
2. (1 が無い/不正) X-Forwarded-For の leftmost エントリ (現行ロジック、変更なし)
3. (1, 2 とも無い) RemoteAddr (現行ロジック、変更なし)
```

`net.ParseIP` での構文検証を挟む理由: `CF-Connecting-IP` は Cloudflare が
書き換える前提のヘッダだが、万一 (Cloudflare 側の障害・misconfiguration・
本 ADR が想定しない新しい呼び出し経路) 予期しない値が来ても、**壊れた文字列を
そのままレート制限バケットのキーにしない** (空文字列や自由形式の文字列を
キーにすると、`Limiter.buckets` map が無制限のキー空間を持つことになり、
1024 件超のエビクション機構はあるものの無意味に薄まる) — 防御的だが必須では
ない追加ガード。

**適用範囲**: `ratelimit.ClientIP` を呼ぶ**全ルート**が対象 (C2 表)。変更点は
1 関数のみなので、ルートごとの個別対応は不要 — この設計自体が「1 箇所を直せば
全消費者が恩恵を受ける」という良い性質を持つ (C2 の表がその根拠)。

### D1b. collector も `CF-Connecting-IP` を strip 対象に加える (新規、security-engineer HIGH finding 2026-08-29 — ADR-0023 自身が開く穴の是正)

**問題**: `internal/collector/collector.go` の `Director` (`collector.go:105-110`)
は `X-Forwarded-For` / `X-Real-IP` を `Del` するが、**`CF-Connecting-IP` を
`Del` しない**。D1 が着地すると `ratelimit.ClientIP` が `CF-Connecting-IP` を
最優先で信頼するようになるため、**workspace pod が毎リクエスト任意の
`CF-Connecting-IP: <ランダム IP>` を付けて collector 経由で `submit`
(brute-force 対策そのもの) と参加者向け `display-name` を叩けば、
scoreboard 側の per-route rate limit を無制限にバイパスできる** (C2 の
「collector forward 経路の再評価」参照)。collector 自身の `remoteIP` キー
limiter は影響を受けず正しく機能し続けるが、それは scoreboard 側の
専用バケットより粗い共有バケットであり、防御としては別物 (弱い) である。

**現状 (D1 着地前) でこの経路が成立しない理由**: 現行の `ClientIP` は XFF
leftmost を見るが、collector が XFF/X-Real-IP を削ったあと `ReverseProxy`
自身が `X-Forwarded-For: <実 RemoteAddr>` を新規に構築する
(`collector.go:102-104` のコメント) ため、workspace 側からの偽装余地が無い。
**この安全性は「XFF だけを見ている」という旧トラスト順序に暗黙に依存していた**
— D1 が新しい最優先ヘッダ (`CF-Connecting-IP`) を導入した瞬間、
このヘッダを剥がす対応が漏れていると同じ安全性は保たれない。**これは
ADR-0023 (本 ADR) 自身が新たに生む regression であり、issue #236 が
指摘していた既存の脆弱性とは別物**である点を明記する。

**是正**: `collector.go` の `Director` の strip 対象に `CF-Connecting-IP`
を追加する:

```go
h.proxy.Director = func(req *http.Request) {
	baseDirector(req)
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("X-Real-IP")
	req.Header.Del("CF-Connecting-IP") // 追加 (ADR-0023 D1b)
}
```

`ReverseProxy` は `CF-Connecting-IP` を再構築しない (`X-Real-IP` と同様、
`ReverseProxy` が自動再設定するのは `X-Forwarded-For` のみ) ため、
削除後は単純に「ヘッダが存在しない」状態になり、scoreboard 側の
`ratelimit.ClientIP` は D1 の優先順位どおり XFF (= collector が再構築した
実 RemoteAddr) にフォールバックする — **今日の XFF 経路の安全性と同じ形**に
揃う。

**スコープ**: collector forward 3 ルート (`exfil`/`submit`/`display-name`)
全てに一律適用する (`Director` はルート共通のミドルウェアなので、
個別ルートだけ外すという選択肢はそもそも無い — `exfil` は
`ratelimit.ClientIP` を使わないので実害には無関係だが、strip 自体は
3 ルート共通でよい)。

**merge 順序の制約 (D4 の cross-repo 独立性とは異なる、同一リポ内のタイトな
結合)**: D1 (app 側 `ratelimit.ClientIP`) と D1b (app 側
`collector.go`) は**同一 PR で着地させる**こと。D1 だけを先に landing
させると、その PR 自体が (D4 で述べた cross-repo の独立性とは別の理由で)
collector 経由の新規 HIGH 脆弱性を生んだ状態で main に乗ることになる。
D1b 単体を先に landing させることは安全 (現状 collector は
`CF-Connecting-IP` を読まないので strip しても無害) だが、意味が無いので
同一 PR にまとめてよい。

### D2. platform 側の契約: `forwarded-for-header`

`prod` / `vm-prod` の `cloudflareEnabled` 時のみ、ingress-nginx の
`config.forwarded-for-header` を `"CF-Connecting-IP"` に設定する。
`cloudflareEnabled` が false のとき (現状 prod/vm-prod 両方とも常に true —
`environments/{prod,vm-prod}.yaml.gotmpl` 実測、C1) はチャート既定の
`X-Forwarded-For` のままにする — `proxy-real-ip-cidr` の既存条件分岐
(`values-{prod,vm-prod}.yaml.gotmpl`) と**同一パターン**を踏襲し、
新しい条件分岐スタイルを持ち込まない。

### D3. local (colima) は変更しない (issue の論点 (a) を採る)

**根拠は「規模が小さいから」ではなく、脅威モデルが実質的に存在しないため**
(CEO 方針「規模を却下理由に使わない」に反しない、独立した理由):

- colima local は**単一の信頼された運用者**が自分のマシンで動かす dev
  環境であり、実参加者・実フラグ・実採点が乗ることはない
  (`falco-ctf-platform/CLAUDE.md`: 「prod 開発フロー: local colima → prod EKS
  の片方向」— local は常に**先行検証ステップ**であって本番イベント面ではない)。
- `network.address: true` で LAN IP に bind されるが、インターネットには
  到達不能 (DNS レコードも無い) — 同一 LAN 上の第三者からの攻撃という
  残余リスクは理論上あるが、rate-limit 偽装が実害として持つ範囲は
  「運営自身のログが荒れる」程度で、認可境界 (I8) やスコアの真正性には
  一切波及しない (rate limit は defense-in-depth と package doc 自身が
  明記、認可層ではない)。
- 固定 CIDR 制限 (issue 論点 (b)) は却下: 運用者のホーム/オフィス
  ネットワークに紐づく CIDR は環境が変わるたびに壊れる (メンテされない
  設定項目は事実上のデッドコードになる)。今回の脅威が実害を持たない
  以上、複雑さに見合わない。
- **Signpost**: local を複数運用者が共有する pre-prod ステージング用途に
  転用する、または `network.address` の到達範囲がインターネットに開かれる
  構成変更が入ったら、この判断を再訪する。

### D4. app 側の変更が脆弱性を閉じるための必要十分条件 (VP の前提の訂正)

VP の発注文は「片方だけの変更は無効 (ヘッダ名の両側整合が必須)」としていたが、
**厳密には非対称**: ingress-nginx はチャートが管理する既知ヘッダ集合
(`X-Forwarded-For`/`X-Forwarded-Host`/`X-Forwarded-Proto`/`X-Forwarded-Port`/
`X-Real-IP`/`X-Scheme`) 以外のヘッダをデフォルトでバックエンドへそのまま
透過する (`allowSnippetAnnotations: false` によりこれを変更する
configuration-snippet の経路も塞がれている = 意図しない加工が入りようがない)。
Cloudflare proxy が有効な hostname では `CF-Connecting-IP` は
Cloudflare の edge が**クライアント指定値を上書きして**設定する
(append-only の XFF とは異なる挙動 — Cloudflare の文書化された保証)。
よって **app 側の D1 変更単体で、`forwarded-for-header` を変えなくても
`CF-Connecting-IP` は scoreboard に届き、脆弱性は閉じる**。platform 側の
D2 は ingress-nginx 自身の `$remote_addr` (アクセスログ・将来の
nginx レベル制御) の正確性向上という**独立した価値**であり、この ADR の
主目的 (rate-limit キーの偽装不可能化) にとっては**推奨だが必須ではない**。

**ただし両方を同一サイクルで実装することを推奨する** (下記 3): 一貫性
(「ingress が渡すヘッダ」の記述が nginx 設定と実挙動で食い違わない)・
レビュー効率・将来 nginx レベル機能を足すときの前提が既に整っている、という
理由による。**merge 順序の技術的な強制は無い** (app 先行・platform 先行
どちらでも安全) — cookie SameSite=None の事例 (conventions.md 「Cookie
`SameSite=None`+Secure embed 契約」行) とは異なり、本契約は片側 landing でも
既存動作を壊さない (D1 は CF-Connecting-IP 不在時 fallback するだけ、
D2 は nginx 内部の realip 解決先を変えるだけで app への影響がフィールド名の
面では中立)。

### D5. `POST /falco/events` はこの修正の恩恵を受けない (正直に記載する)

C2 のとおり falcosidekick は cluster 内部呼び出しであり Cloudflare を経由しない
ため、`CF-Connecting-IP` ヘッダは決して付与されない — このルートは常に
XFF leftmost (未修正のまま) または `RemoteAddr` にフォールバックし続ける。
これは**設計の欠落ではなく対象外**: `ingest.go` の package doc 自身が
「primary controls are NetworkPolicy... a per-pod fallback here」と明記して
おり、このルートの実質的な防御層は NetworkPolicy (falco ns からのみ到達
許可) であって rate-limit キーの精度ではない。**「見ないもの」として
明記し、将来「なぜ #236 後も /falco/events だけ直っていないのか」という
疑問を防ぐ**。

### D6. fail-open を維持する (fail-closed にしない)

`CF-Connecting-IP` が prod/vm-prod で万一欠落した場合 (Cloudflare 側の障害・
`cloudflareEnabled` フラグと実ネットワーク構成の drift 等)、XFF leftmost への
**fallback を維持する** (リクエストを拒否しない)。理由:

- rate limit は認可境界ではなく defense-in-depth の乱用対策
  (`ratelimit` package doc、D4 と同じ整理)。ここを fail-closed にすると、
  Cloudflare 側の一時的な障害が**採点提出そのものを止める**という、
  リスクに不釣り合いな可用性事故を招く (I8 のような認可境界の fail-closed
  とは性質が異なる — 「本当にまずい」の中身が「他人へのなりすまし」ではなく
  「レート制限の精度低下」でしかない)。
- `/csp-report` (rate limit が唯一の防御層) についても同じ判断を適用する:
  fail-closed にして拒否すると、CSP violation report という**可観測性目的の
  補助経路**を守るために**参加者の正当なブラウザ挙動全般を止める**
  非対称なトレードオフになる。#95 の VP 判断「rate limit が偽装されても
  最悪ログ flooding のみ・採点/認可には無害」という既存の受容判断
  (Issue #236 本文引用) と整合させ、`/csp-report` だけ別扱いにしない。
- **fail-open を「観測可能」にする** (D6 が fail-open で妥当な理由を
  裏付ける唯一の担保): `CF-Connecting-IP` 欠落によるフォールバック発生を
  ログ/メトリクスに残す (下記 Verification)。prod/vm-prod で**継続的に**
  非ゼロ発生した場合、それ自体が「Cloudflare 経由が壊れている」という
  rate-limit とは独立に重大な運用シグナル (network lock の drift の疑い) —
  sre-engineer の監視対象に加える。

## Consequences

### 諦めたもの

- `/falco/events` の rate-limit キーは偽装可能なまま残る (D5、対象外と
  明記)。NetworkPolicy が主防御であることに変わりはない。
- local (colima) の rate-limit キーは無条件偽装可能なまま残る (D3、意図的)。
- fail-closed にしないため、Cloudflare 側の障害時に rate-limit の精度が
  一時的に低下する余地を残す (D6)。可用性を優先した trade-off。

### 新たに守る契約 (Hard Invariant ではなく Cross-repo 契約表エントリ)

`ALLOWED_ORIGINS` / cookie domain と同格の契約表エントリとして
`.claude/rules/falco-ctf-app-conventions.md` の Cross-repo 契約表に追記する
(実装 PR と同じ PR で):

> **Rate-limit client-IP ヘッダ (ADR-0023)**: `internal/scoreboard/ratelimit.ClientIP`
> は `CF-Connecting-IP` (非空・valid IP) を最優先し、無ければ `X-Forwarded-For`
> leftmost、無ければ `RemoteAddr` にフォールバックする。`CF-Connecting-IP` は
> `falco-ctf-platform` の `cloudflareEnabled` な環境 (prod/vm-prod) で
> Cloudflare が上書き設定する値であり、ingress-nginx はこれを加工せず
> 透過する (`forwarded-for-header` 設定は ingress-nginx 自身の
> `$remote_addr` 解決にのみ影響し、ヘッダの透過そのものには影響しない —
> D4 参照)。local (colima) は対象外 (D3)。`POST /falco/events` は
> Cloudflare を経由しない内部呼び出しのため対象外 (D5)。**`internal/collector`
> は Cloudflare を経由しない workspace 直叩きの forward proxy であるため、
> `CF-Connecting-IP` を含む参加者制御下のあらゆる client-IP 系ヘッダを
> 無条件に strip する義務を負う** (D1b) — この義務は `X-Forwarded-For`/
> `X-Real-IP` の既存 strip と同格であり、将来 `ratelimit.ClientIP` が
> 新しい信頼ヘッダを追加するたびに `collector.go` の `Director` も
> 追随して strip 対象を拡張しなければならない (この対応漏れ自体が
> D1b の起点だった — 同じ穴を将来のヘッダ追加で再開けないための明記)。

**Hard Invariant として I-番号を昇格させない**理由: 既存の同格契約
(`ALLOWED_ORIGINS`・cookie SameSite・`PORTAL_TTYD_SUFFIX` 一致制約) も
I-番号を持たず、Cross-repo 契約表 + パッケージ doc + 単体テストで担保する
前例に揃える。I1-I15 は「mux 登録」「レプリカ数」「UID」のような
**構造的事実の機械検査**という共通点を持つが、本契約は「どのヘッダを
どちらが供給するか」という**値の合意**であり、後者のクラスに属する。

### runbook / 他ロールへの影響

- **platform-engineer**: D2 の実装 (`values-{prod,vm-prod}.yaml.gotmpl` へ
  `forwarded-for-header` 追加)。**実装前に empirical 確認**
  (Verification 参照) を行うこと — 「ingress-nginx が CF-Connecting-IP を
  透過する」という D4 の主張は architect が既存 chart 設定を読んで導出した
  ものだが、実クラスタでの確認は未実施。
- **software-engineer**: D1 の実装 (`ratelimit.ClientIP`) **と D1b の実装
  (`internal/collector/collector.go` の `Director` に `CF-Connecting-IP`
  strip を追加) を同一 PR で行う** (D1b の merge 順序制約)。既存
  `TestClientIP_XForwardedFor` を壊さないこと (回帰確認)。
- **security-engineer**: D6 (fail-open を維持する判断) と D3 (local を
  変更しない判断) の妥当性を確認すること — 特に D6 は「認可境界ではないので
  fail-closed にしない」という architect の判断であり、security-engineer が
  異なる評価をする可能性がある論点として明示する。
- **sre-engineer**: D6 の fallback 発生ログ/メトリクスを prod/vm-prod の
  監視対象に加える (継続的な非ゼロ発生 = network lock drift の疑い)。

## Signposts (この決定を覆す観測可能な信号)

1. **実クラスタで `CF-Connecting-IP` が scoreboard まで透過しないことが
   判明したら** (D4 の想定が外れる) — ingress-nginx 側で明示的な
   `proxy_set_header CF-Connecting-IP ...` 相当の追加設定が必要になる。
   `allowSnippetAnnotations: false` の制約下でどう実現するかを再設計。
2. **prod/vm-prod で fallback (D6 のログ) が持続的に非ゼロ観測されたら** —
   Cloudflare 経由の network lock 自体が壊れている signal。rate-limit の
   話ではなく、`loadBalancerSourceRanges`/VM firewall の再監査が先。
3. **local が複数運用者・インターネット到達可能な構成に変わったら** —
   D3 を再訪し、固定 CIDR または他の対策を検討する。
4. **`/falco/events` の rate-limit 精度が実際に問題化したら** (falcosidekick
   経路のなりすまし・DoS が実害を持つケースが見つかったら) — D5 の
   「対象外」判断を再訪し、NetworkPolicy 以外の追加防御を検討する。
5. **`ratelimit.ClientIP` に将来別の信頼ヘッダ (例: 将来の CDN 切替) を
   追加するとき、`collector.go` の `Director` の strip 対象を同時に
   拡張し忘れたら** — D1b と全く同型の regression が再発する。実装 PR は
   「新しい信頼ヘッダを 1 つ足したら、同じ PR で collector 側の strip
   リストも見る」というチェックリスト項目をレビュー観点に加えることを
   推奨する (機械強制は無い — advisory な運用規律)。

## Verification (= platform-engineer / software-engineer への発注仕様)

**V1 (app, blocking).** `ratelimit.ClientIP` の単体テスト (表駆動、
`ratelimit_test.go` に追加):
- `CF-Connecting-IP` のみ設定 → その値を返す
- `CF-Connecting-IP` + `X-Forwarded-For` 両方設定 → `CF-Connecting-IP` を
  優先する (既存の `TestClientIP_XForwardedFor` は XFF-only のケースとして
  無変更で green のまま残ることを回帰確認)
- `CF-Connecting-IP` が構文的に invalid (例: 空白文字のみ、非 IP 文字列) →
  XFF leftmost にフォールバックする
- どちらも無し → 既存の `RemoteAddr` fallback (無変更)

**V2 (platform, blocking・実機確認).** `cloudflareEnabled: true` な環境
(vm-prod 推奨 — prod より安価に検証可能) で、Cloudflare 経由のリクエストが
scoreboard pod に届いた時点の実ヘッダを確認する (一時的なログ出力または
`kubectl exec` からの検証用リクエストで可)。**`CF-Connecting-IP` が
client の実 IP のまま加工されずに届いていること**を実出力で示す
(D4 の主張を実証する — 「実証的に調べる」の原則どおり、chart 設定の
読み取りだけで済ませない)。

**V3 (platform, blocking).** `values-{prod,vm-prod}.yaml.gotmpl` の
`forwarded-for-header` 追加が `helm lint`/`helm template` (chart-lint)
を通ること。既存の `proxy-real-ip-cidr` 条件分岐と同じ
`{{ if .Environment.Values.cloudflareEnabled }}` パターンを使うこと。

**V4 (app, blocking・D1b 是正で強化、旧版は「影響なしの回帰確認」だったが
不十分だった — security-engineer HIGH finding 2026-08-29).**
`internal/collector/collector.go` の `Director` が `CF-Connecting-IP` を
**新たに** strip 対象に加えること (D1b) を、collector 側テストで実出力付きで
示す:
1. **故意違反で赤くなることを示す (V8 スタイル)**: `Director` を通した後の
   upstream request に `CF-Connecting-IP: <参加者が注入した任意の値>` が
   **残っていない**ことを assert する。strip 行を一時的にコメントアウトした
   バージョンでこのテストが red になることを実装 PR の本文に貼る
   (D1b の是正が実際に効いていることの証明。V1 の mutation test と同型の
   規律)。
2. **回帰確認 (旧 V4 の主張、残す)**: 既存の `X-Forwarded-For`/`X-Real-IP`
   strip ロジックと、`ReverseProxy` が `X-Forwarded-For` を実 `RemoteAddr`
   から再構築する挙動 (`collector.go:102-104`) が壊れていないこと。
3. **`remoteIP` キー limiter への非波及**: collector 自身の
   `Middleware(remoteIP)` (`collector.go:122`) が `ratelimit.ClientIP` の
   変更と独立した関数のままであることをコード上確認する (呼び出しグラフの
   分離は C1/C2 の grep で確認済みだが、実装 PR でも既存テストを再実行して
   崩れていないことを示す)。

**V5 (app, advisory).** D6 の fallback 発生を観測可能にする
(ログまたはメトリクス — 実装方式は software-engineer の裁量。
必須要件は「`CF-Connecting-IP` 不在によるフォールバックが prod/vm-prod で
発生した事実を、後から運用者が追える形で残すこと」)。

## Advice (受けた助言と出所)

- **VP (2026-08-29、本タスクの委任文)**: 3 点 (ADR 要否、契約確定、両リポ分担)
  を委任。「片方だけの変更は無効 (ヘッダ名の両側整合が必須)」という前提を
  添えていた。→ **D4 でこの前提を訂正した**: app 側の変更が
  `CF-Connecting-IP` というヘッダ自体を読む限り、ingress-nginx のデフォルト
  ヘッダ透過動作により platform 側の `forwarded-for-header` 変更は
  app 側修正の前提条件ではない (ingress-nginx 自身の `$remote_addr` の
  正確性のための独立した価値)。両方を同一サイクルで実装することは
  引き続き推奨するが、merge 順序を技術的に強制する理由は無いことを
  明記した。
- **platform-engineer (Issue #236 の調査、2026-08-28)**: 3 環境の構成実測
  (local 0.0.0.0/0 全信頼・prod/vm-prod の append-only XFF 問題・
  代替ヘッダの却下理由)、および対処案 (ingress 側 `forwarded-for-header`
  切替 + app 側優先順位変更)。→ C1/C2/D1/D2 に全面採用。local の扱いを
  「product/security 判断」として明示的に architect に委譲していた点は
  D3 で判断し理由を明記した。
- **security-engineer (VP 経由の差し戻し, 2026-08-29)**: 3 点。
  **[HIGH] ADR-0023 自身 (D1) が collector 経由の新規 CF-Connecting-IP
  偽装口を開く** — `collector.go` の `Director` が `CF-Connecting-IP` を
  strip しないため、workspace が collector 経由で `submit`/`display-name`
  の per-route rate limit を無制限バイパスできる。**[LOW] C2 の
  display-name 行のラベル誤り** (admin 専用ではなく参加者向け)。
  **[認識の明記の推奨]** Accepted は対処方針確定であって脆弱性解消済みでは
  ないことを本文に明記すべき。→ D1b (collector 側の strip 追加、
  同一 PR での merge 順序制約つき)・C2 表の全面訂正・V4 の強化・
  Status ブロックへの明記、として全面採用した。**HIGH は「自分が書いた
  修正案自体が新しい脆弱性を開く」という、architect 自身の設計に対する
  監査であり、最も価値の高い指摘のクラス** — 非拘束の助言ではなく
  実質的な修正必須事項として扱った。この修正版を再度 security-engineer が
  確認し、objection が無ければ VP が Accepted へ昇格させる。
