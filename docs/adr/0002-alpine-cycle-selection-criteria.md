# ADR-0002: alpine の cycle 選定基準を「リリース後 ~1 年」から「安定性実績 + EOL runway + CVE fix 到達性」に置き換え、3.22 → 3.23 へ bump する

- Status: **Accepted** (2026-09-01, VP merge = 承認。Decision 自体は 2026-08-18 に
  VP が承認済みだったが Status 昇格が漏れ Proposed のまま放置され、まさに本 ADR が
  警告した「同じ議論の再発」が app#266 の 3.23→3.24 即日 re-bump として現実化した
  (security-engineer MEDIUM 指摘、workspace#32)。本 PR の merge が昇格を是正する。
  app#266 の 2 段階 bump (3.22→3.23→3.24) は条件 3 [CVE fix 到達性] の緊急パスとして
  本 ADR の 3 条件方式でそのまま正当化される — 個別の追加決定は不要)
- Date / Deciders: 2026-08-18 / VP (承認) + CEO (merge)
- 関連: P8 (freshness)、P12 (digest pin)、`.claude/rules/falco-ctf-app-conventions.md:47-49`
  (現行の cycle 選定規約) / :75-101 (digest bump 手順)、ADR-0001 (同時期の workspace 変更)

## Context

現行規約 (`.claude/rules/falco-ctf-app-conventions.md:47-49`):

> alpine は最新 cycle ではなく「リリース後 ~1 年経過した supported cycle」を選ぶ
> (apk pin の安定性と EOL 余裕のバランス。2026-07 時点: 3.22)。

software-engineer が `apk policy` で実測した事実:

- `alpine:3.22` (現行 pin: `images/challenge/Dockerfile:8`, `images/ttyd/Dockerfile:4`) には
  curl 8.20.0 / vim 9.1.1947 / libxml2 2.15.2 / jq 1.8.2 が **存在しない** →
  challenge / ttyd の High CVE は 3.22 内で修正不能 (`apk upgrade` は no-op)。
- `3.23` なら curl/libcurl 8.20.0・vim 9.2.0602 が入り **challenge の 77 High が解消**。
- `3.23` でも残る: libxml2 (全 cycle・edge でも upstream 2.15.2 に未到達)、jq 1.8.2 (edge のみ)。
- 経過月数: 3.22 = 14.6 ヶ月 (規約適合) / 3.23 = 8.5 ヶ月 (字義では早い)。
- 3.23 は 3.23.0→3.23.5 の patch 5 回、EOL runway は 3.23 = 2027-11 (3.22 = 2027-05)。
- `make check-freshness` は全 OK。**EOL 由来の緊急性はゼロ** —— bump の動機は
  CVE fix version の入手可能性のみ。

問題の構造: 「~1 年経過」は **代理指標**である。守りたかった性質は
「apk の exact pin が安定していて bump 時の再解決コストが読める」ことで、月数はその近似だった。
月数を基準に据えたままだと、CVE ラウンドごとに「字義では早いが上げないと直せない」という
同じ議論が再発する (software-engineer の指摘)。代理指標ではなく性質そのものを書くべき。

「最新を常に追う」を採らない理由 (規模ではない): apk の exact pin
(`images/ttyd/Dockerfile:13-17` の `ttyd=1.7.7-r0` 等 5 本) は cycle を跨ぐと必ず全滅し、
bump ごとに再解決が要る不可逆でないが確実なコストである。新しすぎる cycle は main/community の
`-rN` が動き続けるため、この再解決を短周期で繰り返すことになる。patch release 回数は
その churn が落ち着いたことの直接の観測値であり、月数より正確。

## Options

### Option A — 規約を据え置き、3.22 のまま CVE を例外として受容

- 変更点: なし。77 High を「fix 不在」として accepted risk に積む。
- コスト: 参加者に配る image に修正可能な High を残す。Sysdig 社員が主催する
  Falco/Sysdig イベントで、自前 image のスキャン結果が赤いまま = 対外的な整合性の毀損。
- リスクと可逆性: 可逆だが、次ラウンドで同じ議論が再燃 (トリガ ⑦ に近づく)。
- 効き始める閾値: 3.22 に fix が backport された時 (観測されていない)。

### Option B — 3.22 → 3.23 に bump し、選定基準も置き換える (推奨)

- 変更点: 2 つの alpine consumer を同時に 3.23 へ (conventions:89 が
  `alpine:3.22 = images/{ttyd,challenge}` を 1 グループとして扱っている)。
  併せて規約 47-49 行を「安定性実績 + EOL runway + CVE fix 到達性」の 3 条件に差し替える。
- コスト: `images/ttyd/Dockerfile:13-17` の exact pin 5 本の再解決 (build が落ちるので
  取りこぼし不可能 = 自己検証的)。challenge 側は version pin なし
  (`images/challenge/Dockerfile:18-34`) なので追随のみ。digest 再解決 1 回 (conventions:75-101)。
  イメージサイズ・依存数は不変。
- リスクと可逆性: 高可逆 (2 Dockerfile の FROM + pin。revert は 1 commit)。
  I5 (イメージ数) に影響なし → CEO のイメージ数批准は不要。
  リスクは apk pin 再解決漏れだけで、それは build 時に必ず露見する。
- 効き始める閾値: 次イベント向け image build の時点で 77 High が消える。

### Option C — 3.23 に bump するが規約は触らない (単発の例外扱い)

- 変更点: Dockerfile のみ。規約 47-49 行は「~1 年」のまま、PR 本文で例外を説明。
- コスト: 規約と実態が乖離した状態を残す (規約 = 3.22 相当、実態 = 3.23)。
  次ラウンドで再議論が確定し、しかも「前回は例外だった」という判例が曖昧に効く。
- リスクと可逆性: 可逆だが、正典が実態と食い違う状態は architect として推奨できない
  (境界の曖昧化 = 紙のルールが守られない前例を作る)。
- 効き始める閾値: 無し。

## Decision

**Option B を採用する** —— 直せる 77 High を直し、かつ同じ議論が再発しないよう
代理指標 (月数) を守りたい性質そのもの (patch 実績・EOL runway・fix 到達性) に置き換える。

### 判定 (同意権の行使)

**yes, if** —— 以下 5 条件をすべて満たすこと:

1. `images/ttyd/Dockerfile` と `images/challenge/Dockerfile` を **同時に** 3.23 へ上げ、
   同一の multi-arch index digest を pin する (conventions:75-101 の手順。
   `MediaType` が image index であることの確認を含む)。
2. `images/ttyd/Dockerfile:13-17` の 5 本の exact pin を 3.23 の実値へ再解決する。
3. `make build TAG=local` / `make test` / `make check-freshness` / `make scan` を通し、
   **bump 後の High 件数と残存 CVE (libxml2 / jq) を PR 本文に実測値で明記**する
   (「77 解消」を主張の根拠として残す)。arm64 (Graviton) でも build を通す
   (2026-08-16 の arm64 pivot 実績があるため amd64 のみの確認では不十分)。
4. UID 表 (conventions:13-14, ttyd = `adduser -D -u 1000`) を再確認する。
   明示 UID なので変わらない見込みだが、cycle bump 時の再確認を規約が要求している。
5. 規約 47-49 行を下記文言案に差し替える (Dockerfile 変更と同一 PR。実態と正典を同時に動かす)。

### 規約の文言案 (`.claude/rules/falco-ctf-app-conventions.md:47-49` を置換)

```markdown
- alpine の cycle は次の 3 条件を満たす **最古の supported cycle** を選ぶ
  (「リリース後 ~1 年経過」という月数基準は 2026-08 に廃止 — ADR-0002):
  1. **安定性実績**: patch release が 3 回以上出ている (= `x.y.3` 以降)
  2. **EOL runway**: EOL まで 12 ヶ月以上ある (`make check-freshness` が検証)
  3. **CVE fix 到達性**: 現在 open な High/Critical の fix version が
     その cycle の main/community に存在する (`apk policy <pkg>` で実測)
  条件 1-3 を満たす cycle が複数あるときは最古を選ぶ (apk exact pin の再解決コストは
  bump 毎に発生するため、無用に新しい cycle を追わない)。条件 3 を満たさない場合に限り
  1 cycle 新しい側へ上げ、PR 本文に `apk policy` の実測出力と bump 後の残存 CVE を明記する。
  2026-08 時点の適合解: **3.23** (3.23.5 まで patch 5 回・EOL 2027-11)。
  fix が全 cycle・edge に存在しない場合は cycle bump では解決しない —— パッケージ自体の
  除去を第一候補とする (前例: wget を busybox wget に置換, images/challenge/Dockerfile:12-17)。
```

## Consequences

- 諦めたもの: 「月数」という一目で判定できる単純さ。今後は `apk policy` の実測が
  cycle 選定の前提作業になる (bump 時のみ、年 1 回程度)。
- 新たに守る規約: 上記 3 条件。**Hard Invariant には昇格させない** —— 条件 1 と 3 は
  機械検証が不完全 (下記 Verification) であり、ORGANIZATION.md §8 の歯止めに従う。
  I1-I10 は変更なし。
- follow-up (別タスク): **libxml2 を誰が引き込んでいるかを特定し、除去可能性を評価する。**
  全 cycle に fix が無い依存を抱え続けるより、wget の前例
  (`images/challenge/Dockerfile:12-17`: 脆弱バイナリを除去して Critical を実解消) に倣うのが
  この repo の作法。jq も同様に、課題で本当に必要かを再評価する。
- runbook への影響: なし (build 手順は不変)。

## Signposts

1. **3.23 の patch が 6 ヶ月以上出ない、または 3.24 が 3.23 より先に必要 fix を持つ** ——
   「最古の適合 cycle」の判定が変わる。条件 3 の再評価トリガ。
2. **`make check-freshness` が 3.23 の EOL runway < 12 ヶ月を報告** (2026-11 頃に到来) ——
   条件 2 違反。次 cycle への計画的 bump を起票する。
3. **cycle bump 後の CVE scan で High が 20 件以上残る** —— cycle 選定では解決しない
   問題 (= パッケージ除去または base 変更、例えば ttyd/challenge の wolfi/apko 化) の兆候。
4. **exact pin の再解決が年 2 回以上必要になる** —— 条件 1 の patch 回数 3 が甘すぎる。
   閾値を上げるか、pin 戦略自体 (exact pin をやめて digest + `apk upgrade` 一本化) を再検討する。

## Verification

- **条件 2 (EOL runway)**: `make check-freshness` (`scripts/check-freshness.sh`) が機械検証。
  scheduled cron (`.github/workflows/freshness.yaml`) で常時監視されている。
- **条件 1 (patch 実績)**: 部分的に機械化可能 (FROM の tag が `x.y` である以上、
  patch 回数は外部データ)。**現状は PR レビュー時の人手確認**。
- **条件 3 (fix 到達性)**: PR CI の image CVE scan が「bump 後に High が減ったこと」を
  事後的に示す。事前の `apk policy` 出力は PR 本文への記載を規約で要求する (人手)。
- **pin の整合**: cycle を誤ると exact pin (`images/ttyd/Dockerfile:13-17`) が解決できず
  `make build` が失敗する = build 時の自動ゲート。
- **digest 一致**: 2 つの alpine consumer が同一 digest であることは grep で機械確認できる
  (現状 CI 未実装。追加は任意 —— conventions:87-91 の「同一 image は同じ digest に揃える」の
  自動化として、将来 `scripts/check-freshness.sh` に足せる)。

→ 総合すると **条件 1/3 は機械検証が不完全** なので Hard Invariant には昇格させない。

## Advice

- software-engineer (2026-08-18, VP 経由): `apk policy` による全 cycle 実測、
  「基準を見直さないと次の CVE ラウンドで同じ議論が再発する」との指摘。
  本 ADR はこの指摘をそのまま採用し、代理指標の置換という形で応答した。
- security-engineer: 未取得 (104 High の棚卸しは同氏の監査結果)。bump 後の残存 CVE の
  accepted risk 判断は同氏のレビューを通すこと。
