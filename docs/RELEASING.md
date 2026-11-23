# リリース手順 (RELEASING)

`falco-ctf-app` の版管理は **各リポ独立の calver の版名 (`vYYYY.M.D`、厳格 SemVer の形) + GitHub Releases の自動リリースノート**。
契約の互換は版の数字ではなく、CHANGELOG の各版の節の記載で示す (下の「契約への影響の区分」)。
要望 (Issue) → PR → Release → CHANGELOG の鎖を GitHub ネイティブ機能で辿れるようにする。

> ⚠️ **タグ打ち・Release publish は CEO のみが行う。** Lead / VP はここまで
> (CHANGELOG 確定・PR ラベル整備) を準備し、実際の `git tag` / push / Release 作成は
> CEO の承認・操作を待つ。

## release タグが contract 版の正典

**release タグ (`vYYYY.M.D`) が contract 版の唯一の正典。** タグは特定の git SHA を指し、その SHA は
platform の `events/<回>/versions.yaml` の `app.ref` と一致させる。外部クライアント
(将来 Roblox 等) は release タグと、その版の CHANGELOG の節の契約への影響の記載を見て、対応する contract 版を判断する。

> ⚠️ **unenforced な断絶点**: release タグ ↔ platform `versions.yaml` の `app.ref` (SHA) の
> 対応は **現状 機械照合されず、CEO のタグ運用に依存する** (タグの指す SHA と `app.ref` の
> SHA が一致していることを誰も自動検証していない)。両者がずれると platform が古い contract
> の app をデプロイしうる。将来 CI-free 方針と両立する範囲で自動照合の余地がある。

CI は非稼働 (CI-free 恒久方針) だが、**リリース時には必ずタグを打つ**。タグ = contract 版の
公開点であり、CI の有無とは独立に運用する (image ビルド/push は別途 platform 側の手動手順)。

## 版名 (calver を厳格 SemVer の形で)

- 版名は `vYYYY.M.D` の 1 形 (月・日は 0 埋めしない。`v2026.11.1`、`v2026.12.24`)。厳格 SemVer の形なので `release.yml` を通る。文法の正典は `.claude/rules/falco-ctf-app-conventions.md` の契約表「Release tag の文法」行。
- 日付は tag を切る日 (JST) か、それより後の日。既存のどの release tag よりも版の順で大きくする。**同じ日の 2 本目は `.N` を付けず、未使用の最小の後の日付で切る** (4 つ目の数字は SemVer の外で Release が作られず、platform も release と認めない)。
- suffix 付き (`v2026.12.24-rc1` など) は GitHub では prerelease になる。platform の prod の pin と release の scan は **suffix なしだけ**を release と認める。
- 並べるときは版の順 (`git tag --sort=v:refname` / `sort -V`)。文字列の順 (`v2026.11.20` < `v2026.11.3`) は誤る。
- **公開 contract の破壊的変更は版の数字ではなく CHANGELOG の該当節に明記する** (MAJOR は年で、契約の互換を表さない。書き方は下の「契約への影響の区分」)。
- 形の外れた過去の tag (`v2026.08.31`・`v2026.09.02`・`v2026.09.03`・`v2026.09.03.1`) は消さず、release としては扱わない。
- 文法の既知の限界: 検査は月 (1〜12) と日 (1〜31) の範囲だけを見て暦を照らさない (`v2026.2.31` も通る)。暦に無い日付で切らないのは運用の規律で、検査は足していない。

なぜこの形か (検討した形と見直す条件):

- 0 埋めの `vYYYY.MM.DD` は、厳格 SemVer が数字の leading zero を許さないので `release.yml` が拒む (2026-11-01 に踏んだ)。
- 4 つ目の数字や `.N` (`vYYYY.M.D.N`) は SemVer の外で、Release が作られず、platform も release と認めない。
- `vYYYYMMDD.N.0` は SemVer に合うが、MAJOR が日ごとに跳び、採った後で `vYYYY.M.D` に戻すと版の順が逆転するので後から戻せない。
- 見直す条件: 同じ日の 2 本目を後の日付に繰り越すことが常態になったら (日付が実際の release の日を表さなくなったら)、この形を見直す。

## 契約への影響の区分 (CHANGELOG)

契約への影響は、CHANGELOG の版の節 (`## [Unreleased]`、release の後は `## [YYYY.M.D] - YYYY-MM-DD`) の各項目に書く。区分は版の数字には反映しない (版名は日付)。

- **MAJOR** — 公開 contract の破壊的変更 (`/falco/events` payload・image 命名・challenges スキーマ)。項目の先頭を `**破壊的変更 (公開 contract)**` とし、両リポ同時 PR の対を書く。
- **MINOR** — 後方互換の機能追加。
- **PATCH** — 後方互換のバグ修正・軽微改善。
- 項目の太字の見出しの中に区分 (`MAJOR` / `MINOR` / `PATCH`) を書く。版を確定するときは、節の冒頭に引用 (`>`) で、その版の区分の要約 (MAJOR の項目の有無) を書く。
- 旧名: この節は 2026-11-24 まで「SemVer bump 基準」だった。過去の版の節の「bump 基準」「`docs/RELEASING.md` の基準」は、この節を指す (区分の意味は変えていない)。

## 手順

1. **`## [Unreleased]` を新バージョン節に確定する**
   `CHANGELOG.md` の `## [Unreleased]` を `## [YYYY.M.D] - YYYY-MM-DD` に変え、
   空の Added/Changed/Fixed/Security を持つ新しい `## [Unreleased]` を上に足す。
2. **compare リンクを更新する**
   `CHANGELOG.md` 末尾の compare リンクを新バージョンへ更新する
   (`[Unreleased]: .../compare/vYYYY.M.D...HEAD` の `vYYYY.M.D` を今回打つタグに差し替え、
   併せて新バージョン節の compare リンク `[YYYY.M.D]: .../compare/<前タグ>...vYYYY.M.D` を足す)。
   step 1 と分けて独立に確認する (リンク更新漏れは Release ノートには現れず気付きにくいため)。
3. **タグを打って push する (CEO)**
   ```sh
   git tag -a vYYYY.M.D -m "<message>"
   git push origin vYYYY.M.D
   ```
   > ⚠️ **タグ名は厳格 SemVer** (`release.yml` の検証: 各数字に leading zero 不可)。日付型なら `v2026.11.1` と書く。`v2026.11.01` は fail する (2026-11-01 に踏んだ)。
   > ⚠️ **タグ push は CEO のみ (運用の規律)。** origin の tag ruleset (`v*`) は **削除と付け替えを拒否する**が、**作成は制限しない** (repo の書き込み権を持つ account は 1 つで、作者で区別できない)。prod に使う tag の作者の証明は、運営の端末での CEO の署名で行う (platform の運用手順)。
4. **Release は自動生成される (`.github/workflows/release.yml`)**
   `v*` のタグを push すると `release.yml` ワークフローが発火し、Release を **自動生成する**。
   手動の `gh release create` は不要になった。ワークフローの動作:
   - **SemVer と calver の検証**: タグは次の 2 つの**両方**に合わなければならない。(1) 厳格 SemVer (`semver=` の行)、
     (2) calver の形 `vYYYY.M.D[-pre]` (0 埋めなし・`+build` なし。`calver=` の行)。この順に検査し、合わなかった最初の検査の error で fail する
     (不正タグ `1.0` / `foo` と 0 埋めの `v2026.11.01` は (1) で、calver でない `v1.2.3` と build metadata 付きは (2) で弾かれ、Release は作られない)。
   - **Release 生成**: `gh release create "$TAG" --generate-notes --verify-tag` 相当を実行。
     プレリリース判定は **core の最初の `-`** で行う (SemVer 準拠)。
     例: `v2026.12.24-rc1` は prerelease、`v2026.12.24` は通常リリース。
   - **カテゴリ分類**: `--generate-notes` が `.github/release.yml` の分類に従い、マージ済み PR を
     ラベル別 (Features / Fixes / UX / Security / Docs / Infra) にグルーピングする。PR には
     **必ず `.github/labels.yml` の `type:*` ラベルを付けてからマージすること** (未付与は Other に入る)。

   ワークフローは `GITHUB_TOKEN` の `contents: write` のみ使用 (新 secret 不要)。実行結果 (Release リンク) は
   Actions タブの release run で確認する。生成に失敗した場合は SemVer / calver の検証の fail か、`--verify-tag`
   でタグ未 push が疑われる (Actions ログを確認)。

## Projects ボード自動追加 (add-to-project)

新規 Issue を user プロジェクト <https://github.com/users/Qfour/projects/1> に自動追加する
`.github/workflows/add-to-project.yml` の運用手順。要望 (Issue) の入口をボードに集約し、
上記のリリース鎖 (Issue → PR → Release → CHANGELOG) の起点を取りこぼさないための自動化。

### PAT 登録

このジョブは `GITHUB_TOKEN` では Projects v2 に書けないため、repo secret
`ADD_TO_PROJECT_PAT` を供給する。

- **fine-grained PAT で `Projects` の Read and write のみ**に絞る。classic PAT は
  `repo` 等の広いスコープを巻き込むため非推奨。
- 所有者は **CEO** (発行・登録・失効管理は CEO 操作)。

### 失効時の症状

PAT 未登録 / 失効 / スコープ剥落のいずれでも、**Issue はボードに乗らず、Actions は
silent に失敗する** (Issue 作成者にも通知は飛ばない)。

- 「新規 Issue がボードに現れない」ときは、まず **Actions タブの add-to-project run**
  (Issue 発火分) の成否と、**PAT の有効性 / スコープ** を確認する。

### PAT ローテ手順

1. CEO が fine-grained PAT を再発行 (`Projects` Read and write のみ)。
2. **両リポ (app / platform) の repo secret `ADD_TO_PROJECT_PAT` を両方更新する。**
   同一 PAT を 2 リポで二重管理している (どちらか片方だけ更新すると、更新漏れ側の
   Issue がボードに乗らなくなる)。

### action の bump 手順

`actions/add-to-project` はサプライチェーン pin ポリシー (P12) の例外表に含まれないため
**commit SHA pin** している。bump は次の手順で行う (現行: `v2.0.0`
`5afcf98fcd03f1c2f92c3c83f58ae24323cc57fd`)。

```sh
# 1. 新しい tag を確認
gh api repos/actions/add-to-project/releases/latest --jq .tag_name
# 2. その tag が指す commit SHA を解決
gh api repos/actions/add-to-project/git/ref/tags/<tag> --jq .object.sha
```

解決した SHA を**両リポの `add-to-project.yml`** の `uses:` pin に反映し、末尾の
`# vX.Y.Z` バージョンコメントも新 tag に揃える (pin SHA とコメントの版表記を一致させる)。

### `transferred` トリガの注記

トリガは `[opened, reopened, transferred]`。`transferred` は **転送元リポで発火する**
仕様のため、他リポから転送されてきた Issue を当リポのボードへ取り込む用途には使えない。
add-to-project 自体は冪等なので、同一 Issue が複数回発火しても二重追加は無害。

## 補足

- contract に触れる変更は platform 側と同時 PR。CHANGELOG の該当節にも contract 影響を明記する。
- 外部クライアントは CHANGELOG の各版の contract 影響の記載で対応版を判断する (版の数字は日付で、MAJOR は契約の互換を表さない)。
