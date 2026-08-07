# リリース手順 (RELEASING)

`falco-ctf-app` の版管理は **各リポ独立 SemVer + GitHub Releases の自動リリースノート**。
要望 (Issue) → PR → Release → CHANGELOG の鎖を GitHub ネイティブ機能で辿れるようにする。

> ⚠️ **タグ打ち・Release publish は CEO のみが行う。** Lead / VP はここまで
> (CHANGELOG 確定・PR ラベル整備) を準備し、実際の `git tag` / push / Release 作成は
> CEO の承認・操作を待つ。

## SemVer タグが contract 版の正典

**SemVer タグが contract 版の唯一の正典。** タグは特定の git SHA を指し、その SHA は
platform の `events/<回>/versions.yaml` の `app.ref` と一致させる。外部クライアント
(将来 Roblox 等) は SemVer タグを見て対応する contract 版を判断する。

CI は非稼働 (CI-free 恒久方針) だが、**リリース時には必ずタグを打つ**。タグ = contract 版の
公開点であり、CI の有無とは独立に運用する (image ビルド/push は別途 platform 側の手動手順)。

## SemVer bump 基準

- **MAJOR (`X`)** — 公開 contract の破壊的変更 (`/falco/events` payload・image 命名・challenges スキーマ)。
- **MINOR (`Y`)** — 後方互換の機能追加。
- **PATCH (`Z`)** — 後方互換のバグ修正・軽微改善。

## 手順

1. **`## [Unreleased]` を新バージョン節に確定する**
   `CHANGELOG.md` の `## [Unreleased]` を `## [X.Y.Z] - YYYY-MM-DD` に変え、
   空の Added/Changed/Fixed/Security を持つ新しい `## [Unreleased]` を上に足す。
   併せて末尾の compare リンクを新バージョンへ更新する
   (`[Unreleased]: .../compare/vX.Y.Z...HEAD` の `vX.Y.Z` を今回打つタグに)。
2. **タグを打って push する (CEO)**
   ```sh
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```
   > ⚠️ **タグ push は CEO のみ。** G1 の tag ruleset (`v*`) で非 CEO の作成/更新は拒否される。
3. **Release は自動生成される (`.github/workflows/release.yml`)**
   `vX.Y.Z` タグを push すると `release.yml` ワークフローが発火し、Release を **自動生成する**。
   手動の `gh release create` は不要になった。ワークフローの動作:
   - **SemVer 検証**: タグが `vX.Y.Z[-pre][+build]` (SemVer) に一致しないと fail する
     (不正タグ `1.0` / `foo` などは弾かれ、Release は作られない)。
   - **Release 生成**: `gh release create "$TAG" --generate-notes --verify-tag` 相当を実行。
     プレリリース (タグに `-` を含む。例 `v1.2.0-rc1`) は自動で `--prerelease` が付く。
   - **カテゴリ分類**: `--generate-notes` が `.github/release.yml` の分類に従い、マージ済み PR を
     ラベル別 (Features / Fixes / UX / Security / Docs / Infra) にグルーピングする。PR には
     **必ず `.github/labels.yml` の `type:*` ラベルを付けてからマージすること** (未付与は Other に入る)。

   ワークフローは `GITHUB_TOKEN` の `contents: write` のみ使用 (新 secret 不要)。実行結果 (Release リンク) は
   Actions タブの release run で確認する。生成に失敗した場合は SemVer 検証 fail か、`--verify-tag`
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
- 外部クライアントは MAJOR 差分を見て contract 対応版を判断する (CHANGELOG ヘッダ参照)。
