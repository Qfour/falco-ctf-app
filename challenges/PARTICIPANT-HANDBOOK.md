# 参加者ハンドブック — falco-ctf

ようこそ。これは **Falco CTF** イベントの参加者向け資料です。
当日の前に一度目を通し、イベント中はワークスペース内からいつでも
参照できるようにしてください (`cat /opt/ctf/fixtures/welcome.txt` で
各チャレンジの個別ガイドが見られます)。

---

## 1. このイベントの目的

[Falco](https://falco.org/) は **コンテナ・ホスト上の syscall を
リアルタイム監視する OSS のランタイムセキュリティツール** です。
攻撃者が侵入後にやりがちな挙動 (機密ファイル読み取り、Reverse Shell、
クレデンシャル探索 …) を **kernel レベル**で観測し、ルールに合致した
ら即時アラートを出します。

このイベントでは、参加者ひとりひとつのコンテナ環境 (= **ワークスペース**)
が割り当てられ、その中で **Falco を発火させる / 回避する** 課題を
順に解いていきます。Falco が見ているのは syscall なので、コマンド
名だけ変えても引っかかります。逆に、ファイルパスのバリエーションや
プロセス名の偽装といった「実際の攻撃テクニック」で初めて回避できます。

---

## 2. ワークスペースの仕組み

### 2.1 アクセス方法

```
ブラウザで:  https://<your-username>.<event-domain>/
```

イベント開始時に運営から **ユーザ名** と **パスワード** が配られます。
URL を開くと OIDC ログイン画面に転送されるので、それを入力してください。
ログインに成功するとブラウザ内に **Web ターミナル (ttyd)** が表示され
ます。ここがあなたのワークスペースです。

> 一度ログインすると Cookie が共有されるので、別のチャレンジ用の URL を
> 開きなおしても再認証は不要です。

### 2.2 ワークスペースに置かれているもの

ログイン直後のディレクトリは `/` (root) ですが、課題用の素材は
`/opt/ctf/` に集約されています。

| パス | 中身 |
|---|---|
| `/opt/ctf/fixtures/welcome.txt` | **このチャレンジの説明**。最初に必ず読む |
| `/opt/ctf/fixtures/submit.sh` | (evade チャレンジのみ) flag 提出関数 |
| `/opt/ctf/fixtures/*` | チャレンジ固有のスクリプト・データ |

使えるツール:

- 基本: `bash`, `cat`, `less`, `vim`, `grep`, `find`, `od`, `file`, `head`, `tail`
- ネットワーク: `curl`, `wget`, `nc` (netcat), `nslookup`/`dig` (bind-tools)
- プロセス: `ps`, `top`, `pstree` (procps)
- その他: `jq` (JSON 整形), `busybox-extras`

> 環境変数で **自分が誰か** が分かります:
> ```bash
> echo $FALCO_CTF_USER         # → 自分のユーザ名
> echo $FALCO_CTF_CHALLENGE    # → 取り組み中のチャレンジ ID
> ```

### 2.3 自分が他のユーザに干渉できないこと

各ユーザのワークスペースは **個別の Namespace** に隔離されています。
NetworkPolicy + RBAC で他ユーザの workspace には到達できません。
スコアボードも見えません (運営のみ閲覧可)。**自分の手元の結果が
すべて**、と考えてください。

---

## 3. チャレンジの種類

| 種類 | 説明 | クリア条件 |
|---|---|---|
| **trigger** | Falco に **指定ルールを発火させる** | コンテナで該当 syscall を実行する。自動で solve に記録される。 |
| **evade** | Falco に **発火させずに flag を取り出す** | flag を `submit` 関数で提出。提出直前 10 秒に該当ルールが発火していないこと。 |

`trigger` は「自分は今 Falco に検知された」をどう示すかが分かりにくい
ですが、**コマンドを実行した瞬間に scoreboard が自動で記録**します。
心配なら運営に「私の name=alice が 01 を解いたか確認してください」と
口頭で確認してください。

`evade` は **提出関数 (`submit`) の戻り値が即座にフィードバック**を
返してくれます (`{"solved":true}` か `{"evaded":false}`)。

---

## 4. 提出方法 (evade チャレンジ)

```bash
# Step 1: スクリプトを source して submit 関数を有効化
source /opt/ctf/fixtures/submit.sh

# Step 2: 関数を呼び出して flag を投げる
submit 'FALCO{...}'
```

レスポンス例:

```json
# 正解 + 検知も逃れた
{"correct":true,"evaded":true,"solved":true,"user":"alice"}

# flag が違う
{"correct":false,"reason":"flag mismatch"}

# flag は正しいが直近 10s に該当ルールが発火している
{"correct":true,"evaded":false,"reason":"forbidden rule(s) [\"Read sensitive file untrusted\"] fired in the last 10s..."}
```

`evaded:false` が出たら、**10 秒待ってから** もう一度 `submit` してみ
てください (rolling window が空くため)。

> 直接 curl したい場合: `submit.sh` の中身を参照。`POST
> /api/challenges/<cid>/submit` に `{"user":"...","flag":"..."}` を
> JSON で送るだけです。

---

## 5. チャレンジ一覧

| ID | 名前 | 種類 | 想定難易度 | 出題する Falco ルール |
|---|---|---|---|---|
| 01-read-shadow | 機密ファイル読み取り | trigger | ★☆☆☆ (入門) | `Read sensitive file untrusted` |
| 02-evade-shadow-read | 同を回避 | evade | ★★☆☆ | 同上 |
| 03-search-credentials | クレデンシャル探索 | trigger | ★☆☆☆ | `Search Private Keys or Passwords` |
| 04-spawn-shell-untrusted | 信頼外プロセスから shell 起動 | trigger | ★★☆☆ | `Run shell untrusted` |
| 05-evade-shell-spawn | 同を回避 + flag 取得 | evade | ★★★☆ | 同上 |

各チャレンジは独立しています。順番通りに進めると **trigger で
ルールを理解 → evade で同じルールを回避** という流れで学べます。

---

## 6. よくある落とし穴

### 6.1 「`cat` したのに solve にならない」

- そもそも Falco DaemonSet が手元のノードで動いているか — 運営に確認。
- コンテナイメージが `falco-ctf/challenge` でない (= scoreboard の
  ingest フィルタで弾かれている可能性)。運営に環境再払い出しを依頼。

### 6.2 「`submit` したのに `evaded:false`」

- 直近 10 秒の **rolling window** 内に該当ルールが発火している。
- 一度 `cat /etc/shadow` した後に回避コマンドを試した → 過去の発火が
  残っている。**10 秒待つ** か、Pod を再起動 (運営に依頼) でリセット。

### 6.3 「Falco が見ているフィールド」

ルールごとに「何を見ているか」が違います:

| ルール | 主に見ているフィールド | 回避の発想 |
|---|---|---|
| `Read sensitive file untrusted` | `fd.name` (open 対象パス) | 別パスで同じ inode に到達 (`/proc/self/root/...` 等) |
| `Search Private Keys or Passwords` | `proc.cmdline` (コマンドライン文字列) | 文字列を分割 / 別名のキーワード |
| `Run shell untrusted` | `proc.pname` (親プロセス comm) | スクリプトを直接 exec せず、別名のインタプリタに渡す |

詳細は `/opt/ctf/REFERENCE.md` (ワークスペース内) または
[challenges/REFERENCE.md](./REFERENCE.md) を参照。

---

## 7. 行き詰まったら

1. `cat /opt/ctf/fixtures/welcome.txt` を再読 — ヒントが段階別に書かれている
2. 同じワークスペースで `man <command>` (alpine の `man` パッケージは
   入っていない場合がありますが) もしくは `<command> --help`
3. それでも分からなければ運営に質問。質問の質を上げるために、以下を
   伝えてください:
   - 自分のユーザ名 (`echo $FALCO_CTF_USER`)
   - 取り組み中のチャレンジ ID
   - 試したコマンド (最後の 2-3 個)
   - 期待した結果と実際の結果

---

## 8. 当日のスケジュール感 (目安)

```
受付・ログイン確認          10 min
全体説明 + ハンドブック共有 10 min
チャレンジ 01-05            60-90 min
振り返り + 表彰             15 min
```

無理にすべて解く必要はありません。**詰まったら次に進む**、**evade を
攻めずに trigger を確実に取る**、など戦略はあなた次第です。

---

## 9. 参考リンク

- [Falco 公式: 概要](https://falco.org/docs/)
- [Falco rules library](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)
- [Falco fields reference](https://falco.org/docs/reference/rules/supported-fields/)
- ワークスペース内のリファレンス: `/opt/ctf/REFERENCE.md`

それでは健闘を祈ります。
