### ルールの読み方

`Search Private Keys or Passwords` の `condition` は、`spawned_process`
(新しいプロセスが起動した `execve(2)` イベント) を起点に、以下のいずれかに
当てはまるかを見ている。

| condition の断片 | 意味 |
|---|---|
| `spawned_process` | プロセスが新規に `exec` された瞬間を対象にする (常駐プロセスの中の動きではなく、起動そのもの) |
| `grep_commands and private_key_or_password` | `grep` 系コマンドで、かつ引数に鍵・パスワードを示すパターン (`BEGIN ... PRIVATE KEY` 等) が含まれる |
| `proc.name = "find" and proc.args contains "id_rsa"` (等) | `find` コマンドで、引数に `id_rsa` / `id_dsa` / `id_ed25519` / `id_ecdsa` を含む |

ここで重要なのは、判定材料が **`proc.args` / `proc.cmdline` = 起動時のコマンドライン
文字列**であることだ。ファイルが実在するかも、実際にヒットしたかも見ていない。
**「鍵を探そうとするコマンドを打った」という意図そのもの**を検知する。

`output` の `command=%proc.cmdline` にそのコマンドライン全体が入るので、SOC は
「何を探そうとしたか」をアラートから直接読める。

### なぜ発火するのか

`find / -name id_rsa` のように打つと、`exec` されたコマンドラインに `id_rsa` が
残る。それが `proc.args contains "id_rsa"` に一致して発火する。結果が空でも、
対象ファイルが無くても、**コマンドラインの文字列が条件を満たした瞬間**に鳴る。

これは「コマンドラインシグネチャ型」の検知で、素早く広く網を張れる反面、
引数から特徴語を消されると抜けられる (それを体験するのが Mission 05)。

### Sysdig のマネージドルールでのカバー

このルールも Sysdig Secure のマネージドポリシーに標準搭載されている。認証情報
探索 (MITRE ATT&CK T1552.001 — Credentials In Files) の代表的なベースライン検知
として、追加設定なしで有効になる。Sysdig 側ではこの単発イベントを
**プロセスツリーや後続の振る舞い**と関連付けるため、「鍵探索 → 実際の読み出し →
外部送信」という連鎖として攻撃ストーリーを組み立てられる。
