# ルール condition の読み方

前の章で、rule は `condition` という論理式が真になったときにアラートを
出すと説明しました。この章では、その `condition` を実際にどう分解して
読むかを、部品ごとに見ていきます。

## macro — 名前付きの条件の断片

`condition` は毎回ゼロから書くと長くなりがちなので、Falco では条件の
一部を **macro** という名前で部品化し、複数の rule から再利用できます。
macro もそれ自体が `and` / `or` / `not` で組んだ条件式です。

## list — 値の集合

`proc.name in (some_list)` のように、複数の値を 1 つの集合として
まとめたものが **list** です。list は要素として別の list を持てるので
(list of lists)、大きな集合を小さな集合の組み合わせで表現できます。

## 例(説明のために簡略化したもの)

実際の Falco ルールセットの構文の雰囲気を見るための簡略化した例です
(この CTF の判定に使われている実際のルールとは対応しません)。

```yaml
- list: known_package_binaries
  items: [apt, apt-get, yum, dnf, apk]

- macro: spawned_package_manager
  condition: (proc.name in (known_package_binaries))

- rule: パッケージ管理コマンドの実行
  condition: >
    evt.type = execve and container and spawned_package_manager
  output: "package manager run in container (command=%proc.cmdline)"
  priority: NOTICE
```

読むときは、`and` で繋がれた断片を **左から順に、1 つずつ**
確認します。「syscall の種類は execve か」「コンテナ内か」
「実行ファイル名が既知のパッケージ管理ツールの集合に入っているか」の
**すべて**が真になったときだけ発火する、という論理積です。

## 除外 (exception) は最後まで読む

多くの rule には「正当な運用を誤検知しないための除外」が
`and not <macro>` の形で末尾に付きます。ここでよくある読み違いが
1 つあります。

> ある名前が「除外リストに載っている」ことだけを見て、
> 「このバイナリは何をしても免除される」と結論してしまう。

実際には、除外の macro 自体が単一の list 所属だけで判定されている
とは限りません。**「このバイナリ **かつ** この親プロセスから
実行された場合」** のように、複数の条件が `and` で組まれた macro に
なっていることが多くあります。除外を読むときは、そこにぶら下がる
macro の condition を **最後まで** たどり、途中の 1 つの gate 条件
だけで判断を止めないことが大切です。

## この章のまとめ

- condition は `and` / `or` / `not` で組んだブール式。macro / list で
  部品化・再利用されている
- `and` で繋がった断片は **すべて** 真である必要がある — 1 つでも
  当たらなければ発火しない
- 除外 (exception) の macro は、名前が list に載っているかだけでなく、
  それを含む **complex な条件全体** を最後まで読む

次の章では、この読み方を使って「自分がこれからやろうとしている操作は
どんな condition に引っかかりそうか」を事前に見積もる練習をします。
