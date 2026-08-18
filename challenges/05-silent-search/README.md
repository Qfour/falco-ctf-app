# 05 — Silent Search

cmdline 判定型ルールの回避を学ぶ。**入力リダイレクト**で外部コマンドの
cmdline からキーワードを消す。

## ゴール (operator view)

`/root/.ssh/id_rsa` (postStart で配置) を、`Search Private Keys or
Passwords` を発火させずに読み出し、中身に埋め込まれた flag を提出。

## Flag

fake openssh-key (`plant.sh` が配置) 中に `FALCO{...}` を埋め込み。
実値はイベント毎に注入される。ローカルは dev default。

## 想定解

```bash
# NG (cmdline に id_rsa を含む):
cat /root/.ssh/id_rsa                # 発火

# OK (入力リダイレクト — exec'd cmdline は "cat" のみ):
cat < /root/.ssh/id_rsa | grep FALCO
xxd < /root/.ssh/id_rsa
od -c < /root/.ssh/id_rsa | tail
```

shell の `<` でファイルを開き stdin に渡すと、fork-exec された `cat`
の `/proc/<pid>/cmdline` は `cat` のみ — 引数に id_rsa は出ない。

## 解説

- cmdline マッチ系ルールの典型的な回避
- 攻撃者の手口: 環境変数経由 / printf 連結 / 入力リダイレクト
- 本番防御: file descriptor 解決後の path を見るルールに切り替え
