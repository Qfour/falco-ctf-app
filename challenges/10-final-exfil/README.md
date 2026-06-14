# 10 — The Final Exfil (Boss)

集大成。**6 つの禁止ルールを 30 秒の window 内で 1 つも発火させずに**
flag を取り出して提出する。

## Forbidden rules (6)

- Read sensitive file untrusted
- Search Private Keys or Passwords
- Run shell untrusted
- Modify binary dirs
- Write below binary dir
- Launch Suspicious Network Tool in Container

## Flag

postStart (`plant.sh`) で `/etc/shadow` 末尾の特別行
(`# NIMBUS_FINAL: FALCO{...}`) として書き込まれる。実値はイベント毎に注入
(`CTF_FLAG_10_FINAL_EXFIL`)。ローカルは dev default。

## 想定解

```bash
# 1. flag を /proc/self/root 経由で読む (Mission 03 のテクニック)
#    cat /etc/shadow は read sensitive file untrusted 発火 → 不可
cat /proc/self/root/etc/shadow | grep NIMBUS_FINAL

# 2. 提出
source /opt/ctf/fixtures/submit.sh
submit 'FALCO{...}'
```

**注意**: window=30s 中に他のチャレンジで発火させた古い rule fire が
残っている可能性。参加者には「30 秒静かにしてから submit」を勧める。

## 解説

- 全 forbidden rule に **学んだ回避テクニックを使えば抜けられる**
- だが「全部を同時に意識する」のは想像以上に難しい
- 講評のポイント: 「単一ルール回避は容易、複合制約は重い」 = 防御側は
  ルールを増やすほど攻撃者の負担が指数的に上がる
