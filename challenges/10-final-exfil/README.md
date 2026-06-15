# 10 — The Final Exfil (Boss)

集大成。master key は **3 つの断片** に分割され、3 つの異なる sensitive
file に隠されている。**7 つの禁止ルールを 30 秒の window 内で 1 つも
発火させずに** 3 断片を回収・連結して提出する。単一ファイルの盗み読み
(= Mission 03 単体) では flag は完成しない。

## Forbidden rules (7)

`falco-rule.yaml` の `forbiddenRules` と一致:

- Contact K8S API Server From Container
- Read sensitive file untrusted
- Search Private Keys or Passwords
- Run shell untrusted
- Drop and execute new binary in container
- Redirect STDOUT/STDIN to Network Connection in Container
- Create Hardlink Over Sensitive Files

## Flag (3 断片)

postStart (`plant.sh`) が `CTF_FLAG_10_FINAL_EXFIL` の中身 (`FALCO{...}`
の内側) を 3 等分し、各断片を行頭 `# CTF_FRAGMENT_N:` として配置する:

| 断片 | 配置先ファイル | 検知ルール |
|---|---|---|
| 1 | `/etc/shadow` | Read sensitive file untrusted |
| 2 | `/etc/sudoers` | Read sensitive file untrusted |
| 3 | `/root/.ssh/authorized_keys` | Read sensitive file untrusted |

flag = `FALCO{...}`(内側に断片 1→2→3 を連結)。3 つすべて + 正しい順序が必要。
実値はイベント毎に注入 (`CTF_FLAG_10_FINAL_EXFIL`)、ローカルは dev default
`FALCO{dev-final-exfil}` → 断片 `dev-f` / `inal-` / `exfil`。

## 想定解

```bash
# 1. 3 ファイルを /proc/self/root 経由で静かに読む (Mission 03 を 3 回)
#    - 直接 cat すると Read sensitive file untrusted が即発火
#    - hardlink で /tmp に逃がす手 (Mission 09) は forbidden に含まれ封鎖
for f in etc/shadow etc/sudoers root/.ssh/authorized_keys; do
  cat /proc/self/root/$f
done | grep CTF_FRAGMENT
#  → CTF_FRAGMENT_1: dev-f / _2: inal- / _3: exfil

# 2. 順に連結して FALCO{...} で囲む
#    FALCO{dev-f + inal- + exfil} = FALCO{dev-final-exfil}

# 3. 30 秒静かに待ってから提出 (過去の rule fire を window から抜く)
source /opt/ctf/submit.sh
submit 10-final-exfil 'FALCO{dev-final-exfil}'
```

**注意**: window=30s 中に他のチャレンジで発火させた古い rule fire が
残っている可能性。参加者には「全断片を回収 → 30 秒静かに → submit」を勧める。

## 解説

- **単一トリックでは解けない設計**: Mission 03 の `/proc/self/root` 読みを
  3 ファイルに適用し、断片を組み立てる「運用」が要る。03 を 1 回やるだけ
  では flag が揃わない。
- ショートカット封じ: hardlink (Mission 09) を forbidden に含めることで、
  「sensitive file を /tmp に複製してから読む」近道を塞いでいる。
- 入力リダイレクト (Mission 05) は cmdline は隠せるが open path は `/etc`
  のままなので Read ルールには効かない — 必ず path aliasing (`/proc/self/root`)。
- 講評のポイント: 「単一ルール回避は容易、複合制約 + 複数ターゲットは重い」
  = 防御側は検知点を増やし機密を分散するほど攻撃者の負担が積み上がる。
