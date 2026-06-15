# NimbusBreach Intro — 2時間版 運営進行台本

初級者中心・2時間枠の Falco CTF。**正準ストーリー (01→10) の昇順スライス**を
6 ミッション厳選した初級トラック (`intro-2h`)。順番は full トラックと同じで、
難しい回 (05/07/09/10) を飛ばすだけ — scoreboard 表示 (id 昇順) とも一致する。

| 枠 | 時間 | 内容 |
|---|---|---|
| ① Falco 初級学習 | 0:00–0:30 | 講義 + ガイド付き初回発火 |
| ② CTF Challenge | 0:30–1:30 | 6 ミッションを各自で (昇順) |
| ③ 解説 | 1:30–2:00 | 想定解 + 実案件マッピング + 防御 (debrief.md) |

## ストーリー(導入で話す)

> あなたは red team。NimbusCorp の cloud-native 環境への侵入を、実際の
> 攻撃キャンペーンの手口どおりに再現する。各ステップで **Falco が何を
> 検知するか** を体感し、途中で **攻撃者がどう検知を回避するか** も学ぶ。

キルチェーン(昇順): **偵察 → 資格情報アクセス →(同ルールを回避)→ 資格情報収集 → Web RCE → C2**。

## ① Falco 初級学習 (0:00–0:30)

話す内容(`challenges/PARTICIPANT-HANDBOOK.md` を投影):
1. Falco とは — コンテナ/ホストの **syscall をリアルタイム監視** する OSS。
2. ルールの仕組み — `condition` が syscall のフィールド (`fd.name`,
   `proc.pname`, `proc.cmdline` …) に **文字列/集合でマッチ**。`REFERENCE.md §2`。
3. trigger 課題 = ルールを**発火させる**、evade 課題 = **発火させずに**目的達成。
4. ワークスペース操作 — ブラウザ → ttyd、`/opt/ctf/INDEX.txt`、各
   `welcome.txt`、evade は `source /opt/ctf/submit.sh && submit '<flag>'`。

**ガイド付き初回発火 (全員で Mission 01)**: `curl -sk https://kubernetes.default.svc/api`
→ scoreboard に発火が出るのを投影。「これが trigger。今からこれを順に解く」。

## ② CTF Challenge (0:30–1:30)

参加者は scoreboard (`intro-2h` シナリオで 6 課題のみ・id 昇順で表示) を見ながら
**01→02→03→04→06→08 の順**に進める。1 課題 ≈ 8–10 分。各 `welcome.txt` に
難易度・目標ルール・段階ヒント (易/中/発展) がある。

| 順 | Mission | type | ★ | Falco rule | 実案件 (導入の一言) |
|---|---|---|---|---|---|
| 1 | 01 initial-recon | trigger | ★1 | Contact K8S API Server | TeamTNT / Hildegard の K8s API 偵察 |
| 2 | 02 credential-files | trigger | ★1 | Read sensitive file untrusted | 侵入後の資格情報窃取 (MITRE T1003) |
| 3 | 03 stealth-read | **evade** | ★2 | (Read sensitive file を回避) | 攻撃者の検知回避: `/proc/self/root` |
| 4 | 04 key-search | trigger | ★2 | Search Private Keys | TeamTNT の SSH 鍵スクレイピング (T1552) |
| 5 | 06 web-rce-shell | trigger | ★3 | Run shell untrusted | Log4Shell (CVE-2021-44228) → web プロセスから shell |
| 6 | 08 c2-beacon | trigger | ★4 | Redirect STDOUT/STDIN to Network | Kinsing 等の reverse shell C2 (T1059) |

→ 01→02 で発火を体験 → **03 で「同じ shadow を発火させずに読む」**回避の山場
→ 04/06/08 で手口を広げる。難易度は ★1→1→2→2→3→4 と緩やかに上昇。

運営の動き:
- 開始 10 分は全員が Mission 01/02 を発火できているか巡回。詰まる人には
  welcome.txt の HINT 1 を促す。
- Mission 03 (evade) で手が止まる人が多い → `/proc/self/root` のヒントを全体に出す。
- scoreboard を投影 (`/me?user=<name>` で個別の発火状況も見える)。

> 高難易度ミッション (05 evade-search / 07 upper-layer / 09 hardlink / 10 boss)
> は **フルトラック (`nimbusbreach-full`, 正準 01→10 統一シナリオ)** に温存。
> 上級者回・長時間回はそちらを使う (順番は同じ、課題が増えるだけ)。

## ③ 解説 (1:30–2:00)

`debrief.md` を投影。各ミッション → 実キャンペーンの該当手口 → Falco の
`condition` のどこが捕まえたか → 本番防御。Mission 03 で「検知は文字列ベース、
攻撃者は別 path で抜ける → 防御は fd.ino ベース等へ」を強調して締める。
