# NimbusBreach — 2時間版 運営進行台本 (本番リハーサル edition)

**本番想定のテスト実施**。シナリオは**フル (01→10) と同等**。2時間で全部を
ハンズオンし切るのは無理なので、**取り組みやすい 6 つを各自ハンズオン**し、
**残りの難問 4 つは解説で実演** → **01→10 のストーリーを最後までやり切る**。

scoreboard は**全 10 課題を表示** (`scoreboardScenario` 未指定 or `nimbusbreach-full`)。
速い参加者は解説枠の課題も先に挑戦してよい。

| 枠 | 時間 | 内容 |
|---|---|---|
| ① Falco 初級学習 | 0:00–0:30 | 講義 + ガイド付き初回発火 (全員で 01) |
| ② CTF ハンズオン | 0:30–1:30 | 01,02,03,04,06,08 を各自 (≈10分/課題) |
| ③ 解説 (やり切る) | 1:30–2:00 | 05,07,09,10 を実演解説 + 全体 recap (debrief.md) |

## ハンズオン / 解説 の振り分け

| Mission | ★ | type | この枠 | 実案件 |
|---|---|---|---|---|
| 01 initial-recon | ★1 | trigger | ハンズオン | TeamTNT の K8s API 偵察 |
| 02 credential-files | ★1 | trigger | ハンズオン | 資格情報窃取 (T1003) |
| 03 stealth-read | ★2 | evade | ハンズオン | 02 と同ルールを回避 (`/proc/self/root`) |
| 04 key-search | ★2 | trigger | ハンズオン | TeamTNT 鍵スクレイピング (T1552) |
| 05 silent-search | ★3 | evade | **解説** | 04 を cmdline 回避 (入力リダイレクト) |
| 06 web-rce-shell | ★3 | trigger | ハンズオン | Log4Shell → web プロセスから shell |
| 07 persist | ★3 | trigger | **解説** | upper-layer からの malware dropper |
| 08 c2-beacon | ★4 | trigger | ハンズオン | Kinsing reverse shell C2 (T1059) |
| 09 hidden-cache | ★4 | trigger | **解説** | hardlink で sensitive を隠す |
| 10 final-exfil | ★5 | evade | **解説** | boss: 全 7 ルール同時回避で exfil |

ハンズオン 6 (01,02,03,04,06,08) ≈ 60分。解説 4 (05,07,09,10) ≈ 30分。

## ① Falco 初級学習 (0:00–0:30)

`challenges/PARTICIPANT-HANDBOOK.md` を投影:
1. Falco とは — syscall をリアルタイム監視する OSS。
2. ルール = `condition` が syscall フィールド (`fd.name`/`proc.pname`/`proc.cmdline`) に
   文字列/集合でマッチ (`REFERENCE.md §2`)。
3. trigger = 発火させる / evade = 発火させず目的達成。
4. ワークスペース操作・`/opt/ctf/INDEX.txt`・各 welcome.txt・submit 方法。

**ガイド付き初回発火 (全員で Mission 01)**: `curl -sk https://kubernetes.default.svc/api`
→ scoreboard に発火が出るのを投影。

## ② CTF ハンズオン (0:30–1:30)

参加者は scoreboard を見ながら **01→02→03→04→06→08** を順に。各 welcome.txt に
難易度・目標/回避ルール・段階ヒント。運営は巡回し、03 (evade) で止まる人に
`/proc/self/root` のヒントを全体に出す。速い人には「05/07/09/10 も挑戦可」と促す。

## ③ 解説 — シナリオをやり切る (1:30–2:00)

`debrief.md` を投影し **01→10 全部**を通す。特に **05/07/09/10 は実演**
(ほとんどの参加者が未着手なので、運営が画面で発火/回避を見せる) → これで
全員が完全な 01→10 の攻撃キルチェーンを体験し切る。

> **本番版**: 時間が長い回は解説枠の課題もハンズオンに回すだけ (順序・課題は不変)。
> この 2h リハーサルで「導入 → ハンズオン → 解説」の流れと所要時間を検証する。
