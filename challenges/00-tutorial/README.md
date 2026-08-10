# 00 — チュートリアル (遊び方 / 0問目)

**採点に影響しない導入課題。** CTF の遊び方 — 提出・ヒント・進行の一連 — を、
安全な 1 コマンドで体験する。難易度の相場観 (trigger は易しい / evade は難しい) を
掴む例題も兼ねる。

## ゴール (operator view)

Falco ルール `Execution from /dev/shm` を発火させる。これは 01-10 の
どの課題も使っていない実ルール (Falco 3.0.1) なので、他ミッションを
巻き込んで auto-solve することはない。

## 想定解

```bash
echo 'echo hello from the tutorial' > /dev/shm/hello.sh
sh /dev/shm/hello.sh
```

`/dev/shm` (共有メモリ上の書込可能領域) 上のスクリプトを shell で実行すると、
condition `shell_procs and proc.args startswith "/dev/shm"` に一致して発火する。
安全な練習操作で実害はない。

## 遊び方 (チュートリアルモード)

- **trigger 課題** = あなたの操作で目標 Falco ルールを発火させると **自動で
  CLEARED** (提出フォーム不要)。この 00 と 01/02/04/06/07/08/09 が trigger。
- **evade 課題** = 目標ルールを **発火させずに** flag を回収し、**フォームから
  提出**する。直前 `windowSeconds` 秒に禁止ルールが鳴っていると弾かれる。03/05/10。
- **ヒント** は「気付き → 概要 → 解答」の 3 段階開示。詰まったら順に開く。
- **進行** は Journey UI がガイド。現在のミッションだけ操作でき、クリアで次が開く。

## 採点非影響の担保

本番の採点シナリオ `scenarios/nimbusbreach-full/scenario.yaml` は 01-10 の 10 課題
のみを列挙し、この `00-tutorial` を **含まない**。scoreboard は `SCENARIO_FILE` で
catalog を `Restrict` (fail-closed) するため、本番では採点・`/api/state`・
leaderboard・total (10) のいずれにも 00-tutorial は現れない。チュートリアルを
単体で回すときは `scenarios/tutorial-intro/scenario.yaml` を使う。

> local `make dev` は SCENARIO_FILE 未指定 = 全課題ロードなので、開発時のみ
> 00-tutorial が 11 番目として見える (本番採点には影響しない)。

## 解説

- `/dev/shm` は tmpfs 上の書込可能領域で、コンテナ再起動をまたいで残ることも
  あるため、攻撃者が malware を置いて実行する隠し場所として悪用される。
- キルチェーンの「drop & execute」テーマ (Mission 07) の入門版。ここで
  「Falco は *何を実行したか* だけでなく *どこから実行したか* も見る」ことを学ぶ。
