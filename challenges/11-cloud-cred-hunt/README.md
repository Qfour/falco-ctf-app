# 11 — Cloud Cred Hunt (クラウド脅威検知・疑似版 / bonus)

本編 01–10 とは独立した **ボーナス課題** (Issue #46 の MVP)。テーマは
「クラウド脅威検知」だが、**実 AWS 接続・実クレデンシャル・実 API 呼び出しは
一切無い**。クラウド侵害の典型的な初動 = **ディスク上に残されたクラウド認証
情報を漁る** 動作を、既存の syscall ベース Falco ルール `Find AWS Credentials`
で疑似再現する自己完結課題。AWS 依存ゼロ・既存 ingest で完結する。

## ゴール (operator view)

Falco ルール `Find AWS Credentials` を発火させる。Rule の condition:

```
spawned_process
and ((grep_commands and private_aws_credentials) or
     (proc.name = "find" and proc.args endswith ".aws/credentials"))
```

- `grep_commands` = proc.name in (grep, egrep, fgrep)
- `private_aws_credentials` = proc.args に aws_access_key_id /
  aws_secret_access_key / aws_session_token / accesskeyid / secretaccesskey
  のいずれかが含まれる (icontains)

**cmdline シグネチャ検知** — 実ファイルの有無に依存しない。探索コマンドの
形が一致した瞬間に発火する。

## 想定解

```bash
# grep パス (proc.args に AWS キーの語)
grep -r aws_secret_access_key ~/.aws/
grep aws_access_key_id /opt/ctf/missions/11-cloud-cred-hunt/fixtures/aws-credentials.sample

# find パス (proc.args が ".aws/credentials" で終わる)
find ~ -path '*.aws/credentials'
```

## 疑似クラウド設計 (何を「クラウド操作」として再現するか)

- **検知対象**: 「クラウド長期資格情報のディスク上探索」= 侵害後にクラウドへ
  横展開する鍵を漁る動作。実運用で最も多い credential exposure の入口。
- **疑似環境の中身** (`fixtures/`, challenge image が `/opt/ctf/missions/` に焼く):
  - `aws-credentials.sample` — AWS 公式ドキュメントの EXAMPLE キー
    (`AKIAIOSFODNN7EXAMPLE` 等 = 非シークレットのダミー) を置いた練習用ファイル。
    参加者が現実的な grep 対象を持てる。`~/.aws/credentials` としても案内するが、
    ルールは cmdline で発火するため実ファイル配置は必須ではない。
  - `aws` — 疑似 aws CLI (flavor prop)。`sts get-caller-identity` /
    `configure list` に canned なダミー出力を返すだけ。**ネットワーク呼び出し
    ゼロ・資格情報保持ゼロ**。solve には関与しない (箱をクラウドっぽく見せるだけ)。
- **AWS 実接続なし**: 実キー・実 API・169.254.169.254 (IMDS) いずれも登場しない。

## ATT&CK

`T1552.001` (Unsecured Credentials: Credentials In Files)。ルールが検知するのは
**ファイルベースの資格情報探索**なので、これが正直なマッピング。`T1552.005`
(Cloud Instance Metadata API) ではない — メタデータ API 呼び出しは疑似版の
スコープ外 (それは Sysdig のクラウド面の担当)。04-key-search も T1552.001 だが、
そちらは SSH 秘密鍵/パスワード全般 (`Search Private Keys or Passwords`)、こちらは
**AWS クラウド資格情報に特化**した別ルールで、学習の焦点が異なる。

## 採点・境界メモ

- type: trigger。`expectedRules: [Find AWS Credentials]` のみ。既存 01–10 の
  expected/forbidden とルール名が重複しないため採点衝突なし。
- 本課題は scenario `nimbusbreach-full` (01–10 固定) には **編入しない**。
  ボーナスとして単体 launch する想定。scoreboard 既定 (SCENARIO_FILE 指定時) の
  01–10 の並び順・物語は不変。`SCENARIO_FILE` 未指定 = 全課題モードでは 11 も出る。
- evade ではないので `plant.sh` / `values.yaml` / フラグ注入は不要 (実フラグ非関与、
  公開境界 OK)。fixtures のダミーキーは AWS 公式 EXAMPLE = LOW 扱い。

## 本番ではどう守るか (Sysdig)

この疑似課題は「ディスク上の鍵漁り」という 1 動作を syscall で捉えたにすぎない。
本物のクラウド脅威検知は箱の外 — クラウドのコントロールプレーン
(CloudTrail / API 監査) と実行環境を横断して面で見る。Sysdig Secure の
クラウドコネクタ (CDR) は CloudTrail を取り込み「漏れた鍵での不審な API 呼び出し」
「権限昇格」「公開設定への変更」をクラウド側で検知し、CSPM が「そもそも鍵を平文で
置かない/露出させない」姿勢を継続評価する。ホスト内 Falco とクラウド面 CDR/CSPM の
二層が本番の守り方。(実 CloudTrail plugin / Sysdig コネクタ連携は post-event。)
