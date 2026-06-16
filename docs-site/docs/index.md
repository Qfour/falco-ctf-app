# はじめに

ようこそ。これは **Falco CTF** イベントの課題資料サイトです。

## 表示名について

スコアボードに出る名前は **デフォルトで識別子(`user1` など)** です。
ワークスペースのターミナルで、好きな表示名にいつでも何回でも変更できます:

```bash
source /opt/ctf/setname.sh && setname 'あなたの名前'
```

識別子と表示名は別物です。提出や認証は識別子で動き、スコアボードの
**表示だけ**が指定した名前に置き換わります(1〜32 文字、`< > & " '`
と制御文字は使えません)。

## Falco とは

[Falco](https://falco.org/) は、コンテナ・ホスト上の **syscall をリアルタイム監視**する
OSS のランタイムセキュリティツールです。攻撃者が侵入後に行いがちな挙動
(機密ファイル読み取り・リバースシェル・クレデンシャル探索 …)を kernel レベルで
観測し、ルールに合致したら即座にアラートを出します。

このイベントでは、参加者ひとりにひとつのコンテナ環境(ワークスペース)が割り当てられ、
その中で Falco を**発火させる / 回避する**課題を順に解いていきます。

!!! tip "ワークスペースとの併用"
    手を動かす環境は各自のワークスペース(Web ターミナル)です。
    このサイトは**読み物**として、ワークスペースと並べて参照してください。

## ストーリー：CTF Company のキルチェーン

このイベントは、攻撃者(あなた)が **CTF Company** の Kubernetes クラスタへ
侵入し、検知を避けながら攻撃を進める一連の物語として構成されています。
各ミッションは攻撃のキルチェーン順に並び、前のミッションを受けて次へ繋がります。
**「発火させて学ぶ(trigger)」→「回避して学ぶ(evade)」** を交互に踏みながら、
最後は全検知をかいくぐる総仕上げ(BOSS)へ向かいます。

| # | ミッション | 物語上の位置づけ(前段から接続) | 種別 |
|---|---|---|---|
| 01 | Initial Recon | Web SSRF で Pod に侵入。まず K8s API を叩いて環境把握 | trigger |
| 02 | Credential Files | 偵察完了 → 機密ファイル(認証情報)を読む | trigger |
| 03 | Stealth Read | 02 が検知された → 同じ機密を**ステルスに**読み直す | evade |
| 04 | Key Search | 足場確保 → 秘密鍵・パスワードを横断捜索 | trigger |
| 05 | Silent Search | 04 の検索が検知 → **静かに**鍵を探す | evade |
| 06 | Web RCE Shell | 入手した資格情報で別サービスへ横展開しシェル奪取 | trigger |
| 07 | Persist | シェルは揮発的 → バイナリを設置し永続化 | trigger |
| 08 | C2 Beacon | 永続化完了 → 標準入出力をネットワークへ向け C2 確立 | trigger |
| 09 | Hidden Cache | 戦利品を hardlink で隠して持ち出し準備 | trigger |
| 10 | The Final Exfil ★BOSS★ | master key を**全検知を回避して箱の外へ持ち出す** | evade |

!!! note "trigger と evade"
    **trigger** 課題は対象の Falco ルールを「発火させる」ことが solve。
    **evade** 課題は「発火させずに目的を達成し、flag を提出する」ことが solve です。

## 参考資料

Falco のルールや設定を深掘りしたい人向けの公式リソース:

- [Falco Rules リファレンス](https://falco.org/docs/reference/rules/)
  — ルール構文(`condition` / `output` / `macro` / `list`)の公式解説
- [falco.yaml(設定ファイル)](https://github.com/falcosecurity/falco/blob/master/falco.yaml)
  — Falco 本体の設定例(出力チャンネル・優先度・プラグイン等)
- [falco_rules.yaml(既定ルールセット)](https://github.com/falcosecurity/rules/blob/705c3db0ace8fddbf31a8e0bd7f1cdb01b5cd33b/rules/falco_rules.yaml)
  — 本イベントの課題が題材にしている既定ルール群(各ミッションの検知ルールの原典)
