# ストーリー：CTF Company のキルチェーン

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
