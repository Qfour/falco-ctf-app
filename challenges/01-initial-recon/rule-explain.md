### ルールの読み方

このルール `Contact K8S API Server From Container` の `condition` を、左から
論理積 (`and`) で読み解く。すべて満たしたイベントだけがアラートになる。

| condition の断片 | 意味 |
|---|---|
| `evt.type=connect` | ネットワーク接続を張る `connect(2)` システムコールを見ている。実際にデータを送ったかは問わず、**接続を開いた瞬間**が対象 |
| `fd.typechar=4` / `=6` | 接続先ファイルディスクリプタが IPv4 (`4`) または IPv6 (`6`) ソケットであること (ローカルソケット等を除外) |
| `container` | ホスト上の素のプロセスではなく、**コンテナ内**からの接続であること |
| `k8s_api_server` | 接続先が Kubernetes API Server の宛先に一致する (マクロで定義された IP/ポート) |
| `not k8s_containers` | 送信元が kube-system 等の**既知のコントロールプレーン Pod ではない** — 一般ワークロードからの接続だけを残す |
| `not user_known_...` | 運用者が「これは正常」と登録した例外に該当しない |

`output` 行はアラートに添える証拠フィールドだ。`connection=%fd.name` で接続先、
`process=%proc.name` / `command=%proc.cmdline` で実行主体、`user=%user.name` で
どのユーザが動かしたかが記録される。**なぜ発火したかを後から説明できる**のが
Falco の output の役割で、SOC はこれを見て一次トリアージする。

### なぜ発火するのか

このミッションのコンテナは ServiceAccount を持たない。API Server へ `connect` を
開いた時点で `not k8s_containers` を通過し、上の条件がすべて真になって発火する。
認証が 401 で弾かれても **接続イベント自体**が検知対象なので、応答内容は無関係だ。

### Sysdig のマネージドルールでのカバー

このルールは Falco コミュニティルールセットに含まれ、Sysdig Secure の
マネージドポリシー (Sysdig Runtime Threat Detection) にそのまま同梱される。
つまり**自分でルールを書かなくても**、Sysdig を入れた環境ではコンテナからの
異常な API Server 接触がデフォルトで検知・可視化される。Sysdig 側ではさらに
プロセスツリーや Kubernetes メタデータ (Pod / Namespace / ServiceAccount) が
イベントに紐付き、トリアージが一段速くなる。
