# NimbusBreach Intro — 解説 (30分)

各ミッションを「実際の攻撃キャンペーン → Falco がどう捕まえたか → 本番防御」
の順で振り返る。投影しながら話す。`REFERENCE.md §3` に各ルールの condition。
順番は CTF と同じ昇順 (01→02→03→04→06→08)。

キルチェーン全体像(昇順):
```
偵察 ──→ 資格情報アクセス ──→(同ルールを回避)──→ 資格情報収集 ──→ Web RCE ──→ C2
 01            02                   03                 04            06        08
```

---

## 1. Mission 01 — 偵察 (`Contact K8S API Server From Container`)

- **実案件**: **TeamTNT** / **Hildegard** 等のクリプトジャッキングは侵入後すぐ
  K8s API を叩いてクラスタを列挙する。SA を持たない pod からの API connect は異常。
- **Falco**: `evt.type=connect and container and k8s_api_server and not k8s_containers
  and not user_known_...`。system pod 以外からの API connect で発火。
- **防御**: `automountServiceAccountToken: false`、NetworkPolicy で API への egress 制限、
  workload identity の最小権限化。

## 2. Mission 02 — 資格情報アクセス (`Read sensitive file untrusted`)

- **実案件**: 侵入後ほぼ必ず起きる `/etc/shadow` / クラウド資格情報の読み取り
  (MITRE **T1003** OS Credential Dumping)。ランサム/クリプトジャッキング両方の初期段。
- **Falco**: `open_read and sensitive_files and not proc.name in (許可リスト)`。
  開いた path (`fd.name`) が sensitive_files に一致したら発火。
- **防御**: 許可プロセスを絞る / 読み取り自体を監査ログ化 / 機密を pod に置かない。

## 3. Mission 03 — 検知回避 (evade: Mission 02 と同じルールを回避)

- **実案件**: 実攻撃者は検知が **path 文字列ベース** と知ると、同じ inode へ
  `/proc/self/root/etc/shadow` 等の別 path で到達して回避する。
- **学び**: Falco の `fd.name` は「開く時に渡した path」。`/proc/<pid>/root` 経由なら
  `/etc/shadow` 文字列にマッチしない → 発火しない。**Mission 02 と同じ目的・違う path**。
- **防御**: 文字列でなく **inode (`fd.ino`)** ベースのルール、`/proc/*/root` 経由読み取り
  自体を別ルールで検知、複数ルールの重ね掛け。← この回が解説の山場。

## 4. Mission 04 — 資格情報収集 (`Search Private Keys or Passwords`)

- **実案件**: **TeamTNT** は SSH 鍵 / クラウド credential を `grep`/`find` で横断収集し
  横展開する (MITRE **T1552** Unsecured Credentials)。
- **Falco**: `spawned_process and ((grep_commands and private_key_or_password) or
  (find ... args contains id_rsa ...))`。**cmdline 文字列**で判定。
- **防御**: 鍵を pod に置かない / cmdline 監査 / 横展開を NetworkPolicy で抑止。

## 5. Mission 06 — Web RCE (`Run shell untrusted`)

- **実案件**: **Log4Shell (CVE-2021-44228)** に代表される Web RCE。脆弱な Java/web
  プロセスが `Runtime.exec()` で shell を起こす。親プロセスが web デーモンなのが異常。
- **Falco**: `spawned_process and shell_procs and protected_shell_spawner and
  not proc.pname in (...)`。**親 comm (`proc.pname`)** が httpd/nginx 等なら発火。
- **防御**: web プロセスを distroless/no-shell 化、`readOnlyRootFilesystem`、
  RCE 自体を WAF / 依存更新で塞ぐ。

## 6. Mission 08 — C2 (`Redirect STDOUT/STDIN to Network Connection`)

- **実案件**: **Kinsing** 等のボットや一般的な reverse shell。socket を stdin/stdout に
  繋いで C2 と対話する (MITRE **T1059**)。
- **Falco**: `dup and container and evt.rawres in (0,1,2) and fd.type in (ipv4,ipv6)`。
  network socket fd を fd 0/1/2 に dup したら発火。
- **防御**: egress NetworkPolicy (C2 への外向き通信を遮断)、不審な outbound の検知。

---

## 締め

- **検知は安くて速いが、文字列マッチには回避余地がある** (Mission 03) — だから
  防御側はルールを重ね、攻撃者の手数 (回避コスト) を上げる。
- 続きをやりたい人へ: フルトラック `nimbusbreach-full` が同じ 01→10 の統一ストーリーで、
  evade 4 種 + boss (全 7 ルール同時回避) まで続く。
