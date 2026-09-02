# CTF Company — 解説 (全 10 ミッション)

正準 01→10 の順に「実際の攻撃キャンペーン → Falco がどう捕まえたか → 本番防御」
で振り返る。`REFERENCE.md §3` に各ルールの実 condition。

2h リハーサル edition では **05 / 07 / 09 / 10 は運営が実演** (参加者は多くが
未着手)。それ以外はハンズオン済みの recap。これで全員が 01→10 をやり切る。

キルチェーン全体像:
```
偵察 → 資格情報アクセス →(回避)→ 資格情報収集 →(回避)→ Web RCE → 永続化 → C2 → 隠蔽 → exfil(boss)
 01        02            03        04          05        06       07      08     09        10
```

---

## 01 — 偵察 `Contact K8S API Server From Container` (trigger ★1)
- **実案件**: TeamTNT / Hildegard の K8s API 偵察。SA を持たない pod の API connect は異常。
- **Falco**: `evt.type=connect and container and k8s_api_server and not k8s_containers ...`。
- **防御**: `automountServiceAccountToken: false`、API への egress 制限、最小権限。

## 02 — 資格情報アクセス `Read sensitive file untrusted` (trigger ★1)
- **実案件**: `/etc/shadow`・クラウド資格情報の読取 (MITRE T1003)。
- **Falco**: `open_read and sensitive_files and not proc.name in (許可リスト)`。判定は `fd.name`。
- **防御**: 許可プロセスを絞る / 読取の監査 / 機密を pod に置かない。

## 03 — 検知回避 (02 と同ルールを回避) (evade ★2)
- **学び**: `fd.name` は「開く時に渡した path」。02 と同じ `Read sensitive file
  untrusted` は `/etc/shadow` 専用ではなく、資格情報退避用の vault ファイル
  (`/opt/nimbus/vault/creds.recover`) にも効いている。
  `/proc/self/root/opt/nimbus/vault/creds.recover` なら監視対象の path 文字列に
  当たらず発火しない。**同じルール・別ファイル・別 path**。
- **防御**: inode (`fd.ino`) ベースのルール、`/proc/*/root` 経由読取の別ルール、重ね掛け。

## 04 — 資格情報収集 `Search Private Keys or Passwords` (trigger ★2)
- **実案件**: TeamTNT の SSH 鍵 / credential 横断収集 (T1552)。
- **Falco**: `spawned_process and ((grep_commands and private_key_or_password) or (find ... id_rsa ...))`。
  判定は `proc.cmdline` 文字列。
- **防御**: 鍵を pod に置かない / cmdline 監査 / 横展開を NetworkPolicy で抑止。

## 05 — 検知回避 (04 を回避) (evade ★3) ★運営実演★
- **学び**: cmdline に keyword を出さない。`cat < /root/.ssh/id_rsa`(入力リダイレクト)なら
  exec された cmdline は `cat` のみ → 発火しない。環境変数経由・文字列分割も同系。
- **防御**: cmdline だけに頼らず、開いた fd の path / 中身パターンも併用。

## 06 — Web RCE `Run shell untrusted` (trigger ★3)
- **実案件**: Log4Shell (CVE-2021-44228) 等。web プロセスが `Runtime.exec()` で shell 起動。
- **Falco**: `spawned_process and shell_procs and protected_shell_spawner and not proc.pname in (...)`。
  判定は**親 comm (`proc.pname`)**。
- **防御**: web を distroless/no-shell、`readOnlyRootFilesystem`、RCE 自体を塞ぐ。

## 07 — 永続化 `Drop and execute new binary in container` (trigger ★3) ★運営実演★
- **実案件**: TeamTNT 等の malware dropper — runtime に置いた binary を実行。
- **Falco**: `spawned_process and container and proc.is_exe_upper_layer=true`。
  overlayfs の upper layer (後から置かれた層) からの exec を検知。
- **防御**: イメージを read-only / 改ざん検知 / 既知 binary のみ許可。

## 08 — C2 `Redirect STDOUT/STDIN to Network Connection` (trigger ★4)
- **実案件**: Kinsing 等の reverse shell C2 (T1059)。socket を stdin/stdout に繋ぐ。
- **Falco**: `dup and container and evt.rawres in (0,1,2) and fd.type in (ipv4,ipv6)`。
- **防御**: egress NetworkPolicy で C2 通信を遮断、不審 outbound 検知。

## 09 — 隠蔽 `Create Hardlink Over Sensitive Files` (trigger ★4) ★運営実演★
- **実案件**: sensitive file への hardlink で別 path を作り、後で静かに読む/隠す手口。
- **Falco**: `create_hardlink and (evt.arg.oldpath in (sensitive_file_names))`。
- **防御**: link syscall の監査、sensitive file の権限/不変属性 (immutable)。

## 10 — The Final Exfil (boss, evade ★5) ★運営実演★
- **集大成**: 7 つの禁止ルールを**同時に回避**しながら flag を exfil。
  03 (別 path)・05 (cmdline 回避)・06/07 の逆 (別名/既存 binary)・08 回避 (curl で転送) 等を**全部**使う。
- **学び**: 単一回避は易しいが、複合制約は重い = 防御側はルールを重ねるほど攻撃者の手数が指数的に増える。

---

## 締め
- **検知は安く速いが、文字列/単一条件には回避余地がある** → 防御はルールを重ね、
  inode/fd ベースや egress 制限など多層で攻撃コストを上げる。
- これが Falco のランタイム検知の勘所。本番ではこの 01→10 を時間いっぱいハンズオンする。
