# 51 — nimbus-desk Egress (調査 B)

モジュール `scenarios/ir-nimbus-desk/` の 2 本目の調査型の課題 (速い人向け)。`50-nimbus-desk-triage`
(調査 A) と**同じ事案・同じ保全の時点**の、通信の側の記録を読む。証拠の束は課題ごとに別で、
`mountDir` も別 (`/srv/ir/evidence-b`)。ADR-0056 D1 (b) で、2 つの課題の mount dir は等しくも入れ子にも
できず、束は (席, 課題) ごとの Secret `ctf-evidence-<cid>` に入る (D11)。だから共有せず、調査 B に要る
記録だけを持つ。

## 設問と答えの出どころ

| id | format | 席ごと | 答えの出どころ |
|---|---|---|---|
| `dest-host` | `name` (語彙 512) | 可 | `egress-gateway.log` で nimbus-desk の Pod の `verdict=deny` の `dst` (address) を得て、`cluster-dns.log` で同じ Pod の、`answer` がその address の行の `query` |
| `lookup-name` | `name` (語彙 512) | 可 | `falco-alerts.jsonl` の 3 件のうち Discovery に当たる段のアラートの宛先の address を得て、`cluster-dns.log` で `answer` がその address の行の `query` |

2 問とも席ごとの値で、固定の設問は無い。`lookup-name` は、以前の固定の `tactic-order` (`sequence`)
の置き換えである (ADR-0056 追補 26)。段と Tactic を対応づける学び (L3) は、`lookup-name` の答えを
特定する過程に残した: prompt は Tactic の名前だけを言い、どの段か (どのアラートか) は参加者が決める。
段を取り違えると、どの記録のどの address を突き合わせるかが決まらない。

2 つの設問の語彙は重ならない (`dest` = `<語>-<数>.example`、`peer` = `<語>-<数>.int.example`)。renderer は
slot の組 (答えと囮) の中でしか値を分けないので、語彙を分けて、設問をまたいだ値の衝突を防いでいる。
1 つの設問の答えから、もう 1 つの答えは決まらない (突き合わせる address が別の記録から来る)。

答えの値は、ここにも journey にも書かない。

設計の前提 (ADR-0056 追補 27): template は公開で、render は行を並べ替えないので、練習版では公開の
template から答えの行の位置が分かる。イベント版は原稿の構造を変える (B4 (2) が写しを、B18 が答えの
行の形の流用を拒否する)。

## 想定解 (手順)

```bash
cd /srv/ir/evidence-b
cat preservation-note.txt
# Q5
grep 'verdict=deny' egress-gateway.log | grep nimbus-desk      # 拒否された宛先の address
grep 'answer=203.0.113.77$' cluster-dns.log                    # その address を返した問い合わせ
# Q6
jq -r '[.time, .rule, .output_fields["fd.name"]] | @tsv' falco-alerts.jsonl
grep 'answer=192.0.2.1$' cluster-dns.log                       # Discovery の段の宛先を返した問い合わせ
```

## 手がかり 1 つだけで絞ったときに残る候補 (答えを含む件数)

`dest-host` の候補 = 束の中で、答えと同じ形の host 名。答え 1 + 囮 20。囮 20 のうち 10 は link preview
を proxy で取りに行った host、10 は確認 (DNS) だけで取りに行かなかった host (誰も ticket を開いていない)。
`lookup-name` の候補 = `*.int.example` の名前。答え 1 + 囮 20。囮は web service とほかの Pod が普段の
処理で引く cluster の中の名前。shell の起動 (17:14:07) から API server への接続 (17:15:32) までの間に
13 個 (うち 11 個は同じ Pod。その間の同じ Pod の最初と最後の問い合わせは囮)。答えは 192.0.2.1、囮の
answer は 192.0.2.2〜22 (隣の .2・.3 と、先頭の一致で紛れる .11〜.19 の 9 個を含む)。

手がかり 1 つずつ、prompt の条件を前提にした手がかり、自然な 2 つの組を数えた (答えを含む、答えと
同じ形の名前の件数)。`dest-host` の prompt の条件は「拒否された接続の宛先」(= 最初の拒否より前の
問い合わせ)、`lookup-name` の prompt の条件は「Discovery の段の、侵入者の問い合わせ」(段を
API server への接続のアラートと読んだとき、shell の起動から設定の読み取りまで)。

| 手がかり / 組 | `dest-host` | `lookup-name` |
|---|---|---|
| node / rule / process / port / type / rcode のどれか | 21 | 21 |
| Pod だけ | 21 | 17 |
| 時刻の窓だけ (17:00〜17:31) | 21 | 21 |
| 宛先の範囲だけ (203.0.113.0/24 / 192.0.2.0/24) | 21 | 21 |
| proxy の記録に無いことだけ | 11 | 21 |
| prompt の条件だけ | 18 | 17 |
| prompt + Pod | 18 | 13 |
| prompt + proxy に無い | 10 | 17 |
| Pod + answer の先頭の一致 (`answer=192.0.2.1` を `$` 無しで) | — | 10 |
| 近い順の 5 件 (最初の拒否の前 / 接続の前 / shell の後) | 答えを含まない | 答えを含まない |
| DNS の answer = 別の記録の宛先 (完全一致) | **1** (決め手) | **1** (決め手) |

起点ごと (固定の時刻の「後 / 前」。束にある起点 = 事案の始まり、shell の起動 17:14:07、API server
への接続 17:15:32、設定の読み取り 17:18:44、最初の拒否 17:23:40、保全 17:49:50):

| 起点 | `dest-host` 単独 / + proxy に無い | `lookup-name` 単独 / + Pod |
|---|---|---|
| 事案の始まり・最初の shell より後 | 21 / 11 | 21 / 17 |
| shell の起動 (17:14:07) より後 | 21 / 11 | 20 / 16 |
| API server への接続より後 | 18 / 11 | — (答えは前) |
| API server への接続より前 | — (答えは後) | 15 / 13 |
| shell の起動〜接続の間 | — | 14 / 12 |
| 設定の読み取りより後 | 16 / 11 | — (答えは前) |
| 設定の読み取りより前 | — (答えは後) | 18 / 14 |
| 最初の拒否より前 | 18 / 10 | 19 / 15 |
| 設定の読み取り〜最初の拒否の間 | 13 / 10 | — |
| 保全より前 | 21 / 11 | 21 / 17 |

どの起点でも 10 以上残る (`dest-host` の Pod、`lookup-name` の proxy は、すべての候補が同じなので
単独と同じ)。`dest-host` の答えと最初の拒否の間には、同じ形の問い合わせが 5 件ある。

10 件未満になるのは、どちらの設問も **DNS の答えと、別の記録の宛先の突き合わせ** (`answer` = 宛先、
address の完全一致) を使ったときだけで、これが正しい調べ方である。時刻の近さ (直前の 1 件) は、
どちらでも囮を指す。`dest-host` は gateway の拒否の `dst`、
`lookup-name` は Discovery の段のアラートの宛先と突き合わせる。どちらも、記録によって見え方が違う
(gateway とアラートには address だけ、DNS には名前もある) ことを使う。

囮だけが持つ書式の違いは作っていない: DNS の行は答えと囮で同じ key と同じ順、proxy の行の有無は
`dest-host` の囮の中でも半々、囮の proxy の行は proxy の記録の書式 (status 200 と 403 が混ざる)。

アラートは `tags` を持たない (50 の export も同じで、全部の行から外した。tags を出力に含めない設定の形)。
default の rule の tags には Tactic の名前が入るので、残すと「Tactic から段を決める」が grep 1 回で
済んでしまう。段は rule とアラートの中身 (何をしたか) から決める。

## 時刻 (調査 A と同じ世界。ADR-0056 追補 26 の B15・B16)

- `time.base` は 50 と同じ文字列 (2026-10-21T17:00:00Z)。この課題に席ごとの時刻の設問は無い。
- B15: template の literal の時刻は、すべて 50 の template の literal の時刻のどれか (共有の
  `egress-gateway.log`、アラート 17:14:07・17:15:32・17:18:44、保全の時刻、50 の記録と同じ秒に置いた
  DNS / proxy の行)。この束にだけある瞬間 (link preview の確認と取得、cluster の中の名前の問い合わせ、
  侵入者の問い合わせ) は、filler の slot `dns-*` / `px-*` で書く。filler の窓は、DNS の行の順と proxy の行の
  順を保ち、proxy の取得は同じ host の DNS の確認より後、侵入者の問い合わせは shell の起動 (17:14:07) と
  API server への接続 (17:15:32) の間、送信先の問い合わせは最初の拒否 (17:23:40) より前に収まる。
- B13・B16: 50 の答えの窓 [17:00:00, 17:10:00) には、この束の時刻を 1 つも置かない (literal も filler も。
  filler の窓は 17:10:05 以後)。50 の最初の shell の時刻 (席ごとの答え) は、この束に現れない。
- **イベント版で 50 の時刻をずらす (50 の `time.base` と template を同じだけ動かす) なら、この課題の
  `time.base` と template の literal の時刻も同じだけずらす。** 機械の検査は A7-x (B15) で入る。

## 調査 A との分離 (ADR-0056 追補 26 の B13・B14)

- この束には、調査 A の席ごとの答え (最初の shell の時刻、資格情報の file・まとめた file・調べた結果の
  file の path) を出さない。選んだアラートは、それらを含まない 3 件 (2 回目以後の shell、API server への
  接続、設定の file の読み取り)。調査 A の束には、この課題の答え (2 つの名前) を出さない (A の束に DNS の
  記録は無い)。
- 2 つの束の `egress-gateway.log` は byte で同じ内容で、slot の印を持たない (B14)。調査 A の束の
  gateway の記録は、拒否の行の `dst_name` が `-` (名前なし) なので、この課題の答えを導けない。共有の
  宣言 (`investigate.evidence.shares` と `investigate.evidence.timeline`) は、A7-x で catalog に key が
  入ってから、この課題の `falco-rule.yaml` に足す (今は load が未知の key を拒否する)。

## 解説

- L1・L2: アラートに出ない送信 (Falco は外向きの接続を記録していない) を、通信の記録から再構成する。
  拒否された通信には名前が無く、名前は DNS から取る。正常な処理 (link preview、cluster の中の名前の
  問い合わせ) が、同じ Pod から同じ形で出ているので、Pod だけ・時刻だけでは絞れない。
- L3: Tactic から段を決める。Discovery は、入り込んだ先に何があり、どこへ届くかを調べる段で、この事案
  では API server への接続がそれに当たる。段 5 (送信の試み) は Command and Control と Exfiltration の
  どちらにも読める (brief §4 の注)。
