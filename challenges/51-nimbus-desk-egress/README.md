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
`lookup-name` の候補 = `*.int.example` の名前。答え 1 + 囮 14。囮は web service とほかの Pod が普段の
処理で引く cluster の中の名前で、9 個は Discovery の段 (17:14:07〜17:18:44) の中 (うち 6 個は同じ Pod。
API server への接続の直前の同じ Pod の問い合わせも囮)、
答えは 192.0.2.1、囮の answer は 192.0.2.2〜16 (隣の .2・.3 を含む。.11〜.16 は先頭の一致で紛れる)。

| 手がかり | `dest-host` | `lookup-name` | 理由 |
|---|---|---|---|
| node だけ | 21 | 15 | DNS と proxy の記録は node を持たない。すべて node-b の Pod |
| container / Pod だけ | 21 | 12 | DNS の client は Pod。囮の多くは同じ Pod の普段の問い合わせ |
| rule の種類だけ | 21 | 15 | 通信の記録には Falco の rule が無い |
| 時刻の窓だけ (17:00〜17:31) | 21 | 14 | 囮はほとんどこの窓の中。`dest-host` は最初の拒否の 20〜35 秒前、拒否と拒否の間、最後の拒否の直後の囮を含む |
| 宛先の種類だけ | 21 (203.0.113.0/24) | 15 (192.0.2.0/24) | どちらも文書用の範囲。答えの address の隣の囮を含む |
| port / type / rcode だけ | 21 | 15 | proxy 経由の囮も拒否された接続も 443。DNS の行はどれも A / NOERROR |
| process の名前だけ | 21 | 15 | DNS・proxy・gateway の記録は process を持たない |
| proxy の記録に無いことだけ | 11 | 15 | `lookup-name` の名前は 1 つも proxy を通らない |
| 段の時間帯だけ (Discovery) | — | 10 | Discovery の段の中に、ほかの Pod と同じ Pod の囮 9 |

2 つ組み合わせても残る例: `lookup-name` の「同じ Pod + Discovery の段」で 7 (回数の上限 5 を超える)。
「同じ Pod の、API server への接続の直前の問い合わせ」は囮を指す (時刻の近さでは決まらない)。
1 つで決まる手がかりは、どちらの設問も **DNS の答えと、別の記録の宛先の突き合わせ** (`answer` = 宛先、
address の完全一致) だけで、これが正しい調べ方である。`dest-host` は gateway の拒否の `dst`、
`lookup-name` は Discovery の段のアラートの宛先と突き合わせる。どちらも、記録によって見え方が違う
(gateway とアラートには address だけ、DNS には名前もある) ことを使う。

囮だけが持つ書式の違いは作っていない: DNS の行は答えと囮で同じ key と同じ順、proxy の行の有無は
`dest-host` の囮の中でも半々、囮の proxy の行は proxy の記録の書式 (status 200 と 403 が混ざる)。

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
