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
| `tactic-order` | `sequence` (10 から 5) | 不可 | 固定: execution → discovery → credential-access → collection → c2-exfiltration |

`tactic-order` の答えは固定で、練習版 (公開) で分かる。`dest-host` (席ごと) に正解しないと solve に
ならない (ADR-0056 D1)。答えの値は、ここにも journey にも書かない。

## 想定解 (手順)

```bash
cd /srv/ir/evidence-b
cat preservation-note.txt
grep 'verdict=deny' egress-gateway.log | grep nimbus-desk      # 拒否された宛先の address
grep 'pod=desk-prod/nimbus-desk' cluster-dns.log               # 同じ Pod の問い合わせ
grep 'answer=203.0.113.77$' cluster-dns.log                    # その address を返した問い合わせ
grep -c "host=<上の query の値> " egress-proxy.log              # 0 = link preview ではない
```

## 手がかり 1 つだけで絞ったときに残る候補 (`dest-host`、答えを含む件数)

候補 = 束の中で、答えと同じ形の host 名 (語彙の名前)。

| 手がかり | 残る件数 | 理由 |
|---|---|---|
| node だけ | 11 | DNS と proxy の記録は node を持たない。すべて node-b の Pod |
| container / Pod だけ | 11 (+ 形の違う正常な名前 5) | DNS の client は Pod。囮 10 は同じ Pod の link preview の問い合わせ |
| rule の種類だけ | 11 | 通信の記録には Falco の rule が無い (Falco はこの接続を記録していない) |
| 時刻の窓だけ (17:00〜17:31) | 11 | 囮 10 はすべてこの窓の中。最初の拒否の 42 秒前と 41 秒後の囮を含む |
| 宛先の種類だけ (外部) | 11 | すべて 203.0.113.0/24 (文書用の範囲)。拒否の宛先の近くの address の囮を含む |
| port だけ | 11 | proxy 経由の囮も拒否された接続も 443 |
| process の名前だけ | 11 | DNS・proxy・gateway の記録は process を持たない |

1 つで決まる手がかりは 2 つで、どちらも正しい調べ方である:

- **DNS の答えと拒否された宛先の突き合わせ** (`answer` = `dst`)。接続の時点で拒否された通信には名前が
  残らない (`dst_name=-`)。名前は、その直前に同じ Pod が引いた DNS の答えから取る、が防御側の定石。
- **proxy の記録に無いこと**。web service の link preview は「DNS で確かめてから proxy で取る」ので、
  囮は DNS と proxy の両方に現れる。答えは DNS だけに現れ、gateway に直接向かって拒否された
  (brief の「記録によって見え方が違う」)。

囮だけが持つ書式の違いは作っていない: DNS の行は答えと囮で同じ key と同じ順、囮の proxy の行は
proxy の記録の書式 (status 200 と 403 が混ざる)。

## 時刻 (調査 A と同じ世界)

- この課題に席ごとの時刻は無い (`edition.yaml` に `time` が無い)。時刻はすべて固定の文字列で、
  調査 A (50) の練習版の固定の時刻と一致させている: shell の木のアラート 17:14:07・17:15:32・
  17:18:44、拒否 17:23:40・17:23:55・17:24:11、DNS の問い合わせ 17:23:38 (拒否の 2 秒前)。
- 調査 A の席ごとの時刻 (最初の shell、窓 17:00:00〜17:09:59) は、この束に出さない
  (`falco-alerts.jsonl` は 17:14:07 以後の選んだアラートだけ)。
- **イベント版で調査 A の時刻をずらす (A の `time.base` と template を同じだけ動かす) なら、この課題の
  template の時刻も同じだけずらす。** 機械の検査は無い。

## 調査 A との分離 (ADR-0056 D1 (ii))

- この束には、調査 A の席ごとの答え (最初の shell の時刻、資格情報の file の path、まとめた file の path)
  を出さない。選んだアラートは、それらを含まない 3 件 (2 回目以後の shell、API server への接続、
  設定の file の読み取り)。
- 調査 A の束の gateway の記録は、拒否の行の `dst_name` が `-` (名前なし) なので、この課題の答えを
  導けない。2 つの束の `egress-gateway.log` は同じ内容。

## 解説

- L1・L2: アラートに出ない送信 (Falco は外向きの接続を記録していない) を、通信の記録から再構成する。
  拒否された通信には名前が無く、名前は DNS から取る。正常な処理 (link preview) の問い合わせが、
  同じ Pod から同じ形で出ているので、Pod だけ・時刻だけでは絞れない。
- L3: 段階に Tactic を当てる。段 5 は Command and Control と Exfiltration のどちらにも読めるので、1 つの
  ラベル `c2-exfiltration` にしてある (brief §4 の注)。
