#!/bin/sh
# Login orientation, printed by /etc/profile. The event domain comes from
# $FALCO_CTF_DNS_SUFFIX (set by the ctf-user chart from dnsSuffix), so the same
# image works for local (.nip.io) and prod (ctf-event.dev). Left-aligned so a
# variable-length domain doesn't break a fixed box border.
SUF="${FALCO_CTF_DNS_SUFFIX:-ctf-event.dev}"
cat <<EOF

═══ Operation NimbusBreach ════════════════════════════════════════
 課題の説明・ヒント・PDF は ドキュメントサイト で:
     https://docs.${SUF}/
 スコアボード(進捗):
     https://scoreboard.${SUF}/

 ここ(ワークスペース)は手を動かす環境です。各課題の手順・ヒントは
 上のドキュメントサイトを参照してください。

 フラグ提出（evade 課題のみ。trigger は Falco 発火で自動 solve）:
     source /opt/ctf/submit.sh && submit <mission-id> '<flag>'
   または answers.yaml に記入して一括提出:
     vi /opt/ctf/answers.yaml   →   sh /opt/ctf/submit-yaml.sh

 スコアボードの表示名を変更（任意・いつでも何度でも）:
     source /opt/ctf/setname.sh && setname 'あなたの名前'
════════════════════════════════════════════════════════════════════
EOF
