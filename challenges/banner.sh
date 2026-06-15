#!/bin/sh
# Login orientation, printed by /etc/profile. The event domain comes from
# $FALCO_CTF_DNS_SUFFIX (set by the ctf-user chart from dnsSuffix), so the same
# image works for local (.nip.io) and prod (ctf-event.dev). Left-aligned so a
# variable-length domain doesn't break a fixed box border.
SUF="${FALCO_CTF_DNS_SUFFIX:-ctf-event.dev}"
cat <<EOF

═══ Falco CTF ════════════════════════════════════════
 課題の説明・ヒントは ドキュメントサイト で:
     https://docs.${SUF}/


 フラグ提出（evade 課題のみ。trigger は Falco 発火で自動 solve）:
     source /opt/ctf/submit.sh && submit <mission-id> '<flag>'


 スコアボードの表示名を変更（任意・いつでも何度でも）:
     source /opt/ctf/setname.sh && setname 'あなたの名前'
════════════════════════════════════════════════════════════════════
EOF
