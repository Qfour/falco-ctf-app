#!/bin/sh
# Login orientation, printed by /etc/profile. Challenge briefing / hints /
# flag submission all happen in the Story tab (portal), not here — this
# banner is intentionally minimal (display-name change only).
cat <<EOF

═══ Falco CTF ════════════════════════════════════════
 スコアボードの表示名を変更（任意・いつでも何度でも）:
     source /opt/ctf/setname.sh && setname 'あなたの名前'
════════════════════════════════════════════════════════════════════
EOF
