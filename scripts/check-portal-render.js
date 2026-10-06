// Harness for scripts/check-portal-render.sh (concatenated after the extracted
// portal functions and run under jsc). Not shipped; not a page script.
var CLAIMS = ['この attempt はクリーンです', 'このまま提出できます',
  'クリーンな attempt を確認', '禁止ルールが一度も発火していなければ自動的にクリアされます'];
var XSS = '<img src=x onerror=alert(1)>';
var fails = 0, total = 0, rows = [];
function check(ok, msg) { total++; if (!ok) { fails++; print('FAIL: ' + msg); } }
function has(h, s) { return h.indexOf(s) >= 0; }

['solved', 'current', 'locked', ''].forEach(function (status) {
  [false, true].forEach(function (dirty) {
    [false, true].forEach(function (requireExfil) {
      [false, true].forEach(function (exfilReceived) {
        var det = { id: '10-final-exfil', status: status, dirty: dirty, requireExfil: requireExfil,
          exfilReceived: exfilReceived, dirtyRules: dirty ? [XSS, 'Rule B'] : [] };
        var h = evadeSection(det);
        var tag = 'status=' + (status || '(none)') + ' dirty=' + dirty + ' exfil=' + requireExfil + '/' + exfilReceived;
        var pending = status !== 'current' && !dirty;
        var found = CLAIMS.filter(function (c) { return has(h, c); });
        var hasNeutral = has(h, '検知状態: 未評価') || has(h, '検知状態: クリア済み');
        var hasDirty = has(h, '検知されています') && has(h, 'id="pane-journey-reset-dirty"');
        var hasClean = has(h, 'この attempt はクリーンです') && has(h, 'このまま提出できます');
        if (pending) {                                                  // (a)
          check(found.length === 0, tag + ': non-current/non-dirty shows ' + JSON.stringify(found));
          check(hasNeutral && !hasDirty, tag + ': neutral card missing');
          check(has(h, status === 'solved' ? '検知状態: クリア済み' : '検知状態: 未評価'), tag + ': wrong neutral heading');
          if (status !== 'solved') check(has(h, 'この課題はまだ進行位置ではありません。'), tag + ': neutral body missing');
        }
        if (dirty) {                                                    // (b)
          check(hasDirty, tag + ': dirty card/reset button missing');
          check(!hasClean && !hasNeutral, tag + ': dirty must not show clean/neutral card');
          check(!has(h, '<img') && has(h, '&lt;img src=x onerror=alert(1)&gt;'), tag + ': dirtyRules not escaped'); // (d)
        }
        if (status === 'current' && !dirty) {                           // (c)
          check(hasClean && !hasNeutral, tag + ': current clean card changed');
          if (requireExfil) {
            check(has(h, '禁止ルールが一度も発火していなければ自動的にクリアされます'), tag + ': current auto-clear copy missing');
            check(has(h, 'クリーンな attempt を確認') === exfilReceived, tag + ': current exfil row wrong');
          }
        }
        rows.push(tag + ' -> ' + (pending ? 'neutral' : dirty ? 'dirty' : 'clean') +
          ' claims=' + found.length + (hasNeutral ? ' neutral' : '') + (hasDirty ? ' dirtyCard' : ''));
      });
    });
  });
});
rows.forEach(function (r) { print(r); });
print('checks: ' + total + ', failures: ' + fails);
if (fails) throw new Error('check-portal-render: ' + fails + ' failure(s)');
print('OK');
