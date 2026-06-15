// Operator-controlled hints. Release state lives in the scoreboard and is
// served same-origin via the docs nginx (/api/hints proxied to the scoreboard
// Service). Participants poll and see a hint only once an admin releases it;
// admin pages (docs-admin, .ctf-hint--admin) render a release/revoke button.
(function () {
  var POLL_MS = 15000;
  var released = {}; // mission -> [hintIdx]

  function isOn(mission, idx) {
    return !!(released[mission] && released[mission].indexOf(idx) !== -1);
  }

  function bodyEls(hint) {
    return Array.prototype.slice.call(hint.children).filter(function (el) {
      return el !== hint._title && el !== hint._ctl;
    });
  }

  function setup(hint) {
    if (hint._ready) return;
    hint._ready = true;
    hint._title = hint.children[0] || null;
    hint._ctl = document.createElement("div");
    hint._ctl.className = "ctf-hint-ctl";
    if (hint.classList.contains("ctf-hint--admin")) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "ctf-hint-release md-button";
      var mission = hint.getAttribute("data-mission");
      var idx = parseInt(hint.getAttribute("data-hint") || "0", 10);
      btn.addEventListener("click", function () {
        btn.disabled = true;
        fetch("/api/admin/hints", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "include",
          body: JSON.stringify({ mission: mission, hint: idx, released: !isOn(mission, idx) })
        })
          .then(function (r) { return r.json(); })
          .then(function () { return refresh(); })
          .catch(function () {})
          .then(function () { btn.disabled = false; });
      });
      hint._btn = btn;
      hint._ctl.appendChild(btn);
    }
    hint.appendChild(hint._ctl);
  }

  function render(hint) {
    var mission = hint.getAttribute("data-mission");
    var idx = parseInt(hint.getAttribute("data-hint") || "0", 10);
    var on = isOn(mission, idx);
    var body = bodyEls(hint);
    if (hint._btn) { // admin: always show body, button reflects state
      body.forEach(function (el) { el.style.display = ""; });
      hint._btn.textContent = on ? "参加者に開放中 — 取り消す" : "参加者に開放する";
      hint.classList.toggle("ctf-hint--released", on);
      return;
    }
    body.forEach(function (el) { el.style.display = on ? "" : "none"; });
    hint._ctl.textContent = on ? "" : "🔒 このヒントはまだ開放されていません(運営の操作待ち)";
    hint.classList.toggle("ctf-hint--unlocked", on);
  }

  function apply() {
    document.querySelectorAll(".ctf-hint").forEach(function (hint) { setup(hint); render(hint); });
  }

  function refresh() {
    return fetch("/api/hints", { credentials: "include" })
      .then(function (r) { return r.json(); })
      .then(function (data) { released = data.released || {}; apply(); })
      .catch(function () { apply(); });
  }

  function init() {
    if (!document.querySelector(".ctf-hint")) return;
    refresh();
    if (!window._ctfHintPoll) window._ctfHintPoll = setInterval(refresh, POLL_MS);
  }

  if (document.readyState !== "loading") init();
  else document.addEventListener("DOMContentLoaded", init);
  if (window.document$) window.document$.subscribe(init); // Material instant nav
})();
