package view

import (
	"encoding/json"
	"html/template"
	"net/http"
)

// portalData is the template payload for templates/portal.html. All fields
// are DISPLAY-ONLY hints the client-side shell uses to decide which tab to
// default to / show, which identity to pre-fill into the Journey/Me panes,
// and (P23-4) which iframe src the Terminal pane renders — see the security
// note below and the matching note inside templates/portal.html's injected
// <script> block.
type portalData struct {
	// RoleJSON is `"admin"` or `"participant"`, pre-marshalled to JSON (and
	// wrapped in template.JS so html/template treats it as a trusted JS
	// expression rather than escaping it as a string literal need be). It
	// drives ONLY whether the shell shows/hides the Scoreboard tab
	// (defense-in-depth) — see api.Handler.state, which independently 403s a
	// non-admin regardless of what this value says.
	RoleJSON template.JS
	// UserJSON is the derived username (api.DeriveUsername) or "" when it
	// could not be determined, pre-marshalled to JSON. It pre-fills the
	// Journey/Me panes' identity so a participant does not have to type
	// their own username — but every API call those panes make
	// independently re-derives + re-checks the SAME X-Auth-Request-Email
	// header server-side (selfOrAdmin / selfOrAdminWrite), so this value
	// cannot be used to widen access even if tampered with client-side.
	UserJSON template.JS
	// TtydURLJSON (P23-4) is the caller's OWN ttyd origin
	// (`https://<derived-username>.<ttydSuffix>`), pre-marshalled to JSON, or
	// "" when it could not be computed (no derived username, or the
	// PORTAL_TTYD_SUFFIX deploy-time env unset — see renderPortal/ttydURLFor
	// below). The Terminal pane's <iframe src> uses this value directly; ""
	// makes the client render the fail-safe "not configured" placeholder
	// instead of an iframe (see templates/portal.html).
	//
	// SECURITY: built ENTIRELY from server-side inputs — the same
	// DeriveUsername(r) result already trusted for UserJSON, plus a
	// deploy-time env, NEVER from any client-supplied header/query/param. A
	// participant cannot make their own portal page iframe someone ELSE's
	// ttyd by tampering with the request: there is no request input this
	// function reads to pick the hostname other than their own authenticated
	// identity. Per-user isolation (I8) is additionally enforced
	// independently at the network layer regardless of this value — the
	// ttyd-proxy's Ingress requires auth-policy's `/check?host=<user>`
	// subrequest, which re-derives identity from the iframe's OWN
	// cookie/Origin and 403s a mismatch — so even a manually-edited iframe
	// src pointed at another user's host still 403s. This field only ever
	// narrows a caller to their OWN workspace; it cannot widen anything.
	TtydURLJSON template.JS
}

// ttydURLFor builds the caller's own ttyd origin from their derived username
// and the deploy-time PORTAL_TTYD_SUFFIX, matching the
// `https://<username>.<dnsSuffix>` host pattern charts/ctf-user's
// values.yaml (ingress.host) already uses for the per-user ttyd Ingress.
// Returns "" (fail-safe: no iframe) when either input is empty.
//
// suffix is intentionally the ONLY caller-supplied piece of the resulting
// URL that isn't the request's own derived identity — it is a deploy-time
// constant (env var wired in cmd/scoreboard/main.go), never read from the
// request, so it cannot be used to redirect a participant's iframe
// off-target.
func ttydURLFor(user, suffix string) string {
	if user == "" || suffix == "" {
		return ""
	}
	return "https://" + user + "." + suffix
}

// renderPortal writes the GET /portal shell to w. isAdmin/deriveUser may be
// nil (matching view.Handler's nil-safety for tests); a nil isAdmin renders
// as participant, a nil deriveUser renders "" (no username hint, which also
// yields "" for the ttyd URL below). ttydSuffix is the PORTAL_TTYD_SUFFIX
// deploy-time value (may be "" — see cmd/scoreboard/main.go).
//
// SECURITY (P23-1 invariants — see task spec / .claude/rules for the full
// text; summarised here for anyone editing this function):
//
//  1. Authorization stays entirely server-side, in the API layer
//     (internal/scoreboard/api: isAdmin / selfOrAdmin / selfOrAdminWrite).
//     This function decides NOTHING about who may read/write what — it only
//     decides what a handful of harmless display hints (role label,
//     username pre-fill, own-ttyd URL) get embedded in HTML the browser
//     already received. Tampering with window.__PORTAL_ROLE__/
//     __PORTAL_USER__/__PORTAL_TTYD_URL__ in devtools cannot grant a
//     participant admin data or another user's workspace: every fetch the
//     panes make is re-gated by the API using the request's own
//     X-Auth-Request-Email header, which the browser cannot forge (see
//     api.selfOrAdmin's doc for why), and the ttyd iframe target is
//     independently re-checked by auth-policy's per-host `/check` (I8) no
//     matter what src ends up in the DOM.
//  2. No admin-only DATA is ever embedded in this HTML (for admin or
//     participant). The only per-viewer data here are a static "admin" or
//     "participant" string, a username slug, and (P23-4) that SAME
//     username's own ttyd URL — never leaderboard/solve/event data or
//     another user's identifiers. The Scoreboard pane's actual data comes
//     from a client-side fetch('/api/state') that 403s a non-admin exactly
//     as it does on the legacy GET / today.
//  3. The portal is served to ANY authenticated caller (isAdmin==false is
//     participant, not denied) — unlike GET / (the legacy operator
//     dashboard), which stays admin-only. This is intentional: the portal
//     shell carries no admin data, so there is nothing to protect by gating
//     the page itself; gating stays where the data is (the API).
//  4. All dynamic values pass through html/template with template.JS on
//     pre-marshalled JSON (never raw string interpolation), so even a
//     future edit that feeds a weirder value through RoleJSON/UserJSON/
//     TtydURLJSON gets template auto-escaping as a safety net, not just
//     discipline.
func renderPortal(w http.ResponseWriter, r *http.Request, isAdmin func(*http.Request) bool, deriveUser func(*http.Request) string, ttydSuffix string) error {
	role := "participant"
	if isAdmin != nil && isAdmin(r) {
		role = "admin"
	}
	user := ""
	if deriveUser != nil {
		user = deriveUser(r)
	}
	ttydURL := ttydURLFor(user, ttydSuffix)

	roleJSON, err := json.Marshal(role)
	if err != nil {
		return err
	}
	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}
	ttydURLJSON, err := json.Marshal(ttydURL)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return portalTmpl.Execute(w, portalData{
		RoleJSON:    template.JS(roleJSON),
		UserJSON:    template.JS(userJSON),
		TtydURLJSON: template.JS(ttydURLJSON),
	})
}
