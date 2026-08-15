package view

import (
	"encoding/json"
	"html/template"
	"net/http"
)

// portalData is the template payload for templates/portal.html. Both fields
// are DISPLAY-ONLY hints the client-side shell uses to decide which tab to
// default to / show and which identity to pre-fill into the Journey/Me
// panes — see the security note below and the matching note inside
// templates/portal.html's injected <script> block.
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
}

// renderPortal writes the GET /portal shell to w. isAdmin/deriveUser may be
// nil (matching view.Handler's nil-safety for tests); a nil isAdmin renders
// as participant, a nil deriveUser renders "" (no username hint).
//
// SECURITY (P23-1 invariants — see task spec / .claude/rules for the full
// text; summarised here for anyone editing this function):
//
//  1. Authorization stays entirely server-side, in the API layer
//     (internal/scoreboard/api: isAdmin / selfOrAdmin / selfOrAdminWrite).
//     This function decides NOTHING about who may read/write what — it only
//     decides what two harmless display hints (role label, username
//     pre-fill) get embedded in HTML the browser already received. Tampering
//     with window.__PORTAL_ROLE__/__PORTAL_USER__ in devtools cannot grant a
//     participant admin data: every fetch the panes make is re-gated by the
//     API using the request's own X-Auth-Request-Email header, which the
//     browser cannot forge (see api.selfOrAdmin's doc for why).
//  2. No admin-only DATA is ever embedded in this HTML (for admin or
//     participant). The only per-viewer datum here is a static "admin" or
//     "participant" string plus a username slug derived from the viewer's
//     OWN email — never leaderboard/solve/event data. The Scoreboard pane's
//     actual data comes from a client-side fetch('/api/state') that 403s a
//     non-admin exactly as it does on the legacy GET / today.
//  3. The portal is served to ANY authenticated caller (isAdmin==false is
//     participant, not denied) — unlike GET / (the legacy operator
//     dashboard), which stays admin-only. This is intentional: the portal
//     shell carries no admin data, so there is nothing to protect by gating
//     the page itself; gating stays where the data is (the API).
//  4. All dynamic values pass through html/template with template.JS on
//     pre-marshalled JSON (never raw string interpolation), so even a
//     future edit that feeds a weirder value through RoleJSON/UserJSON gets
//     template auto-escaping as a safety net, not just discipline.
func renderPortal(w http.ResponseWriter, r *http.Request, isAdmin func(*http.Request) bool, deriveUser func(*http.Request) string) error {
	role := "participant"
	if isAdmin != nil && isAdmin(r) {
		role = "admin"
	}
	user := ""
	if deriveUser != nil {
		user = deriveUser(r)
	}

	roleJSON, err := json.Marshal(role)
	if err != nil {
		return err
	}
	userJSON, err := json.Marshal(user)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return portalTmpl.Execute(w, portalData{
		RoleJSON: template.JS(roleJSON),
		UserJSON: template.JS(userJSON),
	})
}
