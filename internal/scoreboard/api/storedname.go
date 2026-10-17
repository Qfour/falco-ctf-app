package api

import "sort"

// StoredDisplayNameViolations returns, sorted, the seats whose STORED display
// name no longer passes the current display-name rule (validDisplayName).
//
// The rule is enforced when a name is written. A name saved before a tighter
// rule landed (app#331 / #381 added Unicode Cf and C1 controls) is neither
// re-checked at load time nor by any admin write, so it keeps being shown on the
// public board. The scoreboard calls this once at boot to count those rows
// (app#403). It only reads: it never rewrites a stored name, and it returns seats,
// never the names, so a caller cannot log a name by accident.
//
// An empty stored name is skipped: Store.DisplayName already renders it as the
// seat, so it displays nothing of its own.
func StoredDisplayNameViolations(names map[string]string) []string {
	var seats []string
	for seat, name := range names {
		if name == "" {
			continue
		}
		if _, err := validDisplayName(name); err != nil {
			seats = append(seats, seat)
		}
	}
	sort.Strings(seats)
	return seats
}
