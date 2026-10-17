package api

import "sort"

// StoredDisplayNameViolations returns, sorted, the seats whose STORED display
// name is not what the CURRENT write path would store for it.
//
// The rule is enforced when a name is written. A name saved before a tighter
// rule landed (app#331 / #381 added Unicode Cf and C1 controls) is neither
// re-checked at load time nor by any admin write, so it keeps being shown on the
// public board. The scoreboard calls this once at boot to count those rows
// (app#403). It only reads: it never rewrites a stored name, and it returns seats,
// never the names, so a caller cannot log a name by accident.
//
// "Not what the write path would store" is validDisplayName(name) failing OR
// returning a different string: validDisplayName trims (strings.TrimSpace, which
// includes U+0085 NEL and LF), so a stored value with such an edge passes the
// rule on its trimmed form yet is not a value the write path could have produced
// (and renders with the edge in place). Comparing the result to the stored value
// reports it. The seed rows of testdata/display-name-parity/cases.yaml drive the
// test, so the rule itself lives in that one table.
//
// An empty stored name is skipped: Store.DisplayName already renders it as the
// seat, so it displays nothing of its own.
func StoredDisplayNameViolations(names map[string]string) []string {
	var seats []string
	for seat, name := range names {
		if name == "" {
			continue
		}
		if n, err := validDisplayName(name); err != nil || n != name {
			seats = append(seats, seat)
		}
	}
	sort.Strings(seats)
	return seats
}
