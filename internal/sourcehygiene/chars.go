package sourcehygiene

// bidiControls is the one list of the bidirectional controls that are forbidden raw
// (app#501, Trojan Source). It lives here, not in a test file, so that a consumer
// outside this package can ask one question about both sets (Hidden, invisible.go).
// invisibleRanges deliberately does not hold these nine: the gate reports them once,
// by the bidi rule.
var bidiControls = map[rune]string{
	0x202A: "LEFT-TO-RIGHT EMBEDDING",
	0x202B: "RIGHT-TO-LEFT EMBEDDING",
	0x202C: "POP DIRECTIONAL FORMATTING",
	0x202D: "LEFT-TO-RIGHT OVERRIDE",
	0x202E: "RIGHT-TO-LEFT OVERRIDE",
	0x2066: "LEFT-TO-RIGHT ISOLATE",
	0x2067: "RIGHT-TO-LEFT ISOLATE",
	0x2068: "FIRST STRONG ISOLATE",
	0x2069: "POP DIRECTIONAL ISOLATE",
}
