// Package contractmetrics holds ONE test (contract_test.go) and no code: it checks
// that every metric family the cross-repo contract table names exists from the start
// of its owning binary (ADR-0040). It is a package of its own, with nothing else in
// its test process, so the default registry it reads has not been moved by any other
// test (ADR-0040 C5).
package contractmetrics
