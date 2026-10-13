package ingressparity

// ADR-0034 V12 / Hard Invariant I8's other premise: the scoreboard treats
// X-Auth-Request-Email as proof of identity (selfOrAdmin / isAdmin), so the only
// ways to reach it are ingress-nginx (after auth-policy rewrote the header), the
// collector, and falco. Any other source that can open a connection to the pod
// (a rule with no `from`, a selector that matches every namespace, an ipBlock, a
// second NetworkPolicy under another name) lets a workspace supply its own
// X-Auth-Request-Email. The check below is therefore a SET pin over the whole
// rendered chart, not a look at one named policy's matchLabels.
//
// Imported only from *_test.go files, like the rest of this package.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ScoreboardNetworkPolicyNames is the exact set of NetworkPolicy objects the
// scoreboard chart may render. A new NetworkPolicy is a new way in until a
// reviewer has seen it, so adding one must change this pin.
var ScoreboardNetworkPolicyNames = []string{"scoreboard-allow", "scoreboard-default-deny"}

// ScoreboardAllowedSources is the exact set of namespace labels the
// scoreboard-allow policy may admit.
var ScoreboardAllowedSources = []string{
	"app.kubernetes.io/name=collector",
	"kubernetes.io/metadata.name=falco",
	"kubernetes.io/metadata.name=ingress-nginx",
}

type npSelector struct {
	MatchLabels      map[string]string `yaml:"matchLabels"`
	MatchExpressions []yaml.Node       `yaml:"matchExpressions"`
}

type npPeer struct {
	NamespaceSelector *npSelector `yaml:"namespaceSelector"`
	PodSelector       *yaml.Node  `yaml:"podSelector"`
	IPBlock           *yaml.Node  `yaml:"ipBlock"`
}

type npObject struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		PolicyTypes []string `yaml:"policyTypes"`
		Ingress     []struct {
			From []npPeer `yaml:"from"`
		} `yaml:"ingress"`
	} `yaml:"spec"`
}

// CheckScoreboardNetworkPolicies takes the full `helm template charts/scoreboard`
// output and returns one violation per problem (empty = clean).
func CheckScoreboardNetworkPolicies(doc []byte) []string {
	var viol []string
	dec := yaml.NewDecoder(bytes.NewReader(doc))
	var names []string
	var allow, deny *npObject
	for {
		var o npObject
		if err := dec.Decode(&o); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return append(viol, fmt.Sprintf("parse helm output: %v", err))
		}
		if o.Kind != "NetworkPolicy" {
			continue
		}
		cp := o
		names = append(names, cp.Metadata.Name)
		switch cp.Metadata.Name {
		case "scoreboard-allow":
			allow = &cp
		case "scoreboard-default-deny":
			deny = &cp
		}
	}
	sort.Strings(names)
	if strings.Join(names, ",") != strings.Join(ScoreboardNetworkPolicyNames, ",") {
		viol = append(viol, fmt.Sprintf("scoreboard chart renders NetworkPolicy %v, want exactly %v (an unreviewed policy can add a source)", names, ScoreboardNetworkPolicyNames))
	}
	if allow == nil || deny == nil {
		// Extraction broken or a policy was renamed/removed: never read as clean.
		return append(viol, "scoreboard-allow and scoreboard-default-deny must both be present in the render")
	}
	if len(deny.Spec.Ingress) != 0 {
		viol = append(viol, "scoreboard-default-deny has ingress rules: it must admit nothing")
	}
	hasIngress := false
	for _, pt := range allow.Spec.PolicyTypes {
		if pt == "Ingress" {
			hasIngress = true
		}
	}
	if !hasIngress {
		viol = append(viol, "scoreboard-allow does not list Ingress in policyTypes")
	}

	var sources []string
	for i, rule := range allow.Spec.Ingress {
		if len(rule.From) == 0 {
			viol = append(viol, fmt.Sprintf("scoreboard-allow ingress rule %d has no `from`: that admits every source", i))
			continue
		}
		for j, f := range rule.From {
			switch {
			case f.NamespaceSelector == nil || f.PodSelector != nil || f.IPBlock != nil:
				viol = append(viol, fmt.Sprintf("scoreboard-allow rule %d from[%d] is not a plain namespaceSelector with matchLabels", i, j))
			case len(f.NamespaceSelector.MatchExpressions) != 0:
				viol = append(viol, fmt.Sprintf("scoreboard-allow rule %d from[%d] uses matchExpressions: the allowed sources are pinned as exact labels", i, j))
			case len(f.NamespaceSelector.MatchLabels) != 1:
				viol = append(viol, fmt.Sprintf("scoreboard-allow rule %d from[%d] namespaceSelector has %d matchLabels, want exactly 1 (0 = every namespace)", i, j, len(f.NamespaceSelector.MatchLabels)))
			default:
				for k, v := range f.NamespaceSelector.MatchLabels {
					sources = append(sources, k+"="+v)
				}
			}
		}
	}
	sort.Strings(sources)
	if strings.Join(sources, ",") != strings.Join(ScoreboardAllowedSources, ",") {
		viol = append(viol, fmt.Sprintf("scoreboard ingress sources = %v, want exactly %v (ADR-0034 D7: the header-completeness premise)", sources, ScoreboardAllowedSources))
	}
	return viol
}
