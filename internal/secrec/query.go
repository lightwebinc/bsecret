package secrec

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Class is one lookup question class of ls_bsecret (docs/spec.md section
// 10.2).
type Class struct {
	Name    string
	Members []string // sorted
	Free    bool
	Limit   int // most outputs one answer holds
}

// Classes is every class this version defines. A question carries exactly
// the members of one of them. No priced class is a superset of a free one:
// the priced classes carry history or audit, which no free class carries,
// and lack org.
var Classes = []Class{
	{"vault", []string{"crypt", "org", "vault"}, true, 8},
	{"vault-seq", []string{"crypt", "org", "seq", "vault"}, true, 8},
	{"vaults", []string{"crypt", "vaultsOf"}, true, 64},
	{"vaults-after", []string{"after", "crypt", "vaultsOf"}, true, 64},
	{"secret", []string{"crypt", "org", "secret", "vault"}, true, 8},
	{"version", []string{"crypt", "org", "secret", "vault", "version"}, true, 8},
	{"pending", []string{"crypt", "org", "pending", "vault"}, true, 8},
	{"secrets", []string{"crypt", "org", "secretsOf"}, true, 16},
	{"secrets-after", []string{"after", "crypt", "org", "secretsOf"}, true, 16},
	{"label", []string{"crypt", "label", "org", "vault"}, true, 16},
	{"label-after", []string{"after", "crypt", "label", "org", "vault"}, true, 16},
	{"sweep", []string{"crypt", "spent"}, true, 8},
	{"history", []string{"crypt", "history", "secret", "vault"}, false, 16},
	{"history-after", []string{"after", "crypt", "history", "secret", "vault"}, false, 16},
	{"audit", []string{"audit", "crypt", "vault"}, false, 64},
	{"audit-after", []string{"after", "audit", "crypt", "vault"}, false, 64},
}

// Question is a validated question: its class and its members.
type Question struct {
	Class   Class
	Members map[string]string
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func checkKeyHex(s string) error {
	if !isLowerHex(s, 66) {
		return ErrQuery
	}
	b, _ := hex.DecodeString(s)
	if CheckOrgKey(b) != nil {
		return ErrQuery
	}
	return nil
}

// checkDecimal accepts a decimal integer from lo to hi with no sign and no
// leading zero.
func checkDecimal(s string, lo, hi uint64) error {
	if s == "" || len(s) > 16 || (len(s) > 1 && s[0] == '0') {
		return ErrQuery
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return ErrQuery
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n < lo || n > hi {
		return ErrQuery
	}
	return nil
}

// checkOutpoint accepts BRC-100's OutpointString: a display-order txid, a
// dot, and the output index in decimal with no leading zero.
func checkOutpoint(s string) error {
	txid, vout, ok := strings.Cut(s, ".")
	if !ok || !isLowerHex(txid, 64) {
		return ErrQuery
	}
	return checkDecimal(vout, 0, MaxEpoch)
}

func hex32(v string) error {
	if !isLowerHex(v, 64) {
		return ErrQuery
	}
	return nil
}

// checkMember applies one member's value rule.
func checkMember(class, name, v string) error {
	switch name {
	case "crypt":
		if CheckCrypt(v) != nil {
			return ErrQuery
		}
		return nil
	case "org", "vaultsOf", "history", "audit":
		return checkKeyHex(v)
	case "vault", "secretsOf", "secret", "pending":
		return hex32(v)
	case "label":
		if CheckLabel(v) != nil {
			return ErrQuery
		}
		return nil
	case "seq":
		return checkDecimal(v, 0, MaxSafe)
	case "version":
		return checkDecimal(v, 1, MaxSafe)
	case "spent":
		return checkOutpoint(v)
	case "after":
		switch class {
		case "vaults-after", "secrets-after", "label-after":
			return hex32(v)
		case "history-after":
			return checkDecimal(v, 1, MaxSafe)
		case "audit-after":
			return checkDecimal(v, 0, MaxSafe)
		}
		return ErrQuery
	}
	return ErrQuery
}

// ParseQuery validates a BRC-24 query object as parsed: a JSON object whose
// members are all strings (a member given twice takes its last value, as
// JSON parsers do), whose member set is exactly one class's, and whose
// values meet their rules. Anything else is refused, never answered empty.
func ParseQuery(raw []byte) (*Question, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, fmt.Errorf("%w: not a JSON object", ErrQuery)
	}
	vals := make(map[string]string, len(m))
	names := make([]string, 0, len(m))
	for k, v := range m {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return nil, fmt.Errorf("%w: member %q is not a string", ErrQuery, k)
		}
		vals[k] = s
		names = append(names, k)
	}
	sort.Strings(names)
	for _, c := range Classes {
		if strings.Join(c.Members, ",") != strings.Join(names, ",") {
			continue
		}
		for _, n := range names {
			if err := checkMember(c.Name, n, vals[n]); err != nil {
				return nil, fmt.Errorf("%w: member %q", ErrQuery, n)
			}
		}
		return &Question{Class: c, Members: vals}, nil
	}
	return nil, fmt.Errorf("%w: no class has these members", ErrQuery)
}
