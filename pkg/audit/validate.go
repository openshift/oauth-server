package audit

import (
	"errors"
	"fmt"

	"k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/audit/policy"
)

var (
	// ErrNoPolicyFile is returned, when no path to a policy has been given.
	ErrNoPolicyFile = errors.New("no policy file specified")
)

// Validate reads the given file path as policy file and rejects every level
// of audit logging that is more verbose than metadata.
func Validate(policyFile string) error {
	if policyFile == "" {
		return ErrNoPolicyFile
	}

	p, err := policy.LoadPolicyFromFile(policyFile)
	if err != nil {
		return fmt.Errorf("load audit policy file: %w", err)
	}

	for _, rule := range p.Rules {
		if rule.Level != audit.LevelNone && rule.Level != audit.LevelMetadata {
			return fmt.Errorf("policy level is beyond metadata: %s", rule.Level)
		}
	}

	return nil
}
