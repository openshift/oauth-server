package audit_test

import (
	"path"
	"testing"

	"github.com/openshift/oauth-server/pkg/audit"
)

func TestVerify(t *testing.T) {
	rootFilePath := "../.."
	testFilesPath := "test/files"

	for _, tc := range [...]struct {
		name      string
		havePath  string
		wantError bool
	}{
		{
			name:      "metadata-policy should be valid",
			havePath:  path.Join(rootFilePath, testFilesPath, "metadata-policy.yaml"),
			wantError: false,
		},
		{
			name:      "none-policy should be valid",
			havePath:  path.Join(rootFilePath, testFilesPath, "none-policy.yaml"),
			wantError: false,
		},
		{
			name:      "none-metadata-policy should be valid",
			havePath:  path.Join(rootFilePath, testFilesPath, "none-metadata-policy.yaml"),
			wantError: false,
		},
		{
			name:      "metadata-request-policy shouldn't be valid",
			havePath:  path.Join(rootFilePath, testFilesPath, "metadata-request-policy.yaml"),
			wantError: true,
		},
		{
			name:      "request-policy shouldn't be valid",
			havePath:  path.Join(rootFilePath, testFilesPath, "request-policy.yaml"),
			wantError: true,
		},
		{
			name:      "request-response-policy shouldn't be valid",
			havePath:  path.Join(rootFilePath, testFilesPath, "request-response-policy.yaml"),
			wantError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := audit.Validate(tc.havePath)
			haveError := err != nil

			if haveError != tc.wantError {
				t.Errorf("wantError: %t, haveError: %s", tc.wantError, err)
			}
		})
	}
}
