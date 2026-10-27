package tokenrequest

import (
	"bytes"
	"html/template"
	"strings"
	"testing"
)

func TestTokenTemplateWarningAlert(t *testing.T) {
	tests := []struct {
		name      string
		data      tokenData
		wantAlert bool
	}{
		{
			name: "shown below the request another token link",
			data: tokenData{
				sharedData:           sharedData{RequestURL: "/oauth/token/request"},
				AccessToken:          "sha256~test",
				AccessTokenJSStr:     template.JSStr("sha256~test"),
				PublicMasterURL:      "https://example.com",
				PublicMasterURLJSStr: template.JSStr("https://example.com"),
			},
			wantAlert: true,
		},
		{
			name: "hidden when token display fails",
			data: tokenData{
				sharedData: sharedData{
					Error:      "Error getting token",
					RequestURL: "/oauth/token/request",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tokenTemplate.Execute(&buf, tt.data); err != nil {
				t.Fatalf("render token template: %v", err)
			}
			html := buf.String()

			alert := strings.Index(html, `class="alert-warning"`)
			heading := strings.Index(html, "Your API token is")
			requestLink := strings.Index(html, `>Request another token</a>`)
			if tt.wantAlert {
				if heading < 0 || requestLink < 0 || alert < requestLink {
					t.Fatalf("warning alert should render below the request another token link")
				}
				for _, text := range []string{
					"This token can be exposed in CLI logs",
					"oc login --token",
					"shell history, process listings, and CLI logs",
				} {
					if !strings.Contains(html, text) {
						t.Errorf("rendered token page missing %q", text)
					}
				}
				return
			}
			if alert >= 0 || heading >= 0 {
				t.Fatalf("error page should not render the warning alert or token heading")
			}
		})
	}
}
