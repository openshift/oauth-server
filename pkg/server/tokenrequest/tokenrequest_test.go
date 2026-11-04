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
			name: "shown between the API token heading and token",
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
			heading := strings.Index(html, "<h2>Your API token</h2>")
			webCommand := strings.Index(html, "'--web'")
			tokenCommand := strings.Index(html, "'--token=")
			if tt.wantAlert {
				previous := -1
				for _, element := range []string{
					"<h2>Log in with a browser</h2>",
					`<pre id="webLogin">`,
					`<p class="note">`,
					"<h2>Your API token</h2>",
					`class="alert-warning"`,
					`<pre id="token">`,
					"<h3>Log in with this token</h3>",
					`<pre id="tokenLogin">`,
					"<h3>Call the API with this token</h3>",
					`<pre id="apiCall">`,
					`>Request another token</a>`,
				} {
					index := strings.Index(html, element)
					if index <= previous {
						t.Fatalf("page element %q is missing or out of order", element)
					}
					previous = index
				}
				if webCommand < 0 || tokenCommand < webCommand {
					t.Fatalf("oc login --web should render before oc login --token")
				}
				for _, text := range []string{
					"Using this token in commands can expose it in logs",
					"This page shows the token in plaintext.",
					"Logs you in through a browser instead of using the token below. Requires a browser on the machine where you run oc.",
					"Call the API with this token",
					"{ masked: false }",
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
