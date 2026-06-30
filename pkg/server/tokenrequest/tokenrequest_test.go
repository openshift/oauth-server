package tokenrequest

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openshift/oauth-server/pkg/server/csrf"
)

func TestFormatOcLoginCommand(t *testing.T) {
	token := "sha256~abc123"
	server := "https://api.example.com:6443"

	got := formatOcLoginCommand(token, server)
	want := "oc login --token=sha256~abc123 --server=https://api.example.com:6443"
	if got != want {
		t.Fatalf("formatOcLoginCommand() = %q, want %q", got, want)
	}
}

func TestFormatCurlCommand(t *testing.T) {
	token := "sha256~abc123"
	server := "https://api.example.com:6443/"

	got := formatCurlCommand(token, server)
	want := `curl -H "Authorization: Bearer sha256~abc123" "https://api.example.com:6443/apis/user.openshift.io/v1/users/~"`
	if got != want {
		t.Fatalf("formatCurlCommand() = %q, want %q", got, want)
	}
}

func TestRenderTokenIncludesCopyToClipboardControls(t *testing.T) {
	data := tokenData{
		sharedData: sharedData{
			RequestURL: "/oauth/token/request",
		},
		AccessToken:     "sha256~token-value",
		OcLoginCommand:  formatOcLoginCommand("sha256~token-value", "https://api.example.com:6443"),
		CurlCommand:     formatCurlCommand("sha256~token-value", "https://api.example.com:6443"),
		PublicMasterURL: "https://api.example.com:6443",
	}

	var buf bytes.Buffer
	renderToken(&buf, data)
	body := buf.String()

	expectContains(t, body, []string{
		"Your API token is",
		"Log in with this token",
		"Use this token directly against the API",
		`class="copy-button"`,
		`aria-label="Copy to clipboard"`,
		`data-copy-text="sha256~token-value"`,
		`data-copy-text="oc login --token=sha256~token-value --server=https://api.example.com:6443"`,
		`data-copy-text="curl -H &#34;Authorization: Bearer sha256~token-value&#34; &#34;https://api.example.com:6443/apis/user.openshift.io/v1/users/~&#34;"`,
		"navigator.clipboard",
		"document.execCommand('copy')",
		`<a href="/oauth/token/request">Request another token</a>`,
	})

	if strings.Count(body, `class="copy-button"`) != 3 {
		t.Fatalf("expected 3 copy buttons, got %d in:\n%s", strings.Count(body, `class="copy-button"`), body)
	}
}

func TestRenderTokenEscapesSpecialCharactersInCopyAttributes(t *testing.T) {
	token := `sha256~test"onclick='alert(1)'`
	server := "https://api.example.com:6443"

	data := tokenData{
		sharedData: sharedData{
			RequestURL: "/oauth/token/request",
		},
		AccessToken:     token,
		OcLoginCommand:  formatOcLoginCommand(token, server),
		CurlCommand:     formatCurlCommand(token, server),
		PublicMasterURL: server,
	}

	var buf bytes.Buffer
	renderToken(&buf, data)
	body := buf.String()

	if strings.Contains(body, `data-copy-text="sha256~test"onclick`) {
		t.Fatalf("token copy attribute was not HTML-escaped:\n%s", body)
	}
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatalf("unexpected unescaped script content in output:\n%s", body)
	}
	expectContains(t, body, []string{
		`data-copy-text="sha256~test&#34;onclick=&#39;alert(1)&#39;"`,
	})
}

func TestRenderTokenErrorStateOmitsCopyControls(t *testing.T) {
	data := tokenData{
		sharedData: sharedData{
			Error:      "Error checking token",
			RequestURL: "/oauth/token/request",
		},
	}

	var buf bytes.Buffer
	renderToken(&buf, data)
	body := buf.String()

	expectContains(t, body, []string{
		"Error checking token",
		`<a href="/oauth/token/request">Request another token</a>`,
	})
	if strings.Contains(body, `class="copy-button"`) {
		t.Fatalf("error state should not render copy buttons:\n%s", body)
	}
}

func TestRenderFormDisplayTokenStepUnchanged(t *testing.T) {
	data := formData{
		sharedData: sharedData{
			RequestURL: "/oauth/token/request",
		},
		Action: "https://oauth.example.com/oauth/token/display",
		Code:   "auth-code",
		CSRF:   "csrf-token",
	}

	var buf bytes.Buffer
	renderForm(&buf, data)
	body := buf.String()

	expectContains(t, body, []string{
		`action="https://oauth.example.com/oauth/token/display"`,
		`name="code" value="auth-code"`,
		`name="csrf" value="csrf-token"`,
		"Display Token",
	})
	if strings.Contains(body, `class="copy-button"`) {
		t.Fatalf("display token form should not include copy buttons:\n%s", body)
	}
}

func TestDisplayTokenPostRejectsInvalidCSRF(t *testing.T) {
	handler := &tokenRequest{
		csrf: &csrf.FakeCSRF{Token: "expected-csrf"},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token/display", strings.NewReader("csrf=wrong"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	handler.displayTokenPost(nil, rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Could not check CSRF token") {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}

func TestDisplayTokenRejectsUnsupportedMethod(t *testing.T) {
	handler := &tokenRequest{}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/oauth/token/display", nil)
	handler.displayToken(nil, rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status %d, got %d: %s", http.StatusMethodNotAllowed, rec.Code, rec.Body.String())
	}
}

func expectContains(t *testing.T, body string, expected []string) {
	t.Helper()
	for _, fragment := range expected {
		if !strings.Contains(body, fragment) {
			t.Fatalf("expected body to contain %q, got:\n%s", fragment, body)
		}
	}
}
