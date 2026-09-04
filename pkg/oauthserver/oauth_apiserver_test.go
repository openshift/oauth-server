package oauthserver

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	osinv1 "github.com/openshift/api/osin/v1"
	"github.com/openshift/library-go/pkg/config/helpers"
	"k8s.io/apimachinery/pkg/util/wait"
	genericapiserver "k8s.io/apiserver/pkg/server"
)

func TestGetDefaultSessionSecrets(t *testing.T) {
	secrets, err := getSessionSecrets("")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if len(secrets) != 2 {
		t.Errorf("Expected 2 secrets, got: %#v", secrets)
	}
}

func TestGetMissingSessionSecretsFile(t *testing.T) {
	_, err := getSessionSecrets("missing")
	if err == nil {
		t.Errorf("Expected error, got none")
	}
}

func TestGetInvalidSessionSecretsFile(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "invalid.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if err := os.WriteFile(tmpfile.Name(), []byte("invalid content"), os.FileMode(0600)); err != nil {
		t.Fatal(err)
	}

	_, err = getSessionSecrets(tmpfile.Name())
	if err == nil {
		t.Errorf("Expected error, got none")
	}
}

func TestGetEmptySessionSecretsFile(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "empty.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	secrets := &osinv1.SessionSecrets{
		Secrets: []osinv1.SessionSecret{},
	}

	yaml, err := helpers.WriteYAML(secrets, osinv1.Install)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if err := os.WriteFile(tmpfile.Name(), []byte(yaml), os.FileMode(0600)); err != nil {
		t.Fatal(err)
	}

	_, err = getSessionSecrets(tmpfile.Name())
	if err == nil {
		t.Errorf("Expected error, got none")
	}
}

// TestProxyCAIntegration verifies that multiple transports created via
// transportFor all pick up a proxy CA file rotation.
func TestProxyCAIntegration(t *testing.T) {
	proxyCA1PEM, proxyCA1Cert, proxyCA1Key := generateCA(t)
	server1Cert := generateServerCert(t, proxyCA1Cert, proxyCA1Key)
	server1 := startTLSServer(t, server1Cert)

	proxyCA2PEM, proxyCA2Cert, proxyCA2Key := generateCA(t)
	server2Cert := generateServerCert(t, proxyCA2Cert, proxyCA2Key)
	server2 := startTLSServer(t, server2Cert)

	dir := t.TempDir()
	proxyCAFile := filepath.Join(dir, "proxy-ca.pem")
	writeFile(t, proxyCAFile, proxyCA1PEM)

	c := &OAuthServerConfig{}
	c.ExtraOAuthConfig.postStartHooks = map[string]genericapiserver.PostStartHookFunc{}
	if err := configureTransport(&c.ExtraOAuthConfig, proxyCAFile); err != nil {
		t.Fatalf("configureTransport: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	hook := c.ExtraOAuthConfig.postStartHooks["openshift.io-StartProxyCAWatcher"]
	if err := hook(genericapiserver.PostStartHookContext{Context: ctx}); err != nil {
		t.Fatalf("post-start hook: %v", err)
	}

	rt1, err := c.transportFor("", "", "")
	if err != nil {
		t.Fatalf("transportFor (1): %v", err)
	}
	rt2, err := c.transportFor("", "", "")
	if err != nil {
		t.Fatalf("transportFor (2): %v", err)
	}

	transports := []struct {
		name string
		rt   http.RoundTripper
	}{
		{"rt1", rt1},
		{"rt2", rt2},
	}
	for _, tr := range transports {
		mustGet(t, tr.rt, server1.URL, fmt.Sprintf("%s: server signed by initial proxy CA", tr.name))
	}

	// Rotate the proxy CA
	writeFile(t, proxyCAFile, proxyCA2PEM)

	for _, tr := range transports {
		err := wait.PollUntilContextTimeout(t.Context(), 50*time.Millisecond, 10*time.Second, false, func(ctx context.Context) (bool, error) {
			resp, err := doRequest(t, tr.rt, server2.URL)
			if err != nil {
				return false, nil
			}
			_ = resp.Body.Close()
			return true, nil
		})
		if err != nil {
			t.Fatalf("%s: timed out waiting for proxy CA reload", tr.name)
		}
	}
}

func TestConfigureTransport_NoProxyCA(t *testing.T) {
	config := &ExtraOAuthConfig{
		postStartHooks: map[string]genericapiserver.PostStartHookFunc{},
	}
	if err := configureTransport(config, ""); err != nil {
		t.Fatalf("configureTransport: %v", err)
	}
	if config.transportBuilderFunc == nil {
		t.Fatal("expected transportBuilderFunc to be set")
	}
	if _, ok := config.postStartHooks["openshift.io-StartProxyCAWatcher"]; ok {
		t.Fatal("expected no StartProxyCAWatcher hook when proxy CA is empty")
	}
}

func TestConfigureTransport_ProxyCAFileNotFound(t *testing.T) {
	config := &ExtraOAuthConfig{
		postStartHooks: map[string]genericapiserver.PostStartHookFunc{},
	}
	if err := configureTransport(config, "/nonexistent/proxy-ca.pem"); err == nil {
		t.Fatal("expected error for nonexistent proxy CA file")
	}
}

func TestGetValidSessionSecretsFile(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "valid.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	secrets := &osinv1.SessionSecrets{
		Secrets: []osinv1.SessionSecret{
			{Authentication: "a1", Encryption: "e1"},
			{Authentication: "a2", Encryption: "e2"},
		},
	}
	expectedSecrets := [][]byte{[]byte("a1"), []byte("e1"), []byte("a2"), []byte("e2")}

	yaml, err := helpers.WriteYAML(secrets, osinv1.Install)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if err := os.WriteFile(tmpfile.Name(), []byte(yaml), os.FileMode(0600)); err != nil {
		t.Fatal(err)
	}

	readSecrets, err := getSessionSecrets(tmpfile.Name())
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !reflect.DeepEqual(readSecrets, expectedSecrets) {
		t.Errorf("Unexpected %v, got %v", expectedSecrets, readSecrets)
	}
}
