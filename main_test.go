package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"html/template"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func resetGlobals(t *testing.T) {
	t.Helper()
	certCache = make(map[string]cachedCert)
	caCert = nil
	caKey = nil
	blockPageTemplate = nil
}

func TestLoadConfigFromEnv(t *testing.T) {
	t.Setenv("LISTEN_ADDR", "127.0.0.1")
	t.Setenv("LISTEN_PORT", "8443")
	t.Setenv("CA_CERT_PATH", "test/ca.pem")
	t.Setenv("CA_KEY_PATH", "test/key.pem")
	t.Setenv("BLOCK_PAGE_PATH", "test/block.html")
	t.Setenv("WEBROOT_DIR", "test/webroot")
	t.Setenv("SHUTDOWN_TIMEOUT", "3s")

	cfg := loadConfigFromEnv()
	if cfg.ListenAddr != "127.0.0.1" || cfg.ListenPort != "8443" {
		t.Fatalf("unexpected listen config: %#v", cfg)
	}
	if cfg.CACertPath != "test/ca.pem" || cfg.CAKeyPath != "test/key.pem" {
		t.Fatalf("unexpected CA paths: %#v", cfg)
	}
	if cfg.BlockPagePath != "test/block.html" || cfg.WebrootDir != "test/webroot" {
		t.Fatalf("unexpected content paths: %#v", cfg)
	}
	if cfg.ShutdownTimeout != 3*time.Second {
		t.Fatalf("unexpected shutdown timeout: %s", cfg.ShutdownTimeout)
	}
}

func TestGenerateAndLoadCA(t *testing.T) {
	resetGlobals(t)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ssl", "ca_cert.pem")
	keyPath := filepath.Join(dir, "ssl", "private", "ca_key.pem")

	if err := loadCA(certPath, keyPath); err != nil {
		t.Fatalf("loadCA should generate missing CA: %v", err)
	}
	if caCert == nil || caKey == nil {
		t.Fatal("expected CA certificate and key to be loaded")
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("expected CA certificate file: %v", err)
	}

	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("expected CA key file: %v", err)
	}
	if got := keyInfo.Mode().Perm(); got != 0600 {
		t.Fatalf("expected CA key permissions 0600, got %o", got)
	}

	resetGlobals(t)
	if err := loadCA(certPath, keyPath); err != nil {
		t.Fatalf("loadCA should load existing CA: %v", err)
	}
	if caCert == nil || caKey == nil {
		t.Fatal("expected existing CA certificate and key to load")
	}
}

func TestGenerateCertForDomainCachesCertificate(t *testing.T) {
	resetGlobals(t)
	loadTestCA(t)

	first, err := generateCertForDomain("blocked.example")
	if err != nil {
		t.Fatalf("generate first cert: %v", err)
	}
	second, err := generateCertForDomain("blocked.example")
	if err != nil {
		t.Fatalf("generate cached cert: %v", err)
	}

	if !bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("expected cached certificate to be reused")
	}

	leaf, err := x509.ParseCertificate(first.Certificate[0])
	if err != nil {
		t.Fatalf("parse generated leaf: %v", err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "blocked.example" {
		t.Fatalf("unexpected DNS SANs: %#v", leaf.DNSNames)
	}
}

func TestGenerateCertForIPAddress(t *testing.T) {
	resetGlobals(t)
	loadTestCA(t)

	cert, err := generateCertForDomain("192.0.2.10")
	if err != nil {
		t.Fatalf("generate IP certificate: %v", err)
	}

	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse generated leaf: %v", err)
	}
	if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("192.0.2.10")) {
		t.Fatalf("unexpected IP SANs: %#v", leaf.IPAddresses)
	}
}

func TestBlockHandlerRendersRequestedURL(t *testing.T) {
	resetGlobals(t)
	blockPageTemplate = template.Must(template.New("test").Parse(`blocked: {{ .RequestedURL }}`))

	req := httptest.NewRequest(http.MethodGet, "https://blocked.example/admin?next=%2F", nil)
	req.TLS = &tls.ConnectionState{}
	rec := httptest.NewRecorder()

	blockHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "https://blocked.example/admin?next=%2F") {
		t.Fatalf("expected requested URL in body, got %q", rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected no-store cache header, got %q", got)
	}
}

func TestHealthHandler(t *testing.T) {
	resetGlobals(t)
	rec := httptest.NewRecorder()
	healthHandler(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 before init, got %d", rec.Code)
	}

	loadTestCA(t)
	blockPageTemplate = template.Must(template.New("test").Parse("ok"))
	rec = httptest.NewRecorder()
	healthHandler(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 after init, got %d", rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "ok" {
		t.Fatalf("unexpected health body: %q", rec.Body.String())
	}
}

func loadTestCA(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := loadCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatalf("load test CA: %v", err)
	}
}
