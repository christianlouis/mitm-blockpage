package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultListenAddr    = "0.0.0.0"
	defaultListenPort    = "443"
	defaultCACertPath    = "ssl/ca_cert.pem"
	defaultCAKeyPath     = "ssl/ca_key.pem"
	defaultBlockPagePath = "webroot/block.html"
	defaultWebrootDir    = "webroot"
)

type config struct {
	ListenAddr      string
	ListenPort      string
	CACertPath      string
	CAKeyPath       string
	BlockPagePath   string
	WebrootDir      string
	ShutdownTimeout time.Duration
}

type cachedCert struct {
	cert      tls.Certificate
	expiresAt time.Time
}

type blockPageData struct {
	RequestedURL string
	Host         string
	Path         string
}

var (
	certCache = make(map[string]cachedCert)
	cacheMu   sync.Mutex

	caCert *x509.Certificate
	caKey  *rsa.PrivateKey

	blockPageTemplate *template.Template
)

const defaultBlockPageHTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>Access Blocked</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      :root {
        color-scheme: light dark;
        --bg: #f4f7fb;
        --panel: #ffffff;
        --text: #1f2937;
        --muted: #5f6b7a;
        --border: #d7dee8;
        --accent: #c2410c;
      }
      @media (prefers-color-scheme: dark) {
        :root {
          --bg: #101827;
          --panel: #162033;
          --text: #f8fafc;
          --muted: #cbd5e1;
          --border: #334155;
          --accent: #fb923c;
        }
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        padding: 24px;
        background: var(--bg);
        color: var(--text);
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      }
      main {
        width: min(100%, 680px);
        padding: 32px;
        border: 1px solid var(--border);
        border-radius: 8px;
        background: var(--panel);
        box-shadow: 0 18px 45px rgba(15, 23, 42, 0.12);
      }
      .status {
        display: inline-flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 18px;
        color: var(--accent);
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        font-size: 0.8rem;
      }
      .status::before {
        content: "";
        width: 12px;
        height: 12px;
        border-radius: 50%;
        background: var(--accent);
      }
      h1 {
        margin: 0 0 12px;
        font-size: clamp(2rem, 6vw, 3.4rem);
        line-height: 1.05;
        letter-spacing: 0;
      }
      p {
        margin: 0 0 16px;
        color: var(--muted);
        font-size: 1.05rem;
        line-height: 1.6;
      }
      dl {
        margin: 26px 0 0;
        padding-top: 20px;
        border-top: 1px solid var(--border);
      }
      dt {
        margin-bottom: 8px;
        color: var(--muted);
        font-size: 0.85rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
      }
      dd {
        margin: 0;
        overflow-wrap: anywhere;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 0.95rem;
      }
    </style>
  </head>
  <body>
    <main>
      <div class="status">Network policy</div>
      <h1>Access Blocked</h1>
      <p>This destination is blocked by the network policy currently applied to this connection.</p>
      <p>If you believe this is incorrect, contact the network administrator and include the requested URL below.</p>
      <dl>
        <dt>Requested URL</dt>
        <dd>{{ .RequestedURL }}</dd>
      </dl>
    </main>
  </body>
</html>`

func main() {
	cfg := loadConfigFromEnv()

	if err := loadCA(cfg.CACertPath, cfg.CAKeyPath); err != nil {
		log.Fatalf("error loading CA: %v", err)
	}

	tmpl, err := loadBlockPage(cfg.BlockPagePath)
	if err != nil {
		log.Fatalf("error loading block page: %v", err)
	}
	blockPageTemplate = tmpl

	server := newServer(cfg)
	errCh := make(chan error, 1)

	go func() {
		log.Printf("starting HTTPS block page server on %s", server.Addr)
		errCh <- server.ListenAndServeTLS("", "")
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case sig := <-stop:
		log.Printf("received %s, shutting down", sig)
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			log.Fatalf("server shutdown failed: %v", err)
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server error: %v", err)
		}
	}
}

func loadConfigFromEnv() config {
	cfg := config{
		ListenAddr:      envOrDefault("LISTEN_ADDR", defaultListenAddr),
		ListenPort:      envOrDefault("LISTEN_PORT", defaultListenPort),
		CACertPath:      envOrDefault("CA_CERT_PATH", defaultCACertPath),
		CAKeyPath:       envOrDefault("CA_KEY_PATH", defaultCAKeyPath),
		BlockPagePath:   envOrDefault("BLOCK_PAGE_PATH", defaultBlockPagePath),
		WebrootDir:      envOrDefault("WEBROOT_DIR", defaultWebrootDir),
		ShutdownTimeout: 10 * time.Second,
	}

	if timeout := os.Getenv("SHUTDOWN_TIMEOUT"); timeout != "" {
		if parsed, err := time.ParseDuration(timeout); err == nil && parsed > 0 {
			cfg.ShutdownTimeout = parsed
		} else {
			log.Printf("invalid SHUTDOWN_TIMEOUT %q, using %s", timeout, cfg.ShutdownTimeout)
		}
	}

	return cfg
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func newServer(cfg config) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/ca.crt", caPEMHandler(cfg.CACertPath))
	mux.HandleFunc("/cert.cer", caDERHandler)
	mux.Handle("/webroot/", http.StripPrefix("/webroot/", http.FileServer(http.Dir(cfg.WebrootDir))))
	mux.HandleFunc("/", blockHandler)

	return &http.Server{
		Addr:              net.JoinHostPort(cfg.ListenAddr, cfg.ListenPort),
		Handler:           mux,
		TLSConfig:         newTLSConfig(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func newTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: getCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}

func generateAndSaveCA(certPath, keyPath string) error {
	if err := ensureParentDir(certPath, 0755); err != nil {
		return err
	}
	if err := ensureParentDir(keyPath, 0700); err != nil {
		return err
	}

	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return fmt.Errorf("failed to generate CA key: %w", err)
	}

	serialNumber, err := randomSerialNumber()
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"MITM Blockpage"},
			CommonName:   "MITM Blockpage Local CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	if err := writePEMFile(certPath, 0644, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write CA cert: %w", err)
	}
	if err := writePEMFile(keyPath, 0600, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return fmt.Errorf("failed to write CA key: %w", err)
	}

	caCert, err = x509.ParseCertificate(derBytes)
	if err != nil {
		return fmt.Errorf("failed to parse generated CA certificate: %w", err)
	}
	caKey = key

	log.Printf("new CA generated and saved to %s and %s", certPath, keyPath)
	return nil
}

func writePEMFile(path string, perm os.FileMode, block *pem.Block) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer file.Close()

	if err := pem.Encode(file, block); err != nil {
		return err
	}
	return file.Chmod(perm)
}

func loadCA(caCertPath, caKeyPath string) error {
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("CA certificate not found at %s, generating a new CA", caCertPath)
			return generateAndSaveCA(caCertPath, caKeyPath)
		}
		return fmt.Errorf("failed to read CA cert: %w", err)
	}

	certBlock, err := decodeSinglePEMBlock(caCertPEM, "CERTIFICATE")
	if err != nil {
		return fmt.Errorf("failed to decode CA certificate PEM: %w", err)
	}
	caCert, err = x509.ParseCertificate(certBlock)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("CA key not found at %s", caKeyPath)
		}
		return fmt.Errorf("failed to read CA key: %w", err)
	}

	keyBlock, err := decodeSinglePEMBlock(caKeyPEM, "RSA PRIVATE KEY")
	if err != nil {
		return fmt.Errorf("failed to decode CA key PEM: %w", err)
	}
	caKey, err = x509.ParsePKCS1PrivateKey(keyBlock)
	if err != nil {
		return fmt.Errorf("failed to parse CA key: %w", err)
	}

	return nil
}

func decodeSinglePEMBlock(data []byte, expectedType string) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != expectedType {
		return nil, fmt.Errorf("unexpected PEM type %q", block.Type)
	}
	return block.Bytes, nil
}

func ensureParentDir(path string, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "" {
		return nil
	}
	if err := os.MkdirAll(dir, perm); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	return nil
}

func loadBlockPage(path string) (*template.Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("could not load block page from %s: %v", path, err)
		} else {
			log.Printf("block page not found at %s, using built-in fallback", path)
		}
		data = []byte(defaultBlockPageHTML)
	}
	return template.New("block-page").Parse(string(data))
}

func generateCertForDomain(domain string) (tls.Certificate, error) {
	cacheMu.Lock()
	if cached, ok := certCache[domain]; ok && time.Now().Add(time.Minute).Before(cached.expiresAt) {
		cacheMu.Unlock()
		return cached.cert, nil
	}
	cacheMu.Unlock()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating key: %w", err)
	}

	serialNumber, err := randomSerialNumber()
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{domain}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("creating certificate: %w", err)
	}

	certPEM, keyPEM := encodeCertificateAndKey(derBytes, key)
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("loading TLS key pair: %w", err)
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parsing generated certificate: %w", err)
	}

	cacheMu.Lock()
	certCache[domain] = cachedCert{cert: tlsCert, expiresAt: leaf.NotAfter}
	cacheMu.Unlock()

	return tlsCert, nil
}

func encodeCertificateAndKey(derBytes []byte, key *rsa.PrivateKey) ([]byte, []byte) {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM
}

func randomSerialNumber() (*big.Int, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	return serialNumber, nil
}

func getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := strings.TrimSpace(hello.ServerName)
	if domain == "" {
		domain = "localhost"
	}

	cert, err := generateCertForDomain(domain)
	if err != nil {
		log.Printf("error generating cert for %s: %v", domain, err)
		return nil, err
	}
	return &cert, nil
}

func caPEMHandler(caPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		caData, err := os.ReadFile(caPath)
		if err != nil {
			http.Error(w, "CA certificate not available", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="mitm-blockpage-ca.crt"`)
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(caData)
	}
}

func caDERHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if caCert == nil {
		http.Error(w, "CA not loaded", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="mitm-blockpage-ca.cer"`)
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(caCert.Raw)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if caCert == nil || caKey == nil || blockPageTemplate == nil {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte("ok\n"))
	}
}

func blockHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)

	data := blockPageData{
		RequestedURL: requestedURL(r),
		Host:         r.Host,
		Path:         r.URL.RequestURI(),
	}

	if err := blockPageTemplate.Execute(w, data); err != nil {
		log.Printf("error rendering block page for %s: %v", r.Host, err)
	}
}

func requestedURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	return scheme + "://" + host + r.URL.RequestURI()
}
