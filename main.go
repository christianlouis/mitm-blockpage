package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CachedCert holds a generated certificate and its expiration time.
type CachedCert struct {
	cert      tls.Certificate
	expiresAt time.Time
}

var (
	// certCache maps a domain to its generated certificate.
	certCache = make(map[string]CachedCert)
	cacheMu   sync.Mutex

	// Global CA certificate and key.
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey

	// Block page HTML content.
	blockPageHTML string
)

// defaultBlockPageHTML is used if no file is found.
const defaultBlockPageHTML = `<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>Access Blocked</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      body { font-family: sans-serif; text-align: center; padding: 50px; background: #f7f7f7; }
      h1 { font-size: 48px; color: #e74c3c; }
      p  { font-size: 20px; }
    </style>
  </head>
  <body>
    <h1>Access Blocked</h1>
    <p>Hey, this site is blocked by your network policy.</p>
    <p>If you think this is an error, please contact your network administrator.</p>
  </body>
</html>`

// generateAndSaveCA generates a new self-signed CA and writes the certificate and key to disk.
func generateAndSaveCA(certPath, keyPath string) error {
    // Generate a new RSA key for the CA (use a larger key for a CA)
    key, err := rsa.GenerateKey(rand.Reader, 4096)
    if err != nil {
        return fmt.Errorf("failed to generate CA key: %w", err)
    }

    // Create a certificate template for a CA.
    serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
    if err != nil {
        return fmt.Errorf("failed to generate serial number: %w", err)
    }
    template := x509.Certificate{
        SerialNumber: serialNumber,
        Subject: pkix.Name{
            Organization: []string{"Dynamic MITM CA"},
            CommonName:   "Dynamic MITM CA",
        },
        NotBefore:             time.Now().Add(-time.Hour),
        NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // valid for 10 years
        KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
        BasicConstraintsValid: true,
        IsCA:                  true,
    }

    // Self-sign the certificate.
    derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
    if err != nil {
        return fmt.Errorf("failed to create CA certificate: %w", err)
    }

    // Write the certificate to file.
    certOut, err := os.Create(certPath)
    if err != nil {
        return fmt.Errorf("failed to create CA cert file: %w", err)
    }
    defer certOut.Close()
    if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
        return fmt.Errorf("failed to write CA cert: %w", err)
    }

    // Write the key to file.
    keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
    if err != nil {
        return fmt.Errorf("failed to create CA key file: %w", err)
    }
    defer keyOut.Close()
    if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
        return fmt.Errorf("failed to write CA key: %w", err)
    }

    // Assign the global variables.
    caCert, err = x509.ParseCertificate(derBytes)
    if err != nil {
        return fmt.Errorf("failed to parse generated CA certificate: %w", err)
    }
    caKey = key

    log.Printf("New CA generated and saved to %s and %s", certPath, keyPath)
    return nil
}

// loadCA loads the CA certificate and key from the specified files,
// or generates them if they do not exist.
func loadCA(caCertPath, caKeyPath string) error {
    // Try to read the CA certificate.
    caCertPEM, err := ioutil.ReadFile(caCertPath)
    if err != nil {
        if os.IsNotExist(err) {
            // CA certificate not found: generate a new one.
            log.Printf("CA certificate not found at %s. Generating a new CA...", caCertPath)
            return generateAndSaveCA(caCertPath, caKeyPath)
        }
        return fmt.Errorf("failed to read CA cert: %w", err)
    }
    block, _ := pem.Decode(caCertPEM)
    if block == nil {
        return fmt.Errorf("failed to decode CA certificate PEM")
    }
    caCert, err = x509.ParseCertificate(block.Bytes)
    if err != nil {
        return fmt.Errorf("failed to parse CA certificate: %w", err)
    }

    // Try to read the CA key.
    caKeyPEM, err := ioutil.ReadFile(caKeyPath)
    if err != nil {
        if os.IsNotExist(err) {
            // If key not found but cert exists, that's an error.
            return fmt.Errorf("CA key not found at %s", caKeyPath)
        }
        return fmt.Errorf("failed to read CA key: %w", err)
    }
    block, _ = pem.Decode(caKeyPEM)
    if block == nil {
        return fmt.Errorf("failed to decode CA key PEM")
    }
    caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return fmt.Errorf("failed to parse CA key: %w", err)
    }
    return nil
}


// loadBlockPage loads the block page HTML from a file.
func loadBlockPage() string {
	path := os.Getenv("BLOCK_PAGE_PATH")
	if path == "" {
		path = filepath.Join("webroot", "block.html")
	}
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("Could not load block page from %s: %v", path, err)
		return defaultBlockPageHTML
	}
	return string(data)
}

// generateCertForDomain creates (and caches) a new certificate for the given domain.
func generateCertForDomain(domain string) (tls.Certificate, error) {
	// Check cache first.
	cacheMu.Lock()
	if cached, ok := certCache[domain]; ok {
		// If the certificate expires in more than 1 minute, return it.
		if time.Now().Add(1 * time.Minute).Before(cached.expiresAt) {
			cacheMu.Unlock()
			return cached.cert, nil
		}
	}
	cacheMu.Unlock()

	// Generate a new RSA key.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating key: %w", err)
	}

	// Create a certificate template.
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generating serial number: %w", err)
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore: time.Now().Add(-1 * time.Minute),
		NotAfter:  time.Now().Add(30 * 24 * time.Hour), // valid for 30 days

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("creating certificate: %w", err)
	}

	// PEM encode certificate and key.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("loading TLS key pair: %w", err)
	}

	// Parse the certificate to get its expiration.
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parsing generated certificate: %w", err)
	}
	expiry := leaf.NotAfter

	// Cache the certificate.
	cacheMu.Lock()
	certCache[domain] = CachedCert{cert: tlsCert, expiresAt: expiry}
	cacheMu.Unlock()

	return tlsCert, nil
}

// getCertificate is the TLS callback that provides a certificate based on SNI.
func getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := hello.ServerName
	if domain == "" {
		domain = "localhost"
	}
	log.Printf("SNI request for domain: %s", domain)
	cert, err := generateCertForDomain(domain)
	if err != nil {
		log.Printf("Error generating cert for %s: %v", domain, err)
		return nil, err
	}
	return &cert, nil
}

// caHandler serves the CA certificate so that it can be added to a browser trust store.
func caHandler(w http.ResponseWriter, r *http.Request) {
	caPath := os.Getenv("CA_CERT_PATH")
	if caPath == "" {
		caPath = filepath.Join("ssl", "ca_cert.pem")
	}
	caData, err := ioutil.ReadFile(caPath)
	if err != nil {
		http.Error(w, "CA certificate not available", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Write(caData)
}

// caDERHandler serves the CA certificate in DER format.
func caDERHandler(w http.ResponseWriter, r *http.Request) {
	if caCert == nil {
		http.Error(w, "CA not loaded", http.StatusInternalServerError)
		return
	}
	// The DER-encoded certificate is available as caCert.Raw.
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Write(caCert.Raw)
}

// blockHandler serves the block page.
func blockHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Serving block page for %s", r.URL.String())
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(blockPageHTML))
}

func main() {
	// Read configuration from environment variables (with defaults).
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = "0.0.0.0"
	}
	listenPort := os.Getenv("LISTEN_PORT")
	if listenPort == "" {
		listenPort = "443"
	}
	caCertPath := os.Getenv("CA_CERT_PATH")
	if caCertPath == "" {
		caCertPath = filepath.Join("ssl", "ca_cert.pem")
	}
	caKeyPath := os.Getenv("CA_KEY_PATH")
	if caKeyPath == "" {
		caKeyPath = filepath.Join("ssl", "ca_key.pem")
	}
	blockPagePath := os.Getenv("BLOCK_PAGE_PATH")
	if blockPagePath == "" {
		blockPagePath = filepath.Join("webroot", "block.html")
	}

	// Load the CA certificate and key.
	if err := loadCA(caCertPath, caKeyPath); err != nil {
		log.Fatalf("Error loading CA: %v", err)
	}

	// Load the block page HTML.
	blockPageHTML = loadBlockPage()

	// Create a new ServeMux.
	mux := http.NewServeMux()

	// Route to serve the CA certificate.
	mux.HandleFunc("/ca.crt", caHandler)
	// Serve static files from the webroot subdirectory.
	mux.Handle("/webroot/", http.StripPrefix("/webroot/", http.FileServer(http.Dir("webroot"))))
	// All other requests show the block page.
	mux.HandleFunc("/", blockHandler)
	// Route to serve the CA certificate in DER format.
	mux.HandleFunc("/cert.cer", caDERHandler)

	// Create a TLS configuration with our dynamic certificate callback.
	tlsConfig := &tls.Config{
		GetCertificate: getCertificate,
		MinVersion:     tls.VersionTLS12,
	}

	// Create the HTTP server.
	serverAddr := fmt.Sprintf("%s:%s", listenAddr, listenPort)
	server := &http.Server{
		Addr:      serverAddr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	log.Printf("Starting HTTPS server on %s with dynamic certificate generation...", serverAddr)
	// Pass empty strings for cert and key because GetCertificate provides them.
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
