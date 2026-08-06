package verify

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSPRequestFunc allows mocking OCSP request creation for tests
type OCSPRequestFunc func(cert, issuer *x509.Certificate) ([]byte, error)

// performExternalOCSPCheck performs an external OCSP check for the given certificate
func performExternalOCSPCheck(cert, issuer *x509.Certificate, options *VerifyOptions) (*ocsp.Response, error) {
	return performExternalOCSPCheckWithFunc(cert, issuer, options, nil)
}

// performExternalOCSPCheckWithFunc allows injecting a custom OCSP request function for testing
func performExternalOCSPCheckWithFunc(cert, issuer *x509.Certificate, options *VerifyOptions, ocspRequestFunc OCSPRequestFunc) (*ocsp.Response, error) {
	if !options.EnableExternalRevocationCheck {
		return nil, fmt.Errorf("external revocation checking is disabled")
	}

	if len(cert.OCSPServer) == 0 {
		return nil, fmt.Errorf("certificate has no OCSP server URLs")
	}

	// Create OCSP request (use injected func if provided)
	var ocspReq []byte
	var err error
	if ocspRequestFunc != nil {
		ocspReq, err = ocspRequestFunc(cert, issuer)
	} else {
		ocspReq, err = ocsp.CreateRequest(cert, issuer, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP request: %v", err)
	}

	// Get HTTP client with timeout
	client := options.HTTPClient
	if client == nil {
		timeout := options.HTTPTimeout
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}

	// Try each OCSP server URL
	var lastErr error
	for _, serverURL := range cert.OCSPServer {
		req, err := http.NewRequest(http.MethodPost, serverURL, bytes.NewReader(ocspReq))
		if err != nil {
			lastErr = fmt.Errorf("failed to build OCSP request for %s: %v", serverURL, err)
			continue
		}
		// RFC 6960 SS4.2.1: request and response bodies are DER-encoded ASN.1.
		req.Header.Set("Content-Type", "application/ocsp-request")
		req.Header.Set("Accept", "application/ocsp-response")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to contact OCSP server %s: %v", serverURL, err)
			continue
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				// Log error but don't fail the operation
				lastErr = fmt.Errorf("failed to close response body: %v", err)
			}
		}()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("OCSP server %s returned status %d", serverURL, resp.StatusCode)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("failed to read OCSP response from %s: %v", serverURL, err)
			continue
		}

		ocspResp, err := ocsp.ParseResponse(body, issuer)
		if err != nil {
			lastErr = fmt.Errorf("failed to parse OCSP response from %s (content-type %q): %v", serverURL, resp.Header.Get("Content-Type"), err)
			continue
		}

		// Successfully got OCSP response
		return ocspResp, nil
	}

	return nil, lastErr
}

// performExternalCRLCheck performs an external CRL check for the given certificate
// Returns (revocationTime, isRevoked, error)
func performExternalCRLCheck(cert *x509.Certificate, options *VerifyOptions) (*time.Time, bool, error) {
	if !options.EnableExternalRevocationCheck {
		return nil, false, fmt.Errorf("external revocation checking is disabled")
	}

	if len(cert.CRLDistributionPoints) == 0 {
		return nil, false, fmt.Errorf("certificate has no CRL distribution points")
	}

	// Get HTTP client with timeout
	client := options.HTTPClient
	if client == nil {
		timeout := options.HTTPTimeout
		if timeout == 0 {
			timeout = 10 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}

	// Try each CRL distribution point
	var lastErr error
	for _, crlURL := range cert.CRLDistributionPoints {
		req, err := http.NewRequest(http.MethodGet, crlURL, nil)
		if err != nil {
			lastErr = fmt.Errorf("failed to build CRL request for %s: %v", crlURL, err)
			continue
		}
		// CRL distribution points are inconsistent about Content-Type in
		// practice - RFC 5280 implies raw DER as application/pkix-crl, but
		// application/pkcs7-mime, application/x-pkcs7-crl, and a generic
		// application/octet-stream are all common, especially from internal/
		// enterprise CAs - so request the canonical types but sniff the body
		// (see decodeCRLBody) rather than trusting or requiring the header.
		req.Header.Set("Accept", "application/pkix-crl, application/pkcs7-mime, application/x-pkcs7-crl, application/octet-stream")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to download CRL from %s: %v", crlURL, err)
			continue
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				// Log error but don't fail the operation
				lastErr = fmt.Errorf("failed to close response body: %v", err)
			}
		}()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("CRL server %s returned status %d", crlURL, resp.StatusCode)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("failed to read CRL from %s: %v", crlURL, err)
			continue
		}

		crl, err := x509.ParseRevocationList(decodeCRLBody(body))
		if err != nil {
			lastErr = fmt.Errorf("failed to parse CRL from %s (content-type %q): %v", crlURL, resp.Header.Get("Content-Type"), err)
			continue
		}

		// Check if certificate is revoked
		for _, revokedCert := range crl.RevokedCertificateEntries {
			if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return &revokedCert.RevocationTime, true, nil // Certificate is revoked
			}
		}

		// Successfully checked CRL, certificate not revoked
		return nil, false, nil
	}

	return nil, false, lastErr
}

// decodeCRLBody returns the DER-encoded CRL bytes from body. Most CRL
// distribution points serve raw DER as RFC 5280 specifies, but some CAs -
// especially internal/enterprise ones - serve PEM-encoded CRLs instead
// ("-----BEGIN X509 CRL-----"). If body is PEM-encoded, its decoded
// contents are returned; otherwise body is returned unchanged.
func decodeCRLBody(body []byte) []byte {
	if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("-----BEGIN")) {
		return body
	}
	block, _ := pem.Decode(body)
	if block == nil {
		return body
	}
	return block.Bytes
}
