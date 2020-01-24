package cert

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

type ocspFetch struct {
	hc *http.Client
}

// NewOCSPFetch - create a stapler
func NewOCSPFetch(hc *http.Client) *ocspFetch {
	rs := &ocspFetch{hc: hc}
	if hc == nil {
		rs.hc = &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				DisableKeepAlives:     true,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   -1,
				IdleConnTimeout:       90 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
			},
			Timeout: time.Second * 10,
		}
	}
	return rs
}

const ocspContentType = "application/ocsp-request"

// MissingOCSPServer - this is returned when OCSP server extension is missinig from cert
var MissingOCSPServer = errors.New("no OCSP servers in certificate")

// Renew - implements stapler.  This attempts to grab an OCSP response from the OCSPServer listed
// in the certificate.
func (rs *ocspFetch) Renew(cert, issuer *x509.Certificate, options *ocsp.RequestOptions) ([]byte, error) {
	r, err := ocsp.CreateRequest(cert, issuer, options)
	if err != nil {
		return nil, fmt.Errorf("error creating ocsp request: %w", err)
	}
	if len(cert.OCSPServer) == 0 {
		return nil, MissingOCSPServer
	}

	var st []byte

	for _, s := range cert.OCSPServer {
		var resp *http.Response

		resp, err = rs.hc.Post(s, ocspContentType, bytes.NewReader(r))
		if err != nil {
			continue
		}
		if resp.StatusCode >= 400 {
			err = fmt.Errorf("invalid response code %d: %s", resp.StatusCode, resp.Status)
			_, _ = io.Copy(ioutil.Discard, resp.Body)
			_ = resp.Body.Close()
			continue
		}
		st, err = ioutil.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("error requesting data from ocsp server: %w", err)
	}
	return st, nil
}

var ErrMissingIssuer = errors.New("missing issuer, cannot create OCSP request")

func (rs *ocspFetch) RenewTLS(cert *tls.Certificate) (resp []byte, issuer *x509.Certificate, err error) {
	if len(cert.Certificate) < 2 {
		err = ErrMissingIssuer
		return
	}
	var crt *x509.Certificate
	crt, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		err = fmt.Errorf("cert: renewtls: error parsing leaf certificate %w", err)
		return nil, nil, err
	}

	issuer, err = x509.ParseCertificate(cert.Certificate[1])
	if err != nil {
		err = fmt.Errorf("cert: renewtls: error parsing issuer certificate %w", err)
		return

	}

	var raw []byte
	raw, err = rs.Renew(crt, issuer, nil)
	if err != nil {
		err = fmt.Errorf("cert: renewtls: error renewing OCSP: %w", err)
		return nil, nil, err
	}
	_, err = ocsp.ParseResponse(raw, issuer)
	if err != nil {
		err = fmt.Errorf("cert: renewtls: error parsing ocsp response: %w", err)
		return nil, nil, err
	}
	return raw, issuer, nil
}

func halfLife(o *ocsp.Response) time.Duration {
	dur := o.NextUpdate.Sub(o.ThisUpdate)
	if dur == 0 {
		// This should never happen?
		dur = time.Hour * 24
	} else {
		dur >>= 1
	}
	return dur
}

func needsRenewal(o *ocsp.Response) bool {
	return time.Now().Add(halfLife(o)).After(o.NextUpdate)
}
