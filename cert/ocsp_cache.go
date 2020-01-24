package cert

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSPCacher - this interface is implemented by caching backends.
type OCSPCacher interface {

	// This is called once at initialization time.
	Init(in <-chan []tls.Certificate) chan []tls.Certificate

	// Cleanup - called periodically to do housekeeping
	Cleanup() error

	// Close - this is called by fabio before program exit, which
	// gives a chance to ensure data is persisted or cleanup is
	// performed.
	Close() error
}

var ErrEmptyCert = errors.New("no certificate passed")

var ErrNoName = errors.New("no certificate name")

func certKey(cert *tls.Certificate) (string, error) {
	if cert == nil || len(cert.Certificate) == 0 {
		return "", ErrEmptyCert
	}
	crt, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return "", err
	}
	// favor SAN
	var name string
	if len(crt.DNSNames) > 0 {
		name = crt.DNSNames[0]
	} else if len(crt.Subject.CommonName) == 0 {
		return "", ErrNoName
	} else {
		name = crt.Subject.CommonName
	}

	return name, nil
}

type cacheAccessor interface {
	fetch(key string) ([]byte, bool)
	set(key string, val []byte)
	delete(key string)
	keys() []string
}

func evalCert(crt *tls.Certificate, ca cacheAccessor, of *ocspFetch) (renewed bool, err error) {
	var key string
	key, err = certKey(crt)
	if err != nil {
		return false, err
	}
	renew := true
	if oraw, ok := ca.fetch(key); ok {
		oresp, err := ocsp.ParseResponse(oraw, nil)
		if err != nil {
			renew = true
		} else {
			renew = needsRenewal(oresp)
		}
	}
	if renew {
		o, _, err := of.RenewTLS(crt)
		if err != nil {
			return false, err
		}
		crt.OCSPStaple = o
		ca.set(key, o)
		return true, nil
	}
	return false, nil
}

func evict(ca cacheAccessor, certs []tls.Certificate) bool {
	// This evicts invalid entries from the ocspMap
	valids := make(map[string]bool)
	for i := range certs {
		k, err := certKey(&certs[i])
		if err != nil {
			continue
		}
		valids[k] = true
	}
	var deletes []string
	for _, k := range ca.keys() {
		v, _ := ca.fetch(k)
		oresp, err := ocsp.ParseResponse(v, nil)
		if err != nil {
			deletes = append(deletes, k)
			continue
		}

		if !valids[k] || time.Now().After(oresp.NextUpdate) {
			deletes = append(deletes, k)
		}
	}
	for _, v := range deletes {
		ca.delete(v)
	}
	return len(deletes) > 0
}
