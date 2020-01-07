package cert

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"time"
)

type StapleSource struct {
	src Source
	oc  OCSPCacher
}

var ErrNotIssuer = errors.New("not an issuer")

func (ss *StapleSource) Issue(commonName string) (*tls.Certificate, error) {
	if i, ok := ss.src.(Issuer); ok {
		return i.Issue(commonName)
	}
	return nil, ErrNotIssuer
}

func (ss *StapleSource) LoadClientCAs() (*x509.CertPool, error) {
	return ss.src.LoadClientCAs()
}

func (ss *StapleSource) Certificates() chan []tls.Certificate {
	ch := ss.oc.Init(ss.src.Certificates())
	// Periodically run Cleanup()
	go func() {
		goodInt := time.Hour * 1
		badInt := time.Minute
		i := badInt
		t := time.NewTimer(i)
		for {
			<-t.C
			err := ss.oc.Cleanup()
			if err != nil {
				log.Printf("[ERROR] staple_source error from cache: %s", err)
				i = badInt
			} else {
				i = goodInt
			}
			t.Reset(i)

		}
	}()
	return ch
}
