package cert

import (
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"log"
)

// Implement cacheAccessor - not thread safe
type simpleMap map[string][]byte

func (s simpleMap) fetch(key string) ([]byte, bool) {
	val, ok := s[key]
	return val, ok
}

func (s simpleMap) set(key string, val []byte) {
	s[key] = val
}

func (s simpleMap) delete(key string) {
	delete(s, key)
}

func (s simpleMap) keys() []string {
	r := make([]string, 0, len(s))
	for k := range s {
		r = append(r, k)
	}
	return r
}

type OCSPCacheInMem struct {
	certs        []tls.Certificate
	of           *ocspFetch
	sig          chan struct{}
	ocspMap      simpleMap
	errCh        chan error
	storeResults bool
	storePath    string
}

func (ocim *OCSPCacheInMem) Init(in <-chan []tls.Certificate) chan []tls.Certificate {

	ch := make(chan []tls.Certificate)
	ocim.sig = make(chan struct{})
	ocim.errCh = make(chan error)
	ocim.ocspMap = make(map[string][]byte)
	if ocim.storeResults {
		err := ocim.LoadFromDisk()
		if err != nil {
			log.Printf("[ERROR] cert: unable to load ocsp cache from disk: %s", err)
		}
	}

	go func() {
		defer close(ocim.errCh)
		for {
			ok := false
			select {
			case ocim.certs, ok = <-in:
				if !ok {
					return
				}
				for i := range ocim.certs {
					_, _ = evalCert(&ocim.certs[i], ocim.ocspMap, ocim.of)
				}
				ch <- ocim.certs
				if ocim.storeResults {
					err := ocim.StoreOnDisk()
					if err != nil {
						log.Printf("[ERROR] cert: ocsp unable to store on disk: %s", err)
					}
				}
			case _, ok = <-ocim.sig:
				// Cleanup
				if !ok {
					return
				}
				changed := false
				var err error
				for i := range ocim.certs {
					ch, e := evalCert(&ocim.certs[i], ocim.ocspMap, ocim.of)
					if ch {
						changed = true
					}
					if e != nil {
						err = e
					}
				}
				ocim.errCh <- err
				if changed {
					ch <- ocim.certs
				}
				if (evict(ocim.ocspMap, ocim.certs) || changed) && ocim.storeResults {
					err = ocim.StoreOnDisk()
					if err != nil {
						log.Printf("[ERROR] cert: ocsp unable to store on disk: %s", err)
					}
				}
			}
		}
	}()
	return ch
}

func (ocim *OCSPCacheInMem) Cleanup() error {
	ocim.sig <- struct{}{}
	return <-ocim.errCh
}

func (ocim *OCSPCacheInMem) Close() error {
	// This will panic if called more than once
	close(ocim.sig)
	return <-ocim.errCh
}

func (ocim *OCSPCacheInMem) LoadFromDisk() error {
	buf, err := ioutil.ReadFile(ocim.storePath)
	if err != nil {
		return err
	}
	return json.Unmarshal(buf, &ocim.ocspMap)
}

func (ocim *OCSPCacheInMem) StoreOnDisk() error {
	if ocim.ocspMap == nil {
		return nil
	}
	v, err := json.Marshal(ocim.ocspMap)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(ocim.storePath, v, 0644)
}
