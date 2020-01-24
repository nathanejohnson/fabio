package cert

import (
	"crypto/tls"
	"fmt"
	"log"
	"reflect"
	"time"

	"github.com/hashicorp/consul/api"
	"golang.org/x/crypto/ocsp"
)

type cacheEntry struct {
	or  []byte
	idx uint64
}

type cacheEntryMap map[string]*cacheEntry

func (c cacheEntryMap) delete(key string) {
	delete(c, key)
}

func (c cacheEntryMap) keys() []string {
	r := make([]string, 0, len(c))
	for k := range c {
		r = append(r, k)
	}
	return r
}

func (c cacheEntryMap) fetch(key string) ([]byte, bool) {
	v, ok := c[key]
	if v == nil {
		return nil, ok
	}
	return v.or, ok
}

func (c cacheEntryMap) set(key string, val []byte) {
	or, ok := c[key]
	if !ok {
		or = &cacheEntry{
			or:  val,
			idx: 0,
		}
	} else {
		or.or = val
	}
	c[key] = or
}

type OCSPCacheConsul struct {
	CachePrefixURL string
	certs          []tls.Certificate
	sig            chan struct{}
	errCh          chan error
	client         *api.Client
	key            string
	ocspCache      cacheEntryMap
	of             *ocspFetch
}

func (occ *OCSPCacheConsul) Init(in <-chan []tls.Certificate) chan []tls.Certificate {
	occ.ocspCache = make(map[string]*cacheEntry)
	ocspCacheChan := make(chan map[string]*cacheEntry)
	occ.sig = make(chan struct{})
	out := make(chan []tls.Certificate)
	cfg, key, err := parseConsulURL(occ.CachePrefixURL)
	if err != nil {
		log.Printf("[ERROR] cert: consul url parse failed: %s", err)
	}
	client, err := api.NewClient(cfg)
	if err != nil {
		log.Fatalf("error creating consul client: %s", err)
	}
	occ.key = key
	occ.client = client

	go watchCacheKV(client, key, ocspCacheChan)

	isChanged := func() (bool, error) {
		changed := false
		var err error
		for i := range occ.certs {
			ch, e := evalCert(&occ.certs[i], occ.ocspCache, occ.of)
			if ch {
				changed = true
			}
			if e != nil {
				err = e
			}
		}
		return changed, err
	}

	go func() {
		for {
			var ok bool
			select {
			case occ.certs, ok = <-in:
				if !ok {
					return
				}
				for _, crt := range occ.certs {
					_, _ = evalCert(&crt, occ.ocspCache, occ.of)
				}
				out <- occ.certs
				occ.updateConsul()
			case m, ok := <-ocspCacheChan:
				if !ok {
					return
				}
				occ.ocspCache = m
				changed, err := isChanged()
				if err != nil {
					log.Printf("[ERROR] cert: ocsp cache error %s", err)
				}
				if changed {
					out <- occ.certs
					occ.updateConsul()
				}

			case _, ok = <-occ.sig:
				if !ok {
					return
				}
				changed, err := isChanged()
				occ.errCh <- err
				if changed {
					out <- occ.certs
					occ.updateConsul()
				}
			}
		}
	}()
	return out
}

func (occ *OCSPCacheConsul) updateConsul() {
	upstream, _, err := getOCSPs(occ.client, occ.key, 0)
	if err != nil {
		log.Printf("[ERROR] cert: OCSP error fetching cache from consul: %s", err)
		return
	}

	for k, v := range occ.ocspCache {
		oresp, err := ocsp.ParseResponse(v.or, nil)
		if err != nil || oresp.NextUpdate.Before(time.Now()) {
			delete(occ.ocspCache, k)
			_, _, err := occ.client.KV().DeleteCAS(&api.KVPair{
				Key:         k,
				ModifyIndex: v.idx,
			}, nil)
			if err != nil {
				log.Printf("[WARN] cert: ocsp error deleting from consul: %s", err)
			}
			continue
		}
		u := upstream[k]
		if !reflect.DeepEqual(u.or, v.or) {
			_, _, err := occ.client.KV().CAS(&api.KVPair{
				Key:         k,
				ModifyIndex: v.idx,
				Value:       oresp.TBSResponseData,
			}, nil)
			if err != nil {
				log.Printf("[WARN] cert: ocsp error updating consul: %s", err)
				continue
			}
		}
	}
}

func (occ *OCSPCacheConsul) Cleanup() error {
	occ.sig <- struct{}{}
	return <-occ.errCh
}

func (o *OCSPCacheConsul) Close() error {
	return nil
}

// watchKV monitors a key in the KV store for changes.
func watchCacheKV(client *api.Client, key string, ocspCache chan map[string]*cacheEntry) {
	var lastIndex uint64
	var lastValue map[string]*cacheEntry

	for {
		value, index, err := getOCSPs(client, key, lastIndex)
		if err != nil {
			log.Printf("[WARN] cert: Error fetching OCSP cache from %s. %v", key, err)
			time.Sleep(time.Second)
			continue
		}

		if !reflect.DeepEqual(value, lastValue) || index != lastIndex {
			log.Printf("[DEBUG] cert: OCSP cache index changed to #%d", index)
			ocspCache <- value
			lastValue, lastIndex = value, index
		}
	}
}

func getOCSPs(client *api.Client, key string, waitIndex uint64) (ocspCache map[string]*cacheEntry, lastIndex uint64, err error) {
	q := &api.QueryOptions{RequireConsistent: true, WaitIndex: waitIndex}
	ocspCache = make(map[string]*cacheEntry)
	kvpairs, meta, err := client.KV().List(key, q)
	if err != nil {
		return nil, 0, fmt.Errorf("consul: getOCPSs list: %w", err)
	}
	if len(kvpairs) == 0 {
		return ocspCache, meta.LastIndex, nil
	}
	for _, kvpair := range kvpairs {
		_, err := ocsp.ParseResponse(kvpair.Value, nil)
		if err != nil {
			log.Printf("[WARN] cert: invalid ocsp cache entry for %s", kvpair.Key)
			continue
		}
		ocspCache[kvpair.Key] = &cacheEntry{
			or:  kvpair.Value,
			idx: kvpair.ModifyIndex,
		}
	}
	return ocspCache, meta.LastIndex, nil
}
