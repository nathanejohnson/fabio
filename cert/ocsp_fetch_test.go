package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

var (
	crt, issuer *x509.Certificate
	rs          *ocspFetch
	goodSerial  = big.NewInt(5)
	badSerial   = big.NewInt(6)
)

func TestMain(m *testing.M) {
	certPath := os.Getenv("FABIO_TEST_CERT_FILE")
	keyPath := os.Getenv("FABIO_TEST_KEY_FILE")
	var err error
	var hs *httptest.Server

	if len(certPath) > 0 {
		if len(keyPath) == 0 {
			keyPath = certPath
		}
		crt, issuer, err = loadFromDisk(certPath, keyPath)
		if err != nil {
			fmt.Printf("error loading from disk: %s", err)
			os.Exit(1)
		}
	} else {
		hs, crt, issuer, err = mockOCSPServer()
		if err != nil {
			os.Exit(1)
		}
	}
	rs = NewOCSPFetch(nil)

	m.Run()
	if hs != nil {
		hs.Close()
	}
}

func TestOCSPFetch(t *testing.T) {
	// Test good
	r, err := rs.Renew(crt, issuer, nil)
	if err != nil {
		t.Errorf("error stapling: %s", err)
		t.Fail()
	}
	resp, err := ocsp.ParseResponse(r, issuer)
	if err != nil {
		t.Errorf("error parsing stapled response: %s", err)
		t.Fail()
	}
	if resp.Status != ocsp.Good {
		t.Errorf("unexpected ocsp response status: %d", resp.Status)
		t.Fail()
	}

	t.Logf("IssuedAt: %s, Status: %d, NextUpdate: %s", resp.ProducedAt, resp.Status, resp.NextUpdate)

	// test bad
	crt.SerialNumber = badSerial
	time.Sleep(time.Second * 2)
	r, err = rs.Renew(crt, issuer, nil)
	if err != nil {
		t.Errorf("error stapling bad: %s", err)
		t.Fail()
	}
	resp, err = ocsp.ParseResponse(r, issuer)
	if err != nil {
		t.Logf("expected: error parsing response from bad staple: %s", err)
		return
	}
	if resp.Status == ocsp.Good {
		t.Errorf("unexpected ocsp response status: %d", resp.Status)
		t.Fail()
	}

}

func mockOCSPServer() (hs *httptest.Server, crt, issuer *x509.Certificate, err error) {
	var (
		rKey, iKey, lKey *rsa.PrivateKey
		rCsr, iCsr, lCsr *x509.CertificateRequest
		rCrt, iCrt, lCrt *x509.Certificate
	)

	// root
	rKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	rCsr, err = makeCSR("root", rKey)
	if err != nil {
		return
	}
	rCrt, err = signCSR(rCsr, rKey, nil, true, "")

	// intermediate
	iKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	iCsr, err = makeCSR("intermediate", iKey)

	if err != nil {
		return
	}
	iCrt, err = signCSR(iCsr, rKey, rCrt, true, "")
	if err != nil {
		return
	}

	// Create httptest server
	hs = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := ioutil.ReadAll(r.Body)
		_ = r.Body.Close()
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(w, "error reading body: %s", err)
			return
		}
		oReq, err := ocsp.ParseRequest(b)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(w, "error parsing ocsp request: %s", err)
			return
		}

		tmpl := ocsp.Response{
			Status:       ocsp.Good,
			ThisUpdate:   time.Now(),
			NextUpdate:   time.Now().Add(time.Hour),
			SerialNumber: oReq.SerialNumber,
		}
		if oReq.SerialNumber.Cmp(goodSerial) != 0 {
			tmpl.Status = ocsp.Revoked
		}
		oResp, err := ocsp.CreateResponse(iCrt, iCrt, tmpl, iKey)
		if err != nil {
			w.WriteHeader(500)
			fmt.Fprintf(w, "error creating ocsp respoonse: %s", err)
			return
		}
		_, _ = io.Copy(w, bytes.NewReader(oResp))
	}))

	// leaf
	lKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	lCsr, err = makeCSR("fabio.local", lKey)
	if err != nil {
		return
	}

	lCrt, err = signCSR(lCsr, iKey, iCrt, false, hs.URL)
	return hs, lCrt, iCrt, err
}

func makeCSR(cname string, priv interface{}) (request *x509.CertificateRequest, err error) {
	req := &x509.CertificateRequest{
		Version: 0,
		Subject: pkix.Name{
			Organization:       []string{"fabiolb"},
			OrganizationalUnit: []string{"fabio"},
			Country:            []string{"US"},
			Province:           []string{"Tennessee"},
			Locality:           []string{"Nashville"},
			CommonName:         cname,
		},
		DNSNames:           []string{cname},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, req, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(csrBytes)
}

func loadFromDisk(certPath, keyPath string) (crt, issuer *x509.Certificate, err error) {
	fs := FileSource{
		CertFile: certPath,
		KeyFile:  keyPath,
	}
	cChan := fs.Certificates()
	c := <-cChan
	if len(c[0].Certificate) < 2 {
		err = fmt.Errorf("no issuer certificate found")
		return
	}
	crt, err = x509.ParseCertificate(c[0].Certificate[0])
	if err != nil {
		return
	}
	issuer, err = x509.ParseCertificate(c[0].Certificate[1])
	return
}

func signCSR(
	csr *x509.CertificateRequest,
	privKey interface{},
	signCert *x509.Certificate,
	isCA bool,
	ocspServer string) (*x509.Certificate, error) {

	subjKeyID := make([]byte, 8)
	_, err := rand.Read(subjKeyID)
	if err != nil {
		panic(err)
	}

	crtTmpl := &x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		SerialNumber:       goodSerial,
		Subject:            csr.Subject,
		SubjectKeyId:       subjKeyID,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(10, 0, 0),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		OCSPServer:         []string{ocspServer},
		IsCA:               isCA,
		DNSNames:           csr.DNSNames,
	}
	if isCA {
		crtTmpl.KeyUsage = x509.KeyUsageCertSign
		crtTmpl.BasicConstraintsValid = true
	}

	if signCert == nil {
		// self signed root
		signCert = crtTmpl
	}

	signedRaw, err := x509.CreateCertificate(rand.Reader, crtTmpl, signCert, csr.PublicKey, privKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(signedRaw)
}
