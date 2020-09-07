package bankid_test

import (
	"github.com/Kansuler/bankid"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestNew(t *testing.T) {
	cert, err := ioutil.ReadFile("testcert.p12")
	if err != nil {
		t.Fatalf("could not load test certificate: %s", err.Error())
	}

	b, err := bankid.New(bankid.Options{
		Passphrase:     "qwerty123",
		SSLCertificate: cert,
		Test:           true,
		Timeout:        5,
	})

	assert.NoError(t, err)
	assert.NotNil(t, b)

	b, err = bankid.New(bankid.Options{
		Passphrase:     "321ytrewq",
		SSLCertificate: cert,
		Test:           true,
		Timeout:        5,
	})

	assert.Error(t, err)
	assert.Nil(t, b)
}
