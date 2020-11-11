package bankid_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/Kansuler/bankid"
	"github.com/brianvoe/gofakeit"
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

func TestBankId_Auth(t *testing.T) {
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

	response, err := b.Auth(context.Background(), bankid.AuthOptions{
		EndUserIp: gofakeit.IPv4Address(),
	})

	assert.NoError(t, err)
	assert.NotEmpty(t, response.OrderRef)
	assert.NotEmpty(t, response.AutoStartToken)
	assert.NotEmpty(t, response.QrStartSecret)
	assert.NotEmpty(t, response.QrStartToken)

	response, err = b.Auth(context.Background(), bankid.AuthOptions{
		PersonalNumber: fmt.Sprintf("19%02d%02d%02d%d", gofakeit.Number(0, 99), gofakeit.Number(1, 12), gofakeit.Number(1, 28), gofakeit.Number(1000, 9999)),
		EndUserIp:      gofakeit.IPv4Address(),
	})

	assert.NoError(t, err)
	assert.NotEmpty(t, response.OrderRef)
	assert.NotEmpty(t, response.AutoStartToken)
	assert.NotEmpty(t, response.QrStartSecret)
	assert.NotEmpty(t, response.QrStartToken)
}

func TestBankId_Sign(t *testing.T) {
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

	response, err := b.Sign(context.Background(), bankid.SignOptions{
		PersonalNumber:  fmt.Sprintf("19%02d%02d%02d%d", gofakeit.Number(0, 99), gofakeit.Number(1, 12), gofakeit.Number(1, 28), gofakeit.Number(1000, 9999)),
		EndUserIP:       gofakeit.IPv4Address(),
		UserVisibleData: base64.StdEncoding.EncodeToString([]byte("Signing test user")),
	})

	assert.NoError(t, err)
	assert.NotEmpty(t, response.OrderRef)
	assert.NotEmpty(t, response.AutoStartToken)
	assert.NotEmpty(t, response.QrStartSecret)
	assert.NotEmpty(t, response.QrStartToken)
}

func TestBankId_Collect(t *testing.T) {
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

	response, err := b.Sign(context.Background(), bankid.SignOptions{
		PersonalNumber:  fmt.Sprintf("19%02d%02d%02d%d", gofakeit.Number(0, 99), gofakeit.Number(1, 12), gofakeit.Number(1, 28), gofakeit.Number(1000, 9999)),
		EndUserIP:       gofakeit.IPv4Address(),
		UserVisibleData: base64.StdEncoding.EncodeToString([]byte("Signing test user")),
	})

	assert.NoError(t, err)
	assert.NotEmpty(t, response.OrderRef)
	assert.NotEmpty(t, response.AutoStartToken)
	assert.NotEmpty(t, response.QrStartSecret)
	assert.NotEmpty(t, response.QrStartToken)

	response2, err := b.Collect(context.Background(), bankid.CollectOptions{
		OrderRef: response.OrderRef,
	})

	assert.NoError(t, err)
	assert.NotEmpty(t, response2.OrderRef)
	assert.Equal(t, bankid.Pending, response2.Status)
	assert.NotEmpty(t, response2.HintCode)
	assert.Empty(t, response2.CompletionData)
}

func TestBankId_Cancel(t *testing.T) {
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

	response, err := b.Auth(context.Background(), bankid.AuthOptions{
		EndUserIp: gofakeit.IPv4Address(),
	})

	assert.NoError(t, err)
	assert.NotEmpty(t, response.OrderRef)

	err = b.Cancel(context.Background(), bankid.CancelOptions{
		OrderRef: response.OrderRef,
	})

	assert.NoError(t, err)

	err = b.Cancel(context.Background(), bankid.CancelOptions{
		OrderRef: response.OrderRef,
	})

	assert.Error(t, err)
}

func TestQr(t *testing.T) {
	str, err := bankid.Qr("c15f3d1d-a209-4c64-89fe-c54209f55146", "43025f26-7cf3-415b-9c66-50835ee8deb4", 0)
	assert.NoError(t, err)
	assert.NotEmpty(t, str)
}
