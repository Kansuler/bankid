# Kansuler/bankid

![License](https://img.shields.io/github/license/Kansuler/bankid) ![Version](https://img.shields.io/github/go-mod/go-version/Kansuler/bankid) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/03c7bae4e4284cf2977222b8843f312d)](https://app.codacy.com/gh/Kansuler/bankid/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

A package to simplify integrations against the authentication and signing service [BankID](https://www.bankid.com/).

It is recommended to read through the [developer guide](https://www.bankid.com/utvecklare/guider/teknisk-integrationsguide/rp-introduktion) thoroughly to understand the the process, and what responses that can occur.

API and detailed documentation can be found at [https://godoc.org/github.com/Kansuler/bankid](https://godoc.org/github.com/Kansuler/bankid)

## Installation

`go get github.com/Kansuler/bankid`

## Functions

```go
// create new client
New(opts Options) (*bankID, error)

// authenticate user 
(b *bankID) Auth(ctx context.Context, opts AuthOptions) (result authSignResponse, err error)

// authenticate user over phone
(b *BankID) PhoneAuth(ctx context.Context, opts PhoneAuthOptions) (result phoneAuthResponse, err error)

// sign legal document
(b *bankID) Sign(ctx context.Context, opts SignOptions) (result authSignResponse, err error)

// collect status of sign or auth order
(b *bankID) Collect(ctx context.Context, opts CollectOptions) (result collectResponse, err error)

// cancel current pending order
(b *bankID) Cancel(ctx context.Context, opts CancelOptions) error

// generate hashed string for animated qr code
Qr(startToken, startSecret string, seconds int64) (string, error)
```

## Usage

```go
ctx := context.Background()

// For testing, you can use `bankid.TestSSLCertificate`
cert, err := ioutil.ReadFile("/path/to/your/cert.p12")
if err != nil {
	return err
}

b, err := bankid.New(bankid.Options{
    Passphrase:           "qwerty123",
    SSLCertificate:       cert,
	CertificateAuthority: bankid.TestCertificate,
    URL:                  bankid.TestURL,
    Timeout:              5,
})

response, err := b.Sign(ctx, bankid.SignOptions{
    EndUserIP:              "192.168.0.2",
    UserVisibleData:        base64.StdEncoding.EncodeToString([]byte("Signing test user")),
    UserVisibleDataFormat:  "simpleMarkdownV1",
})

qr := bankid.Qr(response.QrStartToken, response.QrStartSecret, 0)
if err != nil {
    return err
}

response2, err := b.Collect(ctx, bankid.CollectOptions{
	OrderRef: response.OrderRef,
})

if err != nil {
    return err
}
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.
