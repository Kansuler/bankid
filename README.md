# Kansuler/bankid

![License](https://img.shields.io/github/license/Kansuler/bankid) ![Version](https://img.shields.io/github/go-mod/go-version/Kansuler/bankid) [![Codacy Badge](https://app.codacy.com/project/badge/Grade/cc405c0102b24c1a8abd15960732856a)](https://www.codacy.com/manual/Kansuler/bankid?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=Kansuler/bankid&amp;utm_campaign=Badge_Grade)

A package to simplify integrations against the authentication and signing service [BankID](https://www.bankid.com/).

It is recommended to read through the [developer guide](https://www.bankid.com/assets/bankid/rp/bankid-relying-party-guidelines-v3.4.pdf) thoroughly to understand the the process, and what responses that can occur.

API and detailed documentation can be found at [https://godoc.org/github.com/Kansuler/bankid](https://godoc.org/github.com/Kansuler/bankid)

## Installation

`go get github.com/Kansuler/bankid`

## Functions

```go
// create new client
New(opts Options) (*bankID, error)

// authenticate user 
(b *bankID) Auth(ctx context.Context, opts AuthOptions) (result authSignResponse, err error)

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
cert, err := ioutil.ReadFile("/path/to/your/cert.p12")
if err != nil {
	return err
}
    
b, err := bankid.New(bankid.Options{
    Passphrase:     "qwerty123",
    SSLCertificate: cert,
    Test:           true,
    Timeout:        5,
})
    
response, err := b.Sign(ctx, bankid.SignOptions{
    PersonalNumber:         "190000000000",
    EndUserIP:              "192.168.0.2",
    UserVisibleData:        base64.StdEncoding.EncodeToString([]byte("Signing test user")),
    UserVisibleDataFormat:  "simpleMarkdownV1",
})

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
