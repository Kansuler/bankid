// Package bankid provides methods that align with the BankID v6.0 API contract.
package bankid

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const (
	TestURL = "https://appapi2.test.bankid.com"
	ProdURL = "https://appapi2.bankid.com"
)

var (
	//go:embed prod.ca.crt
	ProdCACertificate []byte

	//go:embed test.ca.crt
	TestCACertificate []byte

	//go:embed testcert.p12
	TestSSLCertificate []byte
)

// Options are settings that is used by the http client
type Options struct {
	// Passphrase is the password for the p12 encoded SSL certificate
	Passphrase string

	// SSLCertificate is a byte encoded array with the SSL certificate content
	SSLCertificate []byte

	// CertificateAuthority is a byte encoded array with the CA certificate content
	CertificateAuthority []byte

	// URL is the endpoint which we use to talk with BankID and can be replaced
	URL string

	// Timeout in seconds for the http client
	Timeout int // Client timeout in seconds
}

// BankID holds settings for this session
type BankID struct {
	// client is the http client that is used to talk with BankID
	client *http.Client

	// url is the endpoint which we use to talk with BankID
	url string
}

// New creates a new client
func New(opts Options) (*BankID, error) {
	key, leaf, err := pkcs12.Decode([]byte(opts.SSLCertificate), opts.Passphrase)
	if err != nil {
		return nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{leaf.Raw},
		PrivateKey:  key.(crypto.PrivateKey),
		Leaf:        leaf,
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(opts.CertificateAuthority)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates:       []tls.Certificate{cert},
			RootCAs:            caCertPool,
			InsecureSkipVerify: false,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second * time.Duration(opts.Timeout),
	}

	return &BankID{
		client: client,
		url:    strings.TrimSuffix(opts.URL, "/"),
	}, nil
}

func (b *BankID) doHTTP(ctx context.Context, url string, postBody, result interface{}) error {
	body, err := json.Marshal(postBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errCode ServiceError
		err = json.NewDecoder(resp.Body).Decode(&errCode)
		if err != nil {
			return err
		}

		return fmt.Errorf("[%s] %s", errCode.ErrorCode, errCode.Details)
	}

	if result != nil {
		err = json.NewDecoder(resp.Body).Decode(result)
	}

	return err
}

// ServiceError is the error response from the BankID Api
type ServiceError struct {
	ErrorCode string `json:"errorCode"`
	Details   string `json:"details"`
}

// AuthSignResponse is the response from the auth request
type AuthSignResponse struct {
	OrderRef       string `json:"orderRef"`
	AutoStartToken string `json:"autoStartToken"`
	QrStartToken   string `json:"qrStartToken"`
	QrStartSecret  string `json:"qrStartSecret"`
}

// PhoneAuthResponse is the response from the phone auth request
type PhoneAuthResponse struct {
	OrderRef string `json:"orderRef"`
}

// Requirement is optional parameters that control the authentication process
// Read more about these on
// https://www.bankid.com/utvecklare/guider/teknisk-integrationsguide/graenssnittsbeskrivning/auth-and-sign
// Requirements
type Requirement struct {
	PinCode             bool     `json:"pinCode,omitempty"`
	Mrtd                bool     `json:"mrtd,omitempty"`
	CardReader          string   `json:"cardReader,omitempty"`
	CertificatePolicies []string `json:"certificatePolicies,omitempty"`
	PersonalNumber      string   `json:"personalNumber,omitempty"`
}

// AuthOptions for the authentication request
type AuthOptions struct {
	// Required: The user IP address as seen by RP. String. IPv4 and IPv6 is allowed. Correct IP address must be the IP
	// address representing the user agent (the end user device) as seen by the RP. In case of inbound proxy, special
	// considerations may need to be taken into account to get the correct address. In some use cases the IP address is
	// not available, for instance in voice-based services. In these cases, the internal representation of those
	// systems’ IP address may be used.
	EndUserIp string `json:"endUserIp"`

	// Optional: Text displayed to the user during authentication with BankID, with the purpose of providing context for
	// the authentication and to enable users to detect identification errors and averting fraud attempts. The text can
	// be formatted using CR, LF and CRLF for new lines. The text must be encoded as UTF-8 and then base 64 encoded.
	// 1—1 500 characters after base 64 encoding.
	UserVisibleData string `json:"userVisibleData,omitempty"`

	// Optional: Data not displayed to the user. String. The value must be base 64-encoded. 1-1 500 characters after
	// base 64-encoding.
	UserNonVisibleData string `json:"userNonVisibleData,omitempty"`

	// Optional: If present, and set to “simpleMarkdownV1”, this parameter indicates that userVisibleData holds
	// formatting characters which, will potentially make the text displayed to the user nicer to look at. For further
	// information of formatting options, please see the Guidelines for formatting text.
	UserVisibleDataFormat string `json:"userVisibleDataFormat,omitempty"`

	// Optional: Requirements on how the auth or sign order must be performed.
	Requirement Requirement `json:"requirement,omitempty"` // Optional settings for the authentication process
}

// Auth initiates an authentication order. Use the collect method to query the status of the order. If the request is
// successful the response includes orderRef, autoStartToken, qrStartToken and qrStartSecret.
func (b *BankID) Auth(ctx context.Context, opts AuthOptions) (result AuthSignResponse, err error) {
	err = b.doHTTP(ctx, fmt.Sprintf("%s/rp/v6.0/auth", b.url), opts, &result)
	return
}

// PhoneAuthOptions for the phone authentication request
type PhoneAuthOptions struct {
	// Required: The personal number of the user. String. 12 digits.
	PersonalNumber string `json:"personalNumber"`

	// Required: Indicate if the user or the RP initiated the phone call.
	// user: user called the RP
	CallInitiator string `json:"callInitiator"`

	// Optional: Text displayed to the user during authentication with BankID, with the purpose of providing context for
	// the authentication and to enable users to detect identification errors and averting fraud attempts. The text can
	// be formatted using CR, LF and CRLF for new lines. The text must be encoded as UTF-8 and then base 64 encoded.
	// 1—1 500 characters after base 64 encoding.
	UserVisibleData string `json:"userVisibleData,omitempty"`

	// Optional: Data not displayed to the user. String. The value must be base 64-encoded. 1-1 500 characters after
	// base 64-encoding.
	UserNonVisibleData string `json:"userNonVisibleData,omitempty"`

	// Optional: If present, and set to “simpleMarkdownV1”, this parameter indicates that userVisibleData holds
	// formatting characters which, will potentially make the text displayed to the user nicer to look at. For further
	// information of formatting options, please see the Guidelines for formatting text.
	UserVisibleDataFormat string `json:"userVisibleDataFormat,omitempty"`

	// Optional: Requirements on how the auth or sign order must be performed.
	Requirement Requirement `json:"requirement,omitempty"` // Optional settings for the authentication process
}

// PhoneAuth initiates a phone authentication order. Use the collect method to query the status of the order. If the
// request is successful the response includes orderRef, autoStartToken, qrStartToken and qrStartSecret.
func (b *BankID) PhoneAuth(ctx context.Context, opts PhoneAuthOptions) (result PhoneAuthResponse, err error) {
	err = b.doHTTP(ctx, fmt.Sprintf("%s/rp/v6.0/phone/auth", b.url), opts, &result)
	return
}

// SignOptions for the sign request
type SignOptions struct {
	// Required: The user IP address as seen by RP. String. IPv4 and IPv6 is allowed. Correct IP address must be the IP
	// address representing the user agent (the end user device) as seen by the RP. In case of inbound proxy, special
	// considerations may need to be taken into account to get the correct address. In some use cases the IP address is
	// not available, for instance in voice-based services. In these cases, the internal representation of those
	// systems’ IP address may be used.
	EndUserIp string `json:"endUserIp"`

	// Required: Text to be displayed to the user. String. The text can be formatted using CR, LF and CRLF for new
	// lines. The text must be encoded as UTF-8 and then base 64 encoded. 1 – 40,000 characters after base 64 encoding.
	UserVisibleData string `json:"userVisibleData,omitempty"`

	// Optional: Data not displayed to the user. String. The value must be base 64 encoded. 1 – 200,000 characters after
	// base 64-encoding.
	UserNonVisibleData string `json:"userNonVisibleData,omitempty"`

	// Optional: If present, and set to “simpleMarkdownV1”, this parameter indicates that userVisibleData holds
	// formatting characters which, will potentially make the text displayed to the user nicer to look at. For further
	// information of formatting options, please see the Guidelines for formatting text.
	UserVisibleDataFormat string `json:"userVisibleDataFormat,omitempty"`

	// Optional: Requirements on how the sign order must be performed
	Requirement *Requirement `json:"requirement,omitempty"`
}

// Sign initiates an signing order. Use the collect method to query the status of the order. If the request is successful
// the response includes orderRef, autoStartToken, qrStartToken and qrStartSecret.
func (b *BankID) Sign(ctx context.Context, opts SignOptions) (result AuthSignResponse, err error) {
	err = b.doHTTP(ctx, fmt.Sprintf("%s/rp/v6.0/sign", b.url), opts, &result)
	return
}

// CollectOptions for the collect method
type CollectOptions struct {
	// OrderRef as given by either sign or auth request
	OrderRef string `json:"orderRef"`
}

type StatusType string

const (
	// Pending is the status of a pending order and means hintCode was provided
	Pending StatusType = "pending"

	// Failed is the status of a failed order and means hintCode was provided
	Failed StatusType = "failed"

	// Complete is the status of a completed order and means completionData was provided
	Complete StatusType = "complete"
)

type HintCodeType string

// These are possible, but not exclusive hint codes. You need to handle other codes as well
const (
	// OutstandingTransaction Order is pending. The BankID app has not yet received the order. The hintCode will later
	// change to noClient, started or userSign.
	OutstandingTransaction HintCodeType = "outstandingTransaction"

	// NoClient Order is pending. The client has not yet received the order.
	NoClient HintCodeType = "noClient"

	// Started Order is pending. A BankID client has launched with autostarttoken but a usable ID has not yet been found
	// in the client. When the client launches there may be a short delay until all IDs are registered. The user may not
	// have any usable IDs, or is yet to insert their smart card.
	Started HintCodeType = "started"

	// UserMrtd Order is pending. A client has launched and received the order but additional steps for providing MRTD
	// information is required to proceed with the order.
	UserMrtd HintCodeType = "userMrtd"

	// UserCallConfirm Order is waiting for the user to confirm that they have received this order while in a call with
	// the RP.
	UserCallConfirm HintCodeType = "userCallConfirm"

	// UserSign Order is pending. The BankID client has received the order.
	UserSign HintCodeType = "userSign"

	// ExpiredTransaction The order has expired. The BankID security app/program did not launch, the user did not
	// finalize the signing or the RP called collect too late.
	ExpiredTransaction HintCodeType = "expiredTransaction"

	// CertificateErr This error is returned if:
	// 1. The user has entered the wrong PIN code too many times. The BankID cannot be used.
	// 2. The user’s BankID is blocked.
	// 3. The user’s BankID is invalid.
	CertificateErr HintCodeType = "certificateErr"

	// UserCancel The order was cancelled by the user. userCancel may also be returned in some rare cases related to
	// other user interactions.
	UserCancel HintCodeType = "userCancel"

	// Cancelled The order was cancelled. The system received a new order for the user.
	Cancelled HintCodeType = "cancelled"

	// StartFailed The user did not provide their ID or the client did not launch within a certain time limit. Potential
	// causes are:
	// 1. RP did not use autoStartToken when launching the BankID security app. RP must correct this in their
	// implementation.
	// 2. Client software was not installed or other problem with the user’s device.
	StartFailed HintCodeType = "startFailed"
)

type CompletionDataUserType struct {
	PersonalNumber string `json:"personalNumber"`
	Name           string `json:"name"`
	GivenName      string `json:"givenName"`
	Surname        string `json:"surname"`
}

type CompletionDataDeviceType struct {
	IpAddress string `json:"ipAddress"`
	Uhi       string `json:"uhi"`
}

type CompletionDataType struct {
	User            CompletionDataUserType   `json:"user"`
	Device          CompletionDataDeviceType `json:"device"`
	BankIdIssueDate string                   `json:"bankIdIssueDate"`
	StepUp          bool                     `json:"stepUp"`
	Signature       string                   `json:"signature"`
	OcspResponse    string                   `json:"ocspResponse"`
}

type CollectResponse struct {
	OrderRef       string             `json:"orderRef"`
	Status         StatusType         `json:"status"` // pending, failed, complete
	HintCode       HintCodeType       `json:"hintCode"`
	CompletionData CompletionDataType `json:"completionData"`
}

// Collect provides the result of a sign or auth order using the orderRef as reference. You should keep on calling
// collect every two seconds as long as status indicates pending. You must abort if status indicates failed. The user
// identity is returned when complete.
func (b *BankID) Collect(ctx context.Context, opts CollectOptions) (result CollectResponse, err error) {
	err = b.doHTTP(ctx, fmt.Sprintf("%s/rp/v6.0/collect", b.url), opts, &result)
	return
}

// CancelOptions for the cancel method
type CancelOptions struct {
	// OrderRef as given by either sign or auth request
	OrderRef string `json:"orderRef"`
}

// Cancel an ongoing sign or auth order. This is typically used if the user cancels the order in your service or app.
func (b *BankID) Cancel(ctx context.Context, opts CancelOptions) error {
	return b.doHTTP(ctx, fmt.Sprintf("%s/rp/v6.0/cancel", b.url), opts, nil)
}

// Qr is a helper function that generates a string that is transformed into a QR code. It takes startToken, startSecret
// and seconds since the auth order was created. The QR Code need to be updated every second.
func Qr(startToken, startSecret string, seconds int64) (string, error) {
	hash := hmac.New(sha256.New, []byte(startSecret))
	_, err := hash.Write([]byte(fmt.Sprintf("%d", seconds)))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("bankid.%s.%d.%s", startToken, seconds, hex.EncodeToString(hash.Sum(nil))), nil
}
