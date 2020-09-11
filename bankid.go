// Package bankid provides methods that align with the BankID v5.1 API contract.
package bankid

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/pkcs12"
	"net/http"
	"time"
)

type webServiceURL string

const (
	testURL webServiceURL = "https://appapi2.test.bankid.com"
	prodURL webServiceURL = "https://appapi2.bankid.com"
)

type certificateAuthority string

const (
	prodCertificate certificateAuthority = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZ2akNDQTZhZ0F3SUJBZ0lJVHlUaC91MWJFeG93RFFZSktvWklodmNOQVFFTkJRQXdZakVrTUNJR0ExVUUKQ2d3YlJtbHVZVzV6YVdWc2JDQkpSQzFVWld0dWFXc2dRa2xFSUVGQ01Sb3dHQVlEVlFRTERCRkpibVp5WVhOMApjblZqZEhWeVpTQkRRVEVlTUJ3R0ExVUVBd3dWUW1GdWEwbEVJRk5UVENCU2IyOTBJRU5CSUhZeE1CNFhEVEV4Ck1USXdOekV5TXpRd04xb1hEVE0wTVRJek1URXlNelF3TjFvd1lqRWtNQ0lHQTFVRUNnd2JSbWx1WVc1emFXVnMKYkNCSlJDMVVaV3R1YVdzZ1FrbEVJRUZDTVJvd0dBWURWUVFMREJGSmJtWnlZWE4wY25WamRIVnlaU0JEUVRFZQpNQndHQTFVRUF3d1ZRbUZ1YTBsRUlGTlRUQ0JTYjI5MElFTkJJSFl4TUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGCkFBT0NBZzhBTUlJQ0NnS0NBZ0VBd1ZBNHNuWmlTRkkzcjY0THZZdTRtT3NJNDJBOWFMS0VRR3E0SVpvMjU3aXEKdlBIODJTTXZnQkpnRTUya0N4N2dRTW1aN2lTbTM5Q0VBMTlobElMaDhKRUpOVHlKTnhNeFZETjZjZkpQMWpNSApKZVRFUzFUbVZiV1VxR3lMcHlUOExDSmhDOVZxNFczdC9PMXN2R0pOT1VRSVFMNGVBSFN2V1RWb2FseHpvbUpoCk9uOTdFTmpYQXQ0QkxiNnNIZlZCdm1CNVJlSzBVZndwTkFDRk0xUk44YnRFYURkV0M0UGZBNzJ5elYzd0svY1kKNWgyazFSTTFzMTlQam94bnBKcXJtbjRxWm1QNHROL25rMmQ3YzRGRXJKQVAwcG5Oc2xsMStKZmtkTWZpUEQzNQorcWNjbHBzcHpQMkxwYXVRVnlQYk8yMU5oK0VQdHI3K0lpYzJ0a2d6MGcxa0swSUwvZm9GckowSWV2eXIzRHJtCjJ1Um5BMGVzWjQ1R09tWmhFMjJteWNFWDlsN3c5anJkc0t0cXM3Ti9UNDZoaWw0eEJpR2JsWGtxS05HNlR2QVIKazZYcU9wM1J0VXZHR2FLWm5HbGxzZ1R2UDM4L25yU01sc3pOb2pybGJEbm0xNkdHb1JUUW53cjhsK1l2YnovZQp2L2U2d1ZGRGpiNTJaQjBaL0tUZmpYT2w1Y0FKN09DYk9ETVdmOE5hNTZPVGxJa3JrNU55VS91R3pKRlVRU3ZHCmRMSFVpcEovc1RaQ2JxTlNaVXdib0kwb1FOTy9ZZ2V6Mko2emdXWEdwRFdpTjRMR0xEbUJoQjNUOENNUXU5Si8KQmNGdmdqblV5aHlpbTM1a0RwalZQQzhuclNpcjVPa2FZZ0dkWVdkRHV2MTQ1NmxGTlBOTlFjZFpkdDVmY21NQwpBd0VBQWFONE1IWXdIUVlEVlIwT0JCWUVGUGdxc3V4NVJ0Y3JJaEFWZXVMQlNnQnVSREZWTUE4R0ExVWRFd0VCCi93UUZNQU1CQWY4d0h3WURWUjBqQkJnd0ZvQVUrQ3F5N0hsRzF5c2lFQlY2NHNGS0FHNUVNVlV3RXdZRFZSMGcKQkF3d0NqQUlCZ1lxaFhCT0FRUXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01BMEdDU3FHU0liM0RRRUJEUVVBQTRJQwpBUUFKT2pVT1MyR0pQTnJycnFmNTM5YU4xL0ViVWo1WlZSakc0d3pWdFg1eVZxUEdjUlpqVVFsTlRjZk9wd1BvCmN6S0JuTlgyT01GK1FtOTRiYit4WGMvMDhBRVJxSkozRlBLdThvRE5lSytSdjFYNG5oOTVKNFJIWmN2bDRBR2gKRUNtR015aHlDZWEwcVpCRkJzQnFRUjdvQzlhZllPeHNTb3ZhUHFYMzFRTUxVTFdVWW9CS1dXSExWVklvSGpBbQpHdEF6TWtMd2UwL2xyVnlBcHI5aXlYV2hWcitxWUdtRkd3MStyd212RG1tU0xXTldhd1lnSDROWXhUZjh6NWhCCmlET2RBZ2lsdnlpQUY4WWwwa0NLVUIyZkFQaFJOWWxFY04rVVAvS0wyNGgvcEIraFo5bXZSMHRNNm5XM0hWWmEKRHJ2Uno0VmloWjh2UmkzZlluT0FrTkU2a1pkcnJkTzdMZEJjOXlZa2ZRZFRjeTBOK0F3N3E0VGtROG5wb21yVgptVEthUGh0R2hBN1ZJQ3lSTkJWY3Z5b3hyK0NZN2FSUXlIbi9DN24valJzUVl4czd1Yyttc3E2alJTNEhQSzhvCmxuRjl1c1daWDZLWSs4bXdlSmlURTR1TjRaVVVCVXR0OFdjWFhEaUsvYnhFRzJhbWpQY1ovYjRMWHdHQ0piK2EKTldQNCtpWTZrQktyTUFOczAxcEx2dFZqVVM5UnRSclkzY05FT2htS2hPMHFKU0RYaHNUY1Z0cGJEcjM3VVRTcQpRVnc4M2RSZWlBUlB3R2RVUm1ta2FoZUg2ejRrNnFFVVNYdUZjaDB3NTNVQWMrMWFCWFIxYmd5RnFNZHk3WXhpCmIyQVl1N3duckhpb0RXcVA2RFRrVVNVZU1CL3pxV1BNL3F4NlFOTk9jYU9jakE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
	testCertificate certificateAuthority = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUYwRENDQTdpZ0F3SUJBZ0lJSWhZYXh1NGtoZ0F3RFFZSktvWklodmNOQVFFTkJRQXdiREVrTUNJR0ExVUUKQ2d3YlJtbHVZVzV6YVdWc2JDQkpSQzFVWld0dWFXc2dRa2xFSUVGQ01Sb3dHQVlEVlFRTERCRkpibVp5WVhOMApjblZqZEhWeVpTQkRRVEVvTUNZR0ExVUVBd3dmVkdWemRDQkNZVzVyU1VRZ1UxTk1JRkp2YjNRZ1EwRWdkakVnClZHVnpkREFlRncweE5ERXhNakV4TWpNNU16RmFGdzB6TkRFeU16RXhNak01TXpGYU1Hd3hKREFpQmdOVkJBb00KRzBacGJtRnVjMmxsYkd3Z1NVUXRWR1ZyYm1scklFSkpSQ0JCUWpFYU1CZ0dBMVVFQ3d3UlNXNW1jbUZ6ZEhKMQpZM1IxY21VZ1EwRXhLREFtQmdOVkJBTU1IMVJsYzNRZ1FtRnVhMGxFSUZOVFRDQlNiMjkwSUVOQklIWXhJRlJsCmMzUXdnZ0lpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElDRHdBd2dnSUtBb0lDQVFDQUtXc0pjL2tWLzA0MzRkK1MKcW4xOW1Jcjg1UlovUGdSRmFVcGxTcm5odXpBbWFYaWhQTENFc2QzTWgvWUVyeWdjeGhRL01Bemk1T1ovYW5mdQpXU0N3Y2VSbFFJTnR2bFJQZE1vZVp0dTI5RnNudEsxWjVyMlNZTmRGd2JSRmI4V045RnNVMEt2QzV6Vm51RE1nCnM1ZFVad1RtZHpYNVpkTFA3cGRnQjN6aFRucmE1T1J0a2lXaVV4SlZldjlrZVJnQW8wMFpISVJKK3hUZmlTUGQKSmMzMTRtYWlnVlJRWmRHS1N5UWNRTVRXaTFZTHdkMnp3T2FjTnhsZVlmOHhxS2drWnNta3JjNERwMm1SNVBrcgpubktCNkE3c0FPU05hdHVhN004NkVnY0dpOUFhRXlhUk1rWUpJbWJCZnphTmxhQlB5TVN2d21CWnpwMnhLYzlPCkQzVTA2b2dWNkNKakpMN2hTdVZjNXgvMkgwNGQrMkkrREt3ZXA2WUJvVkw5TDgxZ1JZUnljcWcrdytjVFoxVEYKL3M2TkM1WVJLU2VPQ3JMdzNvbWJoanl5dVBsOFQvaDljcFh0Nm0zeTJ4SVZMWVZ6ZURoYXFsM2hkaTZJcFJoNgpyd2tNaEovWG1PcGJEaW5YYjFmV2RGT3lRd3FzWFFXT0V3S0JZSWtNNmNQbnVpZDdxd2F4ZlAyMmhEZ0FvbEdNCkxZN1RQS1VQUndWK2E1WTNWUGw3aDBZU0s3bER5Y2tUSmR0QnFJNmQ0UFdRTG5IYWtVZ1JReTY5blpoR1J0VXQKUE1TSjdJNFF0dDNCNkF3RHErU0pUZ2d3dEpRSGVpZDBqUGtpNnBvdWVuaFBRNmRaVDUzMngxNlhEK1dJY0QyZgovL1h6ek91ZVMyOUtCN2x0L3dINUs2RXV4d0lEQVFBQm8zWXdkREFkQmdOVkhRNEVGZ1FVRFk2WEovRklSRlgzCmRCNFdlcDNSVk04NFJYb3dEd1lEVlIwVEFRSC9CQVV3QXdFQi96QWZCZ05WSFNNRUdEQVdnQlFOanBjbjhVaEUKVmZkMEhoWjZuZEZVenpoRmVqQVJCZ05WSFNBRUNqQUlNQVlHQkNvREJBVXdEZ1lEVlIwUEFRSC9CQVFEQWdFRwpNQTBHQ1NxR1NJYjNEUUVCRFFVQUE0SUNBUUE1czU5L09saW80c3ZIWGlLdTdzUFFSdnJmNEdmR0I3aFVqQkdrCllXMllPSFRZbkhhdlNxbEJBU0hjOGdHR3d1Yzd2NytIK3ZtT2ZTTFpmR0RxeG5CcWVKeDFINUUwWXFFWHROcVcKRzFKdXNJRmE5eFd5cGNPTmpnOXY3SU1ueHhRekxZd3M0WXdnUHljaHBNeldZNkI1aFpzalV5S2dCKzFpZ3huZgp1YUJ1ZUxQdzNaYUpoY0NMOGd6NlNkQ0ttUXBYNFZhQWFkUzB2ZE1yQk9tZDgyNkgrYURHWmVrMXZNanVIMTFGCmZKb1hZMmp5RG5sb2w3WjRCZkhjMDExdG9XTk14b2pJN3crVTRLS0NiU3hwV0ZWWUlUWjhXbFlIY2orYjJBMSsKZEZRWkZ6UU4rWTFXeDNWSVVxU2tzNlA3RjVhRi9sNFJCbmd5MDh6a1A3aUxBL0M3cm02MXhXeFRtcGozcDZTRwpmVUJzcnNCdkJnZkpRSEQvTXg4VTNpUUNhMFZqMVhQb2dFL1BYUVFxMnZ5V2lBUDY2MmhENm9nMS9vbTNsMVBKClRCVXlZWHhxSk83NXV4OElXYmxVd0Fqc21UbEYvUGNqOFFiY01QWExNVGdOUUFnYXJWNmd1Y2hqaXZZcWI2WnIKaHErTmgzSnJGMEhZUXVNZ0V4UTZWWDhUNTZzYU9FdG1scDZMU1FpNEh2S2F0Q05mV1VKR29ZZVQ1U3JjSjZzbgpCeTdYTE1oUVVDT1hjQndLYk52WDZhUDc5VkEzeWVKSFpPN1hQYXJYN1Y5QkIranRmNHR6L3VzbUFULytxWHRICkNDdjlYZjRsdjhqZ2RPbkZmWGJYdVQ4STRnejh1cThFbEJscGJKbnRPNnAvTlk1YTA4RTZDN0ZXVlIrV0o1dloKT1AySHNBPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
)

// Options are settings that is used by the http client
type Options struct {
	// Passphrase is the password for the p12 encoded SSL certificate
	Passphrase string

	// SSLCertificate is a byte encoded array with the SSL certificate content
	SSLCertificate []byte

	// Test indicates whether the http client will use the test environment endpoint and CA certificate
	Test bool // enable test environment

	// Timeout in seconds for the http client
	Timeout int // Client timeout in seconds
}

// BankID holds settings for this session
type BankID struct {
	client *http.Client
	test   bool

	// URL is the endpoint which we use to talk with BankID and can be replaced.
	URL string
}

// New creates a new client
func New(opts Options) (*BankID, error) {
	encodedCaCertificate := string(prodCertificate)
	url := string(prodURL)
	if opts.Test {
		encodedCaCertificate = string(testCertificate)
		url = string(testURL)
	}

	key, leaf, err := pkcs12.Decode(opts.SSLCertificate, opts.Passphrase)
	if err != nil {
		return nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{leaf.Raw},
		PrivateKey:  key.(crypto.PrivateKey),
		Leaf:        leaf,
	}

	ca, err := base64.StdEncoding.DecodeString(string(encodedCaCertificate))
	if err != nil {
		return nil, err
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(ca)

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates:       []tls.Certificate{cert},
			RootCAs:            caCertPool,
			InsecureSkipVerify: true,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Second * time.Duration(opts.Timeout),
	}

	return &BankID{
		client: client,
		URL:    url,
		test:   opts.Test,
	}, nil
}

type serviceError struct {
	ErrorCode string `json:"errorCode"`
	Details   string `json:"details"`
}

type authSignResponse struct {
	OrderRef       string `json:"orderRef"`
	AutoStartToken string `json:"autoStartToken"`
	QrStartToken   string `json:"qrStartToken"`
	QrStartSecret  string `json:"qrStartSecret"`
}

// Requirement is optional parameters that control the autentication process
// Read more about these on https://www.bankid.com/assets/bankid/rp/bankid-relying-party-guidelines-v3.4.pdf
// Chapter 14.5
type Requirement struct {
	CardReader             string `json:"cardReader,omitempty"`
	CertificatePolicies    string `json:"certificatePolicies,omitempty"`
	IssuerCn               string `json:"issuerCn,omitempty"`
	AutoStartTokenRequired string `json:"autoStartTokenRequired,omitempty"`
	AllowFingerprint       bool   `json:"allowFingerprint,omitempty"`
	TokenStartRequired     bool   `json:"tokenStartRequired,omitempty"`
}

// AuthOptions for the authentication request
type AuthOptions struct {
	// Optional: The personal number of the user. String. 12 digits. Century must be included. If the personal number is
	// excluded, the client must be started with the autoStartToken returned in the response.
	PersonalNumber string `json:"personalNumber,omitempty"`

	// Required: The user IP address as seen by your service. String. IPv4 and IPv6 is allowed. Note the importance of
	// using the correct IP address. It must be the IP address representing the user agent (the end user device) as seen
	// by the your service. If there is a proxy for inbound traffic, special considerations may need to be taken to get
	// the correct address. In some use cases the IP address is not available, for instance for voice based services.
	// In this case, the internal representation of those systems IP address is ok to use.
	EndUserIp string `json:"endUserIp"`

	// Optional: Requirements on how the sign order must be performed
	Requirement Requirement `json:"requirement,omitempty"` // Optional settings for the authentication process
}

// Auth initiates an authentication order. Use the collect method to query the status of the order. If the request is
// successful the response includes orderRef, autoStartToken, qrStartToken and qrStartSecret.
func (b *BankID) Auth(ctx context.Context, opts AuthOptions) (result authSignResponse, err error) {
	body, err := json.Marshal(opts)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/rp/v5.1/auth", b.URL), bytes.NewBuffer(body))
	if err != nil {
		return
	}

	req.Header.Add("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errCode serviceError
		err = json.NewDecoder(resp.Body).Decode(&errCode)
		if err != nil {
			return
		}

		return result, fmt.Errorf("[%s] %s", errCode.ErrorCode, errCode.Details)
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	return
}

// SignOptions for the sign request
type SignOptions struct {
	// Optional: The personal number of the user. String. 12 digits. Century must be included. If the personal number is
	// excluded, the client must be started with the autoStartToken returned in the response.
	PersonalNumber string `json:"personalNumber,omitempty"`

	// Required: The user IP address as seen by your service. String. IPv4 and IPv6 is allowed. Note the importance of
	// using the correct IP address. It must be the IP address representing the user agent (the end user device) as seen
	// by the your service. If there is a proxy for inbound traffic, special considerations may need to be taken to get
	// the correct address. In some use cases the IP address is not available, for instance for voice based services.
	// In this case, the internal representation of those systems IP address is ok to use.
	EndUserIP string `json:"endUserIp"`

	// Required: The text to be displayed and signed. String. The text can be formatted using CR, LF and CRLF for new
	// lines. The text must be encoded as UTF-8 and then base 64 encoded. 1--40 000 characters after base 64 encoding.
	UserVisibleData string `json:"userVisibleData"`

	// Optional: Data not displayed to the user. String. The value must be base 64-encoded. 1-200 000 characters after
	// base 64-encoding.
	UserNonVisibleData string `json:"userNonVisibleData,omitempty"`

	// Optional: Requirements on how the sign order must be performed
	Requirement *Requirement `json:"requirement,omitempty"`
}

// Sign initiates an signing order. Use the collect method to query the status of the order. If the request is successful
// the response includes orderRef, autoStartToken, qrStartToken and qrStartSecret.
func (b *BankID) Sign(ctx context.Context, opts SignOptions) (result authSignResponse, err error) {
	body, err := json.Marshal(opts)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/rp/v5.1/sign", b.URL), bytes.NewBuffer(body))
	if err != nil {
		return
	}

	req.Header.Add("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errCode serviceError
		err = json.NewDecoder(resp.Body).Decode(&errCode)
		if err != nil {
			return
		}

		return result, fmt.Errorf("[%s] %s", errCode.ErrorCode, errCode.Details)
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	return
}

// CollectOptions for the collect method
type CollectOptions struct {
	// OrderRef as given by either sign or auth request
	OrderRef string `json:"orderRef"`
}

type statusType string

const (
	// Pending is the status of a pending order and means hintCode was provided
	Pending statusType = "pending"

	// Failed is the status of a failed order and means hintCode was provided
	Failed statusType = "failed"

	// Complete is the status of a completed order and means completionData was provided
	Complete statusType = "complete"
)

type hintCodeType string

// These are possible, but not exclusive hint codes. You need to handle other codes as well
const (
	// The order is pending. The client has not yet received the order. The hintCode will later change to noClient,
	// started or userSign.
	OutstandingTransaction hintCodeType = "outstandingTransaction"

	// The order is pending. The client has not yet received the order.
	NoClient hintCodeType = "noClient"

	// The order is pending. A client has been started with the autostarttoken but a usable ID has not yet been found
	// in the started client. When the client starts there may be a short delay until all ID:s are registered.
	// The user may not have any usable ID:s at all, or has not yet inserted their smart card
	Started hintCodeType = "started"

	// The order is pending. The client has received the order.
	UserSign hintCodeType = "userSign"

	// The order has expired. The BankID security app/program did not start, the user did not finalize the signing or
	// the RP called collect too late.
	ExpiredTransaction hintCodeType = "expiredTransaction"

	// This error is returned if:
	// 1) The user has entered wrong security code too many times. The BankID cannot be used.
	// 2) The users BankID is revoked.
	// 3) The users BankID is invalid.
	CertificateErr hintCodeType = "certificateErr"

	// The user decided to cancel the order.
	UserCancel hintCodeType = "userCancel"

	// The order was cancelled. The system received a new order for the user.
	Cancelled hintCodeType = "cancelled"

	// The user did not provide her ID, or the RP requires autoStartToken to be used, but the client did not start
	// within a certain time limit. The reason may be:
	// 1) RP did not use autoStartToken when starting BankID security program/app. RP must correct this in their
	// implementation.
	// 2) The client software was not installed or other problem with the user’s computer.
	StartFailed hintCodeType = "startFailed"
)

type completionDataUserType struct {
	PersonalNumber string `json:"personalNumber"`
	Name           string `json:"name"`
	GivenName      string `json:"givenName"`
	Surname        string `json:"surname"`
}

type completionDataDeviceType struct {
	IpAddress string `json:"ipAddress"`
}

type completionDataCertType struct {
	NotBefore string `json:"notBefore"` // Unix epoch milliseconds
	NotAfter  string `json:"notAfter"`  // Unix epoch milliseconds
}

type completionDataType struct {
	User         completionDataUserType   `json:"user"`
	Device       completionDataDeviceType `json:"device"`
	Cert         completionDataCertType   `json:"cert"`
	Signature    string                   `json:"signature"`
	OcspResponse string                   `json:"ocsp_response"`
}

type collectResponse struct {
	OrderRef       string             `json:"orderRef"`
	Status         statusType         `json:"status"` // pending, failed, complete
	HintCode       hintCodeType       `json:"hintCode"`
	CompletionData completionDataType `json:"completionData"`
}

// Collect provides the result of a sign or auth order using the orderRef as reference. You should keep on calling
// collect every two seconds as long as status indicates pending. You must abort if status indicates failed. The user
// identity is returned when complete.
func (b *BankID) Collect(ctx context.Context, opts CollectOptions) (result collectResponse, err error) {
	body, err := json.Marshal(opts)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/rp/v5.1/collect", b.URL), bytes.NewBuffer(body))
	if err != nil {
		return
	}

	req.Header.Add("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errCode serviceError
		err = json.NewDecoder(resp.Body).Decode(&errCode)
		if err != nil {
			return
		}

		return result, fmt.Errorf("[%s] %s", errCode.ErrorCode, errCode.Details)
	}

	err = json.NewDecoder(resp.Body).Decode(&result)
	return
}

// CancelOptions for the cancel method
type CancelOptions struct {
	// OrderRef as given by either sign or auth request
	OrderRef string `json:"orderRef"`
}

// Cancel an ongoing sign or auth order. This is typically used if the user cancels the order in your service or app.
func (b *BankID) Cancel(ctx context.Context, opts CancelOptions) error {
	body, err := json.Marshal(opts)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/rp/v5.1/cancel", b.URL), bytes.NewBuffer(body))
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
		var errCode serviceError
		err = json.NewDecoder(resp.Body).Decode(&errCode)
		if err != nil {
			return err
		}

		return fmt.Errorf("[%s] %s", errCode.ErrorCode, errCode.Details)
	}

	return nil
}

// Qr is a helper function that generates a string that is transformed into a QR code. It takes startToken, startSecret
// and seconds since the auth order was created.
func Qr(startToken, startSecret string, seconds int64) (string, error) {
	hash := hmac.New(sha256.New, []byte(startSecret))
	_, err := hash.Write([]byte(fmt.Sprintf("%d", seconds)))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("bankid.%s.%d.%s", startToken, seconds, hex.EncodeToString(hash.Sum(nil))), nil
}
