package bankid

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/pkcs12"
	"net/http"
	"time"
)

type WebServiceUrl string

const (
	TestUrl WebServiceUrl = "https://appapi2.test.bankid.com"
	ProdUrl WebServiceUrl = "https://appapi2.bankid.com"
)

type CertificateAuthority string

const (
	ProdCertificate CertificateAuthority = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUZ2akNDQTZhZ0F3SUJBZ0lJVHlUaC91MWJFeG93RFFZSktvWklodmNOQVFFTkJRQXdZakVrTUNJR0ExVUUKQ2d3YlJtbHVZVzV6YVdWc2JDQkpSQzFVWld0dWFXc2dRa2xFSUVGQ01Sb3dHQVlEVlFRTERCRkpibVp5WVhOMApjblZqZEhWeVpTQkRRVEVlTUJ3R0ExVUVBd3dWUW1GdWEwbEVJRk5UVENCU2IyOTBJRU5CSUhZeE1CNFhEVEV4Ck1USXdOekV5TXpRd04xb1hEVE0wTVRJek1URXlNelF3TjFvd1lqRWtNQ0lHQTFVRUNnd2JSbWx1WVc1emFXVnMKYkNCSlJDMVVaV3R1YVdzZ1FrbEVJRUZDTVJvd0dBWURWUVFMREJGSmJtWnlZWE4wY25WamRIVnlaU0JEUVRFZQpNQndHQTFVRUF3d1ZRbUZ1YTBsRUlGTlRUQ0JTYjI5MElFTkJJSFl4TUlJQ0lqQU5CZ2txaGtpRzl3MEJBUUVGCkFBT0NBZzhBTUlJQ0NnS0NBZ0VBd1ZBNHNuWmlTRkkzcjY0THZZdTRtT3NJNDJBOWFMS0VRR3E0SVpvMjU3aXEKdlBIODJTTXZnQkpnRTUya0N4N2dRTW1aN2lTbTM5Q0VBMTlobElMaDhKRUpOVHlKTnhNeFZETjZjZkpQMWpNSApKZVRFUzFUbVZiV1VxR3lMcHlUOExDSmhDOVZxNFczdC9PMXN2R0pOT1VRSVFMNGVBSFN2V1RWb2FseHpvbUpoCk9uOTdFTmpYQXQ0QkxiNnNIZlZCdm1CNVJlSzBVZndwTkFDRk0xUk44YnRFYURkV0M0UGZBNzJ5elYzd0svY1kKNWgyazFSTTFzMTlQam94bnBKcXJtbjRxWm1QNHROL25rMmQ3YzRGRXJKQVAwcG5Oc2xsMStKZmtkTWZpUEQzNQorcWNjbHBzcHpQMkxwYXVRVnlQYk8yMU5oK0VQdHI3K0lpYzJ0a2d6MGcxa0swSUwvZm9GckowSWV2eXIzRHJtCjJ1Um5BMGVzWjQ1R09tWmhFMjJteWNFWDlsN3c5anJkc0t0cXM3Ti9UNDZoaWw0eEJpR2JsWGtxS05HNlR2QVIKazZYcU9wM1J0VXZHR2FLWm5HbGxzZ1R2UDM4L25yU01sc3pOb2pybGJEbm0xNkdHb1JUUW53cjhsK1l2YnovZQp2L2U2d1ZGRGpiNTJaQjBaL0tUZmpYT2w1Y0FKN09DYk9ETVdmOE5hNTZPVGxJa3JrNU55VS91R3pKRlVRU3ZHCmRMSFVpcEovc1RaQ2JxTlNaVXdib0kwb1FOTy9ZZ2V6Mko2emdXWEdwRFdpTjRMR0xEbUJoQjNUOENNUXU5Si8KQmNGdmdqblV5aHlpbTM1a0RwalZQQzhuclNpcjVPa2FZZ0dkWVdkRHV2MTQ1NmxGTlBOTlFjZFpkdDVmY21NQwpBd0VBQWFONE1IWXdIUVlEVlIwT0JCWUVGUGdxc3V4NVJ0Y3JJaEFWZXVMQlNnQnVSREZWTUE4R0ExVWRFd0VCCi93UUZNQU1CQWY4d0h3WURWUjBqQkJnd0ZvQVUrQ3F5N0hsRzF5c2lFQlY2NHNGS0FHNUVNVlV3RXdZRFZSMGcKQkF3d0NqQUlCZ1lxaFhCT0FRUXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01BMEdDU3FHU0liM0RRRUJEUVVBQTRJQwpBUUFKT2pVT1MyR0pQTnJycnFmNTM5YU4xL0ViVWo1WlZSakc0d3pWdFg1eVZxUEdjUlpqVVFsTlRjZk9wd1BvCmN6S0JuTlgyT01GK1FtOTRiYit4WGMvMDhBRVJxSkozRlBLdThvRE5lSytSdjFYNG5oOTVKNFJIWmN2bDRBR2gKRUNtR015aHlDZWEwcVpCRkJzQnFRUjdvQzlhZllPeHNTb3ZhUHFYMzFRTUxVTFdVWW9CS1dXSExWVklvSGpBbQpHdEF6TWtMd2UwL2xyVnlBcHI5aXlYV2hWcitxWUdtRkd3MStyd212RG1tU0xXTldhd1lnSDROWXhUZjh6NWhCCmlET2RBZ2lsdnlpQUY4WWwwa0NLVUIyZkFQaFJOWWxFY04rVVAvS0wyNGgvcEIraFo5bXZSMHRNNm5XM0hWWmEKRHJ2Uno0VmloWjh2UmkzZlluT0FrTkU2a1pkcnJkTzdMZEJjOXlZa2ZRZFRjeTBOK0F3N3E0VGtROG5wb21yVgptVEthUGh0R2hBN1ZJQ3lSTkJWY3Z5b3hyK0NZN2FSUXlIbi9DN24valJzUVl4czd1Yyttc3E2alJTNEhQSzhvCmxuRjl1c1daWDZLWSs4bXdlSmlURTR1TjRaVVVCVXR0OFdjWFhEaUsvYnhFRzJhbWpQY1ovYjRMWHdHQ0piK2EKTldQNCtpWTZrQktyTUFOczAxcEx2dFZqVVM5UnRSclkzY05FT2htS2hPMHFKU0RYaHNUY1Z0cGJEcjM3VVRTcQpRVnc4M2RSZWlBUlB3R2RVUm1ta2FoZUg2ejRrNnFFVVNYdUZjaDB3NTNVQWMrMWFCWFIxYmd5RnFNZHk3WXhpCmIyQVl1N3duckhpb0RXcVA2RFRrVVNVZU1CL3pxV1BNL3F4NlFOTk9jYU9jakE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg=="
	TestCertificate CertificateAuthority = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUYwRENDQTdpZ0F3SUJBZ0lJSWhZYXh1NGtoZ0F3RFFZSktvWklodmNOQVFFTkJRQXdiREVrTUNJR0ExVUUKQ2d3YlJtbHVZVzV6YVdWc2JDQkpSQzFVWld0dWFXc2dRa2xFSUVGQ01Sb3dHQVlEVlFRTERCRkpibVp5WVhOMApjblZqZEhWeVpTQkRRVEVvTUNZR0ExVUVBd3dmVkdWemRDQkNZVzVyU1VRZ1UxTk1JRkp2YjNRZ1EwRWdkakVnClZHVnpkREFlRncweE5ERXhNakV4TWpNNU16RmFGdzB6TkRFeU16RXhNak01TXpGYU1Hd3hKREFpQmdOVkJBb00KRzBacGJtRnVjMmxsYkd3Z1NVUXRWR1ZyYm1scklFSkpSQ0JCUWpFYU1CZ0dBMVVFQ3d3UlNXNW1jbUZ6ZEhKMQpZM1IxY21VZ1EwRXhLREFtQmdOVkJBTU1IMVJsYzNRZ1FtRnVhMGxFSUZOVFRDQlNiMjkwSUVOQklIWXhJRlJsCmMzUXdnZ0lpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElDRHdBd2dnSUtBb0lDQVFDQUtXc0pjL2tWLzA0MzRkK1MKcW4xOW1Jcjg1UlovUGdSRmFVcGxTcm5odXpBbWFYaWhQTENFc2QzTWgvWUVyeWdjeGhRL01Bemk1T1ovYW5mdQpXU0N3Y2VSbFFJTnR2bFJQZE1vZVp0dTI5RnNudEsxWjVyMlNZTmRGd2JSRmI4V045RnNVMEt2QzV6Vm51RE1nCnM1ZFVad1RtZHpYNVpkTFA3cGRnQjN6aFRucmE1T1J0a2lXaVV4SlZldjlrZVJnQW8wMFpISVJKK3hUZmlTUGQKSmMzMTRtYWlnVlJRWmRHS1N5UWNRTVRXaTFZTHdkMnp3T2FjTnhsZVlmOHhxS2drWnNta3JjNERwMm1SNVBrcgpubktCNkE3c0FPU05hdHVhN004NkVnY0dpOUFhRXlhUk1rWUpJbWJCZnphTmxhQlB5TVN2d21CWnpwMnhLYzlPCkQzVTA2b2dWNkNKakpMN2hTdVZjNXgvMkgwNGQrMkkrREt3ZXA2WUJvVkw5TDgxZ1JZUnljcWcrdytjVFoxVEYKL3M2TkM1WVJLU2VPQ3JMdzNvbWJoanl5dVBsOFQvaDljcFh0Nm0zeTJ4SVZMWVZ6ZURoYXFsM2hkaTZJcFJoNgpyd2tNaEovWG1PcGJEaW5YYjFmV2RGT3lRd3FzWFFXT0V3S0JZSWtNNmNQbnVpZDdxd2F4ZlAyMmhEZ0FvbEdNCkxZN1RQS1VQUndWK2E1WTNWUGw3aDBZU0s3bER5Y2tUSmR0QnFJNmQ0UFdRTG5IYWtVZ1JReTY5blpoR1J0VXQKUE1TSjdJNFF0dDNCNkF3RHErU0pUZ2d3dEpRSGVpZDBqUGtpNnBvdWVuaFBRNmRaVDUzMngxNlhEK1dJY0QyZgovL1h6ek91ZVMyOUtCN2x0L3dINUs2RXV4d0lEQVFBQm8zWXdkREFkQmdOVkhRNEVGZ1FVRFk2WEovRklSRlgzCmRCNFdlcDNSVk04NFJYb3dEd1lEVlIwVEFRSC9CQVV3QXdFQi96QWZCZ05WSFNNRUdEQVdnQlFOanBjbjhVaEUKVmZkMEhoWjZuZEZVenpoRmVqQVJCZ05WSFNBRUNqQUlNQVlHQkNvREJBVXdEZ1lEVlIwUEFRSC9CQVFEQWdFRwpNQTBHQ1NxR1NJYjNEUUVCRFFVQUE0SUNBUUE1czU5L09saW80c3ZIWGlLdTdzUFFSdnJmNEdmR0I3aFVqQkdrCllXMllPSFRZbkhhdlNxbEJBU0hjOGdHR3d1Yzd2NytIK3ZtT2ZTTFpmR0RxeG5CcWVKeDFINUUwWXFFWHROcVcKRzFKdXNJRmE5eFd5cGNPTmpnOXY3SU1ueHhRekxZd3M0WXdnUHljaHBNeldZNkI1aFpzalV5S2dCKzFpZ3huZgp1YUJ1ZUxQdzNaYUpoY0NMOGd6NlNkQ0ttUXBYNFZhQWFkUzB2ZE1yQk9tZDgyNkgrYURHWmVrMXZNanVIMTFGCmZKb1hZMmp5RG5sb2w3WjRCZkhjMDExdG9XTk14b2pJN3crVTRLS0NiU3hwV0ZWWUlUWjhXbFlIY2orYjJBMSsKZEZRWkZ6UU4rWTFXeDNWSVVxU2tzNlA3RjVhRi9sNFJCbmd5MDh6a1A3aUxBL0M3cm02MXhXeFRtcGozcDZTRwpmVUJzcnNCdkJnZkpRSEQvTXg4VTNpUUNhMFZqMVhQb2dFL1BYUVFxMnZ5V2lBUDY2MmhENm9nMS9vbTNsMVBKClRCVXlZWHhxSk83NXV4OElXYmxVd0Fqc21UbEYvUGNqOFFiY01QWExNVGdOUUFnYXJWNmd1Y2hqaXZZcWI2WnIKaHErTmgzSnJGMEhZUXVNZ0V4UTZWWDhUNTZzYU9FdG1scDZMU1FpNEh2S2F0Q05mV1VKR29ZZVQ1U3JjSjZzbgpCeTdYTE1oUVVDT1hjQndLYk52WDZhUDc5VkEzeWVKSFpPN1hQYXJYN1Y5QkIranRmNHR6L3VzbUFULytxWHRICkNDdjlYZjRsdjhqZ2RPbkZmWGJYdVQ4STRnejh1cThFbEJscGJKbnRPNnAvTlk1YTA4RTZDN0ZXVlIrV0o1dloKT1AySHNBPT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
)

type Options struct {
	Passphrase     string // Passphrase to SSL certificate
	SSLCertificate []byte // byte encoded SSL certificate
	Test           bool   // enable test environment
	Timeout        int    // Client timeout in seconds
}

type BankId struct {
	client *http.Client
	url    string
	test   bool
}

// Create a new session with BankId
func New(opts Options) (*BankId, error) {
	encodedCaCertificate := string(ProdCertificate)
	url := string(ProdUrl)
	if opts.Test {
		encodedCaCertificate = string(TestCertificate)
		url = string(TestUrl)
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

	return &BankId{
		client: client,
		url:    url,
		test:   opts.Test,
	}, nil
}

type serviceError struct {
	ErrorCode string `json:"errorCode"`
	Details   string `json:"details"`
}

type AuthSignResponse struct {
	OrderRef       string `json:"orderRef"`
	AutoStartToken string `json:"autoStartToken"`
	QrStartToken   string `json:"qrStartToken"`
	QrStartSecret  string `json:"qrStartSecret"`
}

type Requirement struct {
	CardReader             string `json:"cardReader,omitempty"`
	CertificatePolicies    string `json:"certificatePolicies,omitempty"`
	IssuerCn               string `json:"issuerCn,omitempty"`
	AutoStartTokenRequired string `json:"autoStartTokenRequired,omitempty"`
	AllowFingerprint       bool   `json:"allowFingerprint,omitempty"`
	TokenStartRequired     bool   `json:"tokenStartRequired,omitempty"`
}

type AuthOptions struct {
	PersonalNumber string      `json:"personalNumber,omitempty"`
	EndUserIp      string      `json:"endUserIp"`
	Requirement    Requirement `json:"requirement,omitempty"`
}

// Initiates an authentication order. Use the collect method to query the status of the order. If the request is
// successful the response includes orderRef, autoStartToken, qrStartToken and qrStartSecret.
func (b *BankId) Auth(ctx context.Context, opts AuthOptions) (result AuthSignResponse, err error) {
	body, err := json.Marshal(opts)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/rp/v5.1/auth", b.url), bytes.NewBuffer(body))
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

type SignOptions struct {
	PersonalNumber     string       `json:"personalNumber,omitempty"`
	EndUserIp          string       `json:"endUserIp"`
	UserVisibleData    string       `json:"userVisibleData"`
	UserNonVisibleData string       `json:"userNonVisibleData,omitempty"`
	Requirement        *Requirement `json:"requirement,omitempty"`
}

// Initiates an signing order. Use the collect method to query the status of the order. If the request is successful
// the response includes orderRef, autoStartToken, qrStartToken and qrStartSecret.
func (b *BankId) Sign(ctx context.Context, opts SignOptions) (result AuthSignResponse, err error) {
	body, err := json.Marshal(opts)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/rp/v5.1/sign", b.url), bytes.NewBuffer(body))
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

type CollectOptions struct {
	OrderRef string `json:"orderRef"`
}

type StatusType string

const (
	Pending  StatusType = "pending"
	Failed   StatusType = "failed"
	Complete StatusType = "complete"
)

type HintCodeType string

// These are possible, but not exclusive hint codes. You need to handle other codes as well
const (
	// The order is pending. The client has not yet received the order. The hintCode will later change to noClient,
	// started or userSign.
	OutstandingTransaction HintCodeType = "outstandingTransaction"

	// The order is pending. The client has not yet received the order.
	NoClient HintCodeType = "noClient"

	// The order is pending. A client has been started with the autostarttoken but a usable ID has not yet been found
	// in the started client. When the client starts there may be a short delay until all ID:s are registered.
	// The user may not have any usable ID:s at all, or has not yet inserted their smart card
	Started HintCodeType = "started"

	// The order is pending. The client has received the order.
	UserSign HintCodeType = "userSign"

	// The order has expired. The BankID security app/program did not start, the user did not finalize the signing or
	// the RP called collect too late.
	ExpiredTransaction HintCodeType = "expiredTransaction"

	// This error is returned if:
	// 1) The user has entered wrong security code too many times. The BankID cannot be used.
	// 2) The users BankID is revoked.
	// 3) The users BankID is invalid.
	CertificateErr HintCodeType = "certificateErr"

	// The user decided to cancel the order.
	UserCancel HintCodeType = "userCancel"

	// The order was cancelled. The system received a new order for the user.
	Cancelled HintCodeType = "cancelled"

	// The user did not provide her ID, or the RP requires autoStartToken to be used, but the client did not start
	// within a certain time limit. The reason may be:
	// 1) RP did not use autoStartToken when starting BankID security program/app. RP must correct this in their
	// implementation.
	// 2) The client software was not installed or other problem with the user’s computer.
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
}

type CompletionDataCertType struct {
	NotBefore string `json:"notBefore"` // Unix epoch milliseconds
	NotAfter  string `json:"notAfter"`  // Unix epoch milliseconds
}

type CompletionDataType struct {
	User         CompletionDataUserType   `json:"user"`
	Device       CompletionDataDeviceType `json:"device"`
	Cert         CompletionDataCertType   `json:"cert"`
	Signature    string                   `json:"signature"`
	OcspResponse string                   `json:"ocsp_response"`
}

type CollectResponse struct {
	OrderRef       string             `json:"orderRef"`
	Status         StatusType         `json:"status"` // pending, failed, complete
	HintCode       HintCodeType       `json:"hintCode"`
	CompletionData CompletionDataType `json:"completionData"`
}

// Collects the result of a sign or auth order using the orderRef as reference. You should keep on calling collect
// every two seconds as long as status indicates pending. You must abort if status indicates failed. The user
// identity is returned when complete.
func (b *BankId) Collect(ctx context.Context, opts CollectOptions) (result CollectResponse, err error) {
	body, err := json.Marshal(opts)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/rp/v5.1/collect", b.url), bytes.NewBuffer(body))
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
