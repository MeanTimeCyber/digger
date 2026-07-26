package digging

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	retryabledns "github.com/projectdiscovery/retryabledns"
)

type fakeLookupClient struct {
	queryMultiple func(string) (*retryabledns.DNSData, error)
	queryOne      func(string) (*retryabledns.DNSData, error)
}

func (f fakeLookupClient) QueryMultiple(domain string) (*retryabledns.DNSData, error) {
	return f.queryMultiple(domain)
}

func (f fakeLookupClient) QueryOne(domain string) (*retryabledns.DNSData, error) {
	return f.queryOne(domain)
}

func TestLookupAllRecordsForDomainWithInjectedClients(t *testing.T) {
	lookupClient := fakeLookupClient{
		queryMultiple: func(domain string) (*retryabledns.DNSData, error) {
			if domain != "example.com" {
				t.Fatalf("unexpected domain: %s", domain)
			}

			return &retryabledns.DNSData{
				A:    []string{"1.1.1.1"},
				AAAA: []string{"2001:db8::1"},
				MX:   []string{"mail.example.com"},
				NS:   []string{"ns1.example.com"},
				TXT:  []string{"v=spf1 ~all"},
				PTR:  []string{"ptr.example.com"},
			}, nil
		},
		queryOne: func(domain string) (*retryabledns.DNSData, error) {
			switch domain {
			case "_dmarc.example.com":
				return &retryabledns.DNSData{TXT: []string{"v=DMARC1; p=reject"}}, nil
			case "_mta-sts.example.com":
				return &retryabledns.DNSData{TXT: []string{"v=STSv1; id=12345"}}, nil
			case "_smtp._tls.example.com":
				return &retryabledns.DNSData{TXT: []string{"v=TLSRPTv1; rua=mailto:reports@example.com"}}, nil
			default:
				t.Fatalf("unexpected TXT lookup: %s", domain)
				return nil, nil
			}
		},
	}

	records, err := lookupAllRecordsForDomain("example.com", lookupClient, lookupClient, func(string) (string, error) {
		return "version: STSv1\nmode: enforce", nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if records.Domain != "example.com" {
		t.Fatalf("expected domain to be preserved, got %q", records.Domain)
	}

	if len(records.A) != 1 || records.A[0] != "1.1.1.1" {
		t.Fatalf("unexpected A records: %#v", records.A)
	}

	if len(records.AAAA) != 1 || records.AAAA[0] != "2001:db8::1" {
		t.Fatalf("unexpected AAAA records: %#v", records.AAAA)
	}

	if len(records.MX) != 1 || records.MX[0] != "mail.example.com" {
		t.Fatalf("unexpected MX records: %#v", records.MX)
	}

	if len(records.NS) != 1 || records.NS[0] != "ns1.example.com" {
		t.Fatalf("unexpected NS records: %#v", records.NS)
	}

	if len(records.TXT) != 1 || records.TXT[0] != "v=spf1 ~all" {
		t.Fatalf("unexpected TXT records: %#v", records.TXT)
	}

	if len(records.PTR) != 1 || records.PTR[0] != "ptr.example.com" {
		t.Fatalf("unexpected PTR records: %#v", records.PTR)
	}

	if len(records.DMARC) != 1 || records.DMARC[0] != "v=DMARC1; p=reject" {
		t.Fatalf("unexpected DMARC records: %#v", records.DMARC)
	}

	if records.MTASTSRecord.TXT != "v=STSv1; id=12345" {
		t.Fatalf("unexpected MTA-STS TXT record: %#v", records.MTASTSRecord.TXT)
	}

	if records.MTASTSRecord.Policy != "version: STSv1\nmode: enforce" {
		t.Fatalf("unexpected MTA-STS policy: %#v", records.MTASTSRecord.Policy)
	}

	if records.MTASTSRecord.TLSRPT != "v=TLSRPTv1; rua=mailto:reports@example.com" {
		t.Fatalf("unexpected TLSRPT record: %#v", records.MTASTSRecord.TLSRPT)
	}
}

func TestLookupAllRecordsForDomainReturnsQueryError(t *testing.T) {
	lookupClient := fakeLookupClient{
		queryMultiple: func(string) (*retryabledns.DNSData, error) {
			return nil, errors.New("dns failed")
		},
		queryOne: func(string) (*retryabledns.DNSData, error) {
			t.Fatal("TXT lookup should not be called after query failure")
			return nil, nil
		},
	}

	_, err := lookupAllRecordsForDomain("example.com", lookupClient, lookupClient, func(string) (string, error) {
		t.Fatal("policy fetch should not be called after query failure")
		return "", nil
	})

	if err == nil || !strings.Contains(err.Error(), "could not query domain") {
		t.Fatalf("expected wrapped query error, got %v", err)
	}
}

func TestGetMTAPolicyUsesHTTPGetterAndTrimsBody(t *testing.T) {
	oldGet := httpGetFunc
	httpGetFunc = func(url string) (*http.Response, error) {
		if !strings.Contains(url, "mta-sts.example.com") {
			t.Fatalf("unexpected URL: %s", url)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("  version: STSv1\nmode: enforce\n")),
		}, nil
	}
	t.Cleanup(func() {
		httpGetFunc = oldGet
	})

	policy, err := getMTAPolicy("example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if policy != "version: STSv1\nmode: enforce" {
		t.Fatalf("unexpected policy body: %q", policy)
	}
}
