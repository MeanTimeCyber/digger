package digging

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
	retryabledns "github.com/projectdiscovery/retryabledns"
)

var httpGetFunc = http.Get

// LookupAllRecordsForDomain looks up all DNS records for the given domain using the provided DNS client.
// If no client is provided, it creates a default one. It returns a Records struct containing the results.
func LookupAllRecordsForDomain(domain string, client *dnsx.DNSX) (*Records, error) {
	if client == nil {
		var err error
		client, err = getDefaultClient()

		if err != nil {
			return nil, fmt.Errorf("could not create DNS client: %w", err)
		}
	}

	return lookupAllRecordsForDomain(domain, client, client, getMTAPolicy)
}

type queryMultipleClient interface {
	QueryMultiple(string) (*retryabledns.DNSData, error)
}

type queryOneClient interface {
	QueryOne(string) (*retryabledns.DNSData, error)
}

type policyFetcher func(string) (string, error)

func lookupAllRecordsForDomain(domain string, queryClient queryMultipleClient, txtClient queryOneClient, fetchPolicy policyFetcher) (*Records, error) {
	records := Records{
		Domain: domain,
	}

	// if no client is provided, create a new one
	var err error

	if queryClient == nil {
		queryClient, err = getDefaultClient()

		if err != nil {
			return nil, fmt.Errorf("could not create DNS client: %w", err)
		}
	}

	if txtClient == nil {
		txtClient, err = getTXTClient()

		if err != nil {
			return nil, fmt.Errorf("could not create TXT DNS client: %w", err)
		}
	}

	// Lookup all records
	queryResult, err := queryClient.QueryMultiple(domain)

	if err != nil {
		return nil, fmt.Errorf("could not query domain %q: %w", domain, err)
	}

	// Populate records
	records.A = queryResult.A
	records.AAAA = queryResult.AAAA
	records.MX = queryResult.MX
	records.NS = queryResult.NS
	records.TXT = queryResult.TXT
	records.PTR = queryResult.PTR

	dmarcPath := "_dmarc." + domain
	cnameResult, err := txtClient.QueryOne(dmarcPath)

	if err != nil {
		return nil, fmt.Errorf("could not query TXT for %q: %w", dmarcPath, err)
	}

	records.DMARC = cnameResult.TXT

	// Lookup MTA-STS record separately
	mtaSTSPath := "_mta-sts." + domain
	tlsRPTPath := "_smtp._tls." + domain

	mtaSTSresult, err := txtClient.QueryOne(mtaSTSPath)

	if err != nil {
		return nil, fmt.Errorf("could not query TXT for %q: %w", mtaSTSPath, err)
	}

	if len(mtaSTSresult.TXT) > 0 {
		// save it
		records.MTASTSRecord.TXT = mtaSTSresult.TXT[0]

		// get the policy file
		policy, err := fetchPolicy(domain)

		if err != nil {
			return nil, err
		}

		records.MTASTSRecord.Policy = policy
	}

	// Lookup TLS Report
	mtaSTSresult, err = txtClient.QueryOne(tlsRPTPath)

	if err != nil {
		return nil, fmt.Errorf("could not query TXT for %q: %w", tlsRPTPath, err)
	}

	if len(mtaSTSresult.TXT) > 0 {
		records.MTASTSRecord.TLSRPT = mtaSTSresult.TXT[0]
	}

	// Return records
	return &records, nil
}

// get the MTA Policy file via HTTP
func getMTAPolicy(domain string) (string, error) {
	url := fmt.Sprintf("https://mta-sts.%s/.well-known/mta-sts.txt", domain)
	resp, err := httpGetFunc(url)

	if err != nil {
		return "", fmt.Errorf("error getting MTA-STS policy: %s", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		return "", fmt.Errorf("error parsing MTA-STS policy: %s", err)
	}

	sb := strings.TrimSpace(string(body))

	return sb, nil
}
