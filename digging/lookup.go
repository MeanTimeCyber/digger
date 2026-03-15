package digging

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

func LookupAll(domain string) (*Records, error) {
	records := Records{
		Domain: domain,
	}

	client, err := getDefaultClient()

	if err != nil {
		return nil, fmt.Errorf("could not create DNS client: %w", err)
	}

	// Lookup all records
	queryResult, err := client.QueryMultiple(domain)

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

	// Lookup CNAME record separately
	txtClient, err := getTXTClient()

	if err != nil {
		return nil, fmt.Errorf("could not create TXT DNS client: %w", err)
	}

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
		policy, err := getMTAPolicy(domain)

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
	resp, err := http.Get(url)

	if err != nil {
		return "", fmt.Errorf("error getting MTA-STS policy: %s", err)
	}

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		return "", fmt.Errorf("error parsing MTA-STS policy: %s", err)
	}

	sb := strings.TrimSpace(string(body))

	return sb, nil
}
