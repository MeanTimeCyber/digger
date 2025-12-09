package digging

import (
	"fmt"
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

	records.MTASTSRecord = mtaSTSresult.TXT

	mtaSTSresult, err = txtClient.QueryOne(tlsRPTPath)

	if err != nil {
		return nil, fmt.Errorf("could not query TXT for %q: %w", tlsRPTPath, err)
	}

	records.MTASTSRecord = append(records.MTASTSRecord, mtaSTSresult.TXT...)

	// Return records
	return &records, nil
}
