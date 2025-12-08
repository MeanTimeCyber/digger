package digging

import (
	miekgdns "github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
)

func getDefaultClient() (*dnsx.DNSX, error) {
	// Create DNS Resolver with default options
	dnsClient, err := dnsx.New(
		dnsx.Options{
			QuestionTypes: []uint16{
				miekgdns.TypeA,
				miekgdns.TypeAAAA,
				miekgdns.TypeMX,
				miekgdns.TypeNS,
				miekgdns.TypeTXT,
				miekgdns.TypePTR,
			},
			MaxRetries:    dnsx.DefaultOptions.MaxRetries,
			BaseResolvers: dnsx.DefaultResolvers,
		},
	)

	if err != nil {
		return nil, err
	}

	return dnsClient, nil
}

func getTXTClient() (*dnsx.DNSX, error) {
	// Create DNS Resolver with default options
	dnsClient, err := dnsx.New(
		dnsx.Options{
			QuestionTypes: []uint16{
				miekgdns.TypeTXT,
			},
			MaxRetries:    dnsx.DefaultOptions.MaxRetries,
			BaseResolvers: dnsx.DefaultResolvers,
		},
	)

	if err != nil {
		return nil, err
	}

	return dnsClient, nil
}
