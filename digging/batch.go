package digging

import (
	"fmt"
	"sync"
	"time"
)

const defaultMaxConcurrentLookups = 4

const defaultStartInterval = 250 * time.Millisecond

type BatchLookupOptions struct {
	MaxConcurrentLookups int
	StartInterval        time.Duration
}

type DomainLookupResult struct {
	Domain  string
	Records *Records
	Err     error
}

func DefaultBatchLookupOptions() BatchLookupOptions {
	return BatchLookupOptions{
		MaxConcurrentLookups: defaultMaxConcurrentLookups,
		StartInterval:        defaultStartInterval,
	}
}

type lookupAllRecordsFunc func(string) (*Records, error)

func LookupAllRecordsForDomains(domains []string, opts BatchLookupOptions) ([]DomainLookupResult, error) {
	client, err := getDefaultClient()
	if err != nil {
		return nil, fmt.Errorf("could not create DNS client: %w", err)
	}

	return lookupAllRecordsForDomains(domains, opts, func(domain string) (*Records, error) {
		return LookupAllRecordsForDomain(domain, client)
	}, nil), nil
}

func lookupAllRecordsForDomains(domains []string, opts BatchLookupOptions, lookupFn lookupAllRecordsFunc, tickCh <-chan time.Time) []DomainLookupResult {
	if len(domains) == 0 {
		return nil
	}

	if opts.MaxConcurrentLookups <= 0 {
		opts.MaxConcurrentLookups = defaultMaxConcurrentLookups
	}

	if opts.MaxConcurrentLookups > len(domains) {
		opts.MaxConcurrentLookups = len(domains)
	}

	if opts.StartInterval < 0 {
		opts.StartInterval = 0
	}

	results := make([]DomainLookupResult, len(domains))
	sem := make(chan struct{}, opts.MaxConcurrentLookups)
	var wg sync.WaitGroup

	var ticker *time.Ticker
	if tickCh == nil && opts.StartInterval > 0 {
		ticker = time.NewTicker(opts.StartInterval)
		tickCh = ticker.C
		defer ticker.Stop()
	}

	for index, domain := range domains {
		if index > 0 && opts.StartInterval > 0 {
			<-tickCh
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(resultIndex int, domainName string) {
			defer wg.Done()
			defer func() {
				<-sem
			}()

			records, err := lookupFn(domainName)
			results[resultIndex] = DomainLookupResult{
				Domain:  domainName,
				Records: records,
				Err:     err,
			}
		}(index, domain)
	}

	wg.Wait()

	return results
}
