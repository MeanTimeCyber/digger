package digging

import (
	"fmt"
	"sync"
	"time"
)

const defaultMaxConcurrentLookups = 4 // Default maximum number of lookups to run at once
const defaultStartInterval = 250 * time.Millisecond // Default delay between starting each lookup

// BatchLookupOptions defines the options for batch lookups.
type BatchLookupOptions struct {
	MaxConcurrentLookups int // Maximum number of lookups to run at once
	StartInterval        time.Duration // Delay between starting each lookup
}

// DomainLookupResult represents the result of looking up a domain's DNS records.
type DomainLookupResult struct {
	Domain  string // The domain that was looked up
	Records *Records // The DNS records for the domain
	Err     error // Any error that occurred during the lookup
}

// DefaultBatchLookupOptions returns the default options for batch lookups.
func DefaultBatchLookupOptions() BatchLookupOptions {
	return BatchLookupOptions{
		MaxConcurrentLookups: defaultMaxConcurrentLookups,
		StartInterval:        defaultStartInterval,
	}
}

// lookupAllRecordsFunc defines the function signature for looking up all records for a domain.
type lookupAllRecordsFunc func(string) (*Records, error)

// LookupAllRecordsForDomains looks up all DNS records for the provided domains using the specified options.
func LookupAllRecordsForDomains(domains []string, opts BatchLookupOptions) ([]DomainLookupResult, error) {
	client, err := getDefaultClient()
	if err != nil {
		return nil, fmt.Errorf("could not create DNS client: %w", err)
	}

	return lookupAllRecordsForDomains(domains, opts, func(domain string) (*Records, error) {
		return LookupAllRecordsForDomain(domain, client)
	}, nil), nil
}

// lookupAllRecordsForDomains performs the actual lookup of all records for the provided domains using the specified options and lookup function.
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
