package digging

import (
	"fmt"
	"sync"
	"time"
)

var defaultBatchClientFactory = getDefaultClient

const defaultMaxConcurrentLookups = 4               // Default maximum number of lookups to run at once
const defaultStartInterval = 250 * time.Millisecond // Default delay between starting each lookup
const defaultLookupTimeout = 15 * time.Second       // Default per-domain timeout for batch lookups

// BatchLookupOptions defines the options for batch lookups.
type BatchLookupOptions struct {
	MaxConcurrentLookups int           // Maximum number of lookups to run at once
	StartInterval        time.Duration // Delay between starting each lookup
	LookupTimeout        time.Duration // Maximum time to wait for an individual domain lookup
}

// DomainLookupResult represents the result of looking up a domain's DNS records.
type DomainLookupResult struct {
	Domain  string   // The domain that was looked up
	Records *Records // The DNS records for the domain
	Err     error    // Any error that occurred during the lookup
}

// DefaultBatchLookupOptions returns the default options for batch lookups.
func DefaultBatchLookupOptions() BatchLookupOptions {
	return BatchLookupOptions{
		MaxConcurrentLookups: defaultMaxConcurrentLookups,
		StartInterval:        defaultStartInterval,
		LookupTimeout:        defaultLookupTimeout,
	}
}

// lookupAllRecordsFunc defines the function signature for looking up all records for a domain.
type lookupAllRecordsFunc func(string) (*Records, error)

// LookupAllRecordsForDomains looks up all DNS records for the provided domains using the specified options.
func LookupAllRecordsForDomains(domains []string, opts BatchLookupOptions) ([]DomainLookupResult, error) {
	client, err := defaultBatchClientFactory()
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

	if opts.LookupTimeout < 0 {
		opts.LookupTimeout = 0
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

			records, err := lookupWithTimeout(domainName, opts.LookupTimeout, lookupFn)
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

func lookupWithTimeout(domainName string, timeout time.Duration, lookupFn lookupAllRecordsFunc) (*Records, error) {
	if timeout <= 0 {
		return lookupFn(domainName)
	}

	type lookupResult struct {
		records *Records
		err     error
	}

	resultCh := make(chan lookupResult, 1)
	go func() {
		records, err := lookupFn(domainName)
		resultCh <- lookupResult{records: records, err: err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case result := <-resultCh:
		return result.records, result.err
	case <-timer.C:
		return nil, fmt.Errorf("lookup for %q timed out after %s", domainName, timeout)
	}
}
