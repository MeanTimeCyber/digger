package digging

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestLookupAllRecordsForDomainsCapsConcurrency(t *testing.T) {
	domains := []string{"a.example", "b.example", "c.example", "d.example"}
	release := make(chan struct{})
	started := make(chan string, len(domains))

	var active int64
	var maxActive int64

	resultsCh := make(chan []DomainLookupResult, 1)

	go func() {
		resultsCh <- lookupAllRecordsForDomains(domains, BatchLookupOptions{MaxConcurrentLookups: 2}, func(domain string) (*Records, error) {
			current := atomic.AddInt64(&active, 1)
			for {
				observed := atomic.LoadInt64(&maxActive)
				if current <= observed {
					break
				}
				if atomic.CompareAndSwapInt64(&maxActive, observed, current) {
					break
				}
			}

			started <- domain
			<-release
			atomic.AddInt64(&active, -1)

			return &Records{Domain: domain}, nil
		}, nil)
	}()

	first := <-started
	second := <-started

	if first == second {
		t.Fatalf("expected distinct domains to start concurrently, got %q twice", first)
	}

	select {
	case third := <-started:
		t.Fatalf("expected concurrency cap to block a third lookup, but %q started early", third)
	case <-time.After(50 * time.Millisecond):
	}

	close(release)

	results := <-resultsCh

	if len(results) != len(domains) {
		t.Fatalf("expected %d results, got %d", len(domains), len(results))
	}

	if atomic.LoadInt64(&maxActive) > 2 {
		t.Fatalf("expected at most 2 concurrent lookups, saw %d", atomic.LoadInt64(&maxActive))
	}

	for index, result := range results {
		if result.Err != nil {
			t.Fatalf("result %d unexpectedly failed: %v", index, result.Err)
		}
		if result.Domain != domains[index] {
			t.Fatalf("result %d out of order: want %q got %q", index, domains[index], result.Domain)
		}
	}
}

func TestLookupAllRecordsForDomainsWaitsForTickBeforeStartingNextJob(t *testing.T) {
	domains := []string{"a.example", "b.example", "c.example"}
	tickCh := make(chan time.Time)
	release := make(chan struct{})
	started := make(chan string, len(domains))

	resultsCh := make(chan []DomainLookupResult, 1)

	go func() {
		resultsCh <- lookupAllRecordsForDomains(domains, BatchLookupOptions{MaxConcurrentLookups: 3, StartInterval: time.Second}, func(domain string) (*Records, error) {
			started <- domain
			if domain == domains[0] {
				<-release
			}

			return &Records{Domain: domain}, nil
		}, tickCh)
	}()

	first := <-started
	if first != domains[0] {
		t.Fatalf("expected first started domain to be %q, got %q", domains[0], first)
	}

	select {
	case second := <-started:
		t.Fatalf("expected second lookup to wait for a tick, but %q started early", second)
	case <-time.After(50 * time.Millisecond):
	}

	tickCh <- time.Now()

	second := <-started
	if second != domains[1] {
		t.Fatalf("expected second started domain to be %q, got %q", domains[1], second)
	}

	close(release)
	results := <-resultsCh

	if len(results) != len(domains) {
		t.Fatalf("expected %d results, got %d", len(domains), len(results))
	}
}

func TestLookupAllRecordsForDomainsCapturesErrorsPerDomain(t *testing.T) {
	domains := []string{"ok.example", "bad.example"}

	results := lookupAllRecordsForDomains(domains, BatchLookupOptions{MaxConcurrentLookups: 2, StartInterval: 0}, func(domain string) (*Records, error) {
		if domain == "bad.example" {
			return nil, errors.New("boom")
		}

		return &Records{Domain: domain}, nil
	}, nil)

	if results[0].Err != nil {
		t.Fatalf("expected first domain to succeed, got %v", results[0].Err)
	}

	if results[1].Err == nil {
		t.Fatal("expected second domain to fail")
	}

	if results[1].Records != nil {
		t.Fatalf("expected failed lookup to have no records, got %#v", results[1].Records)
	}
}
