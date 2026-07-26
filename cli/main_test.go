package main

import "testing"

func TestGetHostFromURL(t *testing.T) {
	host, err := getHostFromURL("https://www.example.com:443/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if host != "example.com" {
		t.Fatalf("expected example.com, got %q", host)
	}
}

func TestDomainListSet(t *testing.T) {
	var domains domainList

	if err := domains.Set("one.example,two.example"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := domains.Set("three.example"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(domains) != 3 {
		t.Fatalf("expected 3 domains, got %d", len(domains))
	}

	if domains[0] != "one.example" || domains[1] != "two.example" || domains[2] != "three.example" {
		t.Fatalf("unexpected domains: %#v", domains)
	}
}