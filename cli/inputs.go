package main

import (
	"bufio"
	"net"
	"net/url"
	"os"
	"strings"
)

type domainList []string

// String implements the flag.Value interface for domainList, allowing it to be used as a command line flag.
func (d *domainList) String() string {
	return strings.Join(*d, ",")
}

// Set implements the flag.Value interface for domainList, allowing it to be used as a command line flag.
func (d *domainList) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}

		*d = append(*d, trimmed)
	}

	return nil
}

// getHostFromURL extracts the host from a given URL string, removing any "www." prefix and port number if present.
func getHostFromURL(line string) (string, error) {
	hostname, err := url.Parse(line)

	if err != nil {
		return "", err
	}

	// trim www
	host := strings.TrimPrefix(hostname.Host, "www.")

	if len(host) == 0 {
		host = hostname.Path
	}

	// trim port
	noPort, _, err := net.SplitHostPort(host)

	if err == nil {
		host = noPort
	}

	return host, nil
}

// readDomainsFromFile reads a list of domains from a specified file, returning them as a slice of strings.
func readDomainsFromFile(domainList string) ([]string, error) {
	file, err := os.Open(domainList)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		domains = append(domains, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return domains, nil
}
