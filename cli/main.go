package main

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/MeanTimeCyber/digger/digging"
	"github.com/asaskevich/govalidator"
)

func main() {
	var domains domainList
	var markdown bool
	var maxConcurrentLookups int
	var startInterval time.Duration
	flag.Var(&domains, "i", "Input domain to look up (repeat the flag or separate values with commas)")
	flag.BoolVar(&markdown, "m", false, "Also write output to a markdown file")
	flag.IntVar(&maxConcurrentLookups, "c", 4, "Maximum number of lookups to run at once")
	flag.DurationVar(&startInterval, "interval", 250*time.Millisecond, "Delay between starting each lookup")
	flag.Parse()

	if len(domains) == 0 {
		fmt.Println("No domain provided. Use -i to specify one or more domains.")
		flag.Usage()
		os.Exit(-1)
	}

	lookupDomains(domains, markdown, maxConcurrentLookups, startInterval)

	fmt.Println("Fin.")
}

func lookupDomains(domains []string, markdown bool, maxConcurrentLookups int, startInterval time.Duration) {
	cleanedDomains := make([]string, 0, len(domains))
	for _, domain := range domains {
		host, _ := getHostFromURL(domain)

		if !govalidator.IsDNSName(host) {
			fmt.Printf("%s is not a valid domain\n", domain)
			continue
		}

		cleanedDomains = append(cleanedDomains, host)
	}

	if len(cleanedDomains) == 0 {
		os.Exit(-1)
	}

	results, err := digging.LookupAllRecordsForDomains(cleanedDomains, digging.BatchLookupOptions{
		MaxConcurrentLookups: maxConcurrentLookups,
		StartInterval:        startInterval,
	})
	if err != nil {
		fmt.Printf("Error setting up batch lookup: %s\n", err.Error())
		os.Exit(-1)
	}

	for _, result := range results {
		if result.Err != nil {
			fmt.Printf("Error looking up domain %q: %s\n", result.Domain, result.Err.Error())
			continue
		}

		fmt.Printf("Looking up domain: %q\n", result.Domain)

		records := result.Records
		fmt.Printf("Got %d records for domain %q:\n", records.TotalCount(), result.Domain)
		records.PrintAll()

		if markdown {
			markdownFile, err := records.WriteMarkdown()
			if err != nil {
				fmt.Printf("Error writing markdown output for %q: %s\n", result.Domain, err.Error())
				os.Exit(-1)
			}

			fmt.Printf("Saved markdown output to %q\n", markdownFile)
		}
	}
}

type domainList []string

func (d *domainList) String() string {
	return strings.Join(*d, ",")
}

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
