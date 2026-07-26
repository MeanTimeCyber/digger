package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/MeanTimeCyber/digger/digging"
	"github.com/asaskevich/govalidator"
)

func main() {
	// define and parse command line args
	var domains domainList
	var domainList string
	var markdown bool
	var maxConcurrentLookups int
	var startInterval time.Duration

	flag.Var(&domains, "i", "Input domain to look up (repeat the flag or separate values with commas)")
	flag.StringVar(&domainList, "l", "", "Input file containing domains to look up (one per line)")
	flag.BoolVar(&markdown, "m", false, "Also write output to a markdown file")
	flag.IntVar(&maxConcurrentLookups, "c", 4, "Maximum number of lookups to run at once")
	flag.DurationVar(&startInterval, "interval", 250*time.Millisecond, "Delay between starting each lookup")
	flag.Parse()

	// lookup domains from command line or file
	if len(domains) != 0 {
		fmt.Printf("Looking up %d domains\n", len(domains))
		lookupDomains(domains, markdown, maxConcurrentLookups, startInterval)
	} else if domainList != "" {
		var err error
		domains, err = readDomainsFromFile(domainList)

		if err != nil {
			fmt.Printf("Error reading domains from file %q: %s\n", domainList, err.Error())
			os.Exit(-1)
		}

		fmt.Printf("Read %d domains from file %q\n", len(domains), domainList)
		lookupDomains(domains, markdown, maxConcurrentLookups, startInterval)
	} else {
		fmt.Println("No domain provided. Use -i to specify one or more domains, or -l to specify an input file.")
		flag.Usage()
		os.Exit(-1)
	}

	fmt.Println("Fin.")
}

// lookupDomains looks up all records for the provided domains and prints the results to stdout.
// If markdown is true, it also writes the results to a markdown file.
func lookupDomains(domains []string, markdown bool, maxConcurrentLookups int, startInterval time.Duration) {
	// Clean and validate domains
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
		fmt.Println("No clean domains to process")
		os.Exit(-1)
	}

	// Lookup all records for the cleaned domains
	results, err := digging.LookupAllRecordsForDomains(cleanedDomains, digging.BatchLookupOptions{
		MaxConcurrentLookups: maxConcurrentLookups,
		StartInterval:        startInterval,
	})
	if err != nil {
		fmt.Printf("Error setting up batch lookup: %s\n", err.Error())
		os.Exit(-1)
	}

	// Print results
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
