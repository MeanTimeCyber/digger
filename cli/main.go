package main

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/MeanTimeCyber/digger/digging"
	"github.com/asaskevich/govalidator"
)

func main() {
	var domain string
	var markdown bool
	flag.StringVar(&domain, "i", "", "Input domain to look up")
	flag.BoolVar(&markdown, "m", false, "Also write output to a markdown file")
	flag.Parse()

	// check arg
	if domain == "" {
		fmt.Println("No domain provided. Use -i to specify a domain.")
		flag.Usage()
		os.Exit(-1)
	}

	// check the domain
	if !govalidator.IsDNSName(domain) {
		fmt.Printf("%s is not a valid domain\n", domain)
		os.Exit(-1)
	}

	// lookup all records for the domain
	lookupDomain(domain, markdown)

	fmt.Println("Fin.")
}

func lookupDomain(domain string, markdown bool) {
	// get the host, in case we have a path
	host, _ := getHostFromURL(domain)

	fmt.Printf("Looking up domain: %q\n", host)

	records, err := digging.LookupAll(domain)

	if err != nil {
		fmt.Printf("Error looking up domain %q: %s", domain, err.Error())
		os.Exit(-1)
	}

	fmt.Printf("Got %d records for domain %q:\n", records.TotalCount(), domain)
	records.PrintAll()

	if markdown {
		markdownFile, err := records.WriteMarkdown()
		if err != nil {
			fmt.Printf("Error writing markdown output for %q: %s\n", domain, err.Error())
			os.Exit(-1)
		}

		fmt.Printf("Saved markdown output to %q\n", markdownFile)
	}
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
