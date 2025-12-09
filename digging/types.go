package digging

import (
	"fmt"
	"os"
	"strings"

	"github.com/markkurossi/tabulate"
)

type Records struct {
	A            []string
	AAAA         []string
	CNAME        []string
	MX           []string
	NS           []string
	TXT          []string
	PTR          []string
	Domain       string
	DMARC        []string
	MTASTSRecord []string
}

func (r Records) TotalCount() int {
	count := len(r.A) + len(r.AAAA) + len(r.CNAME) + len(r.MX) + len(r.NS) + len(r.TXT) + len(r.PTR)
	return count
}

func (r Records) PrintAll() {
	fmt.Printf("Records for %q\n\n", r.Domain)

	// A Records
	if len(r.A) > 0 {
		tab := tabulate.New(tabulate.Unicode)
		tab.Header("A (Address) Records").SetAlign(tabulate.ML)

		for _, record := range r.A {
			row := tab.Row()
			row.Column(record)
		}

		tab.Print(os.Stdout)
		fmt.Println()
	}

	// AAAA Records
	if len(r.AAAA) > 0 {
		tab := tabulate.New(tabulate.Unicode)
		tab.Header("AAAA (Address) Records").SetAlign(tabulate.ML)

		for _, record := range r.AAAA {
			row := tab.Row()
			row.Column(record)
		}

		tab.Print(os.Stdout)
		fmt.Println()
	}

	// MX Records
	if len(r.MX) > 0 {
		tab := tabulate.New(tabulate.Unicode)
		tab.Header("Preference").SetAlign(tabulate.MC)
		tab.Header("MX (Email Server) Records").SetAlign(tabulate.ML)

		for i, record := range r.MX {
			row := tab.Row()
			row.Column(fmt.Sprintf("%d", i))
			row.Column(record)
		}

		tab.Print(os.Stdout)
		fmt.Println()
	}

	// NS Records
	if len(r.NS) > 0 {
		tab := tabulate.New(tabulate.Unicode)
		tab.Header("NS (Name Server) Records").SetAlign(tabulate.MC)

		for _, record := range r.NS {
			row := tab.Row()
			row.Column(record)
		}

		tab.Print(os.Stdout)
		fmt.Println()
	}

	// TXT Records
	if len(r.TXT) > 0 {
		tab := tabulate.New(tabulate.Unicode)
		tab.Header("TXT (Text) Records").SetAlign(tabulate.ML)

		for _, record := range r.TXT {
			row := tab.Row()
			row.Column(record)
		}

		tab.Print(os.Stdout)
		fmt.Println()
	}

	// PTR Records
	if len(r.PTR) > 0 {
		tab := tabulate.New(tabulate.Unicode)
		tab.Header("PTR (Pointer) Records").SetAlign(tabulate.ML)

		for _, record := range r.PTR {
			row := tab.Row()
			row.Column(record)
		}

		tab.Print(os.Stdout)
		fmt.Println()
	}

	// DMARC TXT Record
	if len(r.DMARC) > 0 {
		tab := tabulate.New(tabulate.Unicode)
		tab.Header("DMARC Record").SetAlign(tabulate.ML)

		fields := strings.Split(r.DMARC[0], ";")

		for _, field := range fields {
			row := tab.Row()
			row.Column(strings.TrimSpace(field))
		}

		tab.Print(os.Stdout)
		fmt.Println()
	}

	if len(r.DMARC) > 1 {
		fmt.Printf("Note: found %d DMARC recrods\n", len(r.DMARC))
	}

	// MTA-STST Records
	if len(r.MTASTSRecord) > 0 {
		tab := tabulate.New(tabulate.Unicode)
		tab.Header("MTA-STS TXT Records").SetAlign(tabulate.ML)

		for _, record := range r.MTASTSRecord {
			row := tab.Row()
			row.Column(record)
		}

		tab.Print(os.Stdout)
		fmt.Println()
	}
}
