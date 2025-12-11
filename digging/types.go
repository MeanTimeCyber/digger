package digging

import (
	"fmt"
	"os"
	"strings"

	"github.com/MeanTimeCyber/digger/parse"
	"github.com/markkurossi/tabulate"
)

const lineLengthLimit = 90

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
	spfRecord := ""

	if len(r.TXT) > 0 {
		tab := tabulate.New(tabulate.Unicode)
		tab.Header("TXT (Text) Records").SetAlign(tabulate.ML)

		for _, record := range r.TXT {
			// Handle long TXT records
			if len(record) > lineLengthLimit {
				row := tab.Row()
				row.Column(record[:lineLengthLimit] + "...")
				row = tab.Row()
				row.Column(record[lineLengthLimit:])
			} else {
				row := tab.Row()
				row.Column(record)
			}

			if strings.HasPrefix(record, "v=spf1 ") {
				spfRecord = record
			}
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

	// Print SPF Record separately if found
	if len(spfRecord) > 0 {
		tab := tabulate.New(tabulate.Unicode)
		tab.Header("Field").SetAlign(tabulate.ML)
		tab.Header("Value").SetAlign(tabulate.ML)

		fields := parse.ParseIntoFields(spfRecord, " ")
		row := tab.Row()
		row.Column("Version")
		row.Column(fields[0])

		for i := 1; i < len(fields)-1; i++ {
			field, err := parse.ParseKeyValue(fields[i], ":")

			if err != nil {
				continue
			}

			row := tab.Row()
			row.Column(field.Key)
			row.Column(field.Value)
		}

		row = tab.Row()
		row.Column("Others")
		row.Column(fields[len(fields)-1])

		tab.Print(os.Stdout)
		fmt.Println()
	}

	// DMARC TXT Record
	if len(r.DMARC) > 0 {
		tab := tabulate.New(tabulate.Unicode)
		tab.Header("Field").SetAlign(tabulate.ML)
		tab.Header("Value").SetAlign(tabulate.ML)

		// Parse DMARC record into key-value fields
		fields, err := parse.SplitIntoKVFields(r.DMARC[0], ";", "=")

		if err == nil {
			for _, field := range fields {
				row := tab.Row()
				row.Column(field.Key)
				row.Column(field.Value)
			}

		} else {
			// Splitting failed, print raw DMARC record
			// Handle long DMARC record
			if len(r.DMARC[0]) > lineLengthLimit {
				row := tab.Row()
				row.Column(r.DMARC[0][:lineLengthLimit] + "...")
				row = tab.Row()
				row.Column(r.DMARC[0][lineLengthLimit:])
			} else {
				row := tab.Row()
				row.Column(r.DMARC[0])
			}
		}

		tab.Print(os.Stdout)
		fmt.Println()
	}

	if len(r.DMARC) > 1 {
		fmt.Printf("Note: found %d DMARC recrods\n", len(r.DMARC))
	}

	// MTA-STS Records
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
