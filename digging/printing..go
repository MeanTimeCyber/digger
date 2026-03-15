package digging

import (
	"fmt"
	"os"
	"strings"

	"github.com/MeanTimeCyber/digger/parse"
	"github.com/markkurossi/tabulate"
)

// PrintAll prints all DNS records in formatted tables.
func (r Records) PrintAll() {
	fmt.Printf("Records for %q\n\n", r.Domain)

	// A Records
	if len(r.A) > 0 {
		fmt.Println("A (IPv4 Address) Records")
		fmt.Printf("-----------------------------\n\n")

		tab := tabulate.New(tabulate.Unicode)
		tab.Header("Address").SetAlign(tabulate.ML)

		for _, record := range r.A {
			row := tab.Row()
			row.Column(record)
		}

		tab.Print(os.Stdout)
		fmt.Println()
	}

	// AAAA Records
	if len(r.AAAA) > 0 {
		fmt.Println("AAAA (IPv6 Address) Records")
		fmt.Printf("-----------------------------\n\n")

		tab := tabulate.New(tabulate.Unicode)
		tab.Header("Address").SetAlign(tabulate.ML)

		for _, record := range r.AAAA {
			row := tab.Row()
			row.Column(record)
		}

		tab.Print(os.Stdout)
		fmt.Println()
	}

	// MX Records
	if len(r.MX) > 0 {
		fmt.Println("MX (Mail Exchange) Records")
		fmt.Printf("-----------------------------\n\n")

		tab := tabulate.New(tabulate.Unicode)
		tab.Header("Preference").SetAlign(tabulate.ML)
		tab.Header("Email Server").SetAlign(tabulate.ML)

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
		fmt.Println("NS (Name Server) Records")
		fmt.Printf("-----------------------------\n\n")

		tab := tabulate.New(tabulate.Unicode)
		tab.Header("Record").SetAlign(tabulate.ML)
		tab.Header("Name server").SetAlign(tabulate.ML)

		for i, record := range r.NS {
			row := tab.Row()
			row.Column(fmt.Sprintf("%d", i+1))
			row.Column(record)
		}

		tab.Print(os.Stdout)
		fmt.Println()
	}

	// TXT Records
	spfRecord := ""

	if len(r.TXT) > 0 {
		fmt.Println("TXT (Text) Records")
		fmt.Printf("-----------------------------\n\n")

		tab := tabulate.New(tabulate.Unicode)
		tab.Header("Record").SetAlign(tabulate.ML)
		tab.Header("Value").SetAlign(tabulate.ML)

		for i, record := range r.TXT {

			// Handle long TXT records
			if len(record) > lineLengthLimit {
				

				row := tab.Row()
				row.Column(fmt.Sprintf("%d", i+1))
				row.Column(record[:lineLengthLimit] + "...")
				row.Column(fmt.Sprintf("%d...", i+1))
				row = tab.Row()
				row.Column(record[lineLengthLimit:])
			} else {
				row := tab.Row()
				row.Column(fmt.Sprintf("%d", i+1))
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
		fmt.Println("PTR (Pointer) Records")
		fmt.Printf("-----------------------------\n\n")

		tab := tabulate.New(tabulate.Unicode)
		tab.Header("Record").SetAlign(tabulate.ML)
		tab.Header("Pointer").SetAlign(tabulate.ML)

		for i, record := range r.PTR {
			row := tab.Row()
			row.Column(fmt.Sprintf("%d", i+1))
			row.Column(record)
		}

		tab.Print(os.Stdout)
		fmt.Println()
	}

	// Print SPF Record separately if found
	if len(spfRecord) > 0 {
		fmt.Println("SPF Record")
		fmt.Printf("-----------------------------\n\n")
		fmt.Printf("Raw SPF record: %q\n\n", spfRecord)

		tab := tabulate.New(tabulate.Unicode)
		tab.Header("Key").SetAlign(tabulate.ML)
		tab.Header("Field").SetAlign(tabulate.ML)
		tab.Header("Value").SetAlign(tabulate.ML)

		fields := parse.ParseIntoFields(spfRecord, " ")
		row := tab.Row()
		row.Column("v")
		row.Column("Version")
		row.Column(fields[0])

		for i := 1; i < len(fields)-1; i++ {
			field, err := parse.ParseKeyValue(fields[i], ":")

			if err != nil {
				continue
			}

			row := tab.Row()
			row.Column(field.Key)
			row.Column(GetSPFFieldDetails(field.Key))
			row.Column(field.Value)
		}

		row = tab.Row()
		row.Column("All")
		row.Column("All other mechanisms")
		row.Column(fields[len(fields)-1])

		tab.Print(os.Stdout)
		fmt.Println()
	}

	// DMARC TXT Record
	if len(r.DMARC) > 1 {
		fmt.Printf("Note: found %d DMARC records\n", len(r.DMARC))
	}

	if len(r.DMARC) > 0 {
		fmt.Println("DMARC Record")
		fmt.Printf("-----------------------------\n\n")
		fmt.Printf("Raw DMARC record: %q\n\n", r.DMARC[0])

		tab := tabulate.New(tabulate.Unicode)
		tab.Header("Key").SetAlign(tabulate.ML)
		tab.Header("Field").SetAlign(tabulate.ML)
		tab.Header("Value").SetAlign(tabulate.ML)

		// Parse DMARC record into key-value fields
		fields, err := parse.SplitIntoKVFields(r.DMARC[0], ";", "=")

		if err == nil {
			for _, field := range fields {
				row := tab.Row()
				row.Column(field.Key)
				row.Column(GetDMARCFieldDetails(field.Key))
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
	if len(r.MTASTSRecord.TXT) > 0 {
		fmt.Println("MTA-STS Record")
		fmt.Printf("-----------------------------\n\n")

		tab := tabulate.New(tabulate.Unicode)
		tab.Header("Type").SetAlign(tabulate.ML)
		tab.Header("Record").SetAlign(tabulate.ML)

		row := tab.Row()
		row.Column("TXT Record")
		row.Column(r.MTASTSRecord.TXT)

		lines := strings.Split(r.MTASTSRecord.Policy, "\n")

			for _, line := range lines {
				field, err := parse.ParseKeyValue(line, ":")

				if err == nil {
					row := tab.Row()
					row.Column(fmt.Sprintf("Policy %s", field.Key))
					row.Column(field.Value)
				}
			}

		if len(r.MTASTSRecord.TLSRPT) > 0 {
			row := tab.Row()
			row.Column("TLS Report")
			row.Column(r.MTASTSRecord.TLSRPT)
		} 

		tab.Print(os.Stdout)
		fmt.Println()
	}
}
