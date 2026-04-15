package digging

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/MeanTimeCyber/digger/parse"
	"github.com/markkurossi/tabulate"
)

func writeMarkdownTable(builder *strings.Builder, headers []string, rows [][]string) {
	builder.WriteString("|")
	for _, header := range headers {
		builder.WriteString(" ")
		builder.WriteString(header)
		builder.WriteString(" |")
	}
	builder.WriteString("\n")

	builder.WriteString("|")
	for range headers {
		builder.WriteString(" --- |")
	}
	builder.WriteString("\n")

	for _, row := range rows {
		builder.WriteString("|")
		for _, col := range row {
			sanitized := strings.ReplaceAll(col, "|", "\\|")
			sanitized = strings.ReplaceAll(sanitized, "\n", " ")
			builder.WriteString(" ")
			builder.WriteString(sanitized)
			builder.WriteString(" |")
		}
		builder.WriteString("\n")
	}

	builder.WriteString("\n")
}

// WriteMarkdown saves all DNS records in Markdown tables and returns the created filename.
func (r Records) WriteMarkdown() (string, error) {
	var sb strings.Builder

	sb.WriteString("# DNS Records for \"")
	sb.WriteString(r.Domain)
	sb.WriteString("\"\n\n")

	if len(r.A) > 0 {
		sb.WriteString("## A (IPv4 Address) Records\n\n")
		rows := make([][]string, 0, len(r.A))
		for _, record := range r.A {
			rows = append(rows, []string{record})
		}
		writeMarkdownTable(&sb, []string{"Address"}, rows)
	}

	if len(r.AAAA) > 0 {
		sb.WriteString("## AAAA (IPv6 Address) Records\n\n")
		rows := make([][]string, 0, len(r.AAAA))
		for _, record := range r.AAAA {
			rows = append(rows, []string{record})
		}
		writeMarkdownTable(&sb, []string{"Address"}, rows)
	}

	if len(r.MX) > 0 {
		sb.WriteString("## MX (Mail Exchange) Records\n\n")
		rows := make([][]string, 0, len(r.MX))
		for i, record := range r.MX {
			rows = append(rows, []string{fmt.Sprintf("%d", i), record})
		}
		writeMarkdownTable(&sb, []string{"Preference", "Email Server"}, rows)
	}

	if len(r.NS) > 0 {
		sb.WriteString("## NS (Name Server) Records\n\n")
		rows := make([][]string, 0, len(r.NS))
		for i, record := range r.NS {
			rows = append(rows, []string{fmt.Sprintf("%d", i+1), record})
		}
		writeMarkdownTable(&sb, []string{"Record", "Name Server"}, rows)
	}

	spfRecord := ""
	if len(r.TXT) > 0 {
		sb.WriteString("## TXT (Text) Records\n\n")
		rows := make([][]string, 0, len(r.TXT))
		for i, record := range r.TXT {
			rows = append(rows, []string{fmt.Sprintf("%d", i+1), record})
			if strings.HasPrefix(record, "v=spf1 ") {
				spfRecord = record
			}
		}
		writeMarkdownTable(&sb, []string{"Record", "Value"}, rows)
	}

	if len(r.PTR) > 0 {
		sb.WriteString("## PTR (Pointer) Records\n\n")
		rows := make([][]string, 0, len(r.PTR))
		for i, record := range r.PTR {
			rows = append(rows, []string{fmt.Sprintf("%d", i+1), record})
		}
		writeMarkdownTable(&sb, []string{"Record", "Pointer"}, rows)
	}

	if len(spfRecord) > 0 {
		sb.WriteString("## SPF Record\n\n")
		sb.WriteString("Raw SPF record: `")
		sb.WriteString(spfRecord)
		sb.WriteString("`\n\n")

		rows := make([][]string, 0)
		fields := parse.ParseIntoFields(spfRecord, " ")
		if len(fields) > 0 {
			rows = append(rows, []string{"v", "Version", fields[0]})

			for i := 1; i < len(fields)-1; i++ {
				field, err := parse.ParseKeyValue(fields[i], ":")
				if err != nil {
					continue
				}

				rows = append(rows, []string{field.Key, GetSPFFieldDetails(field.Key), field.Value})
			}

			rows = append(rows, []string{"All", "All other mechanisms", fields[len(fields)-1]})
		}

		writeMarkdownTable(&sb, []string{"Key", "Field", "Value"}, rows)
	}

	if len(r.DMARC) > 1 {
		sb.WriteString(fmt.Sprintf("Note: found %d DMARC records\n\n", len(r.DMARC)))
	}

	if len(r.DMARC) > 0 {
		sb.WriteString("## DMARC Record\n\n")
		sb.WriteString("Raw DMARC record: `")
		sb.WriteString(r.DMARC[0])
		sb.WriteString("`\n\n")

		rows := make([][]string, 0)
		fields, err := parse.SplitIntoKVFields(r.DMARC[0], ";", "=")
		if err == nil {
			for _, field := range fields {
				rows = append(rows, []string{field.Key, GetDMARCFieldDetails(field.Key), field.Value})
			}
		} else {
			rows = append(rows, []string{"(raw)", "(unparseable)", r.DMARC[0]})
		}

		writeMarkdownTable(&sb, []string{"Key", "Field", "Value"}, rows)
	}

	if len(r.MTASTSRecord.TXT) > 0 {
		sb.WriteString("## MTA-STS Record\n\n")

		rows := make([][]string, 0)
		rows = append(rows, []string{"TXT Record", r.MTASTSRecord.TXT})

		lines := strings.Split(r.MTASTSRecord.Policy, "\n")
		for _, line := range lines {
			field, err := parse.ParseKeyValue(line, ":")
			if err != nil {
				continue
			}

			rows = append(rows, []string{fmt.Sprintf("Policy %s", field.Key), field.Value})
		}

		if len(r.MTASTSRecord.TLSRPT) > 0 {
			rows = append(rows, []string{"TLS Report", r.MTASTSRecord.TLSRPT})
		}

		writeMarkdownTable(&sb, []string{"Type", "Record"}, rows)
	}

	fileName := fmt.Sprintf("%s-%s.md", r.Domain, time.Now().Format("20060102-150405"))
	err := os.WriteFile(fileName, []byte(sb.String()), 0o644)
	if err != nil {
		return "", err
	}

	return fileName, nil
}

// PrintAll prints all DNS records in formatted tables.
func (r Records) PrintAll() {

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
			row := tab.Row()
			row.Column(fmt.Sprintf("%d", i+1))

			// Break long records into multiple rows
			if len(record) > lineLengthLimit {
				row.Column(record[:lineLengthLimit])
				// Add continuation rows for the remainder
				remaining := record[lineLengthLimit:]
				for len(remaining) > 0 {
					row = tab.Row()
					if len(remaining) > lineLengthLimit {
						row.Column("")
						row.Column(remaining[:lineLengthLimit])
						remaining = remaining[lineLengthLimit:]
					} else {
						row.Column("")
						row.Column(remaining)
						remaining = ""
					}
				}
			} else {
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
			row := tab.Row()
			row.Column("(raw)")
			row.Column("(unparseable)")

			// Break long record into multiple rows
			dmarc := r.DMARC[0]
			if len(dmarc) > lineLengthLimit {
				row.Column(dmarc[:lineLengthLimit])
				// Add continuation rows for the remainder
				remaining := dmarc[lineLengthLimit:]
				for len(remaining) > 0 {
					row = tab.Row()
					row.Column("")
					row.Column("")
					if len(remaining) > lineLengthLimit {
						row.Column(remaining[:lineLengthLimit])
						remaining = remaining[lineLengthLimit:]
					} else {
						row.Column(remaining)
						remaining = ""
					}
				}
			} else {
				row.Column(dmarc)
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
