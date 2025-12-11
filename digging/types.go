package digging

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

func GetSPFFieldDetails(key string) string {
	switch key {
	case "ip4":
		return "Sending IPv4 Address"
	case "ip6":
		return "Sending IPv6 Address"
	case "a":
		return "Sending A Record"
	case "mx":
		return "Sending MX Record"
	case "ptr":
		return "Sending PTR Record"
	case "include":
		return "Included Sending Domain"
	case "redirect":
		return "Redirect Domain"
	case "exp":
		return "Explanation"
	default:
		return "Unknown"
	}
}

func GetDMARCFieldDetails(key string) string {
	switch key {
	case "v":
		return "Version"
	case "p":
		return "Policy"
	case "sp":
		return "Subdomain Policy"
	case "adkim":
		return "DKIM Alignment"
	case "aspf":
		return "SPF Alignment"
	case "rua":
		return "Aggregate Report URI"
	case "ruf":
		return "Forensic Report URI"
	case "pct":
		return "Percentage"
	case "fo":
		return "Failure Options"
	default:
		return "Unknown"
	}
}