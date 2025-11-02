package dns

import (
	"strings"

	"github.com/miekg/dns"
)

func Dnsnames2Regexps(dnsnames []string) []string {
	var out []string
	for _, v := range dnsnames {
		v = strings.ReplaceAll(v, ".", "\\.")
		v = strings.ReplaceAll(v, "*", ".*")
		out = append(out, "^"+v+"$")
	}
	return out
}
func Dnsname2Regexp(dnsname string) (v string) {
	v = strings.ReplaceAll(dnsname, ".", "\\.")
	v = strings.ReplaceAll(v, "*", ".*")
	return "^" + v + "$"
}

func DnsStringTypeToInt(s string) uint16 {
	switch s {
	case "A":
		return dns.TypeA
	case "AAAA":
		return dns.TypeAAAA
	case "CNAME":
		return dns.TypeCNAME
	case "MX":
		return dns.TypeMX
	case "NS":
		return dns.TypeNS
	case "PTR":
		return dns.TypePTR
	case "SOA":
		return dns.TypeSOA
	case "SRV":
		return dns.TypeSRV
	case "TXT":
		return dns.TypeTXT
	default:
		return 0
	}
}

var DnsTypeMap = []string{
	"None", "A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG", "MR", "NULL", "PTR", "HINFO", "MINFO", "MX", "TXT", "RP", "AFSDB", "X25", "ISDN", "RT", "NSAPPTR", "SIG", "KEY", "PX", "GPOS", "AAAA", "LOC", "NXT", "EID", "NIMLOC", "SRV", "ATMA", "NAPTR", "KX", "CERT", "DNAME", "OPT", "APL", "DS", "SSHFP", "IPSECKEY", "RRSIG", "NSEC", "DNSKEY", "DHCID", "NSEC3", "NSEC3PARAM", "TLSA", "SMIMEA", "HIP", "NINFO", "RKEY", "TALINK", "CDS", "CDNSKEY", "OPENPGPKEY", "CSYNC", "ZONEMD", "SVCB", "HTTPS", "SPF", "UINFO", "UID", "GID", "UNSPEC", "NID", "L32", "L64", "LP", "EUI48", "EUI64", "TKEY", "TSIG", "IXFR", "AXFR", "MAILB", "MAILA", "ANY", "URI", "CAA", "AVC", "DOA", "AMTRELAY", "TA", "DLV", "RESERVED",
}

var RcodeTypeMap = []string{
	"NoError", "FormErr", "ServFail", "NXDomain", "NotImp", "Refused", "YXDomain", "YXRRSet", "NXRRSet", "NotAuth", "NotZone", "RESERVED11", "RESERVED12", "RESERVED13", "RESERVED14", "RESERVED15", "BADVERS", "BADSIG", "BADKEY", "BADTIME", "BADMODE", "BADNAME", "BADALG", "BADTRUNC", "BADCOOKIE", "RESERVED25", "RESERVED26", "RESERVED27", "RESERVED28", "RESERVED29", "RESERVED30", "RESERVED31",
}
