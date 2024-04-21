package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

const (
	dohURL  = "https://cloudflare-dns.com/dns-query"
	dotHost = "9.9.9.9"
	dotPort = "853"
	author  = "Nicholas Albright (@nma-io)"
	version = "2024.0.1"
)

var recordType string

func init() { // Toying with the init function a bit to pre-build our flags
	flag.StringVar(&recordType, "t", "A", "DNS record type (e.g., A, AAAA, MX)")
}

type dnsJSONResponse struct {
	Answer []struct {
		Data string `json:"data"`
		Type int    `json:"type"`
		TTL  int    `json:"TTL"`
	} `json:"Answer"`
}

func dohQuery(domain, recordType string) ([]string, error) {
	req, err := http.NewRequest("GET", dohURL, nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Add("name", domain)
	q.Add("type", recordType)
	req.URL.RawQuery = q.Encode()
	req.Header.Add("Accept", "application/dns-json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var dnsResp dnsJSONResponse
	if err := json.Unmarshal(body, &dnsResp); err != nil {
		return nil, err
	}

	var results []string
	for _, answer := range dnsResp.Answer {
		formattedRecord := fmt.Sprintf("%v %d %s", dns.TypeToString[uint16(answer.Type)], answer.TTL, answer.Data)
		results = append(results, formattedRecord)
	}
	return results, nil
}

func dotQuery(domain, recordType string) ([]string, error) {
	c := new(dns.Client)
	c.Net = "tcp-tls"
	c.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.StringToType[recordType])
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, dotHost+":"+dotPort)
	if err != nil {
		return nil, err
	}

	var results []string
	for _, answer := range r.Answer {
		header := answer.Header()
		var recordData string
		switch rr := answer.(type) {
		case *dns.CNAME:
			recordData = rr.Target
		case *dns.A:
			recordData = rr.A.String()
		case *dns.AAAA:
			recordData = rr.AAAA.String()
		case *dns.MX:
			recordData = fmt.Sprintf("%v %s", rr.Preference, rr.Mx)
		case *dns.NS:
			recordData = rr.Ns
		case *dns.TXT:
			recordData = strings.Join(rr.Txt, " ")
		case *dns.SOA:
			recordData = fmt.Sprintf("%s %s %d %d %d %d %d", rr.Ns, rr.Mbox, rr.Serial, rr.Refresh, rr.Retry, rr.Expire, rr.Minttl)
		case *dns.PTR:
			recordData = rr.Ptr
		case *dns.SRV:
			recordData = fmt.Sprintf("%d %d %d %s", rr.Priority, rr.Weight, rr.Port, rr.Target)
		case *dns.CAA:
			recordData = fmt.Sprintf("%d %s %s", rr.Flag, rr.Tag, rr.Value)
		}

		formattedRecord := fmt.Sprintf("%v %d %s", dns.TypeToString[header.Rrtype], header.Ttl, recordData)
		results = append(results, formattedRecord)
	}
	return results, nil
}

func traditionalQuery(domain, recordType string) ([]string, error) {
	c := new(dns.Client)
	c.Net = "udp"

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.StringToType[recordType])
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return nil, err
	}

	var results []string
	for _, answer := range r.Answer {
		header := answer.Header()
		var recordData string
		switch rr := answer.(type) {
		case *dns.CNAME:
			recordData = rr.Target
		case *dns.A:
			recordData = rr.A.String()
		case *dns.AAAA:
			recordData = rr.AAAA.String()
		case *dns.MX:
			recordData = fmt.Sprintf("%v %s", rr.Preference, rr.Mx)
		case *dns.NS:
			recordData = rr.Ns
		case *dns.TXT:
			recordData = strings.Join(rr.Txt, " ")
		case *dns.SOA:
			recordData = fmt.Sprintf("%s %s %d %d %d %d %d", rr.Ns, rr.Mbox, rr.Serial, rr.Refresh, rr.Retry, rr.Expire, rr.Minttl)
		case *dns.PTR:
			recordData = rr.Ptr
		case *dns.SRV:
			recordData = fmt.Sprintf("%d %d %d %s", rr.Priority, rr.Weight, rr.Port, rr.Target)
		case *dns.CAA:
			recordData = fmt.Sprintf("%d %s %s", rr.Flag, rr.Tag, rr.Value)
		}

		formattedRecord := fmt.Sprintf("%v %d %s", dns.TypeToString[header.Rrtype], header.Ttl, recordData)
		results = append(results, formattedRecord)
	}
	return results, nil
}

func main() {
	flag.Parse()

	domain := flag.Arg(0)
	if domain == "" {
		fmt.Println("Domain not specified")
		return
	}
	fmt.Println("PFDNS v" + version + " by " + author)
	fmt.Println("Domain: " + domain)

	recordType = strings.ToUpper(recordType) // Ensure record type is uppercase
	fmt.Println("Trying DoH...")
	response, err := dohQuery(domain, recordType)
	if err != nil {
		fmt.Println("DoH failed:", err)
	}
	fmt.Printf("Response received:	\n")
	for _, record := range response {
		fmt.Printf("\t" + record + "\n")
	}
	fmt.Println("Trying DoT...")
	response, err = dotQuery(domain, recordType)
	if err != nil {
		fmt.Println("DoT failed:", err)
		return
	}

	fmt.Printf("Response received:	\n")
	for _, record := range response {
		fmt.Printf("\t" + record + "\n")
	}
	fmt.Println("Trying Traditional DNS...")
	response, err = traditionalQuery(domain, recordType)
	if err != nil {
		fmt.Println("Traditional DNS failed:", err)
		return
	}
	if len(response) == 0 {
		fmt.Println("No records found")
		return
	}

	fmt.Printf("Response received:	\n")
	for _, record := range response {
		fmt.Printf("\t" + record + "\n")
	}

}
